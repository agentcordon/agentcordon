use std::collections::HashMap;

use axum::{extract::State, routing::post, Json, Router};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use agent_cordon_core::domain::audit::{AuditDecision, AuditEvent, AuditEventType};
use agent_cordon_core::domain::credential::CredentialId;
use agent_cordon_core::domain::mcp::McpServerId;
use agent_cordon_core::domain::policy::{PolicyDecisionResult, StoredPolicy};
use agent_cordon_core::policy::{
    actions, PolicyContext, PolicyEngine, PolicyPrincipal, PolicyResource,
};

use crate::extractors::AuthenticatedUser;
use crate::middleware::request_id::CorrelationId;
use crate::response::{ApiError, ApiResponse};
use crate::state::AppState;

use super::policies::check_manage_policies;

pub fn routes() -> Router<AppState> {
    Router::new().route("/policies/rsop", post(rsop))
}

// --- Request / Response types ---

#[derive(Deserialize)]
struct RsopRequest {
    resource_type: String,
    resource_id: Uuid,
    limit: Option<usize>,
}

#[derive(Serialize)]
struct RsopResponse {
    resource: RsopResource,
    evaluated_at: String,
    principal_count: usize,
    matrix: Vec<RsopMatrixEntry>,
    conditional_policies: Vec<ConditionalPolicy>,
}

#[derive(Serialize)]
struct RsopResource {
    #[serde(rename = "type")]
    resource_type: String,
    id: Uuid,
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    service: Option<String>,
}

#[derive(Serialize)]
struct RsopMatrixEntry {
    principal_type: String,
    principal_id: Uuid,
    principal_name: String,
    principal_tags: Vec<String>,
    results: HashMap<String, ActionResult>,
}

#[derive(Serialize)]
struct ActionResult {
    decision: String,
    reasons: Vec<ReasonEntry>,
}

#[derive(Serialize)]
struct ReasonEntry {
    reason: String,
    policy_id: Option<Uuid>,
    policy_name: Option<String>,
    statement_index: Option<usize>,
}

#[derive(Serialize)]
struct ConditionalPolicy {
    policy_name: String,
    policy_id: Uuid,
    condition_type: String,
    description: String,
}

// --- Conditional policy detection patterns ---

const CONDITION_PATTERNS: &[(&str, &str, &str)] = &[
    (
        "context.timestamp",
        "time-based",
        "Policy depends on evaluation time",
    ),
    (
        "context.tool_name",
        "tool-specific",
        "Policy depends on the MCP tool being called",
    ),
    (
        "context.tag_value",
        "tag-dependent",
        "Policy depends on tag values",
    ),
    (
        "context.requested_scopes",
        "scope-dependent",
        "Policy depends on requested scopes",
    ),
    (
        "context.target_url",
        "url-dependent",
        "Policy depends on the target URL",
    ),
    (
        "context.credential_name",
        "credential-specific",
        "Policy depends on credential name",
    ),
];

// --- Helpers ---

fn resolve_reasons(
    reasons: &[String],
    policy_map: &HashMap<Uuid, StoredPolicy>,
) -> Vec<ReasonEntry> {
    reasons
        .iter()
        .map(|reason| {
            let parsed = reason.rfind('_').and_then(|pos| {
                let prefix = &reason[..pos];
                let suffix = &reason[pos + 1..];
                let uuid = Uuid::parse_str(prefix).ok()?;
                let idx = suffix.parse::<usize>().ok();
                Some((uuid, idx))
            });

            match parsed {
                Some((uuid, idx)) => {
                    let policy = policy_map.get(&uuid);
                    ReasonEntry {
                        reason: reason.clone(),
                        policy_id: Some(uuid),
                        policy_name: policy.map(|p| p.name.clone()),
                        statement_index: idx,
                    }
                }
                None => ReasonEntry {
                    reason: reason.clone(),
                    policy_id: None,
                    policy_name: None,
                    statement_index: None,
                },
            }
        })
        .collect()
}

// --- Handler ---

async fn rsop(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
    axum::Extension(corr): axum::Extension<CorrelationId>,
    Json(req): Json<RsopRequest>,
) -> Result<Json<ApiResponse<RsopResponse>>, ApiError> {
    check_manage_policies(&state, &auth)?;

    let limit = req.limit.unwrap_or(100).min(500);
    let now = chrono::Utc::now();

    // Pre-fetch all policies for reason resolution
    let all_policies = state.store.get_all_enabled_policies().await?;
    let policy_map: HashMap<Uuid, StoredPolicy> =
        all_policies.iter().map(|p| (p.id.0, p.clone())).collect();

    // Load target resource and determine actions + resource repr for evaluation
    let (resource_meta, _actions, build_resource, default_context) =
        match req.resource_type.as_str() {
            "Credential" => {
                let cred = state
                    .store
                    .get_credential(&CredentialId(req.resource_id))
                    .await?
                    .ok_or_else(|| ApiError::NotFound("credential not found".to_string()))?;

                let meta = RsopResource {
                    resource_type: "Credential".to_string(),
                    id: req.resource_id,
                    name: cred.name.clone(),
                    service: Some(cred.service.clone()),
                };

                let context = PolicyContext {
                    requested_scopes: cred.scopes.clone(),
                    credential_name: Some(cred.name.clone()),
                    ..Default::default()
                };

                let resource = PolicyResource::Credential { credential: cred };

                let actions = vec![
                    actions::ACCESS,
                    actions::VEND_CREDENTIAL,
                    actions::LIST,
                    actions::UPDATE,
                    actions::DELETE,
                    actions::MANAGE_PERMISSIONS,
                    actions::UNPROTECT,
                ];

                (meta, actions, resource, context)
            }
            "McpServer" => {
                let server = state
                    .store
                    .get_mcp_server(&McpServerId(req.resource_id))
                    .await?
                    .ok_or_else(|| ApiError::NotFound("MCP server not found".to_string()))?;

                let meta = RsopResource {
                    resource_type: "McpServer".to_string(),
                    id: req.resource_id,
                    name: server.name.clone(),
                    service: None,
                };

                let context = PolicyContext::default();

                let resource = PolicyResource::McpServer {
                    id: server.id.0.to_string(),
                    name: server.name.clone(),
                    enabled: server.enabled,
                    tags: server.tags.clone(),
                };

                let actions = vec![actions::MCP_TOOL_CALL, actions::MCP_LIST_TOOLS];

                (meta, actions, resource, context)
            }
            other => {
                return Err(ApiError::BadRequest(format!(
                    "invalid resource_type: {other}. Expected 'Credential' or 'McpServer'"
                )));
            }
        };

    // All actions evaluated against Workspace principals
    let workspace_actions: &[&str] = match req.resource_type.as_str() {
        "Credential" => &[
            actions::ACCESS,
            actions::VEND_CREDENTIAL,
            actions::LIST,
            actions::UPDATE,
            actions::DELETE,
            actions::MANAGE_PERMISSIONS,
            actions::UNPROTECT,
        ],
        "McpServer" => &[actions::MCP_TOOL_CALL, actions::MCP_LIST_TOOLS],
        _ => &[],
    };

    let mut matrix = Vec::new();

    // Evaluate workspaces
    let workspaces = state.store.list_workspaces().await?;
    for workspace in workspaces.iter().take(limit) {
        let mut results = HashMap::new();
        for &action in workspace_actions {
            let decision = state.policy_engine.evaluate(
                &PolicyPrincipal::Workspace(workspace),
                action,
                &build_resource,
                &default_context,
            )?;

            results.insert(
                action.to_string(),
                ActionResult {
                    decision: match decision.decision {
                        PolicyDecisionResult::Permit => "permit".to_string(),
                        PolicyDecisionResult::Forbid => {
                            if decision.reasons.is_empty() {
                                "deny".to_string()
                            } else {
                                "forbid".to_string()
                            }
                        }
                    },
                    reasons: resolve_reasons(&decision.reasons, &policy_map),
                },
            );
        }

        matrix.push(RsopMatrixEntry {
            principal_type: "Workspace".to_string(),
            principal_id: workspace.id.0,
            principal_name: workspace.name.clone(),
            principal_tags: workspace.tags.clone(),
            results,
        });
    }

    // Detect conditional policies
    let conditional_policies = detect_conditional_policies(&all_policies);

    // Audit event for RSoP evaluation
    let event = AuditEvent::builder(AuditEventType::PolicyEvaluated)
        .action("policy_rsop_evaluated")
        .user_actor(&auth.user)
        .resource(&req.resource_type, &req.resource_id.to_string())
        .correlation_id(&corr.0)
        .decision(AuditDecision::Permit, Some("bypass:rsop_evaluation"))
        .details(serde_json::json!({
            "resource_name": resource_meta.name,
            "principal_count": matrix.len(),
            "limit": limit,
        }))
        .build();
    if let Err(e) = state.store.append_audit_event(&event).await {
        tracing::warn!(error = %e, "Failed to write audit event");
    }

    Ok(Json(ApiResponse::ok(RsopResponse {
        resource: resource_meta,
        evaluated_at: now.to_rfc3339(),
        principal_count: matrix.len(),
        matrix,
        conditional_policies,
    })))
}

/// Scan all enabled policies for context-dependent conditions.
fn detect_conditional_policies(policies: &[StoredPolicy]) -> Vec<ConditionalPolicy> {
    let mut result = Vec::new();

    for policy in policies {
        for &(pattern, condition_type, description) in CONDITION_PATTERNS {
            if policy.cedar_policy.contains(pattern) {
                result.push(ConditionalPolicy {
                    policy_name: policy.name.clone(),
                    policy_id: policy.id.0,
                    condition_type: condition_type.to_string(),
                    description: description.to_string(),
                });
            }
        }
    }

    result
}
