//! Server-side MCP tool-call authorization endpoint.
//!
//! `POST /api/v1/workspaces/mcp-authorize` — evaluates Cedar policy for an
//! MCP tool call and returns the permit/forbid decision with contributing
//! policy reasons.

use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use agent_cordon_core::domain::audit::{AuditDecision, AuditEvent, AuditEventType};
use agent_cordon_core::domain::policy::{PolicyDecisionResult, PolicyId};
use agent_cordon_core::policy::{
    actions, PolicyContext, PolicyEngine, PolicyPrincipal, PolicyResource,
};

use crate::extractors::AuthenticatedWorkspace;
use crate::response::{ApiError, ApiResponse};
use crate::state::AppState;

/// Request body for MCP tool-call authorization.
#[derive(Deserialize)]
pub struct McpAuthorizeRequest {
    server_name: String,
    tool_name: String,
}

/// A single reason entry in the authorization response.
#[derive(Serialize)]
pub struct AuthorizeReasonEntry {
    reason: String,
    policy_id: Option<String>,
    policy_name: Option<String>,
    statement_index: Option<usize>,
}

/// Response for MCP tool-call authorization.
#[derive(Serialize)]
pub struct McpAuthorizeResponse {
    decision: String,
    reasons: Vec<AuthorizeReasonEntry>,
    correlation_id: String,
}

/// POST /api/v1/workspaces/mcp-authorize — evaluate Cedar policy for an MCP tool call.
///
/// Auth: workspace identity JWT (Authorization: Bearer).
/// Returns the permit/forbid decision with contributing policy reasons.
pub(super) async fn authorize(
    State(state): State<AppState>,
    workspace: AuthenticatedWorkspace,
    Json(req): Json<McpAuthorizeRequest>,
) -> Result<Json<ApiResponse<McpAuthorizeResponse>>, ApiError> {
    workspace.require_scope(agent_cordon_core::oauth2::types::OAuthScope::McpInvoke)?;
    let correlation_id = Uuid::new_v4().to_string();

    // Validate inputs.
    let server_name = req.server_name.trim().to_string();
    let tool_name = req.tool_name.trim().to_string();
    if server_name.is_empty() || server_name.len() > 128 {
        return Err(ApiError::BadRequest(
            "server_name must be 1-128 characters".into(),
        ));
    }
    if tool_name.is_empty() || tool_name.len() > 128 {
        return Err(ApiError::BadRequest(
            "tool_name must be 1-128 characters".into(),
        ));
    }

    // MCP servers are a shared catalog — look up by name across all servers,
    // not scoped to the requesting workspace.  Cedar policy handles authorization.
    let all_servers = state.store.list_mcp_servers().await?;
    let mcp_server = all_servers
        .into_iter()
        .find(|s| s.name == server_name && s.enabled);

    let mcp_server = match mcp_server {
        Some(s) => s,
        None => {
            // Unknown server — forbid and audit.
            let event = AuditEvent::builder(AuditEventType::McpToolCallDenied)
                .action(&format!("mcp_tool_call/{}", tool_name))
                .resource("mcp_server", &server_name)
                .workspace_actor(&workspace.workspace.id, &workspace.workspace.name)
                .decision(AuditDecision::Forbid, Some("unknown_server"))
                .details(serde_json::json!({
                    "server_name": server_name,
                    "tool_name": tool_name,
                    "policy_decision": "forbid",
                }))
                .correlation_id(&correlation_id)
                .build();

            if let Err(e) = state.store.append_audit_event(&event).await {
                tracing::warn!(error = %e, "failed to write mcp-authorize audit event");
            }

            return Ok(Json(ApiResponse::ok(McpAuthorizeResponse {
                decision: "forbid".to_string(),
                reasons: vec![AuthorizeReasonEntry {
                    reason: "unknown_server".to_string(),
                    policy_id: None,
                    policy_name: None,
                    statement_index: None,
                }],
                correlation_id,
            })));
        }
    };

    // Evaluate Cedar policy.
    let policy_ctx = PolicyContext {
        tool_name: Some(tool_name.clone()),
        correlation_id: Some(correlation_id.clone()),
        oauth_claims: workspace.oauth_claims.clone(),
        ..Default::default()
    };

    let resource = PolicyResource::McpServer {
        id: mcp_server.id.0.to_string(),
        name: mcp_server.name.clone(),
        enabled: mcp_server.enabled,
        tags: mcp_server.tags.clone(),
    };

    let decision = state.policy_engine.evaluate(
        &PolicyPrincipal::Workspace(&workspace.workspace),
        actions::MCP_TOOL_CALL,
        &resource,
        &policy_ctx,
    )?;

    let is_permit = decision.decision == PolicyDecisionResult::Permit;
    let decision_str = if is_permit { "permit" } else { "forbid" };

    // Resolve reasons: parse `{uuid}_{index}` format, look up policy names.
    let mut reasons = Vec::new();
    for reason_str in &decision.reasons {
        let (policy_id_str, statement_index) = match reason_str.rfind('_') {
            Some(pos) => {
                let suffix = &reason_str[pos + 1..];
                match suffix.parse::<usize>() {
                    Ok(idx) => (&reason_str[..pos], Some(idx)),
                    Err(_) => (reason_str.as_str(), None),
                }
            }
            None => (reason_str.as_str(), None),
        };

        let policy_name = if let Ok(uuid) = Uuid::parse_str(policy_id_str) {
            match state.store.get_policy(&PolicyId(uuid)).await {
                Ok(Some(p)) => Some(p.name),
                _ => None,
            }
        } else {
            None
        };

        reasons.push(AuthorizeReasonEntry {
            reason: decision_str.to_string(),
            policy_id: Some(policy_id_str.to_string()),
            policy_name,
            statement_index,
        });
    }

    // Policy decision audit is emitted automatically by AuditingPolicyEngine.

    Ok(Json(ApiResponse::ok(McpAuthorizeResponse {
        decision: decision_str.to_string(),
        reasons,
        correlation_id,
    })))
}
