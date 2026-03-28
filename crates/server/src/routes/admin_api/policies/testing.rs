use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use agent_cordon_core::domain::audit::{AuditDecision, AuditEvent, AuditEventType};
use agent_cordon_core::domain::credential::{CredentialId, StoredCredential};
use agent_cordon_core::domain::policy::PolicyDecisionResult;
use agent_cordon_core::domain::user::{User, UserId, UserRole};
use agent_cordon_core::domain::workspace::{Workspace, WorkspaceId, WorkspaceStatus};
use agent_cordon_core::policy::{PolicyContext, PolicyEngine, PolicyPrincipal, PolicyResource};

use crate::extractors::AuthenticatedUser;
use crate::middleware::request_id::CorrelationId;
use crate::response::{ApiError, ApiResponse};
use crate::state::AppState;

use super::check_manage_policies;

// --- Policy test endpoint types ---

#[derive(Deserialize)]
pub(crate) struct TestPolicyRequest {
    principal: Option<TestPrincipal>,
    action: Option<String>,
    resource: Option<TestResource>,
    context: Option<TestContext>,
}

#[derive(Deserialize)]
struct TestPrincipal {
    #[serde(rename = "type")]
    entity_type: String,
    id: String,
    #[serde(default)]
    attributes: TestPrincipalAttributes,
}

#[derive(Deserialize, Default)]
struct TestPrincipalAttributes {
    tags: Option<Vec<String>>,
    enabled: Option<bool>,
    name: Option<String>,
    role: Option<String>,
    is_root: Option<bool>,
    owner: Option<String>,
}

#[derive(Deserialize)]
struct TestResource {
    #[serde(rename = "type")]
    entity_type: String,
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    attributes: TestResourceAttributes,
}

#[derive(Deserialize, Default)]
struct TestResourceAttributes {
    name: Option<String>,
    service: Option<String>,
    scopes: Option<Vec<String>>,
    owner: Option<String>,
    tags: Option<Vec<String>>,
    enabled: Option<bool>,
}

#[derive(Deserialize, Default)]
struct TestContext {
    target_url: Option<String>,
    requested_scopes: Option<Vec<String>>,
    tag_value: Option<String>,
    tool_name: Option<String>,
    credential_name: Option<String>,
}

#[derive(Serialize)]
struct DiagnosticDetail {
    reason: String,
    policy_id: Option<String>,
    statement_index: Option<usize>,
}

#[derive(Serialize)]
pub(super) struct TestPolicyResponse {
    decision: String,
    diagnostics: Vec<String>,
    diagnostic_details: Vec<DiagnosticDetail>,
}

/// Parse a string as UUID. If it's not a valid UUID, generate a deterministic
/// one by hashing the input. This allows the test endpoint to accept arbitrary
/// string IDs (like "test-agent") while still producing valid domain objects.
fn id_to_uuid(id: &str) -> Uuid {
    Uuid::parse_str(id).unwrap_or_else(|_| {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        id.hash(&mut hasher);
        let hash = hasher.finish();
        let bytes = hash.to_le_bytes();
        let mut uuid_bytes = [0u8; 16];
        uuid_bytes[..8].copy_from_slice(&bytes);
        uuid_bytes[8..16].copy_from_slice(&bytes);
        uuid::Builder::from_bytes(uuid_bytes)
            .with_variant(uuid::Variant::RFC4122)
            .with_version(uuid::Version::Random)
            .into_uuid()
    })
}

/// Build a `PolicyResource` from the test request's resource type and attributes.
fn build_test_resource(
    entity_type: &str,
    resource_id: Uuid,
    attrs: &TestResourceAttributes,
) -> Result<PolicyResource, ApiError> {
    match entity_type {
        "Credential" => {
            let cred_id = CredentialId(resource_id);

            let credential = StoredCredential {
                id: cred_id,
                name: attrs.name.clone().unwrap_or_default(),
                service: attrs.service.clone().unwrap_or_default(),
                encrypted_value: vec![],
                nonce: vec![],
                scopes: attrs.scopes.clone().unwrap_or_default(),
                metadata: serde_json::json!({}),
                created_by: None,
                created_by_user: attrs.owner.as_ref().map(|o| UserId(id_to_uuid(o))),
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
                allowed_url_pattern: None,
                expires_at: None,
                transform_script: None,
                transform_name: None,
                vault: "default".to_string(),
                credential_type: "generic".to_string(),
                tags: attrs.tags.clone().unwrap_or_default(),
                description: None,
                target_identity: None,
                key_version: 1,
            };

            Ok(PolicyResource::Credential { credential })
        }
        "System" => Ok(PolicyResource::System),
        "PolicyResource" => Ok(PolicyResource::PolicyAdmin),
        "WorkspaceResource" | "AgentResource" => {
            let workspace = Workspace {
                id: WorkspaceId(resource_id),
                name: attrs.name.clone().unwrap_or_default(),
                tags: vec![],
                enabled: attrs.enabled.unwrap_or(true),
                status: WorkspaceStatus::Active,
                pk_hash: None,
                encryption_public_key: None,
                owner_id: attrs.owner.as_ref().map(|o| UserId(id_to_uuid(o))),
                parent_id: None,
                tool_name: None,
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
            };
            Ok(PolicyResource::WorkspaceResource { workspace })
        }
        "McpServer" => Ok(PolicyResource::McpServer {
            id: resource_id.to_string(),
            name: attrs.name.clone().unwrap_or_default(),
            enabled: attrs.enabled.unwrap_or(true),
            tags: attrs.tags.clone().unwrap_or_default(),
        }),
        other => Err(ApiError::BadRequest(format!(
            "unknown resource type: {other}"
        ))),
    }
}

/// Evaluate a Cedar policy with caller-supplied principal, action, resource,
/// and context. Returns the permit/deny decision and diagnostic policy IDs.
///
/// Requires `manage_policies` permission (root users bypass via Cedar).
pub(super) async fn test_policy(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
    axum::Extension(corr): axum::Extension<CorrelationId>,
    Json(req): Json<TestPolicyRequest>,
) -> Result<Json<ApiResponse<TestPolicyResponse>>, ApiError> {
    let policy_decision = check_manage_policies(&state, &auth)?;

    // Validate required fields
    let principal_req = req
        .principal
        .ok_or_else(|| ApiError::BadRequest("principal is required".to_string()))?;
    let action = req
        .action
        .ok_or_else(|| ApiError::BadRequest("action is required".to_string()))?;
    let resource_req = req
        .resource
        .ok_or_else(|| ApiError::BadRequest("resource is required".to_string()))?;
    let context_req = req.context.unwrap_or_default();

    // Build PolicyContext
    let policy_context = PolicyContext {
        target_url: context_req.target_url,
        requested_scopes: context_req.requested_scopes.unwrap_or_default(),
        tool_name: context_req.tool_name,
        credential_name: context_req.credential_name,
        tag_value: context_req.tag_value,
        ..Default::default()
    };

    // Build resource
    let resource_id = id_to_uuid(resource_req.id.as_deref().unwrap_or("system"));
    let resource = build_test_resource(
        &resource_req.entity_type,
        resource_id,
        &resource_req.attributes,
    )?;

    // Build principal and evaluate
    let attrs = &principal_req.attributes;
    let principal_id = id_to_uuid(&principal_req.id);

    let decision = match principal_req.entity_type.as_str() {
        "Workspace" | "Agent" | "Device" => {
            let workspace = Workspace {
                id: WorkspaceId(principal_id),
                name: attrs.name.clone().unwrap_or_default(),
                tags: attrs.tags.clone().unwrap_or_default(),
                enabled: attrs.enabled.unwrap_or(true),
                status: WorkspaceStatus::Active,
                pk_hash: None,
                encryption_public_key: None,
                owner_id: attrs.owner.as_ref().map(|o| UserId(id_to_uuid(o))),
                parent_id: None,
                tool_name: None,
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
            };
            state
                .policy_engine
                .evaluate(
                    &PolicyPrincipal::Workspace(&workspace),
                    &action,
                    &resource,
                    &policy_context,
                )
                .map_err(|e| ApiError::BadRequest(format!("policy evaluation error: {e}")))?
        }
        "User" => {
            let user = User {
                id: UserId(principal_id),
                username: attrs.name.clone().unwrap_or_default(),
                display_name: None,
                password_hash: String::new(),
                role: match attrs.role.as_deref() {
                    Some("admin") => UserRole::Admin,
                    Some("operator") => UserRole::Operator,
                    _ => UserRole::Viewer,
                },
                is_root: attrs.is_root.unwrap_or(false),
                enabled: attrs.enabled.unwrap_or(true),
                show_advanced: true,
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
            };
            state
                .policy_engine
                .evaluate(
                    &PolicyPrincipal::User(&user),
                    &action,
                    &resource,
                    &policy_context,
                )
                .map_err(|e| ApiError::BadRequest(format!("policy evaluation error: {e}")))?
        }
        other => {
            return Err(ApiError::BadRequest(format!(
                "unknown principal type: {other}"
            )));
        }
    };

    let decision_str = match decision.decision {
        PolicyDecisionResult::Permit => "permit",
        PolicyDecisionResult::Forbid => {
            if decision.reasons.is_empty() {
                "deny"
            } else {
                "forbid"
            }
        }
    };

    // Audit log
    let audit_decision = match decision.decision {
        PolicyDecisionResult::Permit => AuditDecision::Permit,
        PolicyDecisionResult::Forbid => AuditDecision::Forbid,
    };
    let event = AuditEvent::builder(AuditEventType::PolicyEvaluated)
        .action("test_policy")
        .user_actor(&auth.user)
        .resource_type("policy")
        .correlation_id(&corr.0)
        .decision(audit_decision, Some(&policy_decision.reasons.join(", ")))
        .details(serde_json::json!({
            "test_action": action,
            "test_principal_type": principal_req.entity_type,
            "test_resource_type": resource_req.entity_type,
            "test_decision": decision_str,
        }))
        .build();
    if let Err(e) = state.store.append_audit_event(&event).await {
        tracing::warn!(error = %e, "Failed to write audit event");
    }

    let diagnostic_details: Vec<DiagnosticDetail> = decision
        .reasons
        .iter()
        .map(|r| {
            let (policy_id, statement_index) = match r.rfind('_') {
                Some(pos) => {
                    let suffix = &r[pos + 1..];
                    match suffix.parse::<usize>() {
                        Ok(idx) => (Some(r[..pos].to_string()), Some(idx)),
                        Err(_) => (None, None),
                    }
                }
                None => (None, None),
            };
            DiagnosticDetail {
                reason: r.clone(),
                policy_id,
                statement_index,
            }
        })
        .collect();

    Ok(Json(ApiResponse::ok(TestPolicyResponse {
        decision: decision_str.to_string(),
        diagnostics: decision.reasons,
        diagnostic_details,
    })))
}
