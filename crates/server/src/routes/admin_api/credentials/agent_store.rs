// ============================================================================
// Workspace-initiated credential creation (workspace JWT auth)
// ============================================================================

use axum::{extract::State, Json};
use serde::Deserialize;

use agent_cordon_core::domain::audit::{AuditDecision, AuditEvent, AuditEventType};
use agent_cordon_core::domain::credential::CredentialSummary;
use agent_cordon_core::domain::policy::PolicyDecisionResult;
use agent_cordon_core::policy::actions;
use agent_cordon_core::policy::{PolicyContext, PolicyEngine, PolicyPrincipal, PolicyResource};

use crate::credential_service::{self, NewCredentialParams};
use crate::extractors::AuthenticatedWorkspace;
use crate::middleware::request_id::CorrelationId;
use crate::response::{ApiError, ApiResponse};
use crate::state::AppState;

#[derive(Deserialize)]
pub(crate) struct AgentStoreRequest {
    name: String,
    service: String,
    secret_value: String,
    credential_type: Option<String>,
    tags: Option<Vec<String>>,
    scopes: Option<Vec<String>>,
    metadata: Option<serde_json::Value>,
    vault: Option<String>,
    /// Workspace ID from caller (ignored — derived from JWT for security).
    #[allow(dead_code)]
    workspace_id: Option<String>,
    /// Workspace name from caller (ignored — derived from JWT for security).
    #[allow(dead_code)]
    workspace_name: Option<String>,
}

/// POST /api/v1/credentials/agent-store — workspace-initiated credential creation.
///
/// Accepts workspace JWT auth (Authorization: Bearer).
/// Auto-adds `llm_exposed` tag. Sets `created_by` to the workspace identity.
/// Emits a `CredentialCreated` audit event with `source: "workspace"`.
pub(crate) async fn agent_store_credential(
    State(state): State<AppState>,
    axum::Extension(corr): axum::Extension<CorrelationId>,
    auth: AuthenticatedWorkspace,
    Json(req): Json<AgentStoreRequest>,
) -> Result<Json<ApiResponse<CredentialSummary>>, ApiError> {
    let workspace = &auth.workspace;

    if !workspace.enabled {
        return Err(ApiError::Forbidden("workspace is disabled".to_string()));
    }

    // Use workspace identity from validated JWT
    let workspace_id = workspace.id.clone();
    let workspace_name = workspace.name.clone();

    // Validate required fields
    if req.name.trim().is_empty() {
        return Err(ApiError::BadRequest("name is required".to_string()));
    }
    if req.service.trim().is_empty() {
        return Err(ApiError::BadRequest("service is required".to_string()));
    }
    if req.secret_value.is_empty() {
        return Err(ApiError::BadRequest("secret_value is required".to_string()));
    }

    // Validate credential_type
    let credential_type = req.credential_type.unwrap_or_else(|| "generic".to_string());
    credential_service::validate_credential_type(&credential_type)?;

    // Cedar policy evaluation — workspace must be authorized to create credentials
    let policy_decision = state.policy_engine.evaluate(
        &PolicyPrincipal::Workspace(workspace),
        actions::CREATE,
        &PolicyResource::System,
        &PolicyContext {
            target_url: None,
            requested_scopes: vec![],
            ..Default::default()
        },
    )?;

    if policy_decision.decision == PolicyDecisionResult::Forbid {
        // Audit the denial
        let event = AuditEvent::builder(AuditEventType::CredentialCreated)
            .action("create")
            .workspace_actor(&workspace_id, &workspace_name)
            .resource_type("credential")
            .correlation_id(&corr.0)
            .decision(
                AuditDecision::Forbid,
                Some(&format!(
                    "workspace_policy: [{}]",
                    policy_decision.reasons.join(", "),
                )),
            )
            .details(serde_json::json!({
                "credential_name": req.name,
                "source": "workspace_store",
            }))
            .build();
        if let Err(e) = state.store.append_audit_event(&event).await {
            tracing::warn!(error = %e, "Failed to write audit event");
        }

        return Err(ApiError::Forbidden("access denied by policy".to_string()));
    }

    // Auto-add llm_exposed tag
    let mut tags = req.tags.unwrap_or_default();
    if !tags.iter().any(|t| t == "llm_exposed") {
        tags.push("llm_exposed".to_string());
    }

    // Build credential via shared service (generates ID, encrypts secret)
    let cred = credential_service::build_credential(
        state.encryptor.as_ref(),
        NewCredentialParams {
            name: req.name.clone(),
            service: req.service.clone(),
            secret_value: req.secret_value,
            credential_type,
            scopes: req.scopes.unwrap_or_default(),
            metadata: req
                .metadata
                .unwrap_or(serde_json::Value::Object(Default::default())),
            tags,
            vault: req.vault.unwrap_or_else(|| "default".to_string()),
            created_by: Some(workspace_id.clone()),
            created_by_user: workspace.owner_id.clone(),
            allowed_url_pattern: None,
            expires_at: None,
            transform_script: None,
            transform_name: None,
            description: None,
            target_identity: None,
        },
    )?;

    // Try to store the credential; on conflict, return 409.
    // Do NOT return metadata about the existing credential — that would leak
    // information about other workspaces' credentials on name collision.
    match state.store.store_credential(&cred).await {
        Ok(()) => {}
        Err(agent_cordon_core::error::StoreError::Conflict { .. }) => {
            return Err(ApiError::Conflict(
                "credential with this name already exists".to_string(),
            ));
        }
        Err(e) => return Err(e.into()),
    };

    // Audit event
    let event = AuditEvent::builder(AuditEventType::CredentialCreated)
        .action("create")
        .workspace_actor(&workspace_id, &workspace_name)
        .resource("credential", &cred.id.0.to_string())
        .correlation_id(&corr.0)
        .decision(
            AuditDecision::Permit,
            Some("workspace-initiated credential creation"),
        )
        .details(serde_json::json!({
            "credential_name": req.name,
            "service": req.service,
            "source": "workspace",
            "llm_exposed": true,
        }))
        .build();
    if let Err(e) = state.store.append_audit_event(&event).await {
        tracing::warn!(error = %e, "Failed to write audit event");
    }

    credential_service::emit_credential_created(&state, cred.id.0, req.name.clone());

    Ok(Json(ApiResponse::ok(CredentialSummary::from(cred))))
}
