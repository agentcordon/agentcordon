// ============================================================================
// Workspace-initiated credential creation (workspace JWT auth)
// ============================================================================

use axum::{extract::State, Json};
use serde::Deserialize;

use agent_cordon_core::domain::credential::CredentialSummary;

use crate::extractors::AuthenticatedWorkspace;
use crate::middleware::request_id::CorrelationId;
use crate::response::{ApiError, ApiResponse};
use crate::services::credentials::NewCredentialParams;
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
    /// Optional vault, by id. A workspace may only use the system default,
    /// so anything else is refused by the placement rule.
    vault_id: Option<String>,
    /// Fences the credential to a URL pattern, checked on every vend. Absent
    /// or blank means unrestricted: the credential may be proxied anywhere.
    allowed_url_pattern: Option<String>,
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
    auth.require_scope(agent_cordon_core::oauth2::types::OAuthScope::CredentialsVend)?;
    let workspace = &auth.workspace;

    if !workspace.is_active() {
        return Err(ApiError::Forbidden("workspace is disabled".to_string()));
    }

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

    let credential_type = req.credential_type.unwrap_or_else(|| "generic".to_string());

    // A blank pattern is "unrestricted", not "a pattern that matches
    // nothing" — the same normalisation the update route applies.
    let allowed_url_pattern = req
        .allowed_url_pattern
        .map(|p| p.trim().to_string())
        .filter(|p| !p.is_empty());

    // Auto-add llm_exposed tag
    let mut tags = req.tags.unwrap_or_default();
    if !tags.iter().any(|t| t == "llm_exposed") {
        tags.push("llm_exposed".to_string());
    }

    let cred = state
        .services
        .credentials
        .create_from_workspace(
            &auth,
            &corr.0,
            NewCredentialParams {
                name: req.name,
                service: req.service,
                secret_value: req.secret_value,
                credential_type,
                scopes: req.scopes.unwrap_or_default(),
                metadata: req
                    .metadata
                    .unwrap_or(serde_json::Value::Object(Default::default())),
                tags,
                vault_id: req.vault_id,
                created_by: Some(workspace.id.clone()),
                created_by_user: workspace.owner_id.clone(),
                allowed_url_pattern,
                expires_at: None,
                transform_script: None,
                transform_name: None,
                description: None,
                target_identity: None,
            },
        )
        .await?;

    Ok(Json(ApiResponse::ok(CredentialSummary::from(cred))))
}
