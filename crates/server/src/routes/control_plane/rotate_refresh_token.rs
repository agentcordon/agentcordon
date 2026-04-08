//! Workspace-scoped OAuth2 refresh-token rotation endpoint.
//!
//! `POST /api/v1/workspaces/mcp/rotate-refresh-token` — called by the broker
//! when an upstream OAuth2 provider rotates a refresh token on refresh. The
//! endpoint persists ONLY the new refresh token, scoped strictly to the
//! calling workspace's own credentials.
//!
//! SECURITY
//! - Authenticated via `AuthenticatedWorkspace` (workspace OAuth Bearer).
//! - Requires the `mcp:invoke` scope.
//! - Looks up the target credential by `(workspace_id, credential_name)`;
//!   a credential not owned by the caller is treated as not-found so the
//!   endpoint cannot be used to probe or mutate foreign credentials.
//! - Only credentials of type `oauth2_user_authorization` may be rotated.
//! - The new refresh token value is encrypted with the credential ID as AAD
//!   and MUST NEVER appear in logs, errors, or audit `details`.

use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};

use agent_cordon_core::crypto::SecretEncryptor;
use agent_cordon_core::domain::audit::{AuditDecision, AuditEvent, AuditEventType};
use agent_cordon_core::domain::credential::CredentialUpdate;

use crate::extractors::AuthenticatedWorkspace;
use crate::response::{ApiError, ApiResponse};
use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct RotateRefreshTokenRequest {
    pub credential_name: String,
    /// The new refresh token returned by the upstream provider. NEVER logged.
    pub new_refresh_token: String,
}

#[derive(Debug, Serialize)]
pub struct RotateRefreshTokenResponse {
    pub rotated: bool,
}

/// POST /api/v1/workspaces/mcp/rotate-refresh-token
pub(super) async fn rotate(
    State(state): State<AppState>,
    workspace: AuthenticatedWorkspace,
    Json(req): Json<RotateRefreshTokenRequest>,
) -> Result<Json<ApiResponse<RotateRefreshTokenResponse>>, ApiError> {
    workspace.require_scope(agent_cordon_core::oauth2::types::OAuthScope::McpInvoke)?;

    // Validate inputs.
    let credential_name = req.credential_name.trim().to_string();
    if credential_name.is_empty() || credential_name.len() > 256 {
        return Err(ApiError::BadRequest(
            "credential_name must be 1-256 characters".into(),
        ));
    }
    if req.new_refresh_token.is_empty() || req.new_refresh_token.len() > 8192 {
        return Err(ApiError::BadRequest(
            "new_refresh_token must be 1-8192 bytes".into(),
        ));
    }

    // Look up the credential scoped to the caller's workspace. A credential
    // not owned by this workspace is reported as not-found so the endpoint
    // cannot be used as an oracle for foreign credential names.
    let cred = state
        .store
        .get_credential_by_workspace_and_name(&workspace.workspace.id, &credential_name)
        .await?
        .ok_or_else(|| ApiError::NotFound("credential not found".to_string()))?;

    if cred.credential_type != "oauth2_user_authorization" {
        return Err(ApiError::BadRequest(
            "credential is not an oauth2_user_authorization credential".to_string(),
        ));
    }

    // Archive the old secret before overwriting so history/restore still works.
    state
        .store
        .store_secret_history(
            &cred.id,
            &cred.encrypted_value,
            &cred.nonce,
            None,
            Some(&workspace.workspace.id.0.to_string()),
        )
        .await?;

    // Encrypt the new refresh token with the credential ID as AAD, matching
    // the encryption layout used by the credential create/update paths.
    let (encrypted, nonce) = state.encryptor.encrypt(
        req.new_refresh_token.as_bytes(),
        cred.id.0.to_string().as_bytes(),
    )?;

    // Scoped partial update: ONLY the encrypted secret changes. All other
    // fields are `None` so the existing update_credential path is a no-op
    // for them. This prevents this endpoint from being used to mutate
    // unrelated fields.
    let updates = CredentialUpdate {
        name: None,
        service: None,
        scopes: None,
        metadata: None,
        allowed_url_pattern: None,
        expires_at: None,
        transform_script: None,
        transform_name: None,
        vault: None,
        tags: None,
        description: None,
        target_identity: None,
        encrypted_value: Some(encrypted),
        nonce: Some(nonce),
        key_version: None,
    };

    let updated = state.store.update_credential(&cred.id, &updates).await?;
    if !updated {
        return Err(ApiError::Internal(
            "credential disappeared during rotation".to_string(),
        ));
    }

    // Audit event: reuse CredentialSecretRotated and tag the source so audit
    // consumers can distinguish operator-initiated rotations from OAuth2
    // provider-initiated rotations. The refresh token value itself is NEVER
    // included in the audit details.
    let event = AuditEvent::builder(AuditEventType::CredentialSecretRotated)
        .action("oauth2_refresh_token_rotated")
        .workspace_actor(&workspace.workspace.id, &workspace.workspace.name)
        .resource("credential", &cred.id.0.to_string())
        .decision(AuditDecision::Permit, Some("oauth2_refresh_rotation"))
        .details(serde_json::json!({
            "credential_name": cred.name,
            "credential_type": cred.credential_type,
            "rotation_source": "oauth2_provider",
        }))
        .build();
    if let Err(e) = state.store.append_audit_event(&event).await {
        tracing::warn!(
            error = %e,
            "failed to write OAuth2 refresh-token rotation audit event"
        );
    }

    tracing::info!(
        workspace_id = %workspace.workspace.id.0,
        credential_name = %credential_name,
        "persisted rotated OAuth2 refresh token"
    );

    Ok(Json(ApiResponse::ok(RotateRefreshTokenResponse {
        rotated: true,
    })))
}
