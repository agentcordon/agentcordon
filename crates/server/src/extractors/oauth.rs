//! OAuth 2.0 Bearer token extractor for workspace authentication.
//!
//! Validates opaque OAuth access tokens via SHA-256 hash lookup. The
//! validation lives in one function, `authenticate_bearer`, used by the
//! extractor here and by the header-based entry point in
//! `authenticated_workspace.rs`, so a lifecycle rule added in one place
//! applies to every workspace request.

use axum::{
    extract::{FromRef, FromRequestParts},
    http::request::Parts,
};

use crate::response::ApiError;
use crate::routes::oauth::hash_token;
use crate::state::AppState;
use agent_cordon_core::domain::user::UserId;
use agent_cordon_core::domain::workspace::{Workspace, WorkspaceStatus};
use agent_cordon_core::oauth2::types::OAuthScope;

/// Authenticated workspace context derived from an OAuth 2.0 access token.
pub struct AuthenticatedOAuthWorkspace {
    pub workspace: Workspace,
    pub user_id: UserId,
    pub scopes: Vec<OAuthScope>,
    pub client_id: String,
    /// Full OAuth token claims for audit enrichment. Excludes token_hash (secret).
    /// Automatically includes all fields — new claims added to OAuthAccessToken
    /// or OAuthClient will appear here without code changes.
    pub oauth_claims: serde_json::Value,
}

/// Validate an `Authorization` header value and resolve the workspace it
/// belongs to.
///
/// 1. Expects `Bearer <token>`
/// 2. SHA-256 hashes the token and looks up `oauth_access_tokens`
/// 3. Rejects revoked or expired tokens and revoked clients
/// 4. Loads the workspace via the client's public key hash
/// 5. Rejects a workspace that is disabled or not `Active`
pub(crate) async fn authenticate_bearer(
    app_state: &AppState,
    auth_header: &str,
) -> Result<AuthenticatedOAuthWorkspace, ApiError> {
    let token = auth_header
        .strip_prefix("Bearer ")
        .ok_or_else(|| ApiError::Unauthorized("expected Bearer token".to_string()))?;

    let token_hash = hash_token(token);

    // One store call: token, its client's revocation state, and the
    // workspace the token is bound to by id.
    let resolved = app_state
        .store
        .resolve_bearer(&token_hash)
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?
        .ok_or_else(|| ApiError::Unauthorized("invalid access token".to_string()))?;
    let access_token = resolved.token;
    let client = resolved.client;

    if access_token.revoked_at.is_some() {
        return Err(ApiError::Unauthorized(
            "access token has been revoked".to_string(),
        ));
    }

    if access_token.expires_at < chrono::Utc::now() {
        return Err(ApiError::Unauthorized(
            "access token has expired".to_string(),
        ));
    }

    if client.revoked_at.is_some() {
        return Err(ApiError::Unauthorized(
            "OAuth client has been revoked".to_string(),
        ));
    }

    let workspace = resolved.workspace.ok_or_else(|| {
        ApiError::Unauthorized("workspace not found for OAuth client".to_string())
    })?;

    if !matches!(workspace.status, WorkspaceStatus::Active) {
        return Err(ApiError::Forbidden(format!(
            "workspace is {}",
            workspace.status.as_str()
        )));
    }

    tracing::debug!(
        workspace_id = %workspace.id.0,
        client_id = %access_token.client_id,
        auth_method = "oauth_bearer",
        "workspace request authenticated via OAuth token"
    );

    // Complete claims snapshot for audit. Serialize the full token + client
    // context so new fields appear in audit logs without code changes.
    let oauth_claims = serde_json::json!({
        "client_id": access_token.client_id,
        "scopes": access_token.scopes,
        "user_id": access_token.user_id.0.to_string(),
        "token_created_at": access_token.created_at.to_rfc3339(),
        "token_expires_at": access_token.expires_at.to_rfc3339(),
        "public_key_hash": client.public_key_hash,
        "workspace_name": client.workspace_name,
        "redirect_uris": client.redirect_uris,
        "allowed_scopes": client.allowed_scopes,
    });

    Ok(AuthenticatedOAuthWorkspace {
        workspace,
        user_id: access_token.user_id,
        scopes: access_token.scopes,
        client_id: access_token.client_id,
        oauth_claims,
    })
}

impl<S> FromRequestParts<S> for AuthenticatedOAuthWorkspace
where
    AppState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let app_state = AppState::from_ref(state);

        let auth_header = parts
            .headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| {
                ApiError::Unauthorized("workspace authentication required".to_string())
            })?;

        authenticate_bearer(&app_state, auth_header).await
    }
}
