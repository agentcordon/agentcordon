//! OAuth 2.0 Bearer token extractor for workspace authentication.
//!
//! Replaces the old JWT-based `AuthenticatedWorkspace` extractor.
//! Validates opaque OAuth access tokens via SHA-256 hash lookup.

use axum::{
    extract::{FromRef, FromRequestParts},
    http::request::Parts,
};

use agent_cordon_core::domain::user::UserId;
use agent_cordon_core::domain::workspace::Workspace;
use agent_cordon_core::oauth2::types::OAuthScope;
use crate::response::ApiError;
use crate::routes::oauth::hash_token;
use crate::state::AppState;

/// Authenticated workspace context derived from an OAuth 2.0 access token.
///
/// This extractor:
/// 1. Reads the `Authorization: Bearer <token>` header
/// 2. SHA-256 hashes the token
/// 3. Looks up `oauth_access_tokens` by hash
/// 4. Verifies not revoked and not expired
/// 5. Loads the OAuth client to find the workspace
/// 6. Returns workspace + user_id + scopes
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

impl<S> FromRequestParts<S> for AuthenticatedOAuthWorkspace
where
    AppState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let app_state = AppState::from_ref(state);

        // Extract Bearer token from Authorization header
        let auth_header = parts
            .headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| {
                ApiError::Unauthorized("workspace authentication required".to_string())
            })?;

        let token = auth_header
            .strip_prefix("Bearer ")
            .ok_or_else(|| ApiError::Unauthorized("expected Bearer token".to_string()))?;

        // Hash the token for lookup
        let token_hash = hash_token(token);

        // Look up the access token
        let access_token = app_state
            .store
            .get_oauth_access_token(&token_hash)
            .await
            .map_err(|e| ApiError::Internal(e.to_string()))?
            .ok_or_else(|| ApiError::Unauthorized("invalid access token".to_string()))?;

        // Check not revoked
        if access_token.revoked_at.is_some() {
            return Err(ApiError::Unauthorized(
                "access token has been revoked".to_string(),
            ));
        }

        // Check not expired
        if access_token.expires_at < chrono::Utc::now() {
            return Err(ApiError::Unauthorized(
                "access token has expired".to_string(),
            ));
        }

        // Look up the OAuth client to find the workspace via public_key_hash
        let client = app_state
            .store
            .get_oauth_client_by_client_id(&access_token.client_id)
            .await
            .map_err(|e| ApiError::Internal(e.to_string()))?
            .ok_or_else(|| {
                ApiError::Unauthorized("OAuth client not found for token".to_string())
            })?;

        if client.revoked_at.is_some() {
            return Err(ApiError::Unauthorized(
                "OAuth client has been revoked".to_string(),
            ));
        }

        // Look up workspace by public_key_hash
        let workspace = app_state
            .store
            .get_workspace_by_pk_hash(&client.public_key_hash)
            .await
            .map_err(|e| ApiError::Internal(e.to_string()))?
            .ok_or_else(|| {
                ApiError::Unauthorized("workspace not found for OAuth client".to_string())
            })?;

        if !workspace.enabled {
            return Err(ApiError::Forbidden("workspace is disabled".to_string()));
        }

        tracing::debug!(
            workspace_id = %workspace.id.0,
            client_id = %access_token.client_id,
            auth_method = "oauth_bearer",
            "workspace request authenticated via OAuth token"
        );

        // Build complete claims snapshot for audit. Serialize the full token +
        // client context so any new fields added in the future automatically
        // appear in audit logs without code changes.
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
}
