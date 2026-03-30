use axum::{
    extract::{FromRef, FromRequestParts},
    http::request::Parts,
};

use agent_cordon_core::domain::workspace::Workspace;

use crate::extractors::oauth::AuthenticatedOAuthWorkspace;
use crate::response::ApiError;
use crate::state::AppState;

/// An authenticated workspace, validated via an OAuth 2.0 Bearer token.
///
/// This is the single auth extractor for all workspace requests.
/// Internally delegates to [`AuthenticatedOAuthWorkspace`].
pub struct AuthenticatedWorkspace {
    pub workspace: Workspace,
}

impl AuthenticatedWorkspace {
    /// Backward-compat accessor: returns the workspace as `agent`.
    pub fn agent(&self) -> &Workspace {
        &self.workspace
    }
}

impl<S> FromRequestParts<S> for AuthenticatedWorkspace
where
    AppState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let oauth = AuthenticatedOAuthWorkspace::from_request_parts(parts, state).await?;
        Ok(AuthenticatedWorkspace {
            workspace: oauth.workspace,
        })
    }
}

/// Authenticate a workspace via OAuth 2.0 Bearer token in the Authorization header.
///
/// This is the function-based equivalent of the extractor, for callsites that
/// need to authenticate from a raw header value rather than via Axum extractors.
pub(crate) async fn authenticate_workspace(
    state: &AppState,
    auth_header: &str,
) -> Result<Workspace, ApiError> {
    let token = auth_header
        .strip_prefix("Bearer ")
        .ok_or_else(|| ApiError::Unauthorized("expected Bearer token".to_string()))?;

    let token_hash = crate::routes::oauth::hash_token(token);

    let access_token = state
        .store
        .get_oauth_access_token(&token_hash)
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?
        .ok_or_else(|| ApiError::Unauthorized("invalid access token".to_string()))?;

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

    let client = state
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

    let workspace = state
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

    Ok(workspace)
}
