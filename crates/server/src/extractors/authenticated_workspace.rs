use axum::{
    extract::{FromRef, FromRequestParts},
    http::request::Parts,
};

use agent_cordon_core::domain::user::UserId;
use agent_cordon_core::domain::workspace::Workspace;
use agent_cordon_core::oauth2::types::OAuthScope;

use crate::extractors::oauth::AuthenticatedOAuthWorkspace;
use crate::response::ApiError;
use crate::state::AppState;

/// An authenticated workspace, validated via an OAuth 2.0 Bearer token.
///
/// This is the single auth extractor for all workspace requests.
/// Internally delegates to [`AuthenticatedOAuthWorkspace`] and preserves
/// the full OAuth context (user_id and scopes) for scope enforcement.
pub struct AuthenticatedWorkspace {
    pub workspace: Workspace,
    pub user_id: Option<UserId>,
    pub scopes: Vec<OAuthScope>,
    pub client_id: Option<String>,
    /// Full OAuth token claims for audit. See [`AuthenticatedOAuthWorkspace::oauth_claims`].
    pub oauth_claims: Option<serde_json::Value>,
}

impl AuthenticatedWorkspace {
    /// Backward-compat accessor: returns the workspace as `agent`.
    pub fn agent(&self) -> &Workspace {
        &self.workspace
    }

    /// Check that this token has the required OAuth scope.
    pub fn require_scope(&self, scope: OAuthScope) -> Result<(), ApiError> {
        if self.scopes.contains(&scope) {
            Ok(())
        } else {
            Err(ApiError::Forbidden(format!(
                "insufficient OAuth scope: requires {}",
                scope
            )))
        }
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
            user_id: Some(oauth.user_id),
            scopes: oauth.scopes,
            client_id: Some(oauth.client_id),
            oauth_claims: Some(oauth.oauth_claims),
        })
    }
}

/// Authenticate a workspace via OAuth 2.0 Bearer token in the Authorization header.
///
/// Function-based entry point for callsites that hold a raw header value
/// rather than request parts. Same validation as the extractor.
pub(crate) async fn authenticate_workspace(
    state: &AppState,
    auth_header: &str,
) -> Result<AuthenticatedWorkspace, ApiError> {
    let oauth = crate::extractors::oauth::authenticate_bearer(state, auth_header).await?;
    Ok(AuthenticatedWorkspace {
        workspace: oauth.workspace,
        user_id: Some(oauth.user_id),
        scopes: oauth.scopes,
        client_id: Some(oauth.client_id),
        oauth_claims: Some(oauth.oauth_claims),
    })
}
