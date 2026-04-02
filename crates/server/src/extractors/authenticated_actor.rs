use axum::{
    extract::{FromRef, FromRequestParts},
    http::request::Parts,
};

use agent_cordon_core::domain::user::{ActorId, User};
use agent_cordon_core::domain::workspace::{Workspace, WorkspaceId};
use agent_cordon_core::oauth2::types::OAuthScope;
use agent_cordon_core::policy::{PolicyContext, PolicyPrincipal};

use crate::response::ApiError;
use crate::state::AppState;

use super::authenticated_user::AuthenticatedUser;
use super::authenticated_workspace::AuthenticatedWorkspace;

/// An authenticated actor that is either a User (via session cookie) or a Workspace
/// (via Bearer token). Tries session cookie first, then falls back to Bearer auth.
pub enum AuthenticatedActor {
    User(User),
    Workspace {
        workspace: Workspace,
        scopes: Vec<OAuthScope>,
        oauth_claims: Option<serde_json::Value>,
    },
}

impl AuthenticatedActor {
    /// Returns the actor's identity as an `ActorId`.
    pub fn actor_id(&self) -> ActorId {
        match self {
            AuthenticatedActor::User(user) => ActorId::User(user.id.clone()),
            AuthenticatedActor::Workspace { workspace, .. } => ActorId::Agent(workspace.id.clone()),
        }
    }

    /// Convert this actor into a `PolicyPrincipal` for Cedar policy evaluation.
    pub fn policy_principal(&self) -> PolicyPrincipal<'_> {
        match self {
            AuthenticatedActor::User(user) => PolicyPrincipal::User(user),
            AuthenticatedActor::Workspace { workspace, .. } => PolicyPrincipal::Workspace(workspace),
        }
    }

    /// Check if the actor has a required OAuth scope.
    /// Always returns Ok for users (scopes are a workspace concept).
    pub fn require_scope(&self, scope: OAuthScope) -> Result<(), ApiError> {
        match self {
            AuthenticatedActor::User(_) => Ok(()),
            AuthenticatedActor::Workspace { scopes, .. } => {
                if scopes.contains(&scope) {
                    Ok(())
                } else {
                    Err(ApiError::Forbidden(format!(
                        "insufficient OAuth scope: requires {}",
                        scope
                    )))
                }
            }
        }
    }

    /// Extract audit event actor fields: (workspace_id, workspace_name, user_id, username).
    pub fn audit_actor_fields(
        &self,
    ) -> (
        Option<WorkspaceId>,
        Option<String>,
        Option<String>,
        Option<String>,
    ) {
        match self {
            AuthenticatedActor::User(user) => (
                None,
                None,
                Some(user.id.0.to_string()),
                Some(user.username.clone()),
            ),
            AuthenticatedActor::Workspace { workspace, .. } => (
                Some(workspace.id.clone()),
                Some(workspace.name.clone()),
                None,
                None,
            ),
        }
    }

    /// Return the OAuth token claims if this actor authenticated via OAuth.
    /// Returns `None` for session-authenticated users.
    pub fn oauth_claims(&self) -> Option<&serde_json::Value> {
        match self {
            AuthenticatedActor::User(_) => None,
            AuthenticatedActor::Workspace { oauth_claims, .. } => oauth_claims.as_ref(),
        }
    }

    /// Build a `PolicyContext` pre-populated with this actor's OAuth claims
    /// and the given correlation ID. Use this instead of constructing
    /// `PolicyContext` manually — it ensures token claims are always
    /// included in audit metadata for workspace-authenticated requests.
    pub fn policy_context(&self, correlation_id: Option<String>) -> PolicyContext {
        PolicyContext {
            correlation_id,
            oauth_claims: self.oauth_claims().cloned(),
            ..Default::default()
        }
    }
}

impl<S> FromRequestParts<S> for AuthenticatedActor
where
    AppState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        // Try session cookie first (user auth)
        if let Ok(auth_user) = AuthenticatedUser::from_request_parts(parts, state).await {
            return Ok(AuthenticatedActor::User(auth_user.user));
        }

        // Fall back to Bearer token (workspace auth)
        let auth_workspace = AuthenticatedWorkspace::from_request_parts(parts, state).await?;
        Ok(AuthenticatedActor::Workspace {
            workspace: auth_workspace.workspace,
            scopes: auth_workspace.scopes,
            oauth_claims: auth_workspace.oauth_claims,
        })
    }
}
