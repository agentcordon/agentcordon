use axum::{
    extract::{FromRef, FromRequestParts},
    http::request::Parts,
};

use agent_cordon_core::domain::user::{ActorId, User};
use agent_cordon_core::domain::workspace::{Workspace, WorkspaceId};
use agent_cordon_core::policy::PolicyPrincipal;

use crate::response::ApiError;
use crate::state::AppState;

use super::authenticated_user::AuthenticatedUser;
use super::authenticated_workspace::AuthenticatedWorkspace;

/// An authenticated actor that is either a User (via session cookie) or a Workspace
/// (via Bearer token). Tries session cookie first, then falls back to Bearer auth.
pub enum AuthenticatedActor {
    User(User),
    Workspace(Workspace),
}

impl AuthenticatedActor {
    /// Returns the actor's identity as an `ActorId`.
    pub fn actor_id(&self) -> ActorId {
        match self {
            AuthenticatedActor::User(user) => ActorId::User(user.id.clone()),
            AuthenticatedActor::Workspace(workspace) => ActorId::Agent(workspace.id.clone()),
        }
    }

    /// Convert this actor into a `PolicyPrincipal` for Cedar policy evaluation.
    pub fn policy_principal(&self) -> PolicyPrincipal<'_> {
        match self {
            AuthenticatedActor::User(user) => PolicyPrincipal::User(user),
            AuthenticatedActor::Workspace(workspace) => PolicyPrincipal::Workspace(workspace),
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
            AuthenticatedActor::Workspace(workspace) => (
                Some(workspace.id.clone()),
                Some(workspace.name.clone()),
                None,
                None,
            ),
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
        Ok(AuthenticatedActor::Workspace(auth_workspace.workspace))
    }
}
