mod crud;
mod operations;

use axum::{routing::get, Router};
use serde::Serialize;

use agent_cordon_core::domain::workspace::Workspace;
use agent_cordon_core::policy::{actions, PolicyResource};

use agent_cordon_core::storage::Store;

use crate::extractors::AuthenticatedUser;
use crate::response::ApiError;
use crate::state::AppState;

use crud::{delete_workspace, get_workspace, list_workspaces, update_workspace};
use operations::{add_workspace_tag, get_workspace_permissions, remove_workspace_tag};

#[derive(Serialize)]
pub(super) struct PermissionsResponse {
    token: String,
    expires_in: u64,
}

/// Workspace response with computed `status` field.
#[derive(Serialize)]
pub(crate) struct WorkspaceResponse {
    #[serde(flatten)]
    pub(crate) workspace: Workspace,
    pub(crate) computed_status: String,
    pub(crate) owner_username: Option<String>,
}

impl WorkspaceResponse {
    pub(crate) fn from_workspace(workspace: Workspace) -> Self {
        let computed_status = workspace.status.as_str().to_string();
        Self {
            workspace,
            computed_status,
            owner_username: None,
        }
    }
}

/// Enrich workspace responses with the owner's display name or username.
pub(crate) async fn enrich_workspace_owner(store: &dyn Store, responses: &mut [WorkspaceResponse]) {
    for resp in responses.iter_mut() {
        if let Some(ref owner_id) = resp.workspace.owner_id {
            if let Ok(Some(user)) = store.get_user(owner_id).await {
                resp.owner_username = user.display_name.or(Some(user.username));
            }
        }
    }
}

pub fn routes() -> Router<AppState> {
    Router::new()
        // No POST /workspaces — enrollment is the only way to create workspaces.
        .route("/workspaces", get(list_workspaces))
        .route(
            "/workspaces/{id}",
            get(get_workspace)
                .put(update_workspace)
                .delete(delete_workspace),
        )
        .route(
            "/workspaces/{id}/permissions",
            get(get_workspace_permissions),
        )
        .route(
            "/workspaces/{id}/tags",
            axum::routing::post(add_workspace_tag),
        )
        .route(
            "/workspaces/{id}/tags/{tag}",
            axum::routing::delete(remove_workspace_tag),
        )
}

/// Check Cedar policy for `manage_workspaces` on `System` resource.
pub(crate) fn check_manage_workspaces(
    state: &AppState,
    auth: &AuthenticatedUser,
) -> Result<agent_cordon_core::domain::policy::PolicyDecision, ApiError> {
    super::check_cedar_permission(
        state,
        auth,
        actions::MANAGE_WORKSPACES,
        PolicyResource::System,
    )
}
