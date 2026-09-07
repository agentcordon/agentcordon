mod consents;
mod crud;
mod operations;

use axum::{routing::get, Router};
use serde::Serialize;

use agent_cordon_core::domain::workspace::Workspace;

use agent_cordon_core::storage::Store;

use crate::state::AppState;

use crud::{delete_workspace, get_workspace, list_workspaces, update_workspace};
use operations::{add_workspace_tag, remove_workspace_tag, revoke_workspace};

/// Workspace response with computed `status` field.
#[derive(Serialize)]
pub(crate) struct WorkspaceResponse {
    #[serde(flatten)]
    pub(crate) workspace: Workspace,
    pub(crate) computed_status: String,
    /// `status == active`, kept for readers of the old two-field shape.
    pub(crate) enabled: bool,
    pub(crate) owner_username: Option<String>,
}

impl WorkspaceResponse {
    pub(crate) fn from_workspace(workspace: Workspace) -> Self {
        let computed_status = workspace.status.as_str().to_string();
        let enabled = workspace.is_active();
        Self {
            workspace,
            computed_status,
            enabled,
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
        // No POST /workspaces — workspace registration via OAuth is the creation path.
        .route("/workspaces", get(list_workspaces))
        .route(
            "/workspaces/{id}",
            get(get_workspace)
                .put(update_workspace)
                .delete(delete_workspace),
        )
        .route(
            "/workspaces/{id}/revoke",
            axum::routing::post(revoke_workspace),
        )
        .route(
            "/workspaces/{id}/tags",
            axum::routing::post(add_workspace_tag),
        )
        .route(
            "/workspaces/{id}/tags/{tag}",
            axum::routing::delete(remove_workspace_tag),
        )
        .route("/workspaces/{id}/consents", get(consents::list_consents))
        .route(
            "/workspaces/{id}/consents/{user_id}",
            axum::routing::delete(consents::delete_consent),
        )
}
