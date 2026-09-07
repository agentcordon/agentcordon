use axum::{
    extract::{Path, State},
    Json,
};
use serde::Deserialize;
use uuid::Uuid;

use agent_cordon_core::domain::workspace::WorkspaceId;

use crate::extractors::AuthenticatedUser;
use crate::middleware::request_id::CorrelationId;
use crate::response::{ApiError, ApiResponse};
use crate::services::workspaces::WorkspaceChanges;
use crate::state::AppState;

use super::{enrich_workspace_owner, WorkspaceResponse};
use agent_cordon_core::policy::actions;
use agent_cordon_core::policy::PolicyResource;

pub(super) async fn list_workspaces(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
) -> Result<Json<ApiResponse<Vec<WorkspaceResponse>>>, ApiError> {
    state
        .authz
        .authorize(&auth, actions::MANAGE_WORKSPACES, &PolicyResource::System)
        .await?;
    // Tenant scoping: admins see all, non-admins see only their owned workspaces
    let is_admin = auth.is_admin();
    let workspaces = if is_admin {
        state.store.list_workspaces().await?
    } else {
        state.store.get_workspaces_by_owner(&auth.user.id).await?
    };
    let mut responses: Vec<WorkspaceResponse> = workspaces
        .into_iter()
        .map(WorkspaceResponse::from_workspace)
        .collect();
    enrich_workspace_owner(&*state.store, &mut responses).await;
    Ok(Json(ApiResponse::ok(responses)))
}

pub(super) async fn get_workspace(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
    Path(id): Path<Uuid>,
) -> Result<Json<ApiResponse<WorkspaceResponse>>, ApiError> {
    let workspace = state.services.workspaces.load(&WorkspaceId(id)).await?;
    state
        .authz
        .authorize(
            &auth,
            actions::MANAGE_WORKSPACES,
            &PolicyResource::WorkspaceResource {
                workspace: workspace.clone(),
            },
        )
        .await?;
    let mut resp = WorkspaceResponse::from_workspace(workspace);
    enrich_workspace_owner(&*state.store, std::slice::from_mut(&mut resp)).await;
    Ok(Json(ApiResponse::ok(resp)))
}

#[derive(Deserialize)]
pub(super) struct UpdateWorkspaceRequest {
    name: Option<String>,
    tags: Option<Vec<String>>,
    enabled: Option<bool>,
    owner_id: Option<Uuid>,
}

pub(super) async fn update_workspace(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
    axum::Extension(corr): axum::Extension<CorrelationId>,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateWorkspaceRequest>,
) -> Result<Json<ApiResponse<WorkspaceResponse>>, ApiError> {
    let workspace = state
        .services
        .workspaces
        .update(
            &auth,
            &corr.0,
            &WorkspaceId(id),
            WorkspaceChanges {
                name: req.name,
                tags: req.tags,
                enabled: req.enabled,
                owner_id: req.owner_id,
            },
        )
        .await?;

    let resp = WorkspaceResponse::from_workspace(workspace);
    Ok(Json(ApiResponse::ok(resp)))
}

pub(super) async fn delete_workspace(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
    axum::Extension(corr): axum::Extension<CorrelationId>,
    Path(id): Path<Uuid>,
) -> Result<Json<ApiResponse<serde_json::Value>>, ApiError> {
    state
        .services
        .workspaces
        .delete(&auth, &corr.0, &WorkspaceId(id))
        .await?;

    Ok(Json(ApiResponse::ok(
        serde_json::json!({ "deleted": true }),
    )))
}
