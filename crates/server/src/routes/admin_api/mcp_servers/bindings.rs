use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use agent_cordon_core::domain::mcp::McpServerId;

use crate::extractors::AuthenticatedUser;
use crate::middleware::request_id::CorrelationId;
use crate::response::{ApiError, ApiResponse};
use crate::state::AppState;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AddWorkspaceBindingsRequest {
    pub workspace_ids: Vec<Uuid>,
}

#[derive(Serialize)]
pub(super) struct AddWorkspaceBindingsData {
    pub added: Vec<String>,
    pub already_bound: Vec<String>,
}

/// GET /api/v1/mcp-servers/{id}/workspaces
///
/// The bindings the share and unshare endpoints write. Until this existed
/// the path answered `405 Allow: POST`, so nothing could read back what
/// provisioning had bound — which is how "No workspaces" on the list page
/// went unnoticed.
pub(super) async fn list_workspace_bindings(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
    Path(id): Path<Uuid>,
) -> Result<Json<ApiResponse<Vec<super::InstalledWorkspaceInfo>>>, ApiError> {
    let server_id = McpServerId(id);
    state
        .services
        .mcp_servers
        .load_and_authorize(&auth, &server_id)
        .await?;

    Ok(Json(ApiResponse::ok(
        super::installed_workspaces_for(state.store.as_ref(), &server_id).await,
    )))
}

/// POST /api/v1/mcp-servers/{id}/workspaces
pub(super) async fn add_workspace_bindings(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
    axum::Extension(corr): axum::Extension<CorrelationId>,
    Path(id): Path<Uuid>,
    Json(req): Json<AddWorkspaceBindingsRequest>,
) -> Result<(StatusCode, Json<ApiResponse<AddWorkspaceBindingsData>>), ApiError> {
    if req.workspace_ids.is_empty() {
        return Err(ApiError::UnprocessableEntity(
            "workspace_ids must contain at least one workspace".to_string(),
        ));
    }

    let outcome = state
        .services
        .mcp_servers
        .add_workspace_bindings(&auth, &corr.0, &McpServerId(id), &req.workspace_ids)
        .await?;

    let status = if outcome.added.is_empty() {
        StatusCode::OK
    } else {
        StatusCode::CREATED
    };

    Ok((
        status,
        Json(ApiResponse::ok(AddWorkspaceBindingsData {
            added: outcome.added,
            already_bound: outcome.already_bound,
        })),
    ))
}

/// DELETE /api/v1/mcp-servers/{id}/workspaces/{workspace_id}
pub(super) async fn remove_workspace_binding(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
    axum::Extension(corr): axum::Extension<CorrelationId>,
    Path((id, workspace_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, ApiError> {
    state
        .services
        .mcp_servers
        .remove_workspace_binding(&auth, &corr.0, &McpServerId(id), workspace_id)
        .await?;

    Ok(StatusCode::NO_CONTENT)
}
