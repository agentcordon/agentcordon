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
use crate::state::AppState;

use super::WorkspaceResponse;

// ============================================================================
// Tag Management
// ============================================================================

#[derive(Deserialize)]
pub(super) struct AddTagRequest {
    tag: String,
}

/// POST /api/v1/workspaces/{id}/tags — add a tag to a workspace (user auth required).
pub(super) async fn add_workspace_tag(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
    axum::Extension(corr): axum::Extension<CorrelationId>,
    Path(id): Path<Uuid>,
    Json(req): Json<AddTagRequest>,
) -> Result<Json<ApiResponse<WorkspaceResponse>>, ApiError> {
    let tag = req.tag.trim().to_string();
    if tag.is_empty() || tag.len() > 128 {
        return Err(ApiError::BadRequest(
            "tag must be 1-128 characters".to_string(),
        ));
    }

    // Non-admin users cannot assign the "admin" tag
    let is_admin = auth.is_admin();
    if !is_admin && tag.eq_ignore_ascii_case("admin") {
        return Err(ApiError::Forbidden(
            "only admins can assign the \"admin\" tag".to_string(),
        ));
    }

    let updated_workspace = state
        .services
        .workspaces
        .add_tag(&auth, &corr.0, &WorkspaceId(id), &tag)
        .await?;

    let resp = WorkspaceResponse::from_workspace(updated_workspace);
    Ok(Json(ApiResponse::ok(resp)))
}

/// DELETE /api/v1/workspaces/{id}/tags/{tag} — remove a tag from a workspace (user auth required).
pub(super) async fn remove_workspace_tag(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
    axum::Extension(corr): axum::Extension<CorrelationId>,
    Path((id, tag)): Path<(Uuid, String)>,
) -> Result<Json<ApiResponse<WorkspaceResponse>>, ApiError> {
    let tag = tag.trim().to_string();

    let updated_workspace = state
        .services
        .workspaces
        .remove_tag(&auth, &corr.0, &WorkspaceId(id), &tag)
        .await?;

    let resp = WorkspaceResponse::from_workspace(updated_workspace);
    Ok(Json(ApiResponse::ok(resp)))
}

// ============================================================================
// Revocation
// ============================================================================

/// POST /api/v1/workspaces/{id}/revoke — revoke a workspace (user auth required).
///
/// Revocation is final: the workspace's tokens stop working at once and the
/// enable toggle cannot bring it back. Authorized against the workspace and
/// its owner, so an operator can only revoke workspaces they own.
pub(super) async fn revoke_workspace(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
    axum::Extension(corr): axum::Extension<CorrelationId>,
    Path(id): Path<Uuid>,
) -> Result<Json<ApiResponse<serde_json::Value>>, ApiError> {
    state
        .services
        .workspaces
        .revoke(&auth, &corr.0, &WorkspaceId(id))
        .await?;

    Ok(Json(ApiResponse::ok(
        serde_json::json!({ "revoked": true }),
    )))
}
