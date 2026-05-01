use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use agent_cordon_core::domain::audit::{AuditDecision, AuditEvent, AuditEventType};
use agent_cordon_core::domain::mcp::McpServerId;
use agent_cordon_core::domain::user::UserRole;
use agent_cordon_core::domain::workspace::{Workspace, WorkspaceId};

use crate::extractors::AuthenticatedUser;
use crate::middleware::request_id::CorrelationId;
use crate::response::{ApiError, ApiResponse};
use crate::state::AppState;

use super::check_manage_mcp_servers;

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

    let policy_decision = check_manage_mcp_servers(&state, &auth)?;

    let server_id = McpServerId(id);
    let server = state
        .store
        .get_mcp_server(&server_id)
        .await?
        .ok_or_else(|| ApiError::NotFound("MCP server not found".to_string()))?;

    let is_admin = auth.user.role == UserRole::Admin || auth.is_root;

    if !is_admin {
        let owner_match = server
            .created_by_user
            .as_ref()
            .map(|u| u == &auth.user.id)
            .unwrap_or(false);
        if !owner_match {
            return Err(ApiError::Forbidden(
                "only the MCP server owner may share it".to_string(),
            ));
        }
    }

    // Pre-check every workspace BEFORE any insert — no partial writes.
    let mut workspaces: Vec<Workspace> = Vec::with_capacity(req.workspace_ids.len());
    for ws_uuid in &req.workspace_ids {
        let ws_id = WorkspaceId(*ws_uuid);
        let ws = state
            .store
            .get_workspace(&ws_id)
            .await?
            .ok_or_else(|| ApiError::NotFound(format!("workspace {} not found", ws_uuid)))?;

        if !is_admin {
            let same_owner = match (ws.owner_id.as_ref(), server.created_by_user.as_ref()) {
                (Some(ws_owner), Some(mcp_owner)) => ws_owner == mcp_owner,
                _ => false,
            };
            if !same_owner {
                return Err(ApiError::Forbidden(format!(
                    "workspace {} is not owned by the MCP server's owner",
                    ws_uuid
                )));
            }
        }
        workspaces.push(ws);
    }

    let mut added: Vec<String> = Vec::new();
    let mut already_bound: Vec<String> = Vec::new();
    for ws in &workspaces {
        let was_added = state
            .store
            .add_mcp_server_workspace(&server_id, &ws.id, Some(&auth.user.id))
            .await?;
        if was_added {
            added.push(ws.id.0.to_string());

            let event = AuditEvent::builder(AuditEventType::McpServerSharedWithWorkspace)
                .action("share")
                .user_actor(&auth.user)
                .resource("mcp_server", &server_id.0.to_string())
                .correlation_id(&corr.0)
                .decision(
                    AuditDecision::Permit,
                    Some(&policy_decision.reasons.join(", ")),
                )
                .details(serde_json::json!({
                    "workspace_id": ws.id.0.to_string(),
                    "workspace_name": ws.name,
                }))
                .build();
            if let Err(e) = state.store.append_audit_event(&event).await {
                tracing::warn!(error = %e, "Failed to write audit event");
            }
        } else {
            already_bound.push(ws.id.0.to_string());
        }
    }

    let status = if added.is_empty() {
        StatusCode::OK
    } else {
        StatusCode::CREATED
    };

    Ok((
        status,
        Json(ApiResponse::ok(AddWorkspaceBindingsData {
            added,
            already_bound,
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
    let policy_decision = check_manage_mcp_servers(&state, &auth)?;

    let server_id = McpServerId(id);
    let server = state
        .store
        .get_mcp_server(&server_id)
        .await?
        .ok_or_else(|| ApiError::NotFound("MCP server not found".to_string()))?;

    let is_admin = auth.user.role == UserRole::Admin || auth.is_root;

    if !is_admin {
        let owner_match = server
            .created_by_user
            .as_ref()
            .map(|u| u == &auth.user.id)
            .unwrap_or(false);
        if !owner_match {
            return Err(ApiError::Forbidden(
                "only the MCP server owner may unshare it".to_string(),
            ));
        }

        let target_ws_id = WorkspaceId(workspace_id);
        let ws = state
            .store
            .get_workspace(&target_ws_id)
            .await?
            .ok_or_else(|| ApiError::NotFound(format!("workspace {} not found", workspace_id)))?;
        let same_owner = match (ws.owner_id.as_ref(), server.created_by_user.as_ref()) {
            (Some(ws_owner), Some(mcp_owner)) => ws_owner == mcp_owner,
            _ => false,
        };
        if !same_owner {
            return Err(ApiError::Forbidden(format!(
                "workspace {} is not owned by the MCP server's owner",
                workspace_id
            )));
        }
    }

    let target_ws_id = WorkspaceId(workspace_id);

    // Last-binding guard. State invariant — applies to admins too.
    let count = state
        .store
        .count_workspaces_for_mcp_server(&server_id)
        .await?;
    if count <= 1 {
        return Err(ApiError::Conflict(
            "cannot remove last workspace binding — delete the MCP server instead".to_string(),
        ));
    }

    let removed = state
        .store
        .remove_mcp_server_workspace(&server_id, &target_ws_id)
        .await?;
    if !removed {
        return Err(ApiError::NotFound(
            "no binding exists between this MCP and workspace".to_string(),
        ));
    }

    let event = AuditEvent::builder(AuditEventType::McpServerUnsharedFromWorkspace)
        .action("unshare")
        .user_actor(&auth.user)
        .resource("mcp_server", &server_id.0.to_string())
        .correlation_id(&corr.0)
        .decision(
            AuditDecision::Permit,
            Some(&policy_decision.reasons.join(", ")),
        )
        .details(serde_json::json!({
            "workspace_id": workspace_id.to_string(),
        }))
        .build();
    if let Err(e) = state.store.append_audit_event(&event).await {
        tracing::warn!(error = %e, "Failed to write audit event");
    }

    Ok(StatusCode::NO_CONTENT)
}
