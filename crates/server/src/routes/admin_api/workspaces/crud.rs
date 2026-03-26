use axum::{
    extract::{Path, State},
    Json,
};
use serde::Deserialize;
use uuid::Uuid;

use agent_cordon_core::domain::audit::{AuditDecision, AuditEvent, AuditEventType};
use agent_cordon_core::domain::user::UserId;
use agent_cordon_core::domain::workspace::WorkspaceId;

use crate::events::UiEvent;
use crate::extractors::AuthenticatedUser;
use crate::middleware::request_id::CorrelationId;
use crate::response::{ApiError, ApiResponse};
use crate::state::AppState;

use super::{check_manage_workspaces, enrich_workspace_owner, WorkspaceResponse};

pub(super) async fn list_workspaces(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
) -> Result<Json<ApiResponse<Vec<WorkspaceResponse>>>, ApiError> {
    check_manage_workspaces(&state, &auth)?;
    // Tenant scoping: admins see all, non-admins see only their owned workspaces
    let is_admin =
        auth.user.role == agent_cordon_core::domain::user::UserRole::Admin || auth.is_root;
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
    check_manage_workspaces(&state, &auth)?;
    let workspace = state
        .store
        .get_workspace(&WorkspaceId(id))
        .await?
        .ok_or_else(|| ApiError::NotFound("workspace not found".to_string()))?;
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
    let policy_decision = check_manage_workspaces(&state, &auth)?;

    let target_id = WorkspaceId(id);

    let mut workspace = state
        .store
        .get_workspace(&target_id)
        .await?
        .ok_or_else(|| ApiError::NotFound("workspace not found".to_string()))?;

    if let Some(name) = req.name {
        workspace.name = name;
    }
    if let Some(tags) = req.tags {
        // Non-admin users cannot assign the "admin" tag
        let is_admin =
            auth.user.role == agent_cordon_core::domain::user::UserRole::Admin || auth.is_root;
        if !is_admin && tags.iter().any(|t| t.eq_ignore_ascii_case("admin")) {
            return Err(ApiError::Forbidden(
                "only admins can assign the \"admin\" tag".to_string(),
            ));
        }
        workspace.tags = tags;
    }
    if let Some(enabled) = req.enabled {
        workspace.enabled = enabled;
    }
    if let Some(owner_id) = req.owner_id {
        workspace.owner_id = Some(UserId(owner_id));
    }
    workspace.updated_at = chrono::Utc::now();

    state.store.update_workspace(&workspace).await?;

    // Audit log
    let event = AuditEvent::builder(AuditEventType::WorkspaceUpdated)
        .action("update")
        .user_actor(&auth.user)
        .resource("workspace", &workspace.id.0.to_string())
        .correlation_id(&corr.0)
        .decision(
            AuditDecision::Permit,
            Some(&policy_decision.reasons.join(", ")),
        )
        .details(serde_json::json!({ "updated_workspace": workspace.name }))
        .build();
    if let Err(e) = state.store.append_audit_event(&event).await {
        tracing::warn!(error = %e, "Failed to write audit event");
    }

    // Emit UI event for browser auto-refresh
    state.ui_event_bus.emit(UiEvent::WorkspaceUpdated {
        workspace_id: workspace.id.0,
    });

    let resp = WorkspaceResponse::from_workspace(workspace);
    Ok(Json(ApiResponse::ok(resp)))
}

pub(super) async fn delete_workspace(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
    axum::Extension(corr): axum::Extension<CorrelationId>,
    Path(id): Path<Uuid>,
) -> Result<Json<ApiResponse<serde_json::Value>>, ApiError> {
    let policy_decision = check_manage_workspaces(&state, &auth)?;

    let target_id = WorkspaceId(id);

    // Get workspace name for audit before deleting
    let target_workspace = state
        .store
        .get_workspace(&target_id)
        .await?
        .ok_or_else(|| ApiError::NotFound("workspace not found".to_string()))?;

    // Cascade: delete all Cedar grant policies for this workspace
    let mut policies_deleted = false;
    if let Ok(policies) = state.store.list_policies().await {
        let workspace_id_str = target_id.0.to_string();
        for policy in &policies {
            if policy.name.starts_with("grant:") && policy.name.contains(&workspace_id_str) {
                state.store.delete_policy(&policy.id).await.ok();
                policies_deleted = true;
            }
        }
    }

    // Reload policy engine so deleted grant policies take effect immediately
    if policies_deleted {
        super::super::policies::reload_engine(&state).await?;
    }

    let deleted = state.store.delete_workspace(&target_id).await?;
    if !deleted {
        return Err(ApiError::NotFound("workspace not found".to_string()));
    }

    // Audit log
    let event = AuditEvent::builder(AuditEventType::WorkspaceDeleted)
        .action("delete")
        .user_actor(&auth.user)
        .resource("workspace", &target_id.0.to_string())
        .correlation_id(&corr.0)
        .decision(
            AuditDecision::Permit,
            Some(&policy_decision.reasons.join(", ")),
        )
        .details(serde_json::json!({ "deleted_workspace": target_workspace.name }))
        .build();
    if let Err(e) = state.store.append_audit_event(&event).await {
        tracing::warn!(error = %e, "Failed to write audit event");
    }

    // Emit UI event for browser auto-refresh
    state.ui_event_bus.emit(UiEvent::WorkspaceDeleted {
        workspace_id: target_id.0,
    });

    Ok(Json(ApiResponse::ok(
        serde_json::json!({ "deleted": true }),
    )))
}
