use axum::{
    extract::{Path, State},
    Json,
};
use chrono::Utc;
use uuid::Uuid;

use agent_cordon_core::domain::audit::{AuditDecision, AuditEvent, AuditEventType};
use agent_cordon_core::domain::workspace::{Workspace, WorkspaceId, WorkspaceStatus};

use crate::extractors::AuthenticatedUser;
use crate::middleware::request_id::CorrelationId;
use crate::response::{ApiError, ApiResponse};
use crate::state::AppState;

// ============================================================================
// Revocation
// ============================================================================

/// DELETE /api/v1/agents/{id}/workspace-identity — admin revokes a workspace.
pub(super) async fn revoke_workspace_identity(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
    axum::Extension(corr): axum::Extension<CorrelationId>,
    Path(id): Path<Uuid>,
) -> Result<Json<ApiResponse<serde_json::Value>>, ApiError> {
    let workspace = state
        .store
        .get_workspace(&WorkspaceId(id))
        .await?
        .ok_or_else(|| ApiError::NotFound("workspace not found".to_string()))?;

    let now = Utc::now();
    let mut revoked = workspace.clone();
    revoked.status = WorkspaceStatus::Revoked;
    revoked.updated_at = now;
    state.store.update_workspace(&revoked).await?;

    // Push revocation event via SSE
    state
        .event_bus
        .emit(crate::events::DeviceEvent::WorkspaceRevoked {
            workspace_id: id,
            pk_hash: workspace.pk_hash.clone().unwrap_or_default(),
        });

    // Audit
    let event = AuditEvent::builder(AuditEventType::WorkspaceRevoked)
        .action("workspace_revoke")
        .user_actor(&auth.user)
        .resource("workspace", &id.to_string())
        .correlation_id(&corr.0)
        .decision(AuditDecision::Permit, Some("bypass:admin"))
        .details(serde_json::json!({ "pk_hash": workspace.pk_hash }))
        .build();
    if let Err(e) = state.store.append_audit_event(&event).await {
        tracing::warn!(error = %e, "Failed to write audit event");
    }

    Ok(Json(ApiResponse::ok(
        serde_json::json!({ "revoked": true }),
    )))
}

// ============================================================================
// Revocation by ID (test/frontend API)
// ============================================================================

/// DELETE /api/v1/workspace-identities/{id}
/// Admin revokes a workspace by UUID.
pub(super) async fn revoke_workspace_identity_by_id(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
    axum::Extension(corr): axum::Extension<CorrelationId>,
    Path(id): Path<Uuid>,
) -> Result<Json<ApiResponse<serde_json::Value>>, ApiError> {
    let workspace = state
        .store
        .get_workspace(&WorkspaceId(id))
        .await?
        .ok_or_else(|| ApiError::NotFound("workspace not found".to_string()))?;

    let now = Utc::now();
    let mut revoked = workspace.clone();
    revoked.status = WorkspaceStatus::Revoked;
    revoked.updated_at = now;
    state.store.update_workspace(&revoked).await?;

    // Push revocation event via SSE
    state
        .event_bus
        .emit(crate::events::DeviceEvent::WorkspaceRevoked {
            workspace_id: id,
            pk_hash: workspace.pk_hash.clone().unwrap_or_default(),
        });

    // Audit
    let event = AuditEvent::builder(AuditEventType::WorkspaceRevoked)
        .action("workspace_revoke")
        .user_actor(&auth.user)
        .resource("workspace", &id.to_string())
        .correlation_id(&corr.0)
        .decision(AuditDecision::Permit, Some("bypass:admin"))
        .details(serde_json::json!({ "pk_hash": workspace.pk_hash }))
        .build();
    if let Err(e) = state.store.append_audit_event(&event).await {
        tracing::warn!(error = %e, "Failed to write audit event");
    }

    Ok(Json(ApiResponse::ok(
        serde_json::json!({ "revoked": true }),
    )))
}

// ============================================================================
// List Workspaces (frontend API)
// ============================================================================

/// GET /api/v1/workspace-identities — list all workspaces.
pub(super) async fn list_workspace_identities(
    State(state): State<AppState>,
    _auth: AuthenticatedUser,
) -> Result<Json<ApiResponse<Vec<Workspace>>>, ApiError> {
    let workspaces = state.store.list_workspaces().await?;
    Ok(Json(ApiResponse::ok(workspaces)))
}

// ============================================================================
// Approve Pending Workspace (frontend API)
// ============================================================================

/// POST /api/v1/workspace-identities/{id}/approve — approve a pending workspace.
pub(super) async fn approve_workspace_identity(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
    axum::Extension(corr): axum::Extension<CorrelationId>,
    Path(id): Path<Uuid>,
) -> Result<Json<ApiResponse<serde_json::Value>>, ApiError> {
    let workspace = state
        .store
        .get_workspace(&WorkspaceId(id))
        .await?
        .ok_or_else(|| ApiError::NotFound("workspace not found".to_string()))?;

    if workspace.status != WorkspaceStatus::Pending {
        return Err(ApiError::BadRequest("workspace is not pending".to_string()));
    }

    let now = Utc::now();
    let mut approved = workspace.clone();
    approved.status = WorkspaceStatus::Active;
    approved.owner_id = Some(auth.user.id.clone());
    approved.updated_at = now;
    state.store.update_workspace(&approved).await?;

    // Audit
    let event = AuditEvent::builder(AuditEventType::WorkspaceRegistered)
        .action("approve_workspace")
        .user_actor(&auth.user)
        .resource("workspace", &id.to_string())
        .correlation_id(&corr.0)
        .decision(AuditDecision::Permit, Some("bypass:admin"))
        .details(serde_json::json!({ "pk_hash": approved.pk_hash }))
        .build();
    if let Err(e) = state.store.append_audit_event(&event).await {
        tracing::warn!(error = %e, "Failed to write audit event");
    }

    Ok(Json(ApiResponse::ok(
        serde_json::json!({ "approved": true }),
    )))
}
