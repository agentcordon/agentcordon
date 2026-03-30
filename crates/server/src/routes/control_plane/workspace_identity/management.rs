use axum::{
    extract::{Path, State},
    Json,
};
use chrono::{Duration, Utc};
use serde::Deserialize;
use uuid::Uuid;

use agent_cordon_core::domain::audit::{AuditDecision, AuditEvent, AuditEventType};
use agent_cordon_core::domain::workspace::{
    self, Workspace, WorkspaceId, WorkspaceRegistration, WorkspaceStatus,
};

use crate::extractors::AuthenticatedUser;
use crate::middleware::request_id::CorrelationId;
use crate::response::{ApiError, ApiResponse};
use crate::state::AppState;

use super::REGISTRATION_TTL_SECONDS;

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
// JSON Admin Approval (test/frontend API)
// ============================================================================

#[derive(Deserialize)]
pub(super) struct JsonApproveRequest {
    pk_hash: String,
    code_challenge: String,
}

/// POST /api/v1/workspace-identities/register
/// JSON admin approval — creates a registration and returns the approval code.
pub(super) async fn json_approve_registration(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
    axum::Extension(corr): axum::Extension<CorrelationId>,
    Json(req): Json<JsonApproveRequest>,
) -> Result<Json<ApiResponse<serde_json::Value>>, ApiError> {
    let pk_hash = req.pk_hash.trim().to_string();
    let pk_hash = pk_hash
        .strip_prefix("sha256:")
        .unwrap_or(&pk_hash)
        .to_string();
    let code_challenge = req.code_challenge.trim().to_string();

    if pk_hash.len() != 64 || !pk_hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(ApiError::BadRequest("invalid pk_hash".to_string()));
    }
    if code_challenge.len() != 64 || !code_challenge.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(ApiError::BadRequest("invalid code_challenge".to_string()));
    }

    // Workspace owner is always the user who approves the registration.
    let owner_id = auth.user.id.0.to_string();

    let approval_code = workspace::generate_approval_code();
    let code_hash = workspace::hash_approval_code(&approval_code);
    let now = Utc::now();

    let registration = WorkspaceRegistration {
        pk_hash: pk_hash.clone(),
        code_challenge,
        code_hash,
        approval_code: Some(approval_code.clone()),
        expires_at: now + Duration::seconds(REGISTRATION_TTL_SECONDS),
        attempts: 0,
        max_attempts: 5,
        approved_by: Some(owner_id),
        created_at: now,
    };

    state
        .store
        .create_workspace_registration(&registration)
        .await?;

    // Audit
    let event = AuditEvent::builder(AuditEventType::WorkspaceRegistered)
        .action("approve_workspace_registration")
        .user_actor(&auth.user)
        .resource("workspace_registration", &pk_hash)
        .correlation_id(&corr.0)
        .decision(AuditDecision::Permit, Some("bypass:admin"))
        .details(serde_json::json!({ "pk_hash_fingerprint": &pk_hash[..16] }))
        .build();
    if let Err(e) = state.store.append_audit_event(&event).await {
        tracing::warn!(error = %e, "Failed to write audit event");
    }

    Ok(Json(ApiResponse::ok(
        serde_json::json!({ "approval_code": approval_code }),
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
