//! Issue #10 — view and delete OAuth consent grants for a workspace.
//!
//! Mounted under `/api/v1/workspaces/{id}/consents`.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use chrono::{DateTime, Utc};
use serde::Serialize;
use uuid::Uuid;

use agent_cordon_core::domain::user::UserId;
use agent_cordon_core::domain::workspace::WorkspaceId;
use agent_cordon_core::policy::{actions, PolicyResource};

use crate::extractors::AuthenticatedUser;
use crate::response::{ApiError, ApiResponse};
use crate::state::AppState;

/// One row in the consent-list response.
#[derive(Debug, Serialize)]
pub struct ConsentGrantResponse {
    pub user_id: Uuid,
    pub username: String,
    pub scopes: Vec<String>,
    pub granted_at: DateTime<Utc>,
}

/// `GET /api/v1/workspaces/{id}/consents` — list all OAuth consents granted to
/// the workspace's OAuth client.
pub(super) async fn list_consents(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
    Path(id): Path<Uuid>,
) -> Result<Json<ApiResponse<Vec<ConsentGrantResponse>>>, ApiError> {
    let workspace = state
        .store
        .get_workspace(&WorkspaceId(id))
        .await?
        .ok_or_else(|| ApiError::NotFound("workspace not found".to_string()))?;
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

    // No OAuth client yet → no possible consents.
    let pk_hash = match workspace.pk_hash.as_deref() {
        Some(s) => s,
        None => return Ok(Json(ApiResponse::ok(Vec::new()))),
    };
    let client = match state
        .store
        .get_oauth_client_by_public_key_hash(pk_hash)
        .await?
    {
        Some(c) => c,
        None => return Ok(Json(ApiResponse::ok(Vec::new()))),
    };

    let consents = state
        .store
        .list_oauth_consents_for_client(&client.client_id)
        .await?;

    let mut rows = Vec::with_capacity(consents.len());
    for c in consents {
        let username = resolve_username(&state, &c.user_id).await;
        rows.push(ConsentGrantResponse {
            user_id: c.user_id.0,
            username,
            scopes: c.scopes.iter().map(|s| s.to_string()).collect(),
            granted_at: c.granted_at,
        });
    }
    Ok(Json(ApiResponse::ok(rows)))
}

/// Best-effort username lookup. Falls back to the UUID string if the user has
/// been deleted but their consent row hasn't been cleaned up.
async fn resolve_username(state: &AppState, user_id: &UserId) -> String {
    match state.store.get_user(user_id).await {
        Ok(Some(u)) => u.display_name.unwrap_or(u.username),
        _ => user_id.0.to_string(),
    }
}

/// `DELETE /api/v1/workspaces/{id}/consents/{user_id}` — revoke a consent grant.
///
/// Cascades: deletes the consent row and revokes every access and refresh
/// token issued to the `(client_id, user_id)` pair, atomically.
pub(super) async fn delete_consent(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
    Path((workspace_id, target_user_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, ApiError> {
    let workspace = state
        .store
        .get_workspace(&WorkspaceId(workspace_id))
        .await?
        .ok_or_else(|| ApiError::NotFound("workspace not found".to_string()))?;
    // Withdrawing one's own consent is self-service. Withdrawing another
    // user's requires managing this workspace, decided before the route
    // says anything about its consents; the consent self-permit below then
    // decides the final answer.
    if target_user_id != auth.user.id.0 {
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
    }
    let pk_hash = workspace
        .pk_hash
        .as_deref()
        .ok_or_else(|| ApiError::NotFound("no consent for that user".to_string()))?;
    let client = state
        .store
        .get_oauth_client_by_public_key_hash(pk_hash)
        .await?
        .ok_or_else(|| ApiError::NotFound("no consent for that user".to_string()))?;

    state
        .services
        .oauth
        .revoke_consent(
            &auth,
            &workspace,
            &client.client_id,
            &UserId(target_user_id),
        )
        .await?;

    Ok(StatusCode::NO_CONTENT)
}
