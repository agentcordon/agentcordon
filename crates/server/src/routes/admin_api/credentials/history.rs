use axum::{
    extract::{Path, State},
    Json,
};
use chrono::{DateTime, Utc};
use serde::Serialize;
use uuid::Uuid;

use agent_cordon_core::domain::credential::{CredentialId, SecretHistoryEntry};
use agent_cordon_core::domain::user::UserId;
use agent_cordon_core::domain::workspace::WorkspaceId;
use agent_cordon_core::policy::{actions, PolicyResource};

use crate::extractors::AuthenticatedActor;
use crate::middleware::request_id::CorrelationId;
use crate::response::{ApiError, ApiResponse};
use crate::state::AppState;

/// Response type for secret history list entries (no secret values).
#[derive(Serialize)]
pub(crate) struct SecretHistoryResponse {
    id: String,
    credential_id: String,
    changed_at: DateTime<Utc>,
    changed_by_user: Option<String>,
    changed_by_agent: Option<String>,
    /// Who rotated the secret, as a reader would recognise them: the user's
    /// display name (else their username), or the workspace's name. The stored
    /// columns are UUIDs, and the History tab showed one of them — which is to
    /// say "-" — where the actor belongs (uat/artifacts/reviews/UI-REVIEW-live.md M10).
    changed_by_name: Option<String>,
}

impl From<SecretHistoryEntry> for SecretHistoryResponse {
    fn from(entry: SecretHistoryEntry) -> Self {
        Self {
            id: entry.id.to_string(),
            credential_id: entry.credential_id.to_string(),
            changed_at: entry.changed_at,
            changed_by_user: entry.changed_by_user,
            changed_by_agent: entry.changed_by_agent,
            changed_by_name: None,
        }
    }
}

/// Fill in `changed_by_name` for each row, the same way `owner_username` is
/// resolved on a credential: display name, else username; a workspace-authored
/// rotation names the workspace. An id that no longer resolves is left unnamed
/// rather than shown raw.
async fn enrich_actor_names(
    store: &dyn agent_cordon_core::storage::Store,
    entries: &mut [SecretHistoryResponse],
) {
    for entry in entries.iter_mut() {
        if let Some(id) = entry
            .changed_by_user
            .as_deref()
            .and_then(|s| Uuid::parse_str(s).ok())
        {
            if let Ok(Some(user)) = store.get_user(&UserId(id)).await {
                entry.changed_by_name = user.display_name.or(Some(user.username));
                continue;
            }
        }
        if let Some(id) = entry
            .changed_by_agent
            .as_deref()
            .and_then(|s| Uuid::parse_str(s).ok())
        {
            if let Ok(Some(workspace)) = store.get_workspace(&WorkspaceId(id)).await {
                entry.changed_by_name = Some(workspace.name);
            }
        }
    }
}

/// GET /credentials/{id}/secret-history
/// Returns the history of secret rotations (no actual secret values).
pub(crate) async fn list_secret_history(
    State(state): State<AppState>,
    actor: AuthenticatedActor,
    Path(id): Path<Uuid>,
) -> Result<Json<ApiResponse<Vec<SecretHistoryResponse>>>, ApiError> {
    let cred_id = CredentialId(id);

    // Load the credential to verify it exists and for policy check
    let cred = state.services.credentials.load(&cred_id).await?;

    // Policy check: use "update" action on the credential resource
    state
        .authz
        .request(
            crate::authz::PolicyCaller::Principal {
                principal: actor.policy_principal(),
                oauth_claims: None,
            },
            &uuid::Uuid::new_v4().to_string(),
        )
        .check(
            actions::UPDATE,
            &PolicyResource::Credential { credential: cred },
        )
        .await?;

    let entries = state.store.list_secret_history(&cred_id).await?;
    let mut response: Vec<SecretHistoryResponse> = entries.into_iter().map(Into::into).collect();
    enrich_actor_names(state.store.as_ref(), &mut response).await;

    Ok(Json(ApiResponse::ok(response)))
}

/// POST /credentials/{id}/secret-history/{history_id}/restore
/// Restores a historical secret value as the current one.
/// Stores the current value in history first. Requires `delegated_use` permission or admin.
pub(crate) async fn restore_secret_history(
    State(state): State<AppState>,
    actor: AuthenticatedActor,
    axum::Extension(corr): axum::Extension<CorrelationId>,
    Path((id, history_id)): Path<(Uuid, String)>,
) -> Result<Json<ApiResponse<serde_json::Value>>, ApiError> {
    state
        .services
        .credentials
        .restore_secret_history(&actor, &corr.0, &CredentialId(id), &history_id)
        .await?;

    Ok(Json(ApiResponse::ok(serde_json::json!({
        "restored": true,
        "from_history_id": history_id,
    }))))
}
