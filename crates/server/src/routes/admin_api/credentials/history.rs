use axum::{
    extract::{Path, State},
    Json,
};
use chrono::{DateTime, Utc};
use serde::Serialize;
use uuid::Uuid;

use agent_cordon_core::domain::audit::{AuditDecision, AuditEvent, AuditEventType};
use agent_cordon_core::domain::credential::{CredentialId, CredentialUpdate, SecretHistoryEntry};
use agent_cordon_core::domain::policy::PolicyDecisionResult;
use agent_cordon_core::policy::{actions, PolicyContext, PolicyEngine, PolicyResource};

use crate::events::UiEvent;
use crate::extractors::AuthenticatedActor;
use crate::middleware::request_id::CorrelationId;
use crate::response::{ApiError, ApiResponse};
use crate::state::AppState;

use super::actor_identity_strings;

/// Response type for secret history list entries (no secret values).
#[derive(Serialize)]
pub(crate) struct SecretHistoryResponse {
    id: String,
    credential_id: String,
    changed_at: DateTime<Utc>,
    changed_by_user: Option<String>,
    changed_by_agent: Option<String>,
}

impl From<SecretHistoryEntry> for SecretHistoryResponse {
    fn from(entry: SecretHistoryEntry) -> Self {
        Self {
            id: entry.id.to_string(),
            credential_id: entry.credential_id.to_string(),
            changed_at: entry.changed_at,
            changed_by_user: entry.changed_by_user,
            changed_by_agent: entry.changed_by_agent,
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
    let cred = state
        .store
        .get_credential(&cred_id)
        .await?
        .ok_or_else(|| ApiError::NotFound("credential not found".to_string()))?;

    // Policy check: use "update" action on the credential resource
    let decision = state.policy_engine.evaluate(
        &actor.policy_principal(),
        actions::UPDATE,
        &PolicyResource::Credential { credential: cred },
        &PolicyContext {
            target_url: None,
            requested_scopes: vec![],
            ..Default::default()
        },
    )?;

    if decision.decision == PolicyDecisionResult::Forbid {
        return Err(ApiError::Forbidden("access denied by policy".to_string()));
    }

    let entries = state.store.list_secret_history(&cred_id).await?;
    let response: Vec<SecretHistoryResponse> = entries.into_iter().map(Into::into).collect();

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
    let cred_id = CredentialId(id);

    // Load the credential to verify it exists and for policy check
    let cred = state
        .store
        .get_credential(&cred_id)
        .await?
        .ok_or_else(|| ApiError::NotFound("credential not found".to_string()))?;

    // Policy check: require "update" action (delegated_use-level access is checked via policy)
    let decision = state.policy_engine.evaluate(
        &actor.policy_principal(),
        actions::UPDATE,
        &PolicyResource::Credential {
            credential: cred.clone(),
        },
        &PolicyContext {
            target_url: None,
            requested_scopes: vec![],
            ..Default::default()
        },
    )?;

    if decision.decision == PolicyDecisionResult::Forbid {
        return Err(ApiError::Forbidden("access denied by policy".to_string()));
    }

    // Get the historical encrypted value + nonce
    let (historical_encrypted, historical_nonce) = state
        .store
        .get_secret_history_value(&history_id)
        .await?
        .ok_or_else(|| ApiError::NotFound("secret history entry not found".to_string()))?;

    // Store the CURRENT encrypted value in history before restoring
    let (changed_by_user, changed_by_agent) = actor_identity_strings(&actor);
    state
        .store
        .store_secret_history(
            &cred_id,
            &cred.encrypted_value,
            &cred.nonce,
            changed_by_user.as_deref(),
            changed_by_agent.as_deref(),
        )
        .await?;

    // Update the credential with the historical value
    let updates = CredentialUpdate {
        name: None,
        service: None,
        scopes: None,
        metadata: None,
        allowed_url_pattern: None,
        expires_at: None,
        transform_script: None,
        transform_name: None,
        vault: None,
        tags: None,
        description: None,
        target_identity: None,
        encrypted_value: Some(historical_encrypted),
        nonce: Some(historical_nonce),
        key_version: None,
    };

    state.store.update_credential(&cred_id, &updates).await?;

    // Audit log
    let (ws_id, ws_name, u_id, u_name) = actor.audit_actor_fields();
    let event = AuditEvent::builder(AuditEventType::CredentialSecretRestored)
        .action("update")
        .actor_fields(ws_id, ws_name, u_id, u_name)
        .resource("credential", &id.to_string())
        .correlation_id(&corr.0)
        .decision(AuditDecision::Permit, Some(&decision.reasons.join(", ")))
        .details(serde_json::json!({
            "credential_name": cred.name,
            "service": cred.service,
            "restored_from_history_id": history_id,
        }))
        .build();
    if let Err(e) = state.store.append_audit_event(&event).await {
        tracing::warn!(error = %e, "Failed to write audit event");
    }

    // Emit UI event for browser auto-refresh
    state
        .ui_event_bus
        .emit(UiEvent::CredentialUpdated { credential_id: id });

    Ok(Json(ApiResponse::ok(serde_json::json!({
        "restored": true,
        "from_history_id": history_id,
    }))))
}
