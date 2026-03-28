use axum::{
    extract::{Path, State},
    Json,
};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use uuid::Uuid;

use agent_cordon_core::crypto::SecretEncryptor;
use agent_cordon_core::domain::audit::{AuditDecision, AuditEvent, AuditEventType};
use agent_cordon_core::domain::credential::{CredentialId, CredentialSummary, CredentialUpdate};
use agent_cordon_core::domain::policy::PolicyDecisionResult;
use agent_cordon_core::policy::actions;
use agent_cordon_core::policy::{PolicyContext, PolicyEngine, PolicyResource};
use agent_cordon_core::transform::MAX_TRANSFORM_SCRIPT_SIZE;

use crate::events::UiEvent;
use crate::extractors::AuthenticatedActor;
use crate::middleware::request_id::CorrelationId;
use crate::response::{ApiError, ApiResponse};
use crate::state::AppState;

use super::{actor_identity_strings, enrich_owner_usernames};

#[derive(Deserialize)]
pub(crate) struct UpdateCredentialRequest {
    name: Option<String>,
    service: Option<String>,
    /// New secret value. When provided, the old secret is archived to history.
    secret_value: Option<String>,
    scopes: Option<Vec<String>>,
    metadata: Option<serde_json::Value>,
    allowed_url_pattern: Option<String>,
    expires_at: Option<DateTime<Utc>>,
    transform_script: Option<String>,
    transform_name: Option<String>,
    vault: Option<String>,
    tags: Option<Vec<String>>,
    description: Option<String>,
    target_identity: Option<String>,
}

pub(crate) async fn update_credential(
    State(state): State<AppState>,
    actor: AuthenticatedActor,
    axum::Extension(corr): axum::Extension<CorrelationId>,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateCredentialRequest>,
) -> Result<Json<ApiResponse<CredentialSummary>>, ApiError> {
    let cred_id = CredentialId(id);

    // Load the credential first to verify it exists
    let cred = state
        .store
        .get_credential(&cred_id)
        .await?
        .ok_or_else(|| ApiError::NotFound("credential not found".to_string()))?;

    // Policy check: can this actor update this credential?
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

    // Validate transform_script size
    if let Some(ref script) = req.transform_script {
        if script.len() > MAX_TRANSFORM_SCRIPT_SIZE {
            return Err(ApiError::BadRequest(format!(
                "transform_script exceeds maximum size of {} bytes ({} bytes provided)",
                MAX_TRANSFORM_SCRIPT_SIZE,
                script.len()
            )));
        }
    }

    // If name is being changed, check uniqueness scoped to the credential's creator
    if let Some(ref new_name) = req.name {
        let existing = if let Some(ref creator) = cred.created_by {
            state
                .store
                .get_credential_by_workspace_and_name(creator, new_name)
                .await?
        } else {
            state.store.get_credential_by_name(new_name).await?
        };
        if let Some(existing) = existing {
            if existing.id != cred_id {
                return Err(ApiError::Conflict(format!(
                    "credential with name '{}' already exists",
                    new_name
                )));
            }
        }
    }

    // Handle secret value rotation
    let secret_rotated = req.secret_value.is_some();
    let (new_encrypted_value, new_nonce) = if let Some(ref new_secret) = req.secret_value {
        // Store the OLD encrypted secret value in history BEFORE updating
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

        // Strip auth prefixes for non-AWS/non-OAuth2 types to prevent double-wrapping
        let cleaned_secret = match cred.credential_type.as_str() {
            "aws" | "oauth2_client_credentials" => new_secret.clone(),
            _ => crate::credential_service::strip_auth_prefix(new_secret),
        };

        // Encrypt the new secret value with credential ID as AAD
        let (encrypted, nonce) = state
            .encryptor
            .encrypt(cleaned_secret.as_bytes(), cred_id.0.to_string().as_bytes())?;
        (Some(encrypted), Some(nonce))
    } else {
        (None, None)
    };

    let updates = CredentialUpdate {
        name: req.name.clone(),
        service: req.service.clone(),
        scopes: req.scopes.clone(),
        metadata: req.metadata.clone(),
        allowed_url_pattern: req.allowed_url_pattern.clone(),
        expires_at: req.expires_at,
        transform_script: req.transform_script.clone(),
        transform_name: req.transform_name.clone(),
        vault: req.vault.clone(),
        tags: req.tags.clone(),
        description: req.description.clone(),
        target_identity: req.target_identity.clone(),
        encrypted_value: new_encrypted_value,
        nonce: new_nonce,
        key_version: None,
    };

    state.store.update_credential(&cred_id, &updates).await?;

    // Evict any cached OAuth2 token when the secret is rotated
    if secret_rotated {
        state.oauth2_token_manager.evict(&cred_id).await;
    }

    // Re-fetch the updated credential to return the summary
    let updated_cred = state
        .store
        .get_credential(&cred_id)
        .await?
        .ok_or_else(|| ApiError::Internal("credential disappeared after update".to_string()))?;

    // Audit log
    let (ws_id, ws_name, u_id, u_name) = actor.audit_actor_fields();
    let event_type = if secret_rotated {
        AuditEventType::CredentialSecretRotated
    } else {
        AuditEventType::CredentialUpdated
    };
    let mut audit_metadata = serde_json::json!({
        "credential_name": updated_cred.name,
        "service": updated_cred.service,
    });
    if secret_rotated {
        audit_metadata["secret_rotated"] = serde_json::json!(true);
    }
    let event = AuditEvent::builder(event_type)
        .action("update")
        .actor_fields(ws_id, ws_name, u_id, u_name)
        .resource("credential", &id.to_string())
        .correlation_id(&corr.0)
        .decision(AuditDecision::Permit, Some(&decision.reasons.join(", ")))
        .details(audit_metadata)
        .build();
    if let Err(e) = state.store.append_audit_event(&event).await {
        tracing::warn!(error = %e, "Failed to write audit event");
    }

    // Emit SSE event if the secret was rotated
    if secret_rotated {
        state
            .event_bus
            .emit(crate::events::DeviceEvent::CredentialRotated {
                credential_name: updated_cred.name.clone(),
            });
    }

    // Emit UI event for browser auto-refresh
    state.ui_event_bus.emit(UiEvent::CredentialUpdated {
        credential_id: updated_cred.id.0,
    });

    let mut summary: CredentialSummary = updated_cred.into();
    enrich_owner_usernames(state.store.as_ref(), std::slice::from_mut(&mut summary)).await;

    Ok(Json(ApiResponse::ok(summary)))
}

pub(crate) async fn get_credential(
    State(state): State<AppState>,
    actor: AuthenticatedActor,
    Path(id): Path<Uuid>,
) -> Result<Json<ApiResponse<CredentialSummary>>, ApiError> {
    let cred_id = CredentialId(id);
    let cred = state
        .store
        .get_credential(&cred_id)
        .await?
        .ok_or_else(|| ApiError::NotFound("credential not found".to_string()))?;

    // Policy check
    let decision = state.policy_engine.evaluate(
        &actor.policy_principal(),
        actions::LIST,
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

    let mut summary: CredentialSummary = cred.into();
    enrich_owner_usernames(state.store.as_ref(), std::slice::from_mut(&mut summary)).await;

    Ok(Json(ApiResponse::ok(summary)))
}

/// Look up a credential by name instead of UUID.
/// Returns the same `CredentialSummary` as `GET /credentials/{id}`.
pub(crate) async fn get_credential_by_name(
    State(state): State<AppState>,
    actor: AuthenticatedActor,
    Path(name): Path<String>,
) -> Result<Json<ApiResponse<CredentialSummary>>, ApiError> {
    let cred = state
        .store
        .get_credential_by_name(&name)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("credential '{}' not found", name)))?;

    // Same policy check as get_credential
    let decision = state.policy_engine.evaluate(
        &actor.policy_principal(),
        actions::LIST,
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

    let mut summary: CredentialSummary = cred.into();
    enrich_owner_usernames(state.store.as_ref(), std::slice::from_mut(&mut summary)).await;

    Ok(Json(ApiResponse::ok(summary)))
}

pub(crate) async fn delete_credential(
    State(state): State<AppState>,
    actor: AuthenticatedActor,
    axum::Extension(corr): axum::Extension<CorrelationId>,
    Path(id): Path<Uuid>,
) -> Result<Json<ApiResponse<serde_json::Value>>, ApiError> {
    let cred_id = CredentialId(id);

    let cred = state
        .store
        .get_credential(&cred_id)
        .await?
        .ok_or_else(|| ApiError::NotFound("credential not found".to_string()))?;

    // Policy check
    let decision = state.policy_engine.evaluate(
        &actor.policy_principal(),
        actions::DELETE,
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

    // Evict any cached OAuth2 token for this credential before deletion
    state.oauth2_token_manager.evict(&cred_id).await;

    // Cascade: delete all Cedar grant policies for this credential
    let grant_prefix = format!("grant:{}:", cred_id.0);
    state
        .store
        .delete_policies_by_name_prefix(&grant_prefix)
        .await?;

    // Reload policy engine and notify devices about deleted policies
    crate::routes::admin_api::policies::reload_engine(&state).await?;
    state
        .event_bus
        .emit(crate::events::DeviceEvent::PolicyChanged {
            policy_name: grant_prefix,
        });

    state.store.delete_credential(&cred_id).await?;

    // Audit log
    let (ws_id, ws_name, u_id, u_name) = actor.audit_actor_fields();
    let event = AuditEvent::builder(AuditEventType::CredentialDeleted)
        .action("delete")
        .actor_fields(ws_id, ws_name, u_id, u_name)
        .resource("credential", &id.to_string())
        .correlation_id(&corr.0)
        .decision(AuditDecision::Permit, Some(&decision.reasons.join(", ")))
        .details(serde_json::json!({
            "credential_name": cred.name,
            "service": cred.service,
        }))
        .build();
    if let Err(e) = state.store.append_audit_event(&event).await {
        tracing::warn!(error = %e, "Failed to write audit event");
    }

    // Emit UI event for browser auto-refresh
    state
        .ui_event_bus
        .emit(UiEvent::CredentialDeleted { credential_id: id });

    Ok(Json(ApiResponse::ok(
        serde_json::json!({ "deleted": true }),
    )))
}
