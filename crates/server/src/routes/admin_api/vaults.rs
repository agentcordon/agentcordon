use axum::{
    extract::{Path, State},
    routing::get,
    Json, Router,
};
use serde::Deserialize;
use uuid::Uuid;

use agent_cordon_core::domain::audit::{AuditDecision, AuditEvent, AuditEventType};
use agent_cordon_core::domain::credential::CredentialSummary;
use agent_cordon_core::domain::policy::PolicyDecisionResult;
use agent_cordon_core::domain::user::UserId;
use agent_cordon_core::domain::vault::VaultShare;
use agent_cordon_core::policy::{actions, PolicyEngine, PolicyResource};

use crate::extractors::AuthenticatedActor;
use crate::middleware::request_id::CorrelationId;
use crate::response::{ApiError, ApiResponse};
use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/vaults", get(list_vaults))
        .route("/vaults/{name}/credentials", get(list_vault_credentials))
        .route("/vaults/{name}/shares", get(list_shares).post(share_vault))
        .route(
            "/vaults/{name}/shares/{user_id}",
            axum::routing::delete(unshare_vault),
        )
}

/// `GET /api/v1/vaults` — list distinct vault names.
///
/// Non-root users only see vaults they own credentials in, or that have been
/// shared with them via `vault_shares`.
async fn list_vaults(
    State(state): State<AppState>,
    actor: AuthenticatedActor,
) -> Result<Json<ApiResponse<Vec<String>>>, ApiError> {
    // Policy check
    let decision = state.policy_engine.evaluate(
        &actor.policy_principal(),
        actions::LIST,
        &PolicyResource::System,
        &actor.policy_context(None),
    )?;

    if decision.decision == PolicyDecisionResult::Forbid {
        return Err(ApiError::Forbidden("access denied by policy".to_string()));
    }

    let vaults = match &actor {
        AuthenticatedActor::User(user) if user.is_root => state.store.list_vaults().await?,
        AuthenticatedActor::User(user) => state.store.list_vaults_for_user(&user.id).await?,
        AuthenticatedActor::Workspace { .. } => state.store.list_vaults().await?,
    };
    Ok(Json(ApiResponse::ok(vaults)))
}

/// `GET /api/v1/vaults/{name}/credentials` — list credentials in a specific vault.
///
/// Enforces vault sharing: non-root users only see credentials they created or
/// that belong to a vault shared with them via `vault_shares`.
async fn list_vault_credentials(
    State(state): State<AppState>,
    actor: AuthenticatedActor,
    Path(name): Path<String>,
) -> Result<Json<ApiResponse<Vec<CredentialSummary>>>, ApiError> {
    // Policy check
    let decision = state.policy_engine.evaluate(
        &actor.policy_principal(),
        actions::LIST,
        &PolicyResource::System,
        &actor.policy_context(None),
    )?;

    if decision.decision == PolicyDecisionResult::Forbid {
        return Err(ApiError::Forbidden("access denied by policy".to_string()));
    }

    let creds = match &actor {
        AuthenticatedActor::User(user) if user.is_root => {
            // Root users see all credentials in the vault
            state.store.list_credentials_by_vault(&name).await?
        }
        AuthenticatedActor::User(user) => {
            // Non-root users: enforce vault sharing — only see credentials
            // they created or in vaults shared with them
            state
                .store
                .list_credentials_by_vault_for_user(&name, &user.id)
                .await?
        }
        AuthenticatedActor::Workspace { .. } => {
            // Fetch all credentials in the vault, then filter each through Cedar
            // policy evaluation to enforce tag-based and other Cedar policies.
            let all_creds = state.store.list_credentials_by_vault(&name).await?;
            let mut allowed_creds = Vec::new();
            let principal = actor.policy_principal();
            let context = actor.policy_context(None);

            for summary in all_creds {
                // Load the full credential for Cedar evaluation
                let cred = match state.store.get_credential(&summary.id).await {
                    Ok(Some(c)) => c,
                    Ok(None) => continue,
                    Err(e) => {
                        tracing::warn!(
                            credential_id = %summary.id.0,
                            error = %e,
                            "failed to load credential for policy evaluation, skipping (deny-by-default)"
                        );
                        continue;
                    }
                };

                match state.policy_engine.evaluate(
                    &principal,
                    actions::LIST,
                    &PolicyResource::Credential { credential: cred },
                    &context,
                ) {
                    Ok(decision) if decision.decision != PolicyDecisionResult::Forbid => {
                        allowed_creds.push(summary);
                    }
                    Ok(_) => {
                        // Cedar denied — skip this credential
                    }
                    Err(e) => {
                        tracing::warn!(
                            credential_id = %summary.id.0,
                            error = %e,
                            "Cedar evaluation failed for credential, skipping (deny-by-default)"
                        );
                    }
                }
            }

            allowed_creds
        }
    };
    Ok(Json(ApiResponse::ok(creds)))
}

#[derive(Deserialize)]
struct ShareVaultRequest {
    user_id: String,
    permission: Option<String>,
}

/// `POST /api/v1/vaults/{name}/shares` — share a vault with another user.
async fn share_vault(
    State(state): State<AppState>,
    actor: AuthenticatedActor,
    axum::Extension(corr): axum::Extension<CorrelationId>,
    Path(name): Path<String>,
    Json(req): Json<ShareVaultRequest>,
) -> Result<Json<ApiResponse<VaultShare>>, ApiError> {
    // Only authenticated users can share vaults; agents cannot.
    let sharer_user_id = match &actor {
        AuthenticatedActor::User(user) => user.id.clone(),
        AuthenticatedActor::Workspace { .. } => {
            return Err(ApiError::Forbidden(
                "workspaces cannot share vaults".to_string(),
            ));
        }
    };

    // Policy check: manage_vaults on System
    let decision = state.policy_engine.evaluate(
        &actor.policy_principal(),
        actions::MANAGE_VAULTS,
        &PolicyResource::System,
        &actor.policy_context(None),
    )?;

    if decision.decision == PolicyDecisionResult::Forbid {
        return Err(ApiError::Forbidden("access denied by policy".to_string()));
    }

    let target_user_id = Uuid::parse_str(&req.user_id)
        .map_err(|_| ApiError::BadRequest("invalid user_id format".to_string()))?;

    // Verify target user exists
    let target_user = state
        .store
        .get_user(&UserId(target_user_id))
        .await?
        .ok_or_else(|| ApiError::NotFound("target user not found".to_string()))?;

    let permission_level = req.permission.unwrap_or_else(|| "read".to_string());
    if !["read", "write", "admin"].contains(&permission_level.as_str()) {
        return Err(ApiError::BadRequest(
            "permission must be 'read', 'write', or 'admin'".to_string(),
        ));
    }

    let now = chrono::Utc::now();
    let share = VaultShare {
        id: Uuid::new_v4().to_string(),
        vault_name: name.clone(),
        shared_with_user_id: target_user.id.clone(),
        permission_level: permission_level.clone(),
        shared_by_user_id: sharer_user_id.clone(),
        created_at: now,
    };

    state.store.share_vault(&share).await?;

    // Audit log
    let (ws_id, ws_name, u_id, u_name) = actor.audit_actor_fields();
    let event = AuditEvent::builder(AuditEventType::VaultShared)
        .action("share")
        .actor_fields(ws_id, ws_name, u_id, u_name)
        .resource("vault", &name)
        .correlation_id(&corr.0)
        .decision(AuditDecision::Permit, Some("bypass:self-service"))
        .details(serde_json::json!({
            "shared_with_user_id": target_user.id.0.to_string(),
            "permission_level": permission_level,
        }))
        .build();
    if let Err(e) = state.store.append_audit_event(&event).await {
        tracing::warn!(error = %e, "Failed to write audit event");
    }

    // Emit UI event for browser auto-refresh
    state
        .ui_event_bus
        .emit(crate::events::UiEvent::VaultChanged {
            vault_name: share.vault_name.clone(),
        });

    Ok(Json(ApiResponse::ok(share)))
}

/// `DELETE /api/v1/vaults/{name}/shares/{user_id}` — revoke vault sharing.
async fn unshare_vault(
    State(state): State<AppState>,
    actor: AuthenticatedActor,
    axum::Extension(corr): axum::Extension<CorrelationId>,
    Path((name, user_id_str)): Path<(String, String)>,
) -> Result<Json<ApiResponse<serde_json::Value>>, ApiError> {
    // Only authenticated users can unshare; agents cannot.
    match &actor {
        AuthenticatedActor::User(_) => {}
        AuthenticatedActor::Workspace { .. } => {
            return Err(ApiError::Forbidden(
                "workspaces cannot unshare vaults".to_string(),
            ));
        }
    };

    // Policy check: manage_vaults on System
    let decision = state.policy_engine.evaluate(
        &actor.policy_principal(),
        actions::MANAGE_VAULTS,
        &PolicyResource::System,
        &actor.policy_context(None),
    )?;

    if decision.decision == PolicyDecisionResult::Forbid {
        return Err(ApiError::Forbidden("access denied by policy".to_string()));
    }

    let target_user_id = Uuid::parse_str(&user_id_str)
        .map_err(|_| ApiError::BadRequest("invalid user_id format".to_string()))?;

    let removed = state
        .store
        .unshare_vault(&name, &UserId(target_user_id))
        .await?;

    if !removed {
        return Err(ApiError::NotFound("vault share not found".to_string()));
    }

    // Audit log
    let (ws_id, ws_name, u_id, u_name) = actor.audit_actor_fields();
    let event = AuditEvent::builder(AuditEventType::VaultUnshared)
        .action("unshare")
        .actor_fields(ws_id, ws_name, u_id, u_name)
        .resource("vault", &name)
        .correlation_id(&corr.0)
        .decision(AuditDecision::Permit, Some("bypass:self-service"))
        .details(serde_json::json!({
            "removed_user_id": user_id_str,
        }))
        .build();
    if let Err(e) = state.store.append_audit_event(&event).await {
        tracing::warn!(error = %e, "Failed to write audit event");
    }

    Ok(Json(ApiResponse::ok(
        serde_json::json!({ "deleted": true }),
    )))
}

/// `GET /api/v1/vaults/{name}/shares` — list shares for a vault.
async fn list_shares(
    State(state): State<AppState>,
    actor: AuthenticatedActor,
    Path(name): Path<String>,
) -> Result<Json<ApiResponse<Vec<VaultShare>>>, ApiError> {
    // Policy check — require list permission
    let decision = state.policy_engine.evaluate(
        &actor.policy_principal(),
        actions::LIST,
        &PolicyResource::System,
        &actor.policy_context(None),
    )?;

    if decision.decision == PolicyDecisionResult::Forbid {
        return Err(ApiError::Forbidden("access denied by policy".to_string()));
    }

    let shares = state.store.list_vault_shares(&name).await?;
    Ok(Json(ApiResponse::ok(shares)))
}
