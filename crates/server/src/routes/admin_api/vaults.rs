use axum::{
    extract::{Path, State},
    routing::get,
    Json, Router,
};
use serde::Deserialize;

use agent_cordon_core::domain::credential::CredentialSummary;
use agent_cordon_core::domain::vault::VaultShare;
use agent_cordon_core::policy::{actions, PolicyResource};

use crate::extractors::AuthenticatedActor;
use crate::middleware::request_id::CorrelationId;
use crate::response::{ApiError, ApiResponse};
use crate::services::vaults::VaultView;
use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/vaults", get(list_vaults).post(create_vault))
        .route(
            "/vaults/{id}",
            axum::routing::patch(rename_vault).delete(delete_vault),
        )
        .route("/vaults/{id}/credentials", get(list_vault_credentials))
        .route("/vaults/{id}/shares", get(list_shares).post(share_vault))
        .route(
            "/vaults/{id}/shares/{user_id}",
            axum::routing::delete(unshare_vault),
        )
}

#[derive(Deserialize)]
struct VaultNameRequest {
    name: String,
}

/// `POST /api/v1/vaults` — create a vault owned by the caller.
async fn create_vault(
    State(state): State<AppState>,
    actor: AuthenticatedActor,
    axum::Extension(corr): axum::Extension<CorrelationId>,
    Json(req): Json<VaultNameRequest>,
) -> Result<Json<ApiResponse<VaultView>>, ApiError> {
    let vault = state
        .services
        .vaults
        .create(&actor, &corr.0, &req.name)
        .await?;
    Ok(Json(ApiResponse::ok(vault.into())))
}

/// `GET /api/v1/vaults` — the vaults this caller can see.
///
/// Their own, the system default, the ones shared with them (naming who
/// shared each), and — for a `manage_vaults` holder — every vault.
async fn list_vaults(
    State(state): State<AppState>,
    actor: AuthenticatedActor,
    axum::Extension(corr): axum::Extension<CorrelationId>,
) -> Result<Json<ApiResponse<Vec<VaultView>>>, ApiError> {
    let vaults = state.services.vaults.list(&actor, &corr.0).await?;
    Ok(Json(ApiResponse::ok(vaults)))
}

/// `PATCH /api/v1/vaults/{id}` — rename a vault.
async fn rename_vault(
    State(state): State<AppState>,
    actor: AuthenticatedActor,
    axum::Extension(corr): axum::Extension<CorrelationId>,
    Path(id): Path<String>,
    Json(req): Json<VaultNameRequest>,
) -> Result<Json<ApiResponse<VaultView>>, ApiError> {
    let vault = state
        .services
        .vaults
        .rename(&actor, &corr.0, &id, &req.name)
        .await?;
    Ok(Json(ApiResponse::ok(vault.into())))
}

/// `DELETE /api/v1/vaults/{id}` — delete an empty vault; 409 otherwise.
async fn delete_vault(
    State(state): State<AppState>,
    actor: AuthenticatedActor,
    axum::Extension(corr): axum::Extension<CorrelationId>,
    Path(id): Path<String>,
) -> Result<Json<ApiResponse<serde_json::Value>>, ApiError> {
    state.services.vaults.delete(&actor, &corr.0, &id).await?;
    Ok(Json(ApiResponse::ok(
        serde_json::json!({ "deleted": true }),
    )))
}

/// `GET /api/v1/vaults/{id}/credentials` — list credentials in a vault.
///
/// Enforces vault sharing: non-root users only see credentials they
/// created, in vaults they own, or in vaults shared with them.
async fn list_vault_credentials(
    State(state): State<AppState>,
    actor: AuthenticatedActor,
    Path(id): Path<String>,
) -> Result<Json<ApiResponse<Vec<CredentialSummary>>>, ApiError> {
    // Policy check
    state
        .authz
        .request(
            crate::authz::PolicyCaller::Principal {
                principal: actor.policy_principal(),
                oauth_claims: None,
            },
            &uuid::Uuid::new_v4().to_string(),
        )
        .check(actions::LIST, &PolicyResource::System)
        .await?;

    let creds = match &actor {
        AuthenticatedActor::User(user) if user.is_root => {
            // Root users see all credentials in the vault
            state.store.list_credentials_by_vault(&id).await?
        }
        AuthenticatedActor::User(user) => {
            // Non-root users: enforce vault ownership and sharing
            state
                .store
                .list_credentials_by_vault_for_user(&id, &user.id)
                .await?
        }
        AuthenticatedActor::Workspace { .. } => {
            // Fetch all credentials in the vault, then filter each through
            // the Authz seam to enforce tag-based and other Cedar policies.
            // The seam silently drops denied items and emits a
            // PolicyEvaluated audit event per item.
            let all_creds = state.store.list_credentials_by_vault(&id).await?;
            let mut full_creds = Vec::new();
            for summary in all_creds {
                if let Ok(Some(c)) = state.store.get_credential(&summary.id).await {
                    full_creds.push((summary, c));
                }
            }
            let kept = state
                .authz
                .request(&actor, &uuid::Uuid::new_v4().to_string())
                .filter(actions::LIST, full_creds, |(_, cred)| {
                    PolicyResource::Credential {
                        credential: cred.clone(),
                    }
                })
                .await?;
            kept.into_iter().map(|(s, _)| s).collect()
        }
    };
    Ok(Json(ApiResponse::ok(creds)))
}

#[derive(Deserialize)]
struct ShareVaultRequest {
    user_id: String,
    permission: Option<String>,
}

/// `POST /api/v1/vaults/{id}/shares` — share a vault with another user.
async fn share_vault(
    State(state): State<AppState>,
    actor: AuthenticatedActor,
    axum::Extension(corr): axum::Extension<CorrelationId>,
    Path(id): Path<String>,
    Json(req): Json<ShareVaultRequest>,
) -> Result<Json<ApiResponse<VaultShare>>, ApiError> {
    let share = state
        .services
        .vaults
        .share(&actor, &corr.0, &id, &req.user_id, req.permission)
        .await?;
    Ok(Json(ApiResponse::ok(share)))
}

/// `DELETE /api/v1/vaults/{id}/shares/{user_id}` — revoke vault sharing.
async fn unshare_vault(
    State(state): State<AppState>,
    actor: AuthenticatedActor,
    axum::Extension(corr): axum::Extension<CorrelationId>,
    Path((id, user_id_str)): Path<(String, String)>,
) -> Result<Json<ApiResponse<serde_json::Value>>, ApiError> {
    state
        .services
        .vaults
        .unshare(&actor, &corr.0, &id, &user_id_str)
        .await?;
    Ok(Json(ApiResponse::ok(
        serde_json::json!({ "deleted": true }),
    )))
}

/// `GET /api/v1/vaults/{id}/shares` — list shares for a vault.
///
/// Gated per vault in the service, like the share writes: a signed-in user
/// who owns nothing in the vault does not get the roster.
async fn list_shares(
    State(state): State<AppState>,
    actor: AuthenticatedActor,
    axum::Extension(corr): axum::Extension<CorrelationId>,
    Path(id): Path<String>,
) -> Result<Json<ApiResponse<Vec<VaultShare>>>, ApiError> {
    let shares = state
        .services
        .vaults
        .list_shares(&actor, &corr.0, &id)
        .await?;
    Ok(Json(ApiResponse::ok(shares)))
}
