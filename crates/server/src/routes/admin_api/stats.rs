use axum::{extract::State, routing::get, Json, Router};
use serde::Serialize;

use agent_cordon_core::domain::credential::{CredentialId, StoredCredential};
use agent_cordon_core::policy::{actions, claim_keys, PolicyPrincipal, PolicyResource};

use crate::extractors::AuthenticatedUser;
use crate::response::{ApiError, ApiResponse};
use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new().route("/stats", get(get_stats))
}

#[derive(Serialize)]
struct StatsResponse {
    workspaces: WorkspaceStats,
    credentials: CredentialStats,
    recent_events: Vec<RecentEvent>,
}

#[derive(Serialize)]
struct WorkspaceStats {
    total: usize,
    active: usize,
}

#[derive(Serialize)]
struct CredentialStats {
    total: usize,
    llm_exposed: usize,
}

#[derive(Serialize)]
struct RecentEvent {
    id: String,
    event_type: String,
    principal: String,
    timestamp: String,
    decision: String,
}

/// GET /api/v1/stats — dashboard statistics (admin/operator only).
///
/// Returns aggregate counts for workspaces, credentials, and the last 10
/// audit events. Read-only; does not emit its own audit event.
async fn get_stats(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
) -> Result<Json<ApiResponse<StatsResponse>>, ApiError> {
    // Cedar policy check: view_audit on System resource
    state
        .authz
        .request(
            crate::authz::PolicyCaller::Principal {
                principal: PolicyPrincipal::User(&auth.user),
                oauth_claims: None,
            },
            &uuid::Uuid::new_v4().to_string(),
        )
        .with_claim(
            claim_keys::REQUESTED_SCOPES,
            serde_json::json!(Vec::<String>::new()),
        )
        .check(actions::VIEW_AUDIT, &PolicyResource::System)
        .await?; // Tenant scoping: admins see all data, non-admins see only their own
    let is_admin = auth.is_admin();
    let workspaces = if is_admin {
        state.store.list_workspaces().await?
    } else {
        state.store.get_workspaces_by_owner(&auth.user.id).await?
    };
    // Tenant-scoped credential count: non-admin users see credentials permitted
    // by Cedar policy OR belonging to workspaces they own (workspace-scoped
    // credentials only have workspace-principal grants, not user-principal grants).
    let credentials = if is_admin {
        state.store.list_credentials().await?
    } else {
        let all_summaries = state.store.list_credentials().await?;
        let all_stored = state.store.list_all_stored_credentials().await?;
        let cred_map: std::collections::HashMap<CredentialId, StoredCredential> =
            all_stored.into_iter().map(|c| (c.id.clone(), c)).collect();

        // A credential counts if the user may list it, or any workspace the
        // user owns may. Each principal is one Cedar filter over the whole
        // set (one audit row per principal), then the results are unioned.
        let corr = uuid::Uuid::new_v4().to_string();
        let mut visible: std::collections::HashSet<CredentialId> = std::collections::HashSet::new();
        let stored: Vec<StoredCredential> = cred_map.values().cloned().collect();

        let as_user = state
            .authz
            .request(
                crate::authz::PolicyCaller::Principal {
                    principal: PolicyPrincipal::User(&auth.user),
                    oauth_claims: None,
                },
                &corr,
            )
            .with_claim(
                claim_keys::REQUESTED_SCOPES,
                serde_json::json!(Vec::<String>::new()),
            )
            .filter(actions::LIST, stored.clone(), |c| {
                PolicyResource::Credential {
                    credential: c.clone(),
                }
            })
            .await?;
        visible.extend(as_user.into_iter().map(|c| c.id));

        for ws in &workspaces {
            let as_ws = state
                .authz
                .request(
                    crate::authz::PolicyCaller::Principal {
                        principal: PolicyPrincipal::Workspace(ws),
                        oauth_claims: None,
                    },
                    &corr,
                )
                .with_claim(
                    claim_keys::REQUESTED_SCOPES,
                    serde_json::json!(Vec::<String>::new()),
                )
                .filter(actions::LIST, stored.clone(), |c| {
                    PolicyResource::Credential {
                        credential: c.clone(),
                    }
                })
                .await?;
            visible.extend(as_ws.into_iter().map(|c| c.id));
        }

        // A vault read share is the vault owner's own decision and Cedar has
        // no `Vault` resource to carry it, so `/api/v1/credentials` unions the
        // shared vaults in after the policy filter. The tile is described by
        // the same sentence in `docs/admin-ui.md § Dashboard`, so it counts
        // the same rows (uat/artifacts/fresh-user-native-2.md F9).
        let shared_vaults = state
            .services
            .credentials
            .shared_vault_ids_for_user(&auth.user.id)
            .await?;

        all_summaries
            .into_iter()
            .filter(|summary| {
                visible.contains(&summary.id) || shared_vaults.contains(&summary.vault_id)
            })
            .collect()
    };
    let events = if is_admin {
        state.store.list_audit_events(10, 0).await?
    } else {
        let filter = agent_cordon_core::storage::AuditFilter {
            limit: 10,
            user_id: Some(auth.user.id.0.to_string()),
            ..Default::default()
        };
        state.store.list_audit_events_filtered(&filter).await?
    };

    let workspace_stats = WorkspaceStats {
        total: workspaces.len(),
        active: workspaces.iter().filter(|w| w.is_active()).count(),
    };

    let credential_stats = CredentialStats {
        total: credentials.len(),
        llm_exposed: credentials
            .iter()
            .filter(|c| c.tags.iter().any(|t| t == "llm_exposed"))
            .count(),
    };

    let recent_events: Vec<RecentEvent> = events
        .into_iter()
        .map(|e| {
            let principal = e
                .user_name
                .as_deref()
                .or(e.workspace_name.as_deref())
                .unwrap_or("system")
                .to_string();
            RecentEvent {
                id: e.id.to_string(),
                event_type: serde_json::to_value(&e.event_type)
                    .ok()
                    .and_then(|v| v.as_str().map(String::from))
                    .unwrap_or_else(|| format!("{:?}", e.event_type)),
                principal,
                timestamp: e.timestamp.to_rfc3339(),
                decision: serde_json::to_value(&e.decision)
                    .ok()
                    .and_then(|v| v.as_str().map(String::from))
                    .unwrap_or_else(|| format!("{:?}", e.decision)),
            }
        })
        .collect();

    Ok(Json(ApiResponse::ok(StatsResponse {
        workspaces: workspace_stats,
        credentials: credential_stats,
        recent_events,
    })))
}
