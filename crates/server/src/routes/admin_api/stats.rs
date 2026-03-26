use axum::{extract::State, routing::get, Json, Router};
use serde::Serialize;

use agent_cordon_core::domain::credential::{CredentialId, StoredCredential};
use agent_cordon_core::domain::policy::PolicyDecisionResult;
use agent_cordon_core::domain::workspace::WorkspaceStatus;
use agent_cordon_core::policy::{
    actions, PolicyContext, PolicyEngine, PolicyPrincipal, PolicyResource,
};

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
    let decision = state.policy_engine.evaluate(
        &PolicyPrincipal::User(&auth.user),
        actions::VIEW_AUDIT,
        &PolicyResource::System,
        &PolicyContext {
            target_url: None,
            requested_scopes: vec![],
            ..Default::default()
        },
    )?;

    if decision.decision == PolicyDecisionResult::Forbid {
        return Err(ApiError::Forbidden("access denied by policy".to_string()));
    }

    // Tenant scoping: admins see all data, non-admins see only their own
    let is_admin =
        auth.user.role == agent_cordon_core::domain::user::UserRole::Admin || auth.is_root;
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

        let principal = PolicyPrincipal::User(&auth.user);
        let ctx = PolicyContext {
            target_url: None,
            requested_scopes: vec![],
            ..Default::default()
        };
        all_summaries
            .into_iter()
            .filter(|summary| {
                if let Some(cred) = cred_map.get(&summary.id) {
                    // 1. Check Cedar with User principal
                    if state
                        .policy_engine
                        .evaluate(
                            &principal,
                            actions::LIST,
                            &PolicyResource::Credential {
                                credential: cred.clone(),
                            },
                            &ctx,
                        )
                        .ok()
                        .is_some_and(|d| d.decision != PolicyDecisionResult::Forbid)
                    {
                        return true;
                    }
                    // 2. Check Cedar with each owned Workspace principal
                    for ws in &workspaces {
                        if state
                            .policy_engine
                            .evaluate(
                                &PolicyPrincipal::Workspace(ws),
                                actions::LIST,
                                &PolicyResource::Credential {
                                    credential: cred.clone(),
                                },
                                &ctx,
                            )
                            .ok()
                            .is_some_and(|d| d.decision != PolicyDecisionResult::Forbid)
                        {
                            return true;
                        }
                    }
                }
                false
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
        active: workspaces
            .iter()
            .filter(|w| w.status == WorkspaceStatus::Active && w.enabled)
            .count(),
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
