mod export;
#[cfg(test)]
mod tests;

use axum::{
    extract::{Path, Query, State},
    routing::get,
    Json, Router,
};
use serde::Deserialize;
use uuid::Uuid;

use agent_cordon_core::domain::audit::AuditEvent;
use agent_cordon_core::domain::policy::PolicyDecisionResult;
use agent_cordon_core::policy::{actions, PolicyContext, PolicyEngine, PolicyResource};
use agent_cordon_core::storage::AuditFilter;

use crate::extractors::AuthenticatedActor;
use crate::response::{ApiError, ApiResponse};
use crate::state::AppState;

/// Maximum number of rows in an export to prevent OOM.
pub(crate) const EXPORT_MAX_ROWS: u32 = 10_000;

/// Backwards-compatible alias used by CSV export.
pub(crate) const CSV_EXPORT_MAX_ROWS: u32 = EXPORT_MAX_ROWS;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/audit", get(list_audit))
        .route("/audit/export", get(export::export_audit_csv))
        .route("/audit/export/syslog", get(export::export_audit_syslog))
        .route("/audit/export/jsonl", get(export::export_audit_jsonl))
        .route("/audit/{id}", get(get_audit_event))
}

#[derive(Deserialize)]
pub(crate) struct AuditQuery {
    pub limit: Option<u32>,
    pub offset: Option<u32>,
    pub resource_type: Option<String>,
    pub resource_id: Option<String>,
    pub user_id: Option<String>,
    /// Filter by event source: "workspace" (workspace_id IS NOT NULL), "server" (workspace_id IS NULL), or "all".
    pub source: Option<String>,
    pub action: Option<String>,
    pub decision: Option<String>,
    pub event_type: Option<String>,
    pub workspace_id: Option<String>,
    pub workspace_name: Option<String>,
}

async fn list_audit(
    State(state): State<AppState>,
    actor: AuthenticatedActor,
    Query(q): Query<AuditQuery>,
) -> Result<Json<ApiResponse<Vec<AuditEvent>>>, ApiError> {
    // Policy check: can this actor view audit logs?
    let decision = state.policy_engine.evaluate(
        &actor.policy_principal(),
        actions::VIEW_AUDIT,
        &PolicyResource::System,
        &PolicyContext {
            target_url: None,
            requested_scopes: vec![],
            ..Default::default()
        },
    )?;

    let has_audit_access = decision.decision == PolicyDecisionResult::Permit;

    // If filtering by a specific credential, allow the credential owner to see its events
    // even without broad view_audit access.
    if q.resource_type.is_some() || q.resource_id.is_some() {
        if q.resource_type.as_deref() == Some("credential") {
            if let Some(ref rid) = q.resource_id {
                if !has_audit_access {
                    // For agents, check credential ownership
                    match &actor {
                        AuthenticatedActor::Workspace(workspace) => {
                            let cred_id = uuid::Uuid::parse_str(rid)
                                .map(agent_cordon_core::domain::credential::CredentialId)
                                .map_err(|_| {
                                    ApiError::BadRequest("invalid resource_id".to_string())
                                })?;
                            let cred =
                                state.store.get_credential(&cred_id).await?.ok_or_else(|| {
                                    ApiError::Forbidden("access denied".to_string())
                                })?;
                            if cred.created_by.as_ref() != Some(&workspace.id) {
                                return Err(ApiError::Forbidden("access denied".to_string()));
                            }
                        }
                        AuthenticatedActor::User(user) => {
                            let cred_id = uuid::Uuid::parse_str(rid)
                                .map(agent_cordon_core::domain::credential::CredentialId)
                                .map_err(|_| {
                                    ApiError::BadRequest("invalid resource_id".to_string())
                                })?;
                            let cred =
                                state.store.get_credential(&cred_id).await?.ok_or_else(|| {
                                    ApiError::Forbidden("access denied".to_string())
                                })?;
                            if cred.created_by_user.as_ref() != Some(&user.id) {
                                return Err(ApiError::Forbidden("access denied".to_string()));
                            }
                        }
                    }
                }
            } else if !has_audit_access {
                // resource_type=credential but no resource_id — requires view_audit
                return Err(ApiError::Forbidden("access denied by policy".to_string()));
            }
        } else if !has_audit_access {
            // non-credential resource_type filter — requires view_audit
            return Err(ApiError::Forbidden("access denied by policy".to_string()));
        }
    } else if !has_audit_access {
        return Err(ApiError::Forbidden("access denied by policy".to_string()));
    }

    // Hide noisy policy_evaluated events from UI panes unless the caller
    // explicitly filters for that event type.
    let exclude = if q.event_type.is_none() {
        vec!["policy_evaluated".to_string()]
    } else {
        vec![]
    };

    // Tenant scoping: non-admin users can only see their own audit events.
    // If a non-admin user doesn't specify a user_id filter, inject their own.
    let scoped_user_id = match &actor {
        AuthenticatedActor::User(user) => {
            let is_admin =
                user.role == agent_cordon_core::domain::user::UserRole::Admin || user.is_root;
            if is_admin {
                q.user_id
            } else {
                // Force non-admin users to only see their own events
                Some(user.id.0.to_string())
            }
        }
        AuthenticatedActor::Workspace(_) => q.user_id,
    };

    let filter = AuditFilter {
        limit: q.limit.unwrap_or(50),
        offset: q.offset.unwrap_or(0),
        resource_type: q.resource_type,
        resource_id: q.resource_id,
        source: q.source,
        action: q.action,
        decision: q.decision,
        event_type: q.event_type,
        workspace_id: q.workspace_id,
        workspace_name: q.workspace_name,
        user_id: scoped_user_id,
        exclude_event_types: exclude,
    };

    let events = state.store.list_audit_events_filtered(&filter).await?;
    Ok(Json(ApiResponse::ok(events)))
}

async fn get_audit_event(
    State(state): State<AppState>,
    actor: AuthenticatedActor,
    Path(id): Path<Uuid>,
) -> Result<Json<ApiResponse<AuditEvent>>, ApiError> {
    // Policy check: can this actor view audit logs?
    let decision = state.policy_engine.evaluate(
        &actor.policy_principal(),
        actions::VIEW_AUDIT,
        &PolicyResource::System,
        &PolicyContext {
            target_url: None,
            requested_scopes: vec![],
            ..Default::default()
        },
    )?;

    if decision.decision != PolicyDecisionResult::Permit {
        return Err(ApiError::Forbidden("access denied by policy".to_string()));
    }

    let event = state
        .store
        .get_audit_event(&id)
        .await?
        .ok_or_else(|| ApiError::NotFound("audit event not found".to_string()))?;

    // Tenant scoping: non-admin users can only view their own audit events
    if let AuthenticatedActor::User(user) = &actor {
        let is_admin =
            user.role == agent_cordon_core::domain::user::UserRole::Admin || user.is_root;
        if !is_admin {
            let user_id_str = user.id.0.to_string();
            if event.user_id.as_deref() != Some(&user_id_str) {
                return Err(ApiError::NotFound("audit event not found".to_string()));
            }
        }
    }

    Ok(Json(ApiResponse::ok(event)))
}
