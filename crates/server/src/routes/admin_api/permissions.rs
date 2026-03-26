use axum::{
    extract::{Path, State},
    routing::get,
    Json, Router,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use agent_cordon_core::domain::credential::CredentialId;
use agent_cordon_core::domain::policy::PolicyDecisionResult;
use agent_cordon_core::domain::workspace::WorkspaceId;
use agent_cordon_core::policy::{actions, templates};
use agent_cordon_core::policy::{PolicyContext, PolicyEngine, PolicyResource};

use crate::events::UiEvent;
use crate::extractors::AuthenticatedActor;
use crate::response::{ApiError, ApiResponse};
use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/credentials/{id}/permissions",
            get(get_permissions)
                .post(grant_permission)
                .put(set_permissions),
        )
        .route(
            "/credentials/{id}/permissions/{agent_id}/{permission}",
            axum::routing::delete(revoke_permission),
        )
}

// --- Response types ---

#[derive(Serialize)]
struct CredentialPermissionsResponse {
    credential_id: Uuid,
    owner_agent: Option<Uuid>,
    owner_user: Option<Uuid>,
    permissions: Vec<PermissionEntry>,
}

#[derive(Serialize)]
struct PermissionEntry {
    /// Workspace (formerly agent) UUID.
    /// Serialized as both `workspace_id` and `agent_id` for backward compatibility.
    workspace_id: Uuid,
    /// Legacy alias — same value as workspace_id, for tests/clients that read `agent_id`.
    #[serde(rename = "agent_id")]
    agent_id_compat: Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    workspace_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    agent_name: Option<String>,
    permission: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    granted_by: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    granted_by_user: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    granted_by_name: Option<String>,
    granted_at: DateTime<Utc>,
}

/// Resolve agent_name and granted_by_name for permission entries.
async fn enrich_permission_names(
    store: &dyn agent_cordon_core::storage::Store,
    entries: &mut [PermissionEntry],
) {
    for entry in entries.iter_mut() {
        // Resolve workspace_name (and agent_name alias)
        let ws_id = WorkspaceId(entry.workspace_id);
        match store.get_workspace(&ws_id).await {
            Ok(Some(workspace)) => {
                entry.workspace_name = Some(workspace.name.clone());
                entry.agent_name = Some(workspace.name);
            }
            _ => {
                entry.workspace_name = Some("Deleted Workspace".to_string());
                entry.agent_name = Some("Deleted Workspace".to_string());
            }
        }

        // Resolve granted_by_name
        if let Some(user_uuid) = entry.granted_by_user {
            let user_id = agent_cordon_core::domain::user::UserId(user_uuid);
            match store.get_user(&user_id).await {
                Ok(Some(user)) => {
                    entry.granted_by_name = user.display_name.or(Some(user.username));
                }
                _ => entry.granted_by_name = Some("Deleted User".to_string()),
            }
        } else if let Some(agent_uuid) = entry.granted_by {
            let grantor_id = WorkspaceId(agent_uuid);
            match store.get_workspace(&grantor_id).await {
                Ok(Some(workspace)) => entry.granted_by_name = Some(workspace.name),
                _ => entry.granted_by_name = Some("Deleted Workspace".to_string()),
            }
        } else {
            // No granted_by — auto-grant
            entry.granted_by_name = Some("System (auto-grant)".to_string());
        }
    }
}

// --- Request types ---

/// Accepts both single and batch permission grant formats:
///
/// - Single: `{ "agent_id": "...", "permission": "read" }`
/// - Batch:  `{ "agent_id": "...", "permissions": ["read", "write"] }`
///
/// If both `permission` and `permissions` are provided, they are merged.
#[derive(Deserialize)]
struct GrantPermissionRequest {
    #[serde(alias = "agent_id")]
    workspace_id: Uuid,
    /// Single permission (backward compatible).
    permission: Option<String>,
    /// Batch permissions.
    permissions: Option<Vec<String>>,
    /// "grant" (default) creates a permit policy; "deny" creates a forbid policy.
    #[serde(default = "default_grant_mode")]
    mode: String,
}

fn default_grant_mode() -> String {
    "grant".to_string()
}

/// Response for the grant permission endpoint.
#[derive(Serialize)]
struct GrantPermissionResponse {
    granted: Vec<String>,
}

#[derive(Deserialize)]
struct SetPermissionsRequest {
    permissions: Vec<PermissionGrant>,
}

#[derive(Deserialize)]
struct PermissionGrant {
    #[serde(alias = "agent_id")]
    workspace_id: Uuid,
    permission: String,
}

const VALID_PERMISSIONS: &[&str] = &[
    "read",
    "write",
    "delete",
    "delegated_use",
    actions::ACCESS,
    actions::VEND_CREDENTIAL,
    actions::LIST,
    actions::UPDATE,
];

fn validate_permission(perm: &str) -> Result<(), ApiError> {
    if VALID_PERMISSIONS.contains(&perm) {
        Ok(())
    } else {
        Err(ApiError::BadRequest(format!(
            "invalid permission '{}'; must be one of: {}",
            perm,
            VALID_PERMISSIONS.join(", ")
        )))
    }
}

/// Map a permission name to the Cedar action(s) it grants.
fn permission_to_cedar_actions(perm: &str) -> Vec<&'static str> {
    templates::permission_to_actions(perm)
}

/// Load credential, then check manage_permissions policy.
async fn load_and_authorize(
    state: &AppState,
    actor: &AuthenticatedActor,
    cred_id: &CredentialId,
) -> Result<(), ApiError> {
    let cred = state
        .store
        .get_credential(cred_id)
        .await?
        .ok_or_else(|| ApiError::NotFound("credential not found".to_string()))?;

    let decision = state.policy_engine.evaluate(
        &actor.policy_principal(),
        actions::MANAGE_PERMISSIONS,
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

    Ok(())
}

async fn get_permissions(
    State(state): State<AppState>,
    actor: AuthenticatedActor,
    axum::Extension(corr): axum::Extension<crate::middleware::request_id::CorrelationId>,
    Path(id): Path<Uuid>,
) -> Result<Json<ApiResponse<CredentialPermissionsResponse>>, ApiError> {
    let cred_id = CredentialId(id);
    load_and_authorize(&state, &actor, &cred_id).await?;

    let cred = state
        .store
        .get_credential(&cred_id)
        .await?
        .ok_or_else(|| ApiError::NotFound("credential not found".to_string()))?;

    // Load grant and deny policies to derive permission entries
    let all_policies = state.store.list_policies().await?;
    let grant_prefix = format!("grant:{}:", cred_id.0);
    let deny_prefix = format!("deny:{}:", cred_id.0);
    let mut entries: Vec<PermissionEntry> = Vec::new();
    for policy in &all_policies {
        // Check both grant: and deny: prefixed policies
        let rest = if let Some(r) = policy.name.strip_prefix(&grant_prefix) {
            Some(r)
        } else {
            policy.name.strip_prefix(&deny_prefix)
        };
        if let Some(rest) = rest {
            // Format: {mode}:{cred_id}:{agent_id}:{permission}
            let parts: Vec<&str> = rest.splitn(2, ':').collect();
            if parts.len() == 2 {
                if let Ok(agent_uuid) = Uuid::parse_str(parts[0]) {
                    entries.push(PermissionEntry {
                        workspace_id: agent_uuid,
                        agent_id_compat: agent_uuid,
                        workspace_name: None,
                        agent_name: None,
                        permission: parts[1].to_string(),
                        granted_by: None,
                        granted_by_user: None,
                        granted_by_name: None,
                        granted_at: policy.created_at,
                    });
                }
            }
        }
    }
    enrich_permission_names(state.store.as_ref(), &mut entries).await;

    // Audit event for permission query (compliance requirement)
    let (ws_id, ws_name, u_id, u_name) = actor.audit_actor_fields();
    let audit_event = agent_cordon_core::domain::audit::AuditEvent::builder(
        agent_cordon_core::domain::audit::AuditEventType::PolicyEvaluated,
    )
    .action("query_permissions")
    .actor_fields(ws_id, ws_name, u_id, u_name)
    .resource("credential", &id.to_string())
    .correlation_id(&corr.0)
    .decision(
        agent_cordon_core::domain::audit::AuditDecision::Permit,
        Some("bypass:manage_permissions"),
    )
    .details(serde_json::json!({
        "permission_count": entries.len(),
    }))
    .build();
    if let Err(e) = state.store.append_audit_event(&audit_event).await {
        tracing::warn!(error = %e, "Failed to write audit event");
    }

    let response = CredentialPermissionsResponse {
        credential_id: id,
        owner_agent: cred.created_by.map(|id| id.0),
        owner_user: cred.created_by_user.map(|id| id.0),
        permissions: entries,
    };

    Ok(Json(ApiResponse::ok(response)))
}

async fn grant_permission(
    State(state): State<AppState>,
    actor: AuthenticatedActor,
    axum::Extension(corr): axum::Extension<crate::middleware::request_id::CorrelationId>,
    Path(id): Path<Uuid>,
    Json(req): Json<GrantPermissionRequest>,
) -> Result<Json<ApiResponse<GrantPermissionResponse>>, ApiError> {
    // Resolve the list of permissions to grant (supports both single and batch)
    let mut perms_to_grant: Vec<String> = Vec::new();
    if let Some(ref p) = req.permission {
        perms_to_grant.push(p.clone());
    }
    if let Some(ref ps) = req.permissions {
        for p in ps {
            if !perms_to_grant.contains(p) {
                perms_to_grant.push(p.clone());
            }
        }
    }
    if perms_to_grant.is_empty() {
        return Err(ApiError::BadRequest(
            "either 'permission' or 'permissions' must be provided".to_string(),
        ));
    }

    // Validate all permissions up front
    for p in &perms_to_grant {
        validate_permission(p)?;
    }

    // Validate mode
    let is_deny = match req.mode.as_str() {
        "grant" => false,
        "deny" => true,
        _ => {
            return Err(ApiError::BadRequest(
                "mode must be 'grant' or 'deny'".to_string(),
            ))
        }
    };

    let cred_id = CredentialId(id);
    load_and_authorize(&state, &actor, &cred_id).await?;

    let target_agent_id = WorkspaceId(req.workspace_id);

    // Verify target workspace exists
    state
        .store
        .get_workspace(&target_agent_id)
        .await?
        .ok_or_else(|| ApiError::NotFound("target workspace not found".to_string()))?;

    // Grant each permission by creating Cedar policies via grant service
    let mode = if is_deny { "deny" } else { "grant" };
    let mut granted = Vec::new();
    for perm in &perms_to_grant {
        let cedar_actions = permission_to_cedar_actions(perm);

        for cedar_action in &cedar_actions {
            crate::grants::ensure_credential_grant(
                &state,
                &cred_id,
                &target_agent_id,
                cedar_action,
                perm,
                mode,
            )
            .await?;
        }

        granted.push(perm.clone());

        // Audit event per permission
        let (ws_id, ws_name, u_id, u_name) = actor.audit_actor_fields();
        let event = agent_cordon_core::domain::audit::AuditEvent::builder(
            agent_cordon_core::domain::audit::AuditEventType::CredentialUpdated,
        )
        .action("grant_permission")
        .actor_fields(ws_id, ws_name, u_id, u_name)
        .resource("credential", &id.to_string())
        .correlation_id(&corr.0)
        .decision(
            agent_cordon_core::domain::audit::AuditDecision::Permit,
            Some("bypass:manage_permissions"),
        )
        .details(serde_json::json!({
            "target_agent_id": req.workspace_id.to_string(),
            "permission": perm,
            "mode": req.mode,
        }))
        .build();
        if let Err(e) = state.store.append_audit_event(&event).await {
            tracing::warn!(error = %e, "Failed to write audit event");
        }
    }

    // Notify devices that policies changed (grants/denies ARE Cedar policies)
    let event_prefix = if is_deny { "deny" } else { "grant" };
    for perm in &granted {
        let cedar_actions = permission_to_cedar_actions(perm);
        for cedar_action in &cedar_actions {
            let policy_name = format!(
                "{}:{}:{}:{}",
                event_prefix, cred_id.0, req.workspace_id, cedar_action
            );
            state
                .event_bus
                .emit(crate::events::DeviceEvent::PolicyChanged { policy_name });
        }
    }

    // Emit UI event for browser auto-refresh (credential detail page)
    state
        .ui_event_bus
        .emit(UiEvent::CredentialUpdated { credential_id: id });

    Ok(Json(ApiResponse::ok(GrantPermissionResponse { granted })))
}

async fn set_permissions(
    State(state): State<AppState>,
    actor: AuthenticatedActor,
    axum::Extension(corr): axum::Extension<crate::middleware::request_id::CorrelationId>,
    Path(id): Path<Uuid>,
    Json(req): Json<SetPermissionsRequest>,
) -> Result<Json<ApiResponse<serde_json::Value>>, ApiError> {
    for grant in &req.permissions {
        validate_permission(&grant.permission)?;
    }

    let cred_id = CredentialId(id);
    load_and_authorize(&state, &actor, &cred_id).await?;

    // Delete all existing grant policies for this credential
    let prefix = format!("grant:{}:", cred_id.0);
    state.store.delete_policies_by_name_prefix(&prefix).await?;

    // Create new grant policies via grant service
    for grant in &req.permissions {
        let cedar_actions = permission_to_cedar_actions(&grant.permission);
        let target_ws = WorkspaceId(grant.workspace_id);
        for cedar_action in &cedar_actions {
            crate::grants::ensure_credential_grant(
                &state,
                &cred_id,
                &target_ws,
                cedar_action,
                &grant.permission,
                "grant",
            )
            .await?;
        }
    }

    // Audit event for bulk permission set
    let (ws_id, ws_name, u_id, u_name) = actor.audit_actor_fields();
    let event = agent_cordon_core::domain::audit::AuditEvent::builder(
        agent_cordon_core::domain::audit::AuditEventType::CredentialUpdated,
    )
    .action("set_permissions")
    .actor_fields(ws_id, ws_name, u_id, u_name)
    .resource("credential", &id.to_string())
    .correlation_id(&corr.0)
    .decision(
        agent_cordon_core::domain::audit::AuditDecision::Permit,
        Some("bypass:manage_permissions"),
    )
    .details(serde_json::json!({
        "permissions": req.permissions.iter().map(|g| serde_json::json!({
            "workspace_id": g.workspace_id.to_string(),
            "permission": g.permission,
        })).collect::<Vec<_>>(),
    }))
    .build();
    if let Err(e) = state.store.append_audit_event(&event).await {
        tracing::warn!(error = %e, "Failed to write audit event");
    }

    // Notify devices that policies changed (grants ARE Cedar policies)
    for grant in &req.permissions {
        let cedar_actions = permission_to_cedar_actions(&grant.permission);
        for cedar_action in &cedar_actions {
            let policy_name = format!(
                "grant:{}:{}:{}",
                cred_id.0, grant.workspace_id, cedar_action
            );
            state
                .event_bus
                .emit(crate::events::DeviceEvent::PolicyChanged { policy_name });
        }
    }

    // Emit UI event for browser auto-refresh (credential detail page)
    state
        .ui_event_bus
        .emit(UiEvent::CredentialUpdated { credential_id: id });

    Ok(Json(ApiResponse::ok(
        serde_json::json!({ "updated": true }),
    )))
}

async fn revoke_permission(
    State(state): State<AppState>,
    actor: AuthenticatedActor,
    axum::Extension(corr): axum::Extension<crate::middleware::request_id::CorrelationId>,
    Path((id, agent_id, permission)): Path<(Uuid, Uuid, String)>,
) -> Result<Json<ApiResponse<serde_json::Value>>, ApiError> {
    validate_permission(&permission)?;
    let cred_id = CredentialId(id);
    load_and_authorize(&state, &actor, &cred_id).await?;

    // Delete the Cedar grant policies for this permission
    let cedar_actions = permission_to_cedar_actions(&permission);
    for cedar_action in &cedar_actions {
        let policy_name = format!("grant:{}:{}:{}", cred_id.0, agent_id, cedar_action);
        state.store.delete_policy_by_name(&policy_name).await?;
    }

    // Reload policy engine
    super::policies::reload_engine(&state).await?;

    // Audit event for permission revocation
    let (ws_id, ws_name, u_id, u_name) = actor.audit_actor_fields();
    let event = agent_cordon_core::domain::audit::AuditEvent::builder(
        agent_cordon_core::domain::audit::AuditEventType::CredentialUpdated,
    )
    .action("revoke_permission")
    .actor_fields(ws_id, ws_name, u_id, u_name)
    .resource("credential", &id.to_string())
    .correlation_id(&corr.0)
    .decision(
        agent_cordon_core::domain::audit::AuditDecision::Permit,
        Some("bypass:manage_permissions"),
    )
    .details(serde_json::json!({
        "target_agent_id": agent_id.to_string(),
        "permission": permission,
    }))
    .build();
    if let Err(e) = state.store.append_audit_event(&event).await {
        tracing::warn!(error = %e, "Failed to write audit event");
    }

    // Notify devices that policies changed (grants ARE Cedar policies)
    let cedar_actions_rev = permission_to_cedar_actions(&permission);
    for cedar_action in &cedar_actions_rev {
        let policy_name = format!("grant:{}:{}:{}", cred_id.0, agent_id, cedar_action);
        state
            .event_bus
            .emit(crate::events::DeviceEvent::PolicyChanged { policy_name });
    }

    // Emit UI event for browser auto-refresh (credential detail page)
    state
        .ui_event_bus
        .emit(UiEvent::CredentialUpdated { credential_id: id });

    Ok(Json(ApiResponse::ok(
        serde_json::json!({ "revoked": true }),
    )))
}
