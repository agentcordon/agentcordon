use axum::{
    extract::{Path, State},
    routing::get,
    Json, Router,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use agent_cordon_core::domain::credential::CredentialId;
use agent_cordon_core::domain::workspace::WorkspaceId;
use agent_cordon_core::policy::actions;

use crate::extractors::AuthenticatedActor;
use crate::response::{ApiError, ApiResponse};
use crate::services::policies::PermissionGrant as ServiceGrant;
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
            // No granted_by recorded on the policy — show generic label
            // TODO: add `created_by_user` to StoredPolicy so grants can show the operator who created them
            entry.granted_by_name = Some("System".to_string());
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

async fn get_permissions(
    State(state): State<AppState>,
    actor: AuthenticatedActor,
    axum::Extension(_corr): axum::Extension<crate::middleware::request_id::CorrelationId>,
    Path(id): Path<Uuid>,
) -> Result<Json<ApiResponse<CredentialPermissionsResponse>>, ApiError> {
    let cred_id = CredentialId(id);
    // Read-only authorization: allows manage_permissions OR credential ownership.
    // Credential owners and workspace owners can view permissions on their resources.
    let cred = state
        .services
        .policies
        .load_and_authorize_permissions(&actor, &cred_id)
        .await?;

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

    // Policy decision audit is emitted automatically by the Authz seam.

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
    let mode = match req.mode.as_str() {
        "grant" => "grant",
        "deny" => "deny",
        _ => {
            return Err(ApiError::BadRequest(
                "mode must be 'grant' or 'deny'".to_string(),
            ))
        }
    };

    let granted = state
        .services
        .policies
        .grant_credential_permissions(
            &actor,
            &corr.0,
            &CredentialId(id),
            &WorkspaceId(req.workspace_id),
            &perms_to_grant,
            mode,
        )
        .await?;

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

    let grants: Vec<ServiceGrant> = req
        .permissions
        .into_iter()
        .map(|g| ServiceGrant {
            workspace_id: WorkspaceId(g.workspace_id),
            permission: g.permission,
        })
        .collect();

    state
        .services
        .policies
        .set_credential_permissions(&actor, &corr.0, &CredentialId(id), &grants)
        .await?;

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

    state
        .services
        .policies
        .revoke_credential_permission(
            &actor,
            &corr.0,
            &CredentialId(id),
            &WorkspaceId(agent_id),
            &permission,
        )
        .await?;

    Ok(Json(ApiResponse::ok(
        serde_json::json!({ "revoked": true }),
    )))
}
