use axum::{
    extract::{Path, State},
    Json,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use agent_cordon_core::domain::audit::{AuditDecision, AuditEvent, AuditEventType};
use agent_cordon_core::domain::mcp::McpServerId;
use agent_cordon_core::domain::workspace::WorkspaceId;
use agent_cordon_core::policy::actions;

use crate::events::UiEvent;
use crate::extractors::AuthenticatedUser;
use crate::middleware::request_id::CorrelationId;
use crate::response::{ApiError, ApiResponse};
use crate::state::AppState;

use super::check_manage_mcp_servers;

// --- Request/Response types ---

#[derive(Deserialize)]
pub(super) struct GrantPermissionRequest {
    #[serde(alias = "agent_id")]
    workspace_id: Uuid,
    permission: String,
    /// "grant" (default) creates a permit policy; "deny" creates a forbid policy.
    #[serde(default = "default_grant_mode")]
    mode: String,
}

fn default_grant_mode() -> String {
    "grant".to_string()
}

#[derive(Serialize)]
pub(super) struct GrantPermissionResponse {
    policy_id: String,
    policy_name: String,
}

#[derive(Serialize)]
struct McpPermissionEntry {
    workspace_id: Uuid,
    /// Legacy alias for backward compatibility.
    #[serde(rename = "agent_id")]
    agent_id_compat: Uuid,
    workspace_name: Option<String>,
    agent_name: Option<String>,
    permissions: Vec<String>,
}

#[derive(Serialize)]
pub(super) struct McpPermissionsResponse {
    mcp_server_id: Uuid,
    permissions: Vec<McpPermissionEntry>,
}

const VALID_MCP_PERMISSIONS: &[&str] = &[actions::MCP_TOOL_CALL, actions::MCP_LIST_TOOLS];

fn validate_mcp_permission(perm: &str) -> Result<(), ApiError> {
    // Accept base permissions
    if VALID_MCP_PERMISSIONS.contains(&perm) {
        return Ok(());
    }
    // Accept per-tool permissions: mcp_tool_call:<tool_name>
    if let Some(tool_name) = perm.strip_prefix("mcp_tool_call:") {
        if !tool_name.is_empty()
            && tool_name.len() <= 128
            && tool_name
                .chars()
                .all(|c| c.is_alphanumeric() || c == '_' || c == '-')
        {
            return Ok(());
        }
        return Err(ApiError::BadRequest(format!(
            "invalid tool name in permission '{}'; tool names must be 1-128 alphanumeric/underscore/hyphen characters",
            perm
        )));
    }
    Err(ApiError::BadRequest(format!(
        "invalid permission '{}'; must be one of: {}, or mcp_tool_call:<tool_name>",
        perm,
        VALID_MCP_PERMISSIONS.join(", ")
    )))
}

/// GET /api/v1/mcp-servers/{id}/permissions
pub(super) async fn get_permissions(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
    axum::Extension(corr): axum::Extension<CorrelationId>,
    Path(id): Path<Uuid>,
) -> Result<Json<ApiResponse<McpPermissionsResponse>>, ApiError> {
    check_manage_mcp_servers(&state, &auth)?;

    let server_id = McpServerId(id);
    let server = state
        .store
        .get_mcp_server(&server_id)
        .await?
        .ok_or_else(|| ApiError::NotFound("MCP server not found".to_string()))?;

    // Load policies matching prefix grant:mcp:{server_id}: or deny:mcp:{server_id}:
    let all_policies = state.store.list_policies().await?;
    let grant_prefix = format!("grant:mcp:{}:", server.id.0);
    let deny_prefix = format!("deny:mcp:{}:", server.id.0);

    // Collect permissions grouped by agent_id
    let mut agent_perms: std::collections::HashMap<Uuid, (Option<String>, Vec<String>)> =
        std::collections::HashMap::new();

    for policy in &all_policies {
        let rest = policy
            .name
            .strip_prefix(&grant_prefix)
            .or_else(|| policy.name.strip_prefix(&deny_prefix));

        if let Some(rest) = rest {
            // Format: {agent_id}:{action} or {agent_id}:mcp_tool_call:{tool_name}
            let parts: Vec<&str> = rest.splitn(2, ':').collect();
            if parts.len() == 2 {
                if let Ok(agent_uuid) = Uuid::parse_str(parts[0]) {
                    let entry = agent_perms
                        .entry(agent_uuid)
                        .or_insert_with(|| (None, Vec::new()));
                    entry.1.push(parts[1].to_string());
                    if entry.0.is_none() {
                        entry.0 = match state.store.get_workspace(&WorkspaceId(agent_uuid)).await {
                            Ok(Some(ws)) => Some(ws.name),
                            _ => Some("Deleted Workspace".to_string()),
                        };
                    }
                }
            }
        }
    }

    let entries: Vec<McpPermissionEntry> = agent_perms
        .into_iter()
        .map(|(ws_id, (ws_name, permissions))| McpPermissionEntry {
            workspace_id: ws_id,
            agent_id_compat: ws_id,
            workspace_name: ws_name.clone(),
            agent_name: ws_name,
            permissions,
        })
        .collect();

    // Audit
    let event = AuditEvent::builder(AuditEventType::PolicyEvaluated)
        .action("query_mcp_permissions")
        .user_actor(&auth.user)
        .resource("mcp_server", &id.to_string())
        .correlation_id(&corr.0)
        .decision(AuditDecision::Permit, Some("bypass:manage_mcp_servers"))
        .details(serde_json::json!({
            "permission_count": entries.len(),
        }))
        .build();
    if let Err(e) = state.store.append_audit_event(&event).await {
        tracing::warn!(error = %e, "Failed to write audit event");
    }

    Ok(Json(ApiResponse::ok(McpPermissionsResponse {
        mcp_server_id: id,
        permissions: entries,
    })))
}

/// POST /api/v1/mcp-servers/{id}/permissions
pub(super) async fn grant_permission(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
    axum::Extension(corr): axum::Extension<CorrelationId>,
    Path(id): Path<Uuid>,
    Json(req): Json<GrantPermissionRequest>,
) -> Result<
    (
        axum::http::StatusCode,
        Json<ApiResponse<GrantPermissionResponse>>,
    ),
    ApiError,
> {
    validate_mcp_permission(&req.permission)?;
    check_manage_mcp_servers(&state, &auth)?;

    let server_id = McpServerId(id);
    let server = state
        .store
        .get_mcp_server(&server_id)
        .await?
        .ok_or_else(|| ApiError::NotFound("MCP server not found".to_string()))?;

    // Verify workspace exists
    let target_workspace_id = WorkspaceId(req.workspace_id);
    state
        .store
        .get_workspace(&target_workspace_id)
        .await?
        .ok_or_else(|| ApiError::NotFound("workspace not found".to_string()))?;

    let is_deny = match req.mode.as_str() {
        "grant" => false,
        "deny" => true,
        _ => {
            return Err(ApiError::BadRequest(
                "mode must be 'grant' or 'deny'".to_string(),
            ))
        }
    };

    let mode = if is_deny { "deny" } else { "grant" };

    // Create grant/deny policy via grant service (idempotent + engine reload)
    let stored_policy = crate::grants::ensure_mcp_grant(
        &state,
        &server.id,
        &target_workspace_id,
        &req.permission,
        mode,
    )
    .await?;

    let policy_name = stored_policy.name.clone();
    let policy_uuid = stored_policy.id.0;

    // Emit PolicyChanged (not PermissionChanged — grants ARE Cedar policies)
    state
        .event_bus
        .emit(crate::events::DeviceEvent::PolicyChanged {
            policy_name: policy_name.clone(),
        });

    // Emit UI event
    state.ui_event_bus.emit(UiEvent::McpServerChanged {
        server_name: policy_name.clone(),
    });

    // Audit
    let event = AuditEvent::builder(AuditEventType::McpServerUpdated)
        .action("grant_mcp_permission")
        .user_actor(&auth.user)
        .resource("mcp_server", &id.to_string())
        .correlation_id(&corr.0)
        .decision(AuditDecision::Permit, Some("bypass:manage_mcp_servers"))
        .details(serde_json::json!({
            "target_agent_id": req.workspace_id.to_string(),
            "permission": req.permission,
        }))
        .build();
    if let Err(e) = state.store.append_audit_event(&event).await {
        tracing::warn!(error = %e, "Failed to write audit event");
    }

    Ok((
        axum::http::StatusCode::CREATED,
        Json(ApiResponse::ok(GrantPermissionResponse {
            policy_id: policy_uuid.to_string(),
            policy_name,
        })),
    ))
}

/// DELETE /api/v1/mcp-servers/{id}/permissions/{agent_id}/{permission}
pub(super) async fn revoke_permission(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
    axum::Extension(corr): axum::Extension<CorrelationId>,
    Path((id, agent_id, permission)): Path<(Uuid, Uuid, String)>,
) -> Result<Json<ApiResponse<serde_json::Value>>, ApiError> {
    validate_mcp_permission(&permission)?;
    check_manage_mcp_servers(&state, &auth)?;

    let server_id = McpServerId(id);
    let server = state
        .store
        .get_mcp_server(&server_id)
        .await?
        .ok_or_else(|| ApiError::NotFound("MCP server not found".to_string()))?;

    // Try grant first, then deny — matches the naming format used in grant_permission().
    let grant_name = format!("grant:mcp:{}:{}:{}", server.id.0, agent_id, permission);
    let deny_name = format!("deny:mcp:{}:{}:{}", server.id.0, agent_id, permission);

    let deleted_grant = state.store.delete_policy_by_name(&grant_name).await?;
    let policy_name = if deleted_grant {
        grant_name
    } else {
        let deleted_deny = state.store.delete_policy_by_name(&deny_name).await?;
        if !deleted_deny {
            return Err(ApiError::NotFound(
                "permission policy not found".to_string(),
            ));
        }
        deny_name
    };

    // Reload policy engine
    super::super::policies::reload_engine(&state).await?;

    // Emit PolicyChanged
    state
        .event_bus
        .emit(crate::events::DeviceEvent::PolicyChanged {
            policy_name: policy_name.clone(),
        });

    // Emit UI event
    state.ui_event_bus.emit(UiEvent::McpServerChanged {
        server_name: policy_name.clone(),
    });

    // Audit
    let event = AuditEvent::builder(AuditEventType::McpServerUpdated)
        .action("revoke_mcp_permission")
        .user_actor(&auth.user)
        .resource("mcp_server", &id.to_string())
        .correlation_id(&corr.0)
        .decision(AuditDecision::Permit, Some("bypass:manage_mcp_servers"))
        .details(serde_json::json!({
            "target_agent_id": agent_id.to_string(),
            "permission": permission,
        }))
        .build();
    if let Err(e) = state.store.append_audit_event(&event).await {
        tracing::warn!(error = %e, "Failed to write audit event");
    }

    Ok(Json(ApiResponse::ok(
        serde_json::json!({ "revoked": true }),
    )))
}
