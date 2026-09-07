use axum::{
    extract::{Path, State},
    Json,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use agent_cordon_core::domain::mcp::McpServerId;
use agent_cordon_core::domain::workspace::WorkspaceId;
use agent_cordon_core::policy::actions;

use crate::extractors::AuthenticatedUser;
use crate::middleware::request_id::CorrelationId;
use crate::response::{ApiError, ApiResponse};
use crate::state::AppState;

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
    let server_id = McpServerId(id);
    let (server, _) = state
        .services
        .mcp_servers
        .load_and_authorize(&auth, &server_id)
        .await?;

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

    // Audit the read: which server's permissions were listed.
    state
        .services
        .mcp_servers
        .record_permissions_query(&auth, &corr.0, &id, entries.len())
        .await;

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

    let mode = match req.mode.as_str() {
        "grant" => "grant",
        "deny" => "deny",
        _ => {
            return Err(ApiError::BadRequest(
                "mode must be 'grant' or 'deny'".to_string(),
            ))
        }
    };

    let stored_policy = state
        .services
        .mcp_servers
        .grant_permission(
            &auth,
            &corr.0,
            &McpServerId(id),
            &WorkspaceId(req.workspace_id),
            &req.permission,
            mode,
        )
        .await?;

    Ok((
        axum::http::StatusCode::CREATED,
        Json(ApiResponse::ok(GrantPermissionResponse {
            policy_id: stored_policy.id.0.to_string(),
            policy_name: stored_policy.name,
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

    state
        .services
        .mcp_servers
        .revoke_permission(&auth, &corr.0, &McpServerId(id), agent_id, &permission)
        .await?;

    Ok(Json(ApiResponse::ok(
        serde_json::json!({ "revoked": true }),
    )))
}
