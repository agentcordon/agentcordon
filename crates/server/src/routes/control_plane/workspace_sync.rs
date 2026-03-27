//! Workspace-authenticated sync endpoints for devices.
//!
//! These endpoints allow authenticated devices (workspace identity JWT) to
//! sync Cedar policies and receive server-push events.

use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};

use crate::events::UiEvent;
use crate::extractors::AuthenticatedWorkspace;
use crate::response::{ApiError, ApiResponse};
use crate::state::AppState;

/// A single Cedar policy entry for device sync.
#[derive(Serialize)]
pub(super) struct PolicySyncEntry {
    id: String,
    name: String,
    cedar_policy: String,
}

/// Response for `GET /api/v1/workspaces/policies`.
#[derive(Serialize)]
pub(super) struct PolicySyncResponse {
    policies: Vec<PolicySyncEntry>,
}

/// GET /api/v1/workspaces/policies -- sync enabled Cedar policies relevant to this workspace.
///
/// Auth: workspace identity JWT (Authorization: Bearer).
/// Returns only policies the requesting workspace needs for local evaluation:
/// - System/default policies (not per-entity grants or denies)
/// - Per-entity grant/deny policies that specifically reference this workspace
///
/// Per-entity policies follow the naming conventions:
/// - `grant:{cred_id}:{workspace_id}:{action}`
/// - `deny:{cred_id}:{workspace_id}:{action}`
/// - `grant:mcp:{server_id}:{workspace_id}:{action}`
/// - `deny:mcp:{server_id}:{workspace_id}:{action}`
pub(super) async fn sync_policies(
    State(state): State<AppState>,
    workspace: AuthenticatedWorkspace,
) -> Result<Json<ApiResponse<PolicySyncResponse>>, ApiError> {
    let policies = state.store.get_all_enabled_policies().await?;
    let workspace_id_str = workspace.workspace.id.0.to_string();

    let entries: Vec<PolicySyncEntry> = policies
        .into_iter()
        .filter(|p| is_policy_relevant_to_workspace(p, &workspace_id_str))
        .map(|p| PolicySyncEntry {
            id: p.id.0.to_string(),
            name: p.name,
            cedar_policy: p.cedar_policy,
        })
        .collect();

    Ok(Json(ApiResponse::ok(PolicySyncResponse {
        policies: entries,
    })))
}

/// Determine whether a policy is relevant to a specific workspace.
///
/// A policy is relevant if:
/// 1. It is NOT a per-entity grant/deny (i.e., its name does not start with
///    `grant:` or `deny:`), meaning it is a system/default policy, OR
/// 2. It IS a per-entity grant/deny that references the workspace, checked via
///    the policy name containing the workspace UUID or the Cedar text containing
///    the `Workspace::"{workspace_id}"` entity reference.
fn is_policy_relevant_to_workspace(
    policy: &agent_cordon_core::domain::policy::StoredPolicy,
    workspace_id: &str,
) -> bool {
    let is_per_entity = policy.name.starts_with("grant:") || policy.name.starts_with("deny:");
    if !is_per_entity {
        // System/default policy -- always include
        return true;
    }
    // Per-entity grant/deny: include only if it references this workspace.
    // Check the policy name (contains the workspace UUID as a segment) and
    // the Cedar text (contains the Workspace entity reference).
    policy.name.contains(workspace_id) || policy.cedar_policy.contains(workspace_id)
}

// ---------------------------------------------------------------------------
// MCP server sync
// ---------------------------------------------------------------------------

/// A single MCP server entry for device sync.
#[derive(Serialize)]
pub(super) struct McpServerSyncEntry {
    pub id: String,
    pub name: String,
    pub transport: String,
    pub tools: Vec<String>,
    pub enabled: bool,
    pub required_credentials: Option<Vec<String>>,
}

/// Response for `GET /api/v1/workspaces/mcp-servers`.
#[derive(Serialize)]
pub(super) struct McpServerSyncResponse {
    pub servers: Vec<McpServerSyncEntry>,
}

/// GET /api/v1/workspaces/mcp-servers -- list MCP servers for the authenticated workspace.
///
/// Auth: workspace identity JWT (Authorization: Bearer).
/// Returns all enabled MCP servers belonging to this workspace so the device
/// can populate its local cache and serve them to agents.
pub(super) async fn sync_mcp_servers(
    State(state): State<AppState>,
    workspace: AuthenticatedWorkspace,
) -> Result<Json<ApiResponse<McpServerSyncResponse>>, ApiError> {
    let servers = state
        .store
        .list_mcp_servers_by_workspace(&workspace.workspace.id)
        .await?;

    let entries: Vec<McpServerSyncEntry> = servers
        .into_iter()
        .filter(|s| s.enabled)
        .map(|s| McpServerSyncEntry {
            id: s.id.0.to_string(),
            name: s.name,
            transport: s.transport,
            tools: s.allowed_tools.unwrap_or_default(),
            enabled: s.enabled,
            required_credentials: s
                .required_credentials
                .map(|creds| creds.iter().map(|c| c.0.to_string()).collect()),
        })
        .collect();

    Ok(Json(ApiResponse::ok(McpServerSyncResponse {
        servers: entries,
    })))
}

// ---------------------------------------------------------------------------
// MCP tool reporting
// ---------------------------------------------------------------------------

/// Request body for `POST /api/v1/workspaces/mcp-report-tools`.
#[derive(Deserialize)]
pub(super) struct ReportToolsRequest {
    server_name: String,
    tools: Vec<ReportedTool>,
}

#[derive(Deserialize)]
pub(super) struct ReportedTool {
    name: String,
    #[allow(dead_code)]
    description: Option<String>,
}

/// POST /api/v1/workspaces/mcp-report-tools -- workspace reports discovered tools for an MCP server.
///
/// Auth: workspace identity JWT (Authorization: Bearer).
/// Updates `allowed_tools` on the matching MCP server record so the web UI
/// and policy engine know which tools are available.
pub(super) async fn report_tools(
    State(state): State<AppState>,
    workspace: AuthenticatedWorkspace,
    Json(req): Json<ReportToolsRequest>,
) -> Result<Json<ApiResponse<serde_json::Value>>, ApiError> {
    let ws_id = &workspace.workspace.id;

    let server = state
        .store
        .get_mcp_server_by_workspace_and_name(ws_id, &req.server_name)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("MCP server '{}' not found", req.server_name)))?;

    let tool_names: Vec<String> = req.tools.iter().map(|t| t.name.clone()).collect();
    let tool_count = tool_names.len();

    let mut updated = server.clone();
    updated.allowed_tools = Some(tool_names);
    updated.updated_at = chrono::Utc::now();
    state.store.update_mcp_server(&updated).await?;

    // Notify UI of updated tools
    state.ui_event_bus.emit(UiEvent::McpServerChanged {
        server_name: req.server_name.clone(),
    });

    tracing::info!(
        server = %req.server_name,
        workspace = %ws_id.0,
        tools = tool_count,
        "workspace reported MCP tools"
    );

    Ok(Json(ApiResponse::ok(serde_json::json!({
        "server_name": req.server_name,
        "tools_updated": tool_count,
    }))))
}
