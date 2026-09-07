mod bindings;
mod crud;
pub(crate) mod discover;
mod import;
pub(crate) mod oauth;
mod oauth_token;
mod permissions;
pub(crate) mod provision;

use axum::{
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};

use agent_cordon_core::domain::mcp::McpServer;

use crate::state::AppState;

use crud::{delete_mcp_server, get_mcp_server, list_mcp_servers, update_mcp_server};
use discover::{generate_policies, rediscover_tools};
use import::import_mcp_servers;
use permissions::{get_permissions, grant_permission, revoke_permission};

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/mcp-servers", get(list_mcp_servers))
        .route("/mcp-servers/import", post(import_mcp_servers))
        .route(
            "/mcp-servers/provision",
            post(provision::provision_from_catalog),
        )
        .route("/mcp-servers/oauth/initiate", post(oauth::initiate_oauth))
        .route(
            "/mcp-servers/oauth/callback",
            get(oauth::oauth_callback_wrapper),
        )
        .route(
            "/mcp-servers/{id}",
            get(get_mcp_server)
                .put(update_mcp_server)
                .delete(delete_mcp_server),
        )
        .route(
            "/mcp-servers/{id}/generate-policies",
            post(generate_policies),
        )
        .route("/mcp-servers/{id}/discover-tools", post(rediscover_tools))
        .route(
            "/mcp-servers/{id}/permissions",
            get(get_permissions).post(grant_permission),
        )
        .route(
            "/mcp-servers/{id}/permissions/{agent_id}/{permission}",
            axum::routing::delete(revoke_permission),
        )
        .route(
            "/mcp-servers/{id}/workspaces",
            get(bindings::list_workspace_bindings).post(bindings::add_workspace_bindings),
        )
        .route(
            "/mcp-servers/{id}/workspaces/{workspace_id}",
            axum::routing::delete(bindings::remove_workspace_binding),
        )
}

// --- Request/Response Types ---

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct UpdateMcpServerRequest {
    pub name: Option<String>,
    /// Flip the server on or off. Disabling is the documented immediate
    /// revocation path: the Cedar forbid on `!resource.enabled` then refuses
    /// every `mcp_tool_call`/`mcp_list_tools`, and workspace sync stops
    /// handing the server to brokers. Absent means "leave as is".
    pub enabled: Option<bool>,
}

#[derive(Serialize)]
pub(crate) struct McpServerResponse {
    pub id: String,
    /// Legacy provisioner workspace. `None` for MCPs created after #37
    /// consolidation; the authoritative binding set is `installed_workspaces`.
    pub workspace_id: Option<String>,
    pub workspace_name: Option<String>,
    /// Every workspace bound to this MCP through the
    /// `mcp_server_workspaces` junction. Filled by
    /// [`enrich_mcp_server_responses`]; the list and the detail endpoint both
    /// report it, because the list page's Workspaces column is rendered from
    /// it and read "No workspaces" while only the detail endpoint had it.
    pub installed_workspaces: Vec<InstalledWorkspaceInfo>,
    pub name: String,
    pub upstream_url: String,
    pub transport: String,
    pub allowed_tools: Option<Vec<String>>,
    pub enabled: bool,
    pub created_by: Option<String>,
    pub created_by_name: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub tags: Vec<String>,
    pub required_credentials: Option<Vec<String>>,
    pub auth_method: String,
    pub template_key: Option<String>,
    pub created_by_user: Option<String>,
}

impl McpServerResponse {
    pub(crate) fn from_server(s: &McpServer) -> Self {
        Self {
            id: s.id.0.to_string(),
            workspace_id: s.workspace_id.as_ref().map(|w| w.0.to_string()),
            workspace_name: None,
            installed_workspaces: Vec::new(),
            name: s.name.clone(),
            upstream_url: s.upstream_url.clone(),
            transport: s.transport.to_string(),
            allowed_tools: s.allowed_tools.clone(),
            enabled: s.enabled,
            created_by: s.created_by.as_ref().map(|w| w.0.to_string()),
            created_by_name: None,
            created_at: s.created_at.to_rfc3339(),
            updated_at: s.updated_at.to_rfc3339(),
            tags: s.tags.clone(),
            required_credentials: s
                .required_credentials
                .as_ref()
                .map(|creds| creds.iter().map(|c| c.0.to_string()).collect()),
            auth_method: s.auth_method.to_string(),
            template_key: s.template_key.clone(),
            created_by_user: s.created_by_user.as_ref().map(|u| u.0.to_string()),
        }
    }
}

/// The workspaces bound to one MCP through the junction, active ones only.
///
/// One MCP can be bound to many workspaces; a workspace that has been
/// disabled keeps its junction row but is not a live binding, so it is
/// filtered out and neither the list nor the detail page shows it.
pub(crate) async fn installed_workspaces_for(
    store: &dyn agent_cordon_core::storage::Store,
    server_id: &agent_cordon_core::domain::mcp::McpServerId,
) -> Vec<InstalledWorkspaceInfo> {
    let Ok(bindings) = store.list_workspaces_for_mcp_server(server_id).await else {
        return Vec::new();
    };
    let mut out = Vec::with_capacity(bindings.len());
    for (ws_id, ws_name) in bindings {
        if let Ok(Some(w)) = store.get_workspace(&ws_id).await {
            if w.status == agent_cordon_core::domain::workspace::WorkspaceStatus::Active {
                out.push(InstalledWorkspaceInfo {
                    id: ws_id.0.to_string(),
                    name: ws_name,
                });
            }
        }
    }
    out
}

/// Resolve created_by_name, the legacy workspace name, and the live
/// workspace bindings for MCP server responses from the store.
pub(crate) async fn enrich_mcp_server_responses(
    store: &dyn agent_cordon_core::storage::Store,
    responses: &mut [McpServerResponse],
) {
    for resp in responses.iter_mut() {
        if let Ok(id) = uuid::Uuid::parse_str(&resp.id) {
            resp.installed_workspaces =
                installed_workspaces_for(store, &agent_cordon_core::domain::mcp::McpServerId(id))
                    .await;
        }
        if let Some(ref created_by) = resp.created_by {
            if let Ok(ws_uuid) = uuid::Uuid::parse_str(created_by) {
                if let Ok(Some(ws)) = store
                    .get_workspace(&agent_cordon_core::domain::workspace::WorkspaceId(ws_uuid))
                    .await
                {
                    resp.created_by_name = Some(ws.name);
                }
            }
        }
        // Resolve workspace_name from legacy workspace_id if present.
        if let Some(workspace_id) = resp.workspace_id.as_deref() {
            if let Ok(ws_uuid) = uuid::Uuid::parse_str(workspace_id) {
                if let Ok(Some(ws)) = store
                    .get_workspace(&agent_cordon_core::domain::workspace::WorkspaceId(ws_uuid))
                    .await
                {
                    resp.workspace_name = Some(ws.name);
                }
            }
        }
    }
}

/// Tool entry for the detail response (matches what the FE template expects).
#[derive(Serialize)]
pub(crate) struct ToolEntry {
    pub name: String,
    pub description: Option<String>,
    /// The JSON Schema for the tool's arguments, as discovery found it.
    /// `None` for a server whose tools are known only by name.
    pub input_schema: Option<serde_json::Value>,
}

impl ToolEntry {
    /// Every tool the detail endpoint reports: the full metadata discovery
    /// captured when it is there, falling back to the bare `allowed_tools`
    /// names for a server that was never discovered against.
    pub(crate) fn list_for(server: &McpServer) -> Vec<Self> {
        if let Some(discovered) = server.discovered_tools.as_deref() {
            if !discovered.is_empty() {
                return discovered
                    .iter()
                    .map(|t| Self {
                        name: t.name.clone(),
                        description: t.description.clone(),
                        input_schema: t.input_schema.clone(),
                    })
                    .collect();
            }
        }
        server
            .allowed_tools
            .as_deref()
            .unwrap_or(&[])
            .iter()
            .map(|name| Self {
                name: name.clone(),
                description: None,
                input_schema: None,
            })
            .collect()
    }
}

/// MCP server detail response: the record (with its bound workspaces) plus
/// the tools discovery found.
#[derive(Serialize)]
pub(crate) struct McpServerDetailResponse {
    #[serde(flatten)]
    pub server: McpServerResponse,
    pub tools: Vec<ToolEntry>,
}

#[derive(Clone, Serialize)]
pub(crate) struct InstalledWorkspaceInfo {
    pub id: String,
    pub name: String,
}

// --- Helpers ---

/// Validate that a string is safe for use as a Cedar policy identifier.
///
/// Only allows alphanumeric characters, hyphens, underscores, and dots.
/// This prevents Cedar policy injection via crafted tool or tag names.
pub(crate) use crate::services::mcp_servers::is_safe_identifier;
