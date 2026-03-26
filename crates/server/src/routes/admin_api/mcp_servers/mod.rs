mod crud;
mod discover;
mod import;
mod permissions;

use axum::{
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};

use agent_cordon_core::domain::mcp::McpServer;
use agent_cordon_core::policy::actions;

use crate::extractors::AuthenticatedUser;
use crate::response::ApiError;
use crate::state::AppState;

use crud::{delete_mcp_server, get_mcp_server, list_mcp_servers, update_mcp_server};
use discover::generate_policies;
use import::import_mcp_servers;
use permissions::{get_permissions, grant_permission, revoke_permission};

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/mcp-servers", get(list_mcp_servers))
        .route("/mcp-servers/import", post(import_mcp_servers))
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
        .route(
            "/mcp-servers/{id}/permissions",
            get(get_permissions).post(grant_permission),
        )
        .route(
            "/mcp-servers/{id}/permissions/{agent_id}/{permission}",
            axum::routing::delete(revoke_permission),
        )
}

// --- Request/Response Types ---

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct UpdateMcpServerRequest {
    pub name: Option<String>,
}

#[derive(Serialize)]
pub(crate) struct McpServerResponse {
    pub id: String,
    pub workspace_id: String,
    pub workspace_name: Option<String>,
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
}

impl McpServerResponse {
    pub(crate) fn from_server(s: &McpServer) -> Self {
        Self {
            id: s.id.0.to_string(),
            workspace_id: s.workspace_id.0.to_string(),
            workspace_name: None,
            name: s.name.clone(),
            upstream_url: s.upstream_url.clone(),
            transport: s.transport.clone(),
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
        }
    }
}

/// Resolve created_by_name and device_name for MCP server responses from the store.
pub(crate) async fn enrich_mcp_server_responses(
    store: &dyn agent_cordon_core::storage::Store,
    responses: &mut [McpServerResponse],
) {
    for resp in responses.iter_mut() {
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
        // Resolve workspace_name from workspace_id
        if let Ok(ws_uuid) = uuid::Uuid::parse_str(&resp.workspace_id) {
            if let Ok(Some(ws)) = store
                .get_workspace(&agent_cordon_core::domain::workspace::WorkspaceId(ws_uuid))
                .await
            {
                resp.workspace_name = Some(ws.name);
            }
        }
    }
}

/// Tool entry for the detail response (matches what the FE template expects).
#[derive(Serialize)]
pub(crate) struct ToolEntry {
    pub name: String,
    pub description: Option<String>,
}

/// MCP server detail response with installed workspaces and tools.
#[derive(Serialize)]
pub(crate) struct McpServerDetailResponse {
    #[serde(flatten)]
    pub server: McpServerResponse,
    pub installed_workspaces: Vec<InstalledWorkspaceInfo>,
    pub tools: Vec<ToolEntry>,
}

#[derive(Serialize)]
pub(crate) struct InstalledWorkspaceInfo {
    pub id: String,
    pub name: String,
}

// --- Helpers ---

/// Check Cedar policy for `manage_mcp_servers` on `System` resource.
pub(crate) fn check_manage_mcp_servers(
    state: &AppState,
    auth: &AuthenticatedUser,
) -> Result<agent_cordon_core::domain::policy::PolicyDecision, ApiError> {
    super::check_cedar_permission(
        state,
        auth,
        actions::MANAGE_MCP_SERVERS,
        agent_cordon_core::policy::PolicyResource::System,
    )
}

/// Validate that a string is safe for use as a Cedar policy identifier.
///
/// Only allows alphanumeric characters, hyphens, underscores, and dots.
/// This prevents Cedar policy injection via crafted tool or tag names.
pub(crate) fn is_safe_identifier(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == '.')
}
