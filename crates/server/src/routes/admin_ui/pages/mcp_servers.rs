//! MCP Server page handlers.

use askama::Template;
use axum::{
    extract::{Path, Request, State},
    response::Response,
};
use uuid::Uuid;

use crate::state::AppState;

use super::{is_admin_user, render_template, CsrfToken, NotFoundPage, UserContext};

// ---------------------------------------------------------------------------
// View model for MCP server list rows
// ---------------------------------------------------------------------------

/// Pre-formatted MCP server data for Askama templates.
pub struct McpServerView {
    pub id: String,
    pub name: String,
    pub upstream_url: String,
    pub transport: String,
    pub enabled: bool,
    pub tools_count: usize,
    pub workspace_id: String,
    pub workspace_name: String,
    pub auth_method: String,
    pub template_key: String,
}

// ---------------------------------------------------------------------------
// MCP Servers List
// ---------------------------------------------------------------------------

#[derive(Template)]
#[template(path = "pages/mcp_servers/list.html")]
pub struct McpServerListPage {
    pub show_nav: bool,
    pub current_page: String,
    pub user: UserContext,
    pub csrf_token: String,
    pub servers: Vec<McpServerView>,
    pub servers_json: String,
    pub workspaces_json: String,
}

/// GET /mcp-servers — render the MCP servers list page.
pub async fn mcp_server_list_page(State(state): State<AppState>, request: Request) -> Response {
    let user = match super::extract_page_user(&request) {
        Ok(u) => u,
        Err(redirect) => return redirect,
    };
    let csrf = request
        .extensions()
        .get::<CsrfToken>()
        .cloned()
        .unwrap_or(CsrfToken(String::new()));

    // Tenant scoping: admins see all servers, non-admins see servers they created
    let workspaces = if is_admin_user(&user) {
        state.store.list_workspaces().await.unwrap_or_default()
    } else {
        state
            .store
            .get_workspaces_by_owner(&user.id)
            .await
            .unwrap_or_default()
    };
    let servers: Vec<_> = if is_admin_user(&user) {
        state.store.list_mcp_servers().await.unwrap_or_default()
    } else {
        state
            .store
            .list_mcp_servers_by_user(&user.id)
            .await
            .unwrap_or_default()
    };

    let workspace_map: std::collections::HashMap<String, String> = workspaces
        .iter()
        .map(|w| (w.id.0.to_string(), w.name.clone()))
        .collect();
    let server_views: Vec<McpServerView> = servers
        .iter()
        .map(|s| {
            let workspace_name = workspace_map
                .get(&s.workspace_id.0.to_string())
                .cloned()
                .unwrap_or_default();
            McpServerView {
                id: s.id.0.to_string(),
                name: s.name.clone(),
                upstream_url: if s.upstream_url.is_empty() {
                    "\u{2014}".to_string()
                } else {
                    s.upstream_url.clone()
                },
                transport: s.transport.to_string(),
                enabled: s.enabled,
                tools_count: s.allowed_tools.as_ref().map(|t| t.len()).unwrap_or(0),
                workspace_id: s.workspace_id.0.to_string(),
                workspace_name,
                auth_method: s.auth_method.to_string(),
                template_key: s.template_key.clone().unwrap_or_default(),
            }
        })
        .collect();

    let servers_json = serde_json::to_string(
        &server_views
            .iter()
            .map(|s| {
                serde_json::json!({
                    "id": s.id,
                    "name": s.name,
                    "upstream_url": s.upstream_url,
                    "transport": s.transport,
                    "enabled": s.enabled,
                    "tools_count": s.tools_count,
                    "workspace_id": s.workspace_id,
                    "workspace_name": s.workspace_name,
                    "auth_method": s.auth_method,
                    "template_key": s.template_key,
                })
            })
            .collect::<Vec<_>>(),
    )
    .unwrap_or_else(|_| "[]".to_string())
    .replace("</", "<\\/");

    let workspaces_json = serde_json::to_string(
        &workspaces
            .iter()
            .map(|w| {
                serde_json::json!({
                    "id": w.id.0.to_string(),
                    "name": w.name,
                })
            })
            .collect::<Vec<_>>(),
    )
    .unwrap_or_else(|_| "[]".to_string())
    .replace("</", "<\\/");

    render_template(&McpServerListPage {
        show_nav: true,
        current_page: "mcp-servers".to_string(),
        user: UserContext::from(&user),
        csrf_token: csrf.0,
        servers: server_views,
        servers_json,
        workspaces_json,
    })
}

// ---------------------------------------------------------------------------
// MCP Server Detail
// ---------------------------------------------------------------------------

#[derive(Template)]
#[template(path = "pages/mcp_servers/detail.html")]
pub struct McpServerDetailPage {
    pub show_nav: bool,
    pub current_page: String,
    pub user: UserContext,
    pub csrf_token: String,
    pub server_id: String,
}

/// GET /mcp-servers/{id} — render the MCP server detail page.
pub async fn mcp_server_detail_page(Path(id): Path<String>, request: Request) -> Response {
    if Uuid::parse_str(&id).is_err() {
        return render_template(&NotFoundPage { show_nav: true });
    }

    let user = match super::extract_page_user(&request) {
        Ok(u) => u,
        Err(redirect) => return redirect,
    };
    let csrf = request
        .extensions()
        .get::<CsrfToken>()
        .cloned()
        .unwrap_or(CsrfToken(String::new()));

    render_template(&McpServerDetailPage {
        show_nav: true,
        current_page: "mcp-servers".to_string(),
        user: UserContext::from(&user),
        csrf_token: csrf.0,
        server_id: id,
    })
}
