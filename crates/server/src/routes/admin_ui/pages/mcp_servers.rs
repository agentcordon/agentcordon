//! MCP Server page handlers.
//!
//! Both pages are shells: the list comes from `GET /api/v1/mcp-servers`
//! (and the install picker's workspaces from `GET /api/v1/workspaces`), the
//! detail page from `GET /api/v1/mcp-servers/{id}`.

use askama::Template;
use axum::{
    extract::{Path, Request},
    response::Response,
};
use uuid::Uuid;

use super::{page_shell, render_template, NotFoundPage, UserContext};

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
}

/// GET /mcp-servers — render the MCP servers list page.
pub async fn mcp_server_list_page(request: Request) -> Response {
    let shell = match page_shell(&request) {
        Ok(s) => s,
        Err(redirect) => return redirect,
    };

    render_template(&McpServerListPage {
        show_nav: true,
        current_page: "mcp-servers".to_string(),
        user: shell.user,
        csrf_token: shell.csrf_token,
    })
}

// ---------------------------------------------------------------------------
// MCP Marketplace
// ---------------------------------------------------------------------------

#[derive(Template)]
#[template(path = "pages/mcp_servers/marketplace.html")]
pub struct McpMarketplacePage {
    pub show_nav: bool,
    pub current_page: String,
    pub user: UserContext,
    pub csrf_token: String,
}

/// GET /mcp-servers/marketplace — the template catalog and its install modal.
///
/// It used to be the bottom half of the list page: two `content-header`s, two
/// searches and two fetches of `/api/v1/mcp-servers` on one screen
/// (uat/artifacts/reviews/DESIGN-REVIEW.md §2.5). The list's primary action links here.
pub async fn mcp_marketplace_page(request: Request) -> Response {
    let shell = match page_shell(&request) {
        Ok(s) => s,
        Err(redirect) => return redirect,
    };

    render_template(&McpMarketplacePage {
        show_nav: true,
        current_page: "mcp-servers".to_string(),
        user: shell.user,
        csrf_token: shell.csrf_token,
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

    let shell = match page_shell(&request) {
        Ok(s) => s,
        Err(redirect) => return redirect,
    };

    render_template(&McpServerDetailPage {
        show_nav: true,
        current_page: "mcp-servers".to_string(),
        user: shell.user,
        csrf_token: shell.csrf_token,
        server_id: id,
    })
}
