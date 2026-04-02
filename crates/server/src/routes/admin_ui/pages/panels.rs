//! Slide-in panel partial handlers.
//!
//! These endpoints return HTML fragments (no full page wrapper) for
//! rendering in slide-in panels via AJAX fetch.

use askama::Template;
use axum::{
    extract::{Path, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
};
use uuid::Uuid;

use agent_cordon_core::domain::credential::CredentialId;
use agent_cordon_core::domain::mcp::McpServerId;
use agent_cordon_core::domain::policy::PolicyId;
use agent_cordon_core::domain::workspace::WorkspaceId;

use crate::state::AppState;

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

fn render_partial(tmpl: &impl Template) -> Response {
    match tmpl.render() {
        Ok(html) => Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
            .body(html.into())
            .unwrap(),
        Err(e) => {
            tracing::error!(error = %e, "partial template render error");
            (StatusCode::INTERNAL_SERVER_ERROR, "render error").into_response()
        }
    }
}

fn not_found() -> Response {
    (StatusCode::NOT_FOUND, "not found").into_response()
}

// ---------------------------------------------------------------------------
// Workspace Panel
// ---------------------------------------------------------------------------

#[derive(Template)]
#[template(path = "partials/panels/workspace.html")]
struct WorkspacePanel {
    workspace_id: String,
    workspace_name: String,
    description: String,
    status: String,
    status_class: String,
    tags: String,
    created_at: String,
    last_token_issued: String,
}

/// GET /workspaces/{id}/partial — HTML fragment for workspace slide-in panel.
pub async fn workspace_partial(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    let uuid = match Uuid::parse_str(&id) {
        Ok(u) => u,
        Err(_) => return not_found(),
    };

    let workspace = match state.store.get_workspace(&WorkspaceId(uuid)).await {
        Ok(Some(w)) => w,
        _ => return not_found(),
    };

    let status = format!("{:?}", workspace.status).to_lowercase();
    let status_class = match status.as_str() {
        "active" => "ok",
        "idle" | "pending" => "warn",
        _ => "type",
    };

    let tags = if workspace.tags.is_empty() {
        "None".to_string()
    } else {
        workspace.tags.join(", ")
    };

    render_partial(&WorkspacePanel {
        workspace_id: uuid.to_string(),
        workspace_name: workspace.name,
        description: "No description".to_string(),
        status,
        status_class: status_class.to_string(),
        tags,
        created_at: workspace.created_at.format("%Y-%m-%d %H:%M").to_string(),
        last_token_issued: "N/A".to_string(),
    })
}

// ---------------------------------------------------------------------------
// Credential Panel
// ---------------------------------------------------------------------------

#[derive(Template)]
#[template(path = "partials/panels/credential.html")]
struct CredentialPanel {
    credential_id: String,
    credential_name: String,
    credential_type: String,
    service: String,
    vault: String,
    expires_at: String,
    created_at: String,
}

/// GET /credentials/{id}/partial — HTML fragment for credential slide-in panel.
pub async fn credential_partial(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    let uuid = match Uuid::parse_str(&id) {
        Ok(u) => u,
        Err(_) => return not_found(),
    };

    let cred = match state.store.get_credential(&CredentialId(uuid)).await {
        Ok(Some(c)) => c,
        _ => return not_found(),
    };

    render_partial(&CredentialPanel {
        credential_id: uuid.to_string(),
        credential_name: cred.name,
        credential_type: cred.credential_type,
        service: cred.service,
        vault: cred.vault,
        expires_at: cred
            .expires_at
            .map(|dt| dt.format("%Y-%m-%d %H:%M").to_string())
            .unwrap_or_else(|| "Never".to_string()),
        created_at: cred.created_at.format("%Y-%m-%d %H:%M").to_string(),
    })
}

// ---------------------------------------------------------------------------
// Policy Panel
// ---------------------------------------------------------------------------

#[derive(Template)]
#[template(path = "partials/panels/policy.html")]
struct PolicyPanel {
    policy_id: String,
    policy_name: String,
    description: String,
    enabled: bool,
    is_system: bool,
    cedar_policy: String,
    updated_at: String,
}

/// GET /security/{id}/partial — HTML fragment for policy slide-in panel.
pub async fn policy_partial(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    let uuid = match Uuid::parse_str(&id) {
        Ok(u) => u,
        Err(_) => return not_found(),
    };

    let policy = match state.store.get_policy(&PolicyId(uuid)).await {
        Ok(Some(p)) => p,
        _ => return not_found(),
    };

    render_partial(&PolicyPanel {
        policy_id: uuid.to_string(),
        policy_name: policy.name,
        description: policy.description.unwrap_or_default(),
        enabled: policy.enabled,
        is_system: policy.is_system,
        cedar_policy: policy.cedar_policy,
        updated_at: policy.updated_at.format("%Y-%m-%d %H:%M").to_string(),
    })
}

// ---------------------------------------------------------------------------
// MCP Server Panel
// ---------------------------------------------------------------------------

#[derive(Template)]
#[template(path = "partials/panels/mcp_server.html")]
struct McpServerPanel {
    server_id: String,
    server_name: String,
    transport: String,
    upstream_url: String,
    enabled: bool,
    workspace_name: String,
    #[allow(dead_code)] // Used by askama template (mcp_server.html)
    workspace_id: String,
    #[allow(dead_code)] // Used by askama template (mcp_server.html)
    tools: Vec<String>,
    tools_count: usize,
    created_at: String,
}

/// GET /mcp-servers/{id}/partial — HTML fragment for MCP server slide-in panel.
pub async fn mcp_server_partial(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    let uuid = match Uuid::parse_str(&id) {
        Ok(u) => u,
        Err(_) => return not_found(),
    };

    let server = match state.store.get_mcp_server(&McpServerId(uuid)).await {
        Ok(Some(s)) => s,
        _ => return not_found(),
    };

    let workspace_name = state
        .store
        .get_workspace(&server.workspace_id)
        .await
        .ok()
        .flatten()
        .map(|w| w.name)
        .unwrap_or_else(|| server.workspace_id.0.to_string());

    let tools = server
        .allowed_tools
        .as_ref()
        .cloned()
        .unwrap_or_default();
    let tools_count = tools.len();

    render_partial(&McpServerPanel {
        server_id: uuid.to_string(),
        server_name: server.name,
        transport: server.transport,
        upstream_url: if server.upstream_url.is_empty() {
            "\u{2014}".to_string()
        } else {
            server.upstream_url
        },
        enabled: server.enabled,
        workspace_name,
        workspace_id: server.workspace_id.0.to_string(),
        tools,
        tools_count,
        created_at: server.created_at.format("%Y-%m-%d %H:%M").to_string(),
    })
}
