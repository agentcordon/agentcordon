//! Control-plane routes — broker-facing API (MCP sync and authorization).

pub mod mcp_authorize;
mod workspace_sync;

use axum::{
    routing::{get, post},
    Router,
};

use crate::state::AppState;

/// API routes for the control plane (nested under `/api/v1`).
pub fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/workspaces/mcp-servers",
            get(workspace_sync::sync_mcp_servers),
        )
        .route("/workspaces/mcp-tools", get(workspace_sync::sync_mcp_tools))
        .route("/workspaces/mcp-authorize", post(mcp_authorize::authorize))
}
