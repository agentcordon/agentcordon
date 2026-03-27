//! Control-plane routes — agent/device-facing API (auth, sync, JWKS).

pub mod audit_stream;
pub mod auth;
pub mod jwks;
pub mod mcp_authorize;
pub mod workspace_identity;
mod workspace_sync;

use axum::{
    routing::{get, post},
    Router,
};

use crate::state::AppState;

/// API routes for the control plane (nested under `/api/v1`).
pub fn routes() -> Router<AppState> {
    Router::new()
        .merge(auth::routes())
        .merge(workspace_identity::routes())
        .route("/workspaces/policies", get(workspace_sync::sync_policies))
        .route(
            "/workspaces/mcp-servers",
            get(workspace_sync::sync_mcp_servers),
        )
        .route("/workspaces/mcp-authorize", post(mcp_authorize::authorize))
        .route(
            "/workspaces/audit-stream",
            get(audit_stream::audit_stream_ws),
        )
        .route(
            "/workspaces/audit-events",
            post(audit_stream::audit_ingest_post),
        )
        .route(
            "/workspaces/mcp-report-tools",
            post(workspace_sync::report_tools),
        )
}
