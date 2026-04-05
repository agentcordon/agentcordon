//! Library target for agent-cordon-server.
//!
//! Exposes the router builder and AppState so that integration tests can
//! construct a test application without starting a TCP listener.

pub mod auditing_policy_engine;
pub mod compose;
pub mod config;
pub mod credential_service;
pub mod crypto_helpers;
pub mod docs;
pub mod events;
pub mod extractors;
pub mod grants;
pub mod metrics;
pub mod middleware;
pub mod migrations;
pub mod rate_limit;
pub mod response;
pub mod routes;
pub mod seed;
pub mod state;
pub mod swagger;
#[cfg(any(test, feature = "test-helpers"))]
pub mod test_helpers;
pub mod ui;
pub mod utils;

use axum::{
    extract::State,
    http::{header, HeaderMap, StatusCode},
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use serde_json::{json, Value};

use crate::state::AppState;

/// Build the full application router (same as `main` but without binding).
pub fn build_router(app_state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/metrics", get(metrics_handler))
        .route(
            "/.well-known/jwks.json",
            get(routes::control_plane::jwks::jwks),
        )
        .merge(swagger::routes())
        .nest(
            "/api/v1",
            routes::api_routes().merge(routes::shared::sse::routes()),
        )
        .merge(routes::admin_ui::pages::page_routes(app_state.clone()))
        .route("/install.sh", get(install_sh_info))
        .fallback(ui::static_handler)
        // CSRF middleware runs after request-id (closer to routes).
        // In Axum, layers are applied outside-in, so this layer is added
        // before the request-id layer.
        .layer(axum::middleware::from_fn(middleware::csrf::csrf_protection))
        .layer(axum::middleware::from_fn(
            middleware::request_log::log_request,
        ))
        .layer(axum::middleware::from_fn(
            middleware::metrics::record_http_metrics,
        ))
        .layer(axum::middleware::from_fn(
            middleware::request_id::inject_request_id,
        ))
        .with_state(app_state)
}

async fn health() -> Json<Value> {
    Json(json!({ "status": "ok" }))
}

async fn metrics_handler(State(state): State<AppState>) -> String {
    state.metrics_handle.render()
}

/// GET /install.sh — serve an install script that downloads the CLI from GitHub Releases.
///
/// The script auto-detects OS and architecture via `uname` and downloads the
/// appropriate binary from the latest GitHub release.
async fn install_sh_info(headers: HeaderMap) -> impl IntoResponse {
    let host = headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("localhost:3140");
    let server_url = format!("http://{host}");

    let script = format!(
        r#"#!/bin/bash
set -euo pipefail

INSTALL_DIR="${{HOME}}/.local/bin"
mkdir -p "$INSTALL_DIR"

SERVER_URL="${{AGENTCORDON_SERVER_URL:-{server_url}}}"
GITHUB_RELEASE="https://github.com/agentcordon/agentcordon/releases/latest/download"

OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

case "$OS" in
    linux)
        case "$ARCH" in
            x86_64|amd64) TARGET="x86_64-unknown-linux-gnu" ;;
            aarch64|arm64) TARGET="aarch64-unknown-linux-gnu" ;;
            *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
        esac
        ;;
    darwin)
        case "$ARCH" in
            x86_64|amd64) TARGET="x86_64-apple-darwin" ;;
            aarch64|arm64) TARGET="aarch64-apple-darwin" ;;
            *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
        esac
        ;;
    *)
        echo "Unsupported OS: $OS (use the Windows binary from GitHub Releases)"
        exit 1
        ;;
esac

DOWNLOAD_URL_CLI="${{GITHUB_RELEASE}}/agentcordon-${{TARGET}}"
DOWNLOAD_URL_BROKER="${{GITHUB_RELEASE}}/agentcordon-broker-${{TARGET}}"

echo "Downloading agentcordon CLI (${{TARGET}})..."
curl -fsSL "$DOWNLOAD_URL_CLI" -o "${{INSTALL_DIR}}/agentcordon"
chmod +x "${{INSTALL_DIR}}/agentcordon"

echo "Downloading agentcordon-broker (${{TARGET}})..."
curl -fsSL "$DOWNLOAD_URL_BROKER" -o "${{INSTALL_DIR}}/agentcordon-broker"
chmod +x "${{INSTALL_DIR}}/agentcordon-broker"

echo ""
echo "Installed:"
echo "  ${{INSTALL_DIR}}/agentcordon        (workspace CLI)"
echo "  ${{INSTALL_DIR}}/agentcordon-broker  (credential broker)"
echo ""

# Check if install dir is on PATH
case ":$PATH:" in
    *":$INSTALL_DIR:"*) ;;
    *)
        echo "Add ${{INSTALL_DIR}} to your PATH:"
        echo "  export PATH=\"${{INSTALL_DIR}}:\$PATH\""
        echo ""
        ;;
esac

echo "Get started:"
echo "  agentcordon setup ${{SERVER_URL}}"
"#
    );

    (
        StatusCode::OK,
        [("content-type", "text/x-shellscript; charset=utf-8")],
        script,
    )
}
