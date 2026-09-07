// AgentCordon — credential brokering and policy enforcement for AI agents.
// Copyright (C) 2026 The AgentCordon Authors
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, version 3.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Affero
// General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

//! Library target for agent-cordon-server.
//!
//! Exposes the router builder and AppState so that integration tests can
//! construct a test application without starting a TCP listener.

pub mod authz;
pub mod config;
pub mod crypto_helpers;
pub mod docs;
pub mod events;
pub mod extractors;
pub mod install_script;
pub mod metrics;
pub mod middleware;
pub mod migrations;
pub mod oauth_discovery;
pub mod rate_limit;
pub mod response;
pub mod routes;
pub mod services;
pub mod state;
pub mod swagger;
pub mod templates;
#[cfg(any(test, feature = "test-helpers"))]
pub mod test_helpers;
pub mod ui;
pub mod utils;

use axum::{extract::State, routing::get, Json, Router};
use serde_json::{json, Value};

use crate::state::AppState;

/// Build the full application router (same as `main` but without binding).
pub fn build_router(app_state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/metrics", get(metrics_handler))
        .merge(swagger::routes())
        .nest(
            "/api/v1",
            routes::api_routes(app_state.clone()).merge(routes::shared::sse::routes()),
        )
        .merge(routes::admin_ui::pages::page_routes(app_state.clone()))
        .route("/install.sh", get(install_script::handler))
        .route("/install.ps1", get(install_script::ps1_handler))
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
