//! Library target for agent-cordon-server.
//!
//! Exposes the router builder and AppState so that integration tests can
//! construct a test application without starting a TCP listener.

pub mod auditing_policy_engine;
pub mod compose;
pub mod config;
pub mod credential_service;
pub mod crypto_helpers;
pub mod device_code_service;
pub mod docs;
pub mod events;
pub mod extractors;
pub mod grants;
pub mod install_script;
pub mod metrics;
pub mod middleware;
pub mod migrations;
pub mod oauth_discovery;
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

use axum::{extract::State, routing::get, Json, Router};
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
            routes::api_routes(app_state.clone()).merge(routes::shared::sse::routes()),
        )
        .merge(routes::admin_ui::pages::page_routes(app_state.clone()))
        .route("/install.sh", get(install_script::handler))
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
