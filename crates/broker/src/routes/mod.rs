pub mod credentials;
pub mod deregister;
pub mod health;
pub mod helpers;
pub mod mcp;
pub mod proxy;
pub mod register;
pub mod status;

use axum::middleware;
use axum::routing::{get, post};
use axum::Router;

use crate::auth::auth_middleware;
use crate::state::SharedState;

/// Build the broker's axum router.
pub fn build_router(state: SharedState) -> Router {
    // Routes that require workspace Ed25519 authentication
    let authenticated = Router::new()
        .route("/status", get(status::get_status))
        .route("/deregister", post(deregister::post_deregister))
        .route("/credentials", get(credentials::get_credentials))
        .route(
            "/credentials/create",
            post(credentials::post_create_credential),
        )
        .route("/proxy", post(proxy::post_proxy))
        .route("/mcp/list-servers", post(mcp::list_servers))
        .route("/mcp/list-tools", post(mcp::list_tools))
        .route("/mcp/call", post(mcp::call_tool))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ))
        .with_state(state.clone());

    // Routes that do NOT require workspace authentication
    let public = Router::new()
        .route("/health", get(health::get_health))
        .route("/register", post(register::post_register))
        .with_state(state);

    public.merge(authenticated)
}
