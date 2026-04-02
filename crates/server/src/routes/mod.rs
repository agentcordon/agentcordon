//! Route module — organized into logical boundaries.
//!
//! - `control_plane` — Agent/device-facing API (auth, sync, OAuth, JWKS)
//! - `admin_api` — Admin REST API (CRUD operations)
//! - `admin_ui` — Askama page routes (HTML rendering)
//! - `shared` — Cross-boundary utilities (SSE, proxy, OpenAPI, docs)

pub mod admin_api;
pub mod admin_ui;
pub mod control_plane;
pub mod oauth;
pub mod shared;

use axum::Router;

use crate::state::AppState;

pub fn api_routes() -> Router<AppState> {
    Router::new()
        .merge(control_plane::routes())
        .merge(admin_api::routes())
        .merge(oauth::routes())
        .merge(shared::docs::routes())
        .merge(shared::openapi::routes())
}
