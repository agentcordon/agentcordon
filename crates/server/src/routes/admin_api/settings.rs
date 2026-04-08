//! Settings API endpoints for user preferences.
//!
//! Currently empty — the previous `advanced-mode` toggle has been removed.
//! Kept as a module to preserve the routing namespace for future settings.

use axum::Router;

use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
}
