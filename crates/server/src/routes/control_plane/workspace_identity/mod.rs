mod management;

use axum::{
    routing::{get, post},
    Router,
};

use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/agents/{id}/workspace-identity",
            axum::routing::delete(management::revoke_workspace_identity),
        )
        // Frontend management routes
        .route(
            "/workspace-identities",
            get(management::list_workspace_identities),
        )
        .route(
            "/workspace-identities/{id}/approve",
            post(management::approve_workspace_identity),
        )
        .route(
            "/workspace-identities/{id}",
            axum::routing::delete(management::revoke_workspace_identity_by_id),
        )
}
