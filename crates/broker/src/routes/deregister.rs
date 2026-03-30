use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;

use crate::auth::AuthenticatedWorkspace;
use crate::state::SharedState;

/// Remove a workspace's registration from the broker.
///
/// This is used by `agentcordon register --force` to clear stale broker state
/// when the server-side workspace has been deleted but the broker still holds
/// old tokens and registration data.
pub async fn post_deregister(
    State(state): State<SharedState>,
    request: axum::extract::Request,
) -> impl IntoResponse {
    let auth = request
        .extensions()
        .get::<AuthenticatedWorkspace>()
        .cloned()
        .unwrap();

    // Remove workspace from active registrations
    {
        let mut workspaces = state.workspaces.write().await;
        workspaces.remove(&auth.pk_hash);
    }

    // Remove any pending registrations for this pk_hash
    {
        let mut pending = state.pending.write().await;
        pending.retain(|_state, reg| reg.pk_hash != auth.pk_hash);
    }

    tracing::info!(pk_hash = %auth.pk_hash, "workspace deregistered via --force");

    (
        StatusCode::OK,
        axum::Json(serde_json::json!({
            "data": {
                "deregistered": true
            }
        })),
    )
}
