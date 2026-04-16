use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;

use crate::auth::AuthenticatedWorkspace;
use crate::state::SharedState;
use crate::token_store;

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

    // Remove workspace from active registrations and persist to disk
    {
        let mut workspaces = state.workspaces.write().await;
        workspaces.remove(&auth.pk_hash);

        if let Err(e) = token_store::save(
            &state.config.token_store_path(),
            &workspaces,
            &state.encryption_key,
        ) {
            tracing::warn!(error = %e, "failed to persist token store after deregister");
        }
    }

    // Update recovery store (remove deregistered workspace)
    token_store::save_recovery_store(&state).await;

    // Remove any pending device-flow registration for this pk_hash.
    // The background poll task observes this deletion and exits cleanly.
    {
        let mut pending = state.pending.write().await;
        pending.remove(&auth.pk_hash);
    }
    {
        let mut errs = state.registration_errors.write().await;
        errs.remove(&auth.pk_hash);
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
