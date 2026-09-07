use axum::{extract::State, routing::post, Json, Router};

use crate::extractors::AuthenticatedUser;
use crate::middleware::request_id::CorrelationId;
use crate::response::{ApiError, ApiResponse};
use crate::services::credentials::ResealReport;
use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new().route("/admin/rotate-key", post(rotate_encryption_key))
}

/// Re-seal every credential and every history row under the current master
/// key version.
///
/// Each row is opened with the key its `key_version` names (the previous
/// secret, during a rotation window), sealed again under the current key
/// with a fresh nonce, and stamped with the current version. Rows already
/// at the current version are re-sealed too, so the call also refreshes
/// nonces; it is safe to repeat. Once it reports no errors the previous
/// secret can be dropped from the configuration.
///
/// Only admin users can call this endpoint. Agent JWTs are rejected.
async fn rotate_encryption_key(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
    axum::Extension(corr): axum::Extension<CorrelationId>,
) -> Result<Json<ApiResponse<ResealReport>>, ApiError> {
    let report = state
        .services
        .credentials
        .reseal_all(&auth, &corr.0)
        .await?;
    Ok(Json(ApiResponse::ok(report)))
}
