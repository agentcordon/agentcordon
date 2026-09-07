//! OAuth 2.0 Token revocation endpoint (RFC 7009).

use axum::{extract::State, http::StatusCode, Json};
use serde::{Deserialize, Serialize};

use crate::middleware::request_id::CorrelationId;
use crate::response::ApiResponse;
use crate::state::AppState;

#[derive(Deserialize)]
pub(crate) struct RevokeRequest {
    token: String,
    token_type_hint: Option<String>,
    client_id: String,
}

#[derive(Serialize)]
pub(crate) struct RevokeResponse {
    revoked: bool,
}

/// POST /api/v1/oauth/revoke
///
/// Per RFC 7009: always return 200, even if the token is unknown or already revoked.
/// Requires client_id and validates that the token belongs to the requesting client.
pub(crate) async fn revoke_token(
    State(state): State<AppState>,
    axum::Extension(corr): axum::Extension<CorrelationId>,
    axum::Form(req): axum::Form<RevokeRequest>,
) -> (StatusCode, Json<ApiResponse<RevokeResponse>>) {
    let revoked = state
        .services
        .oauth
        .revoke_token(
            &corr.0,
            &req.token,
            req.token_type_hint.as_deref(),
            &req.client_id,
        )
        .await;

    // RFC 7009: always 200
    (
        StatusCode::OK,
        Json(ApiResponse::ok(RevokeResponse { revoked })),
    )
}
