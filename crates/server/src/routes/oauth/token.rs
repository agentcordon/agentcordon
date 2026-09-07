//! OAuth 2.0 Token endpoint — authorization code exchange, refresh, client
//! credentials, and the RFC 8628 device-code grant.
//!
//! The grant logic lives in [`OAuthService`](crate::services::OAuthService);
//! this handler parses the form and shapes the RFC 6749 §5.1 response.

use agent_cordon_core::oauth2::types::OAuthScope;
use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};

use crate::middleware::request_id::CorrelationId;
use crate::state::AppState;

pub(crate) use crate::services::oauth::TokenRequest;

// ---------------------------------------------------------------------------
// Token response (RFC 6749 Section 5.1)
// ---------------------------------------------------------------------------

use agent_cordon_core::wire::oauth::TokenResponse;

/// POST /api/v1/oauth/token
pub(crate) async fn token_endpoint(
    State(state): State<AppState>,
    axum::Extension(corr): axum::Extension<CorrelationId>,
    axum::Form(req): axum::Form<TokenRequest>,
) -> axum::response::Response {
    match state.services.oauth.token(&corr.0, &req).await {
        Ok(issued) => {
            let response = TokenResponse {
                access_token: issued.access_token,
                token_type: "Bearer".to_string(),
                expires_in: issued.expires_in,
                refresh_token: issued.refresh_token,
                scope: Some(OAuthScope::to_scope_string(&issued.scopes)),
                client_id: Some(issued.client_id),
            };
            (StatusCode::OK, Json(response)).into_response()
        }
        Err(e) => e.into_response(),
    }
}
