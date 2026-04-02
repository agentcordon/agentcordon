//! OAuth 2.0 Token revocation endpoint (RFC 7009).

use axum::{extract::State, http::StatusCode, Json};
use serde::{Deserialize, Serialize};

use agent_cordon_core::domain::audit::{AuditDecision, AuditEvent, AuditEventType};

use crate::middleware::request_id::CorrelationId;
use crate::response::ApiResponse;
use crate::state::AppState;

use super::hash_token;

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
    let token_hash = hash_token(&req.token);

    // Try to revoke based on hint, falling back to both types.
    // Ownership is verified before revocation: the token must belong to client_id.
    let hint = req.token_type_hint.as_deref().unwrap_or("access_token");

    let revoked = match hint {
        "refresh_token" => {
            try_revoke_refresh_then_access(&state, &token_hash, &req.client_id).await
        }
        _ => {
            try_revoke_access_then_refresh(&state, &token_hash, &req.client_id).await
        }
    };

    // Audit event (only if we actually revoked something)
    if revoked {
        let event = AuditEvent::builder(AuditEventType::Oauth2TokenFailed)
            .action("oauth_token_revoked")
            .resource("oauth_token", &token_hash[..16])
            .correlation_id(&corr.0)
            .decision(AuditDecision::Permit, Some("token revoked"))
            .details(serde_json::json!({
                "token_type_hint": hint,
                "client_id": req.client_id,
            }))
            .build();
        if let Err(e) = state.store.append_audit_event(&event).await {
            tracing::warn!(error = %e, "failed to write audit event");
        }
    }

    // RFC 7009: always 200
    (
        StatusCode::OK,
        Json(ApiResponse::ok(RevokeResponse { revoked })),
    )
}

/// Try revoking as refresh token first (with cascade), then fall back to access token.
/// Verifies ownership via client_id before revoking.
async fn try_revoke_refresh_then_access(
    state: &AppState,
    token_hash: &str,
    client_id: &str,
) -> bool {
    // Check refresh token ownership
    if let Ok(Some(rt)) = state.store.get_oauth_refresh_token(token_hash).await {
        if rt.client_id == client_id {
            let rt_revoked = state
                .store
                .revoke_oauth_refresh_token(token_hash)
                .await
                .unwrap_or(false);
            if rt_revoked {
                let _ = state
                    .store
                    .revoke_access_tokens_for_refresh_token(token_hash)
                    .await;
                return true;
            }
        }
        // Token exists but belongs to a different client — silently deny per RFC 7009
        return false;
    }

    // Fallback: try as access token
    try_revoke_access_token(state, token_hash, client_id).await
}

/// Try revoking as access token first, then fall back to refresh token (with cascade).
/// Verifies ownership via client_id before revoking.
async fn try_revoke_access_then_refresh(
    state: &AppState,
    token_hash: &str,
    client_id: &str,
) -> bool {
    if try_revoke_access_token(state, token_hash, client_id).await {
        return true;
    }

    // Fallback: try as refresh token with cascade
    if let Ok(Some(rt)) = state.store.get_oauth_refresh_token(token_hash).await {
        if rt.client_id == client_id {
            let rt_revoked = state
                .store
                .revoke_oauth_refresh_token(token_hash)
                .await
                .unwrap_or(false);
            if rt_revoked {
                let _ = state
                    .store
                    .revoke_access_tokens_for_refresh_token(token_hash)
                    .await;
            }
            return rt_revoked;
        }
    }

    false
}

/// Revoke an access token after verifying it belongs to the given client_id.
async fn try_revoke_access_token(
    state: &AppState,
    token_hash: &str,
    client_id: &str,
) -> bool {
    if let Ok(Some(at)) = state.store.get_oauth_access_token(token_hash).await {
        if at.client_id == client_id {
            return state
                .store
                .revoke_oauth_access_token(token_hash)
                .await
                .unwrap_or(false);
        }
    }
    false
}
