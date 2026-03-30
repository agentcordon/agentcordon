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
    client_id: Option<String>,
}

#[derive(Serialize)]
pub(crate) struct RevokeResponse {
    revoked: bool,
}

/// POST /api/v1/oauth/revoke
///
/// Per RFC 7009: always return 200, even if the token is unknown or already revoked.
pub(crate) async fn revoke_token(
    State(state): State<AppState>,
    axum::Extension(corr): axum::Extension<CorrelationId>,
    axum::Form(req): axum::Form<RevokeRequest>,
) -> (StatusCode, Json<ApiResponse<RevokeResponse>>) {
    let token_hash = hash_token(&req.token);

    // Try to revoke based on hint, falling back to both types
    let hint = req.token_type_hint.as_deref().unwrap_or("access_token");

    let revoked = match hint {
        "refresh_token" => {
            // Revoke refresh token and cascade to associated access tokens
            let rt_revoked = state
                .store
                .revoke_oauth_refresh_token(&token_hash)
                .await
                .unwrap_or(false);
            if rt_revoked {
                let _ = state
                    .store
                    .revoke_access_tokens_for_refresh_token(&token_hash)
                    .await;
                true
            } else {
                // Fallback: try as access token
                state
                    .store
                    .revoke_oauth_access_token(&token_hash)
                    .await
                    .unwrap_or(false)
            }
        }
        _ => {
            // Try access token first
            let at_revoked = state
                .store
                .revoke_oauth_access_token(&token_hash)
                .await
                .unwrap_or(false);
            if at_revoked {
                true
            } else {
                // Fallback: try as refresh token with cascade
                let rt_revoked = state
                    .store
                    .revoke_oauth_refresh_token(&token_hash)
                    .await
                    .unwrap_or(false);
                if rt_revoked {
                    let _ = state
                        .store
                        .revoke_access_tokens_for_refresh_token(&token_hash)
                        .await;
                }
                rt_revoked
            }
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
        Json(ApiResponse::ok(RevokeResponse { revoked: true })),
    )
}
