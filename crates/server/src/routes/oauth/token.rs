//! OAuth 2.0 Token endpoint — authorization code exchange, refresh, client credentials.

use axum::{extract::State, http::StatusCode, Json};
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};

use agent_cordon_core::domain::audit::{AuditDecision, AuditEvent, AuditEventType};
use agent_cordon_core::oauth2::types::{OAuthAccessToken, OAuthRefreshToken, OAuthScope};

use crate::middleware::request_id::CorrelationId;
use crate::state::AppState;

use subtle::ConstantTimeEq;

use super::{generate_access_token, generate_refresh_token, hash_token, validate_pkce};

/// Access token TTL: 15 minutes.
const ACCESS_TOKEN_TTL_SECS: i64 = 900;
/// Refresh token TTL: 30 days.
const REFRESH_TOKEN_TTL_SECS: i64 = 30 * 24 * 3600;

// ---------------------------------------------------------------------------
// RFC 6749 error response
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct OAuthError {
    error: String,
    error_description: String,
}

fn oauth_error(
    status: StatusCode,
    error: &str,
    description: &str,
) -> (StatusCode, Json<OAuthError>) {
    (
        status,
        Json(OAuthError {
            error: error.to_string(),
            error_description: description.to_string(),
        }),
    )
}

// ---------------------------------------------------------------------------
// Token response (RFC 6749 Section 5.1)
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct TokenResponse {
    access_token: String,
    token_type: String,
    expires_in: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    refresh_token: Option<String>,
    scope: String,
}

// ---------------------------------------------------------------------------
// POST /api/v1/oauth/token
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub(crate) struct TokenRequest {
    #[serde(default)]
    grant_type: Option<String>,
    // authorization_code fields
    code: Option<String>,
    redirect_uri: Option<String>,
    code_verifier: Option<String>,
    // refresh_token fields
    refresh_token: Option<String>,
    // device_code grant fields (RFC 8628)
    device_code: Option<String>,
    // common
    client_id: Option<String>,
    client_secret: Option<String>,
    scope: Option<String>,
}

/// POST /api/v1/oauth/token
pub(crate) async fn token_endpoint(
    State(state): State<AppState>,
    axum::Extension(corr): axum::Extension<CorrelationId>,
    axum::Form(req): axum::Form<TokenRequest>,
) -> axum::response::Response {
    match req.grant_type.as_deref().unwrap_or("") {
        "authorization_code" => handle_authorization_code(state, corr, req).await,
        "refresh_token" => handle_refresh_token(state, corr, req).await,
        "client_credentials" => handle_client_credentials(state, corr, req).await,
        "urn:ietf:params:oauth:grant-type:device_code" => {
            handle_device_code(state, corr, req).await
        }
        _ => {
            let (status, body) = oauth_error(
                StatusCode::BAD_REQUEST,
                "unsupported_grant_type",
                "grant_type must be authorization_code, refresh_token, client_credentials, \
                 or urn:ietf:params:oauth:grant-type:device_code",
            );
            (status, body).into_response()
        }
    }
}

use axum::response::IntoResponse;

// ---------------------------------------------------------------------------
// grant_type=authorization_code
// ---------------------------------------------------------------------------

async fn handle_authorization_code(
    state: AppState,
    corr: CorrelationId,
    req: TokenRequest,
) -> axum::response::Response {
    let code = match &req.code {
        Some(c) if !c.is_empty() => c.as_str(),
        _ => {
            let (s, b) = oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "code is required",
            );
            return (s, b).into_response();
        }
    };

    let client_id = match &req.client_id {
        Some(c) if !c.is_empty() => c.as_str(),
        _ => {
            let (s, b) = oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "client_id is required",
            );
            return (s, b).into_response();
        }
    };

    // Authenticate client
    let client = match state.store.get_oauth_client_by_client_id(client_id).await {
        Ok(Some(c)) => c,
        _ => {
            let (s, b) = oauth_error(StatusCode::UNAUTHORIZED, "invalid_client", "unknown client");
            return (s, b).into_response();
        }
    };
    if client.revoked_at.is_some() {
        let (s, b) = oauth_error(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            "client is revoked",
        );
        return (s, b).into_response();
    }

    // Verify client_secret if confidential
    if let Some(ref secret_hash) = client.client_secret_hash {
        match &req.client_secret {
            Some(secret)
                if bool::from(hash_token(secret).as_bytes().ct_eq(secret_hash.as_bytes())) => {}
            _ => {
                let (s, b) = oauth_error(
                    StatusCode::UNAUTHORIZED,
                    "invalid_client",
                    "invalid client credentials",
                );
                return (s, b).into_response();
            }
        }
    }

    // Look up auth code by hash
    let code_hash = hash_token(code);
    let auth_code = match state.store.get_oauth_auth_code(&code_hash).await {
        Ok(Some(c)) => c,
        _ => {
            let (s, b) = oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "invalid authorization code",
            );
            return (s, b).into_response();
        }
    };

    // Validate: not expired
    if auth_code.expires_at < Utc::now() {
        let (s, b) = oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "authorization code has expired",
        );
        return (s, b).into_response();
    }

    // Validate: client_id matches
    if auth_code.client_id != client_id {
        let (s, b) = oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "client_id mismatch",
        );
        return (s, b).into_response();
    }

    // Validate: redirect_uri matches
    if let Some(ref redirect_uri) = req.redirect_uri {
        if *redirect_uri != auth_code.redirect_uri {
            let (s, b) = oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "redirect_uri mismatch",
            );
            return (s, b).into_response();
        }
    }

    // PKCE validation
    if let Some(ref challenge) = auth_code.code_challenge {
        match &req.code_verifier {
            Some(verifier) if validate_pkce(verifier, challenge) => {}
            Some(_) => {
                let (s, b) = oauth_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_grant",
                    "PKCE verification failed",
                );
                return (s, b).into_response();
            }
            None => {
                let (s, b) = oauth_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "code_verifier is required",
                );
                return (s, b).into_response();
            }
        }
    }

    // Atomically consume the auth code — the WHERE clause includes
    // `consumed_at IS NULL`, so only the first concurrent request wins.
    match state.store.consume_oauth_auth_code(&code_hash).await {
        Ok(true) => {} // successfully consumed
        Ok(false) => {
            // Another request already consumed this code (race condition)
            let (s, b) = oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "authorization code already used",
            );
            return (s, b).into_response();
        }
        Err(e) => {
            tracing::error!(error = %e, "failed to consume auth code");
            let (s, b) = oauth_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "internal error",
            );
            return (s, b).into_response();
        }
    }

    // Issue tokens
    let now = Utc::now();
    let (access_token_raw, access_token_hash) = generate_access_token();
    let (refresh_token_raw, refresh_token_hash) = generate_refresh_token();

    let access_token = OAuthAccessToken {
        token_hash: access_token_hash.clone(),
        client_id: client_id.to_string(),
        user_id: auth_code.user_id.clone(),
        scopes: auth_code.scopes.clone(),
        created_at: now,
        expires_at: now + Duration::seconds(ACCESS_TOKEN_TTL_SECS),
        revoked_at: None,
    };

    let refresh_token = OAuthRefreshToken {
        token_hash: refresh_token_hash,
        client_id: client_id.to_string(),
        user_id: auth_code.user_id.clone(),
        scopes: auth_code.scopes.clone(),
        access_token_hash,
        created_at: now,
        expires_at: now + Duration::seconds(REFRESH_TOKEN_TTL_SECS),
        revoked_at: None,
    };

    if let Err(e) = state.store.create_oauth_access_token(&access_token).await {
        tracing::error!(error = %e, "failed to store access token");
        let (s, b) = oauth_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "internal error",
        );
        return (s, b).into_response();
    }
    if let Err(e) = state.store.create_oauth_refresh_token(&refresh_token).await {
        tracing::error!(error = %e, "failed to store refresh token");
        let (s, b) = oauth_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "internal error",
        );
        return (s, b).into_response();
    }

    // Audit event
    let event = AuditEvent::builder(AuditEventType::Oauth2TokenAcquired)
        .action("oauth_token_issued")
        .resource("oauth_client", &client.id.to_string())
        .correlation_id(&corr.0)
        .decision(AuditDecision::Permit, Some("authorization_code exchange"))
        .details(serde_json::json!({
            "client_id": client_id,
            "grant_type": "authorization_code",
        }))
        .build();
    if let Err(e) = state.store.append_audit_event(&event).await {
        tracing::warn!(error = %e, "failed to write audit event");
    }

    let scope_string = OAuthScope::to_scope_string(&auth_code.scopes);
    let response = TokenResponse {
        access_token: access_token_raw,
        token_type: "Bearer".to_string(),
        expires_in: ACCESS_TOKEN_TTL_SECS,
        refresh_token: Some(refresh_token_raw),
        scope: scope_string,
    };

    (StatusCode::OK, Json(response)).into_response()
}

// ---------------------------------------------------------------------------
// grant_type=refresh_token
// ---------------------------------------------------------------------------

async fn handle_refresh_token(
    state: AppState,
    corr: CorrelationId,
    req: TokenRequest,
) -> axum::response::Response {
    let refresh_token_raw = match &req.refresh_token {
        Some(t) if !t.is_empty() => t.as_str(),
        _ => {
            let (s, b) = oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "refresh_token is required",
            );
            return (s, b).into_response();
        }
    };

    let client_id = match &req.client_id {
        Some(c) if !c.is_empty() => c.as_str(),
        _ => {
            let (s, b) = oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "client_id is required",
            );
            return (s, b).into_response();
        }
    };

    // Authenticate client
    let client = match state.store.get_oauth_client_by_client_id(client_id).await {
        Ok(Some(c)) => c,
        _ => {
            let (s, b) = oauth_error(StatusCode::UNAUTHORIZED, "invalid_client", "unknown client");
            return (s, b).into_response();
        }
    };
    if client.revoked_at.is_some() {
        let (s, b) = oauth_error(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            "client is revoked",
        );
        return (s, b).into_response();
    }

    if let Some(ref secret_hash) = client.client_secret_hash {
        match &req.client_secret {
            Some(secret)
                if bool::from(hash_token(secret).as_bytes().ct_eq(secret_hash.as_bytes())) => {}
            _ => {
                let (s, b) = oauth_error(
                    StatusCode::UNAUTHORIZED,
                    "invalid_client",
                    "invalid client credentials",
                );
                return (s, b).into_response();
            }
        }
    }

    // Look up refresh token
    let rt_hash = hash_token(refresh_token_raw);
    let stored_rt = match state.store.get_oauth_refresh_token(&rt_hash).await {
        Ok(Some(t)) => t,
        _ => {
            let (s, b) = oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "invalid refresh token",
            );
            return (s, b).into_response();
        }
    };

    if stored_rt.revoked_at.is_some() {
        let (s, b) = oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "refresh token has been revoked",
        );
        return (s, b).into_response();
    }

    if stored_rt.expires_at < Utc::now() {
        let (s, b) = oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "refresh token has expired",
        );
        return (s, b).into_response();
    }

    if stored_rt.client_id != client_id {
        let (s, b) = oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "client_id mismatch",
        );
        return (s, b).into_response();
    }

    // Determine scopes — if requested, must be subset of original
    let scopes = if let Some(ref scope_str) = req.scope {
        let requested = match OAuthScope::parse_scope_string(scope_str) {
            Ok(s) => s,
            Err(e) => {
                let (s, b) = oauth_error(StatusCode::BAD_REQUEST, "invalid_scope", &e);
                return (s, b).into_response();
            }
        };
        for s in &requested {
            if !stored_rt.scopes.contains(s) {
                let (s, b) = oauth_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_scope",
                    "requested scope exceeds original grant",
                );
                return (s, b).into_response();
            }
        }
        requested
    } else {
        stored_rt.scopes.clone()
    };

    // Revoke old refresh token (rotation)
    let _ = state.store.revoke_oauth_refresh_token(&rt_hash).await;
    // Revoke the old access token associated with the old refresh token
    let _ = state
        .store
        .revoke_access_tokens_for_refresh_token(&rt_hash)
        .await;

    // Issue new tokens
    let now = Utc::now();
    let (new_access_raw, new_access_hash) = generate_access_token();
    let (new_refresh_raw, new_refresh_hash) = generate_refresh_token();

    let new_access = OAuthAccessToken {
        token_hash: new_access_hash.clone(),
        client_id: client_id.to_string(),
        user_id: stored_rt.user_id.clone(),
        scopes: scopes.clone(),
        created_at: now,
        expires_at: now + Duration::seconds(ACCESS_TOKEN_TTL_SECS),
        revoked_at: None,
    };
    let new_refresh = OAuthRefreshToken {
        token_hash: new_refresh_hash,
        client_id: client_id.to_string(),
        user_id: stored_rt.user_id.clone(),
        scopes: scopes.clone(),
        access_token_hash: new_access_hash,
        created_at: now,
        expires_at: now + Duration::seconds(REFRESH_TOKEN_TTL_SECS),
        revoked_at: None,
    };

    if let Err(e) = state.store.create_oauth_access_token(&new_access).await {
        tracing::error!(error = %e, "failed to store new access token");
        let (s, b) = oauth_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "internal error",
        );
        return (s, b).into_response();
    }
    if let Err(e) = state.store.create_oauth_refresh_token(&new_refresh).await {
        tracing::error!(error = %e, "failed to store new refresh token");
        let (s, b) = oauth_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "internal error",
        );
        return (s, b).into_response();
    }

    // Audit
    let event = AuditEvent::builder(AuditEventType::Oauth2TokenAcquired)
        .action("oauth_token_refreshed")
        .resource("oauth_client", &client.id.to_string())
        .correlation_id(&corr.0)
        .decision(AuditDecision::Permit, Some("refresh_token exchange"))
        .details(serde_json::json!({
            "client_id": client_id,
            "grant_type": "refresh_token",
        }))
        .build();
    if let Err(e) = state.store.append_audit_event(&event).await {
        tracing::warn!(error = %e, "failed to write audit event");
    }

    let scope_string = OAuthScope::to_scope_string(&scopes);
    let response = TokenResponse {
        access_token: new_access_raw,
        token_type: "Bearer".to_string(),
        expires_in: ACCESS_TOKEN_TTL_SECS,
        refresh_token: Some(new_refresh_raw),
        scope: scope_string,
    };

    (StatusCode::OK, Json(response)).into_response()
}

// ---------------------------------------------------------------------------
// grant_type=client_credentials
// ---------------------------------------------------------------------------

async fn handle_client_credentials(
    state: AppState,
    corr: CorrelationId,
    req: TokenRequest,
) -> axum::response::Response {
    let client_id = match &req.client_id {
        Some(c) if !c.is_empty() => c.as_str(),
        _ => {
            let (s, b) = oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "client_id is required",
            );
            return (s, b).into_response();
        }
    };
    let client_secret = match &req.client_secret {
        Some(s) if !s.is_empty() => s.as_str(),
        _ => {
            let (s, b) = oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "client_secret is required for client_credentials",
            );
            return (s, b).into_response();
        }
    };

    // Authenticate client
    let client = match state.store.get_oauth_client_by_client_id(client_id).await {
        Ok(Some(c)) => c,
        _ => {
            let (s, b) = oauth_error(StatusCode::UNAUTHORIZED, "invalid_client", "unknown client");
            return (s, b).into_response();
        }
    };
    if client.revoked_at.is_some() {
        let (s, b) = oauth_error(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            "client is revoked",
        );
        return (s, b).into_response();
    }

    match &client.client_secret_hash {
        Some(secret_hash)
            if bool::from(
                hash_token(client_secret)
                    .as_bytes()
                    .ct_eq(secret_hash.as_bytes()),
            ) => {}
        _ => {
            let (s, b) = oauth_error(
                StatusCode::UNAUTHORIZED,
                "invalid_client",
                "invalid client credentials",
            );
            return (s, b).into_response();
        }
    }

    // Determine scopes
    let scopes = if let Some(ref scope_str) = req.scope {
        match OAuthScope::parse_scope_string(scope_str) {
            Ok(requested) => {
                for s in &requested {
                    if !client.allowed_scopes.contains(s) {
                        let (s, b) = oauth_error(
                            StatusCode::BAD_REQUEST,
                            "invalid_scope",
                            "requested scope not allowed",
                        );
                        return (s, b).into_response();
                    }
                }
                requested
            }
            Err(e) => {
                let (s, b) = oauth_error(StatusCode::BAD_REQUEST, "invalid_scope", &e);
                return (s, b).into_response();
            }
        }
    } else {
        client.allowed_scopes.clone()
    };

    // Issue access token only (no refresh for client_credentials)
    let now = Utc::now();
    let (access_raw, access_hash) = generate_access_token();

    let access_token = OAuthAccessToken {
        token_hash: access_hash,
        client_id: client_id.to_string(),
        user_id: client.created_by_user.clone(),
        scopes: scopes.clone(),
        created_at: now,
        expires_at: now + Duration::seconds(ACCESS_TOKEN_TTL_SECS),
        revoked_at: None,
    };

    if let Err(e) = state.store.create_oauth_access_token(&access_token).await {
        tracing::error!(error = %e, "failed to store access token");
        let (s, b) = oauth_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "internal error",
        );
        return (s, b).into_response();
    }

    // Audit
    let event = AuditEvent::builder(AuditEventType::Oauth2TokenAcquired)
        .action("oauth_token_issued")
        .resource("oauth_client", &client.id.to_string())
        .correlation_id(&corr.0)
        .decision(AuditDecision::Permit, Some("client_credentials grant"))
        .details(serde_json::json!({
            "client_id": client_id,
            "grant_type": "client_credentials",
        }))
        .build();
    if let Err(e) = state.store.append_audit_event(&event).await {
        tracing::warn!(error = %e, "failed to write audit event");
    }

    let scope_string = OAuthScope::to_scope_string(&scopes);
    let response = TokenResponse {
        access_token: access_raw,
        token_type: "Bearer".to_string(),
        expires_in: ACCESS_TOKEN_TTL_SECS,
        refresh_token: None,
        scope: scope_string,
    };

    (StatusCode::OK, Json(response)).into_response()
}

// ---------------------------------------------------------------------------
// grant_type=urn:ietf:params:oauth:grant-type:device_code (RFC 8628)
// ---------------------------------------------------------------------------
//
// Polling contract per RFC 8628 §3.5:
//   - `authorization_pending`: user has not yet approved; retry after `interval`.
//   - `slow_down`: client polled too fast; MUST increase interval by 5s. We
//     implement this as "double the stored interval" and persist, so a client
//     that ignores the hint keeps hitting slow_down on subsequent polls.
//   - `expired_token`: device_code TTL elapsed; row transitioned to `expired`.
//   - `access_denied`: user denied via `/activate`.
//   - `invalid_grant`: unknown device_code, client_id mismatch, or the row is
//     in a terminal state it shouldn't be polled from (denied — covered above
//     — or already `consumed`, which is invalid_grant to prevent replay).
//
// **Secret handling**: the `device_code` sent by the broker is the plaintext
// issued at `/oauth/device/code`. We persist only its hash, so every lookup
// MUST call `hash_token` first. A DB dump alone cannot yield a pollable
// device_code.
async fn handle_device_code(
    state: AppState,
    corr: CorrelationId,
    req: TokenRequest,
) -> axum::response::Response {
    use agent_cordon_core::domain::user::UserId;
    use agent_cordon_core::oauth2::types::DeviceCodeStatus;
    use uuid::Uuid;

    use crate::device_code_service::DeviceCodeService;

    // --- Parse required fields ---
    let device_code_plain = match req.device_code.as_deref() {
        Some(s) if !s.is_empty() => s,
        _ => {
            let (s, b) = oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "device_code is required",
            );
            return (s, b).into_response();
        }
    };
    let client_id_req = match req.client_id.as_deref() {
        Some(s) if !s.is_empty() => s.to_string(),
        _ => {
            let (s, b) = oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "client_id is required",
            );
            return (s, b).into_response();
        }
    };

    let device_code_hash = hash_token(device_code_plain);
    let service = DeviceCodeService::new(state.store.clone());

    // --- Lookup by hash ---
    let row = match service.get_by_device_code(&device_code_hash).await {
        Ok(Some(r)) => r,
        Ok(None) => {
            // RFC 6749 §5.2: if the client_id is also unknown, the proper
            // error is invalid_client (401), not invalid_grant.
            let client_exists = matches!(
                state
                    .store
                    .get_oauth_client_by_client_id(&client_id_req)
                    .await,
                Ok(Some(c)) if c.revoked_at.is_none()
            );
            if !client_exists {
                let (s, b) = oauth_error(
                    StatusCode::UNAUTHORIZED,
                    "invalid_client",
                    "unknown or revoked client",
                );
                return (s, b).into_response();
            }
            let (s, b) = oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "unknown device_code",
            );
            return (s, b).into_response();
        }
        Err(e) => {
            tracing::error!(error = %e, "device_code lookup failed");
            let (s, b) = oauth_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "internal error",
            );
            return (s, b).into_response();
        }
    };

    if row.client_id != client_id_req {
        let (s, b) = oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "client_id does not match device_code",
        );
        return (s, b).into_response();
    }

    let now = Utc::now();

    // --- Terminal/state dispatch ---
    match row.status {
        DeviceCodeStatus::Denied => {
            let (s, b) = oauth_error(
                StatusCode::BAD_REQUEST,
                "access_denied",
                "user denied request",
            );
            (s, b).into_response()
        }
        DeviceCodeStatus::Expired => {
            let (s, b) = oauth_error(
                StatusCode::BAD_REQUEST,
                "expired_token",
                "device_code expired",
            );
            (s, b).into_response()
        }
        DeviceCodeStatus::Consumed => {
            let (s, b) = oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "device_code already exchanged",
            );
            (s, b).into_response()
        }
        DeviceCodeStatus::Pending => {
            // Expiry check: if TTL elapsed, transition to expired and return expired_token.
            // The row won't self-heal otherwise until the sweeper runs.
            if row.expires_at <= now {
                // Best-effort: mark expired so subsequent polls get expired_token
                // directly. A failure here just means the sweeper will catch it.
                if let Err(e) = service.sweep_expired(&corr.0).await {
                    tracing::warn!(error = %e, "failed to transition expired device_code");
                }
                let (s, b) = oauth_error(
                    StatusCode::BAD_REQUEST,
                    "expired_token",
                    "device_code expired",
                );
                return (s, b).into_response();
            }

            // Poll interval enforcement.
            let too_fast = match row.last_polled_at {
                Some(last) => (now - last).num_seconds() < row.interval_secs,
                None => false,
            };

            if too_fast {
                // slow_down: double the stored interval, update poll timestamp.
                let new_interval = row.interval_secs.saturating_mul(2).min(60);
                if let Err(e) = service
                    .update_poll(&device_code_hash, Some(new_interval))
                    .await
                {
                    tracing::warn!(error = %e, "failed to update device_code poll (slow_down)");
                }
                let (s, b) = oauth_error(
                    StatusCode::BAD_REQUEST,
                    "slow_down",
                    "polling too fast; increase interval",
                );
                return (s, b).into_response();
            }

            // Not too fast — bump the last_polled_at timestamp and return pending.
            if let Err(e) = service.update_poll(&device_code_hash, None).await {
                tracing::warn!(error = %e, "failed to update device_code poll");
            }
            let (s, b) = oauth_error(
                StatusCode::BAD_REQUEST,
                "authorization_pending",
                "waiting for user approval",
            );
            (s, b).into_response()
        }
        DeviceCodeStatus::Approved => {
            // CAS consume: strict single-use. If two pollers race, exactly one wins.
            let consumed = match service.consume(&device_code_hash).await {
                Ok(true) => true,
                Ok(false) => {
                    let (s, b) = oauth_error(
                        StatusCode::BAD_REQUEST,
                        "invalid_grant",
                        "device_code already exchanged",
                    );
                    return (s, b).into_response();
                }
                Err(e) => {
                    tracing::error!(error = %e, "CAS consume failed");
                    let (s, b) = oauth_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "server_error",
                        "internal error",
                    );
                    return (s, b).into_response();
                }
            };
            debug_assert!(consumed);

            // Resolve approving user.
            let approving_user_id_str = match row.approved_user_id.as_deref() {
                Some(s) => s,
                None => {
                    tracing::error!("approved row missing approved_user_id");
                    let (s, b) = oauth_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "server_error",
                        "internal error",
                    );
                    return (s, b).into_response();
                }
            };
            let approving_user_uuid = match Uuid::parse_str(approving_user_id_str) {
                Ok(u) => u,
                Err(_) => {
                    tracing::error!("approved_user_id is not a valid UUID");
                    let (s, b) = oauth_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "server_error",
                        "internal error",
                    );
                    return (s, b).into_response();
                }
            };
            let user_id = UserId(approving_user_uuid);

            // If the device code was bound to a workspace identity during
            // approval, look up the workspace-specific OAuth client and issue
            // the token against that client. No silent bootstrap fallback:
            // a workspace-bound row with a missing workspace, missing pk_hash,
            // or missing/revoked client is an inconsistent state and MUST
            // fail with invalid_grant rather than issuing a token against
            // the bootstrap client.
            let token_client_id = if let Some(workspace_name) = row.workspace_name_prefill.as_deref() {
                let ws = match state.store.get_workspace_by_name(workspace_name).await {
                    Ok(Some(ws)) => ws,
                    _ => {
                        tracing::error!(%workspace_name, "approved device_code has no workspace row");
                        let (s, b) = oauth_error(
                            StatusCode::BAD_REQUEST,
                            "invalid_grant",
                            "workspace registration is incomplete; retry device authorization",
                        );
                        return (s, b).into_response();
                    }
                };
                let pk_hash = ws.pk_hash.as_deref().unwrap_or("");
                if pk_hash.is_empty() {
                    tracing::error!(workspace_id = %ws.id.0, "workspace missing pk_hash");
                    let (s, b) = oauth_error(
                        StatusCode::BAD_REQUEST,
                        "invalid_grant",
                        "workspace registration is incomplete; retry device authorization",
                    );
                    return (s, b).into_response();
                }
                let client = match state.store.get_oauth_client_by_public_key_hash(pk_hash).await {
                    Ok(Some(c)) if c.revoked_at.is_none() => c,
                    _ => {
                        tracing::error!(%pk_hash, "workspace missing OAuth client");
                        let (s, b) = oauth_error(
                            StatusCode::BAD_REQUEST,
                            "invalid_grant",
                            "workspace OAuth client is missing or revoked",
                        );
                        return (s, b).into_response();
                    }
                };
                // Scope intersect defense-in-depth: every device_code scope
                // must be within the client's allowed_scopes envelope.
                for s in &row.scopes {
                    if !client.allowed_scopes.contains(s) {
                        let (code, body) = oauth_error(
                            StatusCode::BAD_REQUEST,
                            "invalid_scope",
                            "device_code scope exceeds workspace client allowed_scopes",
                        );
                        return (code, body).into_response();
                    }
                }
                client.client_id
            } else {
                // Non-workspace-bound device_code: pin to the device_code's
                // own client (bootstrap or direct). Legacy path, unchanged.
                row.client_id.clone()
            };

            // Issue access + refresh tokens (parity with authorization_code arm).
            let (access_raw, access_hash) = generate_access_token();
            let (refresh_raw, refresh_hash) = generate_refresh_token();

            let access_token = OAuthAccessToken {
                token_hash: access_hash.clone(),
                client_id: token_client_id.clone(),
                user_id: user_id.clone(),
                scopes: row.scopes.clone(),
                created_at: now,
                expires_at: now + Duration::seconds(ACCESS_TOKEN_TTL_SECS),
                revoked_at: None,
            };
            let refresh_token = OAuthRefreshToken {
                token_hash: refresh_hash,
                client_id: token_client_id,
                user_id,
                scopes: row.scopes.clone(),
                access_token_hash: access_hash,
                created_at: now,
                expires_at: now + Duration::seconds(REFRESH_TOKEN_TTL_SECS),
                revoked_at: None,
            };

            if let Err(e) = state.store.create_oauth_access_token(&access_token).await {
                tracing::error!(error = %e, "failed to store access token");
                let (s, b) = oauth_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "server_error",
                    "internal error",
                );
                return (s, b).into_response();
            }
            if let Err(e) = state.store.create_oauth_refresh_token(&refresh_token).await {
                tracing::error!(error = %e, "failed to store refresh token");
                let (s, b) = oauth_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "server_error",
                    "internal error",
                );
                return (s, b).into_response();
            }

            let event = AuditEvent::builder(AuditEventType::Oauth2TokenAcquired)
                .action("oauth_token_issued")
                .resource("oauth_client", &row.client_id)
                .correlation_id(&corr.0)
                .decision(AuditDecision::Permit, Some("device_code exchange"))
                .details(serde_json::json!({
                    "client_id": row.client_id,
                    "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                }))
                .build();
            if let Err(e) = state.store.append_audit_event(&event).await {
                tracing::warn!(error = %e, "failed to write audit event");
            }

            let scope_string = OAuthScope::to_scope_string(&row.scopes);
            let response = TokenResponse {
                access_token: access_raw,
                token_type: "Bearer".to_string(),
                expires_in: ACCESS_TOKEN_TTL_SECS,
                refresh_token: Some(refresh_raw),
                scope: scope_string,
            };
            (StatusCode::OK, Json(response)).into_response()
        }
    }
}
