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
    grant_type: String,
    // authorization_code fields
    code: Option<String>,
    redirect_uri: Option<String>,
    code_verifier: Option<String>,
    // refresh_token fields
    refresh_token: Option<String>,
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
    match req.grant_type.as_str() {
        "authorization_code" => handle_authorization_code(state, corr, req).await,
        "refresh_token" => handle_refresh_token(state, corr, req).await,
        "client_credentials" => handle_client_credentials(state, corr, req).await,
        _ => {
            let (status, body) = oauth_error(
                StatusCode::BAD_REQUEST,
                "unsupported_grant_type",
                "grant_type must be authorization_code, refresh_token, or client_credentials",
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
