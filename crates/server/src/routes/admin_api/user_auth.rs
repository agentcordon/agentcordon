use axum::{
    extract::State,
    http::header::{HeaderMap, SET_COOKIE},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};

use agent_cordon_core::auth::password::PasswordAuthenticator;
use agent_cordon_core::crypto::session::{
    generate_csrf_token, generate_session_token, hash_session_token_hmac,
};
use agent_cordon_core::domain::audit::{AuditDecision, AuditEvent, AuditEventType};
use agent_cordon_core::domain::session::Session;
use agent_cordon_core::domain::user::{User, UserRole};
use agent_cordon_core::error::AuthError;

use crate::extractors::AuthenticatedUser;
use crate::middleware::request_id::CorrelationId;
use crate::response::{ApiError, ApiResponse};
use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/auth/login", post(login))
        .route("/auth/logout", post(logout))
        .route("/auth/me", get(me))
}

// --- Request/Response Types ---

#[derive(Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
}

#[derive(Serialize)]
struct LoginResponse {
    user: UserInfo,
    expires_at: String,
    csrf_token: String,
}

#[derive(Serialize)]
struct UserInfo {
    id: String,
    username: String,
    display_name: Option<String>,
    role: UserRole,
    is_root: bool,
    enabled: bool,
    created_at: String,
    updated_at: String,
}

impl From<&User> for UserInfo {
    fn from(user: &User) -> Self {
        Self {
            id: user.id.0.to_string(),
            username: user.username.clone(),
            display_name: user.display_name.clone(),
            role: user.role.clone(),
            is_root: user.is_root,
            enabled: user.enabled,
            created_at: user.created_at.to_rfc3339(),
            updated_at: user.updated_at.to_rfc3339(),
        }
    }
}

// --- Handlers ---

async fn login(
    State(state): State<AppState>,
    axum::Extension(corr): axum::Extension<CorrelationId>,
    Json(req): Json<LoginRequest>,
) -> Result<impl IntoResponse, ApiError> {
    // Check rate limit before attempting authentication
    if state.login_rate_limiter.is_rate_limited(&req.username) {
        // Audit the rate-limited attempt
        let event = AuditEvent::builder(AuditEventType::LoginRateLimited)
            .action("login_rate_limited")
            .user_name_only(&req.username)
            .resource_type("session")
            .correlation_id(&corr.0)
            .decision(
                AuditDecision::Forbid,
                Some(&format!(
                    "bypass:rate_limited (max {})",
                    state.config.login_max_attempts
                )),
            )
            .details(serde_json::json!({
                "username": req.username,
                "lockout_seconds": state.config.login_lockout_seconds,
            }))
            .build();
        if let Err(e) = state.store.append_audit_event(&event).await {
            tracing::warn!(error = %e, "Failed to write audit event");
        }

        metrics::counter!("login_attempts_total", "result" => "rate_limited").increment(1);
        return Err(ApiError::TooManyRequests(
            "too many failed login attempts, please try again later".to_string(),
        ));
    }

    let authenticator = PasswordAuthenticator::new(state.store.clone());

    let user = match authenticator
        .authenticate(&req.username, &req.password)
        .await
    {
        Ok(user) => user,
        Err(err) => {
            // Record the failed attempt in the rate limiter
            state.login_rate_limiter.record_failure(&req.username);

            // Extract the failure reason for audit logging. The error message
            // shown to the client is always generic to prevent user enumeration.
            let reason = match &err {
                AuthError::LoginFailed(r) => r.as_audit_str(),
                _ => "unknown",
            };

            let event = AuditEvent::builder(AuditEventType::UserLoginFailed)
                .action("login_failed")
                .user_name_only(&req.username)
                .resource_type("session")
                .correlation_id(&corr.0)
                .decision(AuditDecision::Forbid, Some(reason))
                .details(serde_json::json!({
                    "username": req.username,
                    "reason": reason,
                }))
                .build();
            if let Err(e) = state.store.append_audit_event(&event).await {
                tracing::warn!(error = %e, "Failed to write audit event");
            }

            metrics::counter!("login_attempts_total", "result" => "failed").increment(1);
            return Err(ApiError::Unauthorized(
                "invalid username or password".to_string(),
            ));
        }
    };

    metrics::counter!("login_attempts_total", "result" => "success").increment(1);

    // Successful login — reset the rate limiter for this user
    state.login_rate_limiter.reset(&req.username);

    // Create session
    let raw_token = generate_session_token();
    let token_hash = hash_session_token_hmac(&raw_token, &state.session_hash_key);
    let now = chrono::Utc::now();
    let ttl = chrono::Duration::seconds(state.config.session_ttl_seconds as i64);
    let expires_at = now + ttl;

    let session = Session {
        id: token_hash.clone(),
        user_id: user.id.clone(),
        created_at: now,
        expires_at,
        last_seen_at: now,
    };

    state.store.create_session(&session).await?;

    // Audit successful login
    let event = AuditEvent::builder(AuditEventType::UserLoginSuccess)
        .action("login_success")
        .user_actor(&user)
        .resource("session", &user.id.0.to_string())
        .correlation_id(&corr.0)
        .decision(AuditDecision::Permit, Some("bypass:credentials_verified"))
        .details(serde_json::json!({
            "username": user.username,
            "user_id": user.id.0.to_string(),
        }))
        .build();
    if let Err(e) = state.store.append_audit_event(&event).await {
        tracing::warn!(error = %e, "Failed to write audit event");
    }

    // Build Set-Cookie headers.
    // Always set Secure flag so the cookie is only sent over HTTPS.
    // In development without HTTPS, browsers will still set the cookie for
    // localhost, but for any non-localhost deployment HTTPS is required.
    //
    // SameSite=Lax: We use Lax instead of Strict for consistency with the
    // OIDC callback flow (which requires Lax for cross-origin redirects).
    // Mixed SameSite modes between password login and OIDC login would cause
    // confusing behavior when both auth methods coexist.
    let session_cookie = format!(
        "agtcrdn_session={}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age={}",
        raw_token, state.config.session_ttl_seconds
    );

    // CSRF cookie: NOT HttpOnly so JavaScript can read it for double-submit.
    let csrf_token = generate_csrf_token();
    let csrf_cookie = format!(
        "agtcrdn_csrf={}; Secure; SameSite=Lax; Path=/; Max-Age={}",
        csrf_token, state.config.session_ttl_seconds
    );

    let mut headers = HeaderMap::new();
    headers.append(
        SET_COOKIE,
        session_cookie
            .parse()
            .map_err(|_| ApiError::Internal("invalid session cookie header".into()))?,
    );
    headers.append(
        SET_COOKIE,
        csrf_cookie
            .parse()
            .map_err(|_| ApiError::Internal("invalid csrf cookie header".into()))?,
    );

    let response = (
        headers,
        Json(ApiResponse::ok(LoginResponse {
            user: UserInfo::from(&user),
            expires_at: expires_at.to_rfc3339(),
            csrf_token,
        })),
    );

    Ok(response)
}

async fn logout(
    State(state): State<AppState>,
    axum::Extension(corr): axum::Extension<CorrelationId>,
    auth: AuthenticatedUser,
) -> Result<impl IntoResponse, ApiError> {
    // Delete all sessions for the user (logout everywhere)
    // For single-session logout, we would need the token hash,
    // but we extract the user first. Let's get the token from cookie for targeted logout.
    // Actually the extractor already verified the session — let's re-extract the token hash.
    // We'll delete all sessions for this user for a clean logout.
    let deleted_count = state.store.delete_user_sessions(&auth.user.id).await?;

    // Audit logout
    let event = AuditEvent::builder(AuditEventType::UserLogout)
        .action("user_logout")
        .user_actor(&auth.user)
        .resource_type("session")
        .correlation_id(&corr.0)
        .decision(AuditDecision::Permit, Some("bypass:self-service"))
        .details(serde_json::json!({
            "sessions_deleted": deleted_count,
        }))
        .build();
    if let Err(e) = state.store.append_audit_event(&event).await {
        tracing::warn!(error = %e, "Failed to write audit event");
    }

    // Clear cookies (must match flags from login to ensure browser clears them)
    let clear_session =
        "agtcrdn_session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0".to_string();
    let clear_csrf = "agtcrdn_csrf=; Secure; SameSite=Lax; Path=/; Max-Age=0".to_string();

    let mut headers = HeaderMap::new();
    headers.append(
        SET_COOKIE,
        clear_session
            .parse()
            .map_err(|_| ApiError::Internal("invalid session cookie header".into()))?,
    );
    headers.append(
        SET_COOKIE,
        clear_csrf
            .parse()
            .map_err(|_| ApiError::Internal("invalid csrf cookie header".into()))?,
    );

    let response = (
        headers,
        Json(ApiResponse::ok(serde_json::json!({ "logged_out": true }))),
    );

    Ok(response)
}

async fn me(auth: AuthenticatedUser) -> Result<Json<ApiResponse<UserInfo>>, ApiError> {
    Ok(Json(ApiResponse::ok(UserInfo::from(&auth.user))))
}
