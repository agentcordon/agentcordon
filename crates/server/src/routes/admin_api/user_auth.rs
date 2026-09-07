use axum::{
    extract::State,
    http::header::{HeaderMap, SET_COOKIE},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};

use agent_cordon_core::crypto::session::generate_csrf_token;
use agent_cordon_core::domain::user::{User, UserRole};

use crate::extractors::{AuthenticatedUser, ClientAddr};
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
    ClientAddr(client_addr): ClientAddr,
    Json(req): Json<LoginRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let session = state
        .services
        .users
        .login(&corr.0, &client_addr, &req.username, &req.password)
        .await?;

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
        session.raw_token, state.config.session_ttl_seconds
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
            user: UserInfo::from(&session.user),
            expires_at: session.expires_at.to_rfc3339(),
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
    // Delete all sessions for the user (logout everywhere).
    state.services.users.logout(&auth, &corr.0).await?;

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
