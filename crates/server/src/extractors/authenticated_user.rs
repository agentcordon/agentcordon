use axum::{
    extract::{FromRef, FromRequestParts},
    http::request::Parts,
};

use agent_cordon_core::crypto::session::hash_session_token_hmac;
use agent_cordon_core::domain::user::User;

use crate::response::ApiError;
use crate::state::AppState;
use crate::utils::cookies::parse_cookie;

const SESSION_COOKIE_NAME: &str = "agtcrdn_session";

/// Extractor that authenticates a request via session cookie.
///
/// Reads the `agtcrdn_session` cookie, hashes the token, looks up the session
/// in the store, and validates that the session is not expired and the user is
/// enabled. Updates `last_seen_at` on each successful extraction.
pub struct AuthenticatedUser {
    pub user: User,
    pub is_root: bool,
}

impl<S> FromRequestParts<S> for AuthenticatedUser
where
    AppState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let app_state = AppState::from_ref(state);

        // Extract session token from cookie header
        let cookie_header = parts
            .headers
            .get(axum::http::header::COOKIE)
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| ApiError::Unauthorized("authentication required".to_string()))?;

        let session_token = parse_cookie(cookie_header, SESSION_COOKIE_NAME)
            .ok_or_else(|| ApiError::Unauthorized("authentication required".to_string()))?;

        // Hash token and look up session
        let token_hash = hash_session_token_hmac(session_token, &app_state.session_hash_key);

        let session = app_state
            .store
            .get_session(&token_hash)
            .await?
            .ok_or_else(|| ApiError::Unauthorized("invalid or expired session".to_string()))?;

        // Check expiration
        if session.expires_at < chrono::Utc::now() {
            // Clean up expired session
            let _ = app_state.store.delete_session(&token_hash).await;
            return Err(ApiError::Unauthorized("session expired".to_string()));
        }

        // Load user
        let user = app_state
            .store
            .get_user(&session.user_id)
            .await?
            .ok_or_else(|| ApiError::Unauthorized("user not found".to_string()))?;

        // Check user is enabled
        if !user.enabled {
            return Err(ApiError::Unauthorized("account is disabled".to_string()));
        }

        // Touch session (update last_seen_at)
        let _ = app_state.store.touch_session(&token_hash).await;

        tracing::debug!(
            user_id = %user.id.0,
            username = %user.username,
            auth_method = "session_cookie",
            "user request authenticated"
        );

        let is_root = user.is_root;
        Ok(AuthenticatedUser { user, is_root })
    }
}

// parse_cookie moved to crate::utils::cookies
