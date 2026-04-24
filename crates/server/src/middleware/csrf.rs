//! CSRF protection middleware using the double-submit cookie pattern.
//!
//! For state-changing requests (POST, PUT, DELETE, PATCH) that use cookie
//! authentication, the middleware requires an `X-CSRF-Token` header whose
//! value matches the `agtcrdn_csrf` cookie. Requests that do not carry a
//! session cookie (i.e. API key / JWT authenticated) are exempt, as are
//! safe HTTP methods (GET, HEAD, OPTIONS) and the login endpoint.

use axum::{
    extract::Request,
    http::{Method, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use subtle::ConstantTimeEq;

use crate::utils::cookies::parse_cookie;

/// Cookie name for the CSRF token (readable by JavaScript — NOT HttpOnly).
pub const CSRF_COOKIE_NAME: &str = "agtcrdn_csrf";

/// Header name the client must send the CSRF token in.
const CSRF_HEADER_NAME: &str = "x-csrf-token";

/// Session cookie name — used to determine if the request is cookie-authenticated.
const SESSION_COOKIE_NAME: &str = "agtcrdn_session";

/// Login path — exempt from CSRF because no session exists yet.
const LOGIN_PATH: &str = "/api/v1/auth/login";

/// OAuth authorize path — exempt because the consent form uses its own
/// HMAC-based CSRF token embedded in a hidden form field (validated by
/// the handler itself). Browser form POSTs cannot send custom headers.
const OAUTH_AUTHORIZE_PATH: &str = "/api/v1/oauth/authorize";

/// Device-flow activation page — exempt for the same reason as the OAuth
/// authorize consent form. `POST /activate` validates its own HMAC-based
/// CSRF token from a hidden form field; the hand-off is an HTML form
/// submission from the browser, which cannot attach custom headers.
const ACTIVATE_PATH: &str = "/activate";

/// CSRF validation middleware.
///
/// Must be applied as a layer **after** the request-id middleware and before
/// route handlers. It runs on every request but only enforces the CSRF check
/// for state-changing methods with cookie authentication.
pub async fn csrf_protection(request: Request, next: Next) -> Response {
    let method = request.method().clone();

    // Safe methods are always exempt.
    if method == Method::GET || method == Method::HEAD || method == Method::OPTIONS {
        return next.run(request).await;
    }

    // The login endpoint is exempt (no session exists yet).
    if request.uri().path() == LOGIN_PATH {
        return next.run(request).await;
    }

    // The OAuth authorize endpoint is exempt — it validates its own
    // HMAC-based CSRF token from a hidden form field, since browser
    // form POSTs cannot include custom headers.
    if request.uri().path() == OAUTH_AUTHORIZE_PATH {
        return next.run(request).await;
    }

    // The device-flow activation page is exempt for the same reason — it
    // validates its own HMAC-based CSRF token from a hidden form field.
    if request.uri().path() == ACTIVATE_PATH {
        return next.run(request).await;
    }

    // Check if the request carries a session cookie. If not, this is an
    // API key / JWT authenticated request and CSRF does not apply.
    let cookie_header = request
        .headers()
        .get(axum::http::header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let has_session_cookie = parse_cookie(cookie_header, SESSION_COOKIE_NAME).is_some();

    if !has_session_cookie {
        // No session cookie → agent/JWT auth → no CSRF needed.
        return next.run(request).await;
    }

    // This is a cookie-authenticated, state-changing request.
    // Enforce double-submit cookie CSRF validation.
    let csrf_cookie = parse_cookie(cookie_header, CSRF_COOKIE_NAME);
    let csrf_header = request
        .headers()
        .get(CSRF_HEADER_NAME)
        .and_then(|v| v.to_str().ok());

    match (csrf_cookie, csrf_header) {
        (Some(cookie_val), Some(header_val))
            if cookie_val.as_bytes().ct_eq(header_val.as_bytes()).into() =>
        {
            // Valid CSRF token (constant-time comparison to prevent timing attacks) — proceed.
            next.run(request).await
        }
        (None, _) | (_, None) => {
            tracing::warn!(
                method = %method,
                path = %request.uri().path(),
                "CSRF validation failed: missing CSRF token"
            );
            csrf_forbidden("CSRF token missing").into_response()
        }
        _ => {
            tracing::warn!(
                method = %method,
                path = %request.uri().path(),
                "CSRF validation failed: token mismatch"
            );
            csrf_forbidden("CSRF token mismatch").into_response()
        }
    }
}

/// Build a 403 Forbidden response with a structured error body.
fn csrf_forbidden(message: &str) -> impl IntoResponse {
    (
        StatusCode::FORBIDDEN,
        Json(serde_json::json!({
            "error": {
                "code": "csrf_validation_failed",
                "message": message,
            }
        })),
    )
}

// parse_cookie moved to crate::utils::cookies
