//! Integration tests — v1.9.1 Feature 2: Page Handler .unwrap() Fix.
//!
//! Verifies that page handlers do not panic when the User extension is missing
//! from request extensions (e.g., unauthenticated access). Instead, they should
//! return a redirect to `/login`.

use crate::common;

use agent_cordon_core::domain::user::UserRole;
use agent_cordon_server::test_helpers::TestAppBuilder;
use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Make a GET request with a session cookie and return (status, content_type, body).
async fn get_authed(app: &axum::Router, uri: &str, cookie: &str) -> (StatusCode, String, String) {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(uri)
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let status = resp.status();
    let content_type = resp
        .headers()
        .get(header::CONTENT_TYPE)
        .map(|v| v.to_str().unwrap_or("").to_string())
        .unwrap_or_default();
    let body = String::from_utf8(
        resp.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();

    (status, content_type, body)
}

/// Make a GET request without any auth and return (status, headers, body).
async fn get_unauthed(
    app: &axum::Router,
    uri: &str,
) -> (StatusCode, Vec<(String, String)>, String) {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(uri)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let status = resp.status();
    let headers: Vec<(String, String)> = resp
        .headers()
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();
    let body = String::from_utf8(
        resp.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();

    (status, headers, body)
}

/// Make a GET request with a specific cookie value and return (status, headers, body).
async fn get_with_cookie(
    app: &axum::Router,
    uri: &str,
    cookie: &str,
) -> (StatusCode, Vec<(String, String)>, String) {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(uri)
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let status = resp.status();
    let headers: Vec<(String, String)> = resp
        .headers()
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();
    let body = String::from_utf8(
        resp.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();

    (status, headers, body)
}

/// Assert that a response is a redirect to /login (302/303) and NOT a 500 panic.
fn assert_redirects_to_login(status: StatusCode, headers: &[(String, String)], context: &str) {
    assert!(
        status == StatusCode::FOUND
            || status == StatusCode::SEE_OTHER
            || status == StatusCode::TEMPORARY_REDIRECT,
        "{}: expected redirect (302/303/307), got {} — this may indicate a .unwrap() panic",
        context,
        status,
    );

    if let Some((_, location)) = headers.iter().find(|(k, _)| k == "location") {
        assert!(
            location.contains("/login"),
            "{}: redirect should go to /login, got: {}",
            context,
            location,
        );
    }
}

/// Create a test context with an admin user logged in.
async fn setup() -> (agent_cordon_server::test_helpers::TestContext, String) {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let _user = common::create_test_user(
        &*ctx.store,
        "page-auth-user",
        common::TEST_PASSWORD,
        UserRole::Admin,
    )
    .await;
    let cookie =
        common::login_user_combined(&ctx.app, "page-auth-user", common::TEST_PASSWORD).await;
    (ctx, cookie)
}

// ===========================================================================
// 2A. Happy Path
// ===========================================================================

#[tokio::test]
async fn test_dashboard_page_loads_with_valid_session() {
    let (ctx, cookie) = setup().await;

    let (status, content_type, body) = get_authed(&ctx.app, "/dashboard", &cookie).await;

    assert_eq!(
        status,
        StatusCode::OK,
        "dashboard should return 200 with valid session"
    );
    assert!(content_type.contains("text/html"));
    assert!(
        body.contains("<!DOCTYPE html>"),
        "response should be full HTML page"
    );
}

#[tokio::test]
async fn test_credentials_page_loads_with_valid_session() {
    let (ctx, cookie) = setup().await;

    let (status, content_type, _body) = get_authed(&ctx.app, "/credentials", &cookie).await;

    assert_eq!(
        status,
        StatusCode::OK,
        "credentials page should return 200 with valid session"
    );
    assert!(content_type.contains("text/html"));
}

// ===========================================================================
// 2C. Error Handling
// ===========================================================================

/// The key regression test: GET /credentials without session must redirect,
/// NOT panic with a 500 from `.unwrap()` on missing User extension.
#[tokio::test]
async fn test_page_without_session_returns_redirect_not_panic() {
    let ctx = TestAppBuilder::new().with_admin().build().await;

    let (status, headers, _body) = get_unauthed(&ctx.app, "/credentials").await;

    // Must NOT be 500 (which would indicate a .unwrap() panic)
    assert_ne!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "unauthenticated page access must not panic (500)"
    );
    assert_redirects_to_login(status, &headers, "GET /credentials without session");
}

#[tokio::test]
async fn test_page_with_expired_session_returns_redirect() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let _user = common::create_test_user(
        &*ctx.store,
        "expired-session-user",
        common::TEST_PASSWORD,
        UserRole::Admin,
    )
    .await;
    let cookie =
        common::login_user_combined(&ctx.app, "expired-session-user", common::TEST_PASSWORD).await;

    // Verify the session works first
    let (status, _, _) = get_authed(&ctx.app, "/credentials", &cookie).await;
    assert_eq!(status, StatusCode::OK, "session should be valid initially");

    // Delete all sessions from the store to simulate expiry
    // The session hash won't match any stored session, so auth middleware
    // should reject and redirect.
    let fake_cookie =
        "agtcrdn_session=expired-session-token-that-does-not-exist; agtcrdn_csrf=fake-csrf";

    let (status, headers, _body) = get_with_cookie(&ctx.app, "/credentials", fake_cookie).await;

    assert_ne!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "expired/invalid session must not cause a panic"
    );
    assert_redirects_to_login(status, &headers, "GET /credentials with expired session");
}

#[tokio::test]
async fn test_page_with_malformed_cookie_returns_redirect() {
    let ctx = TestAppBuilder::new().with_admin().build().await;

    let (status, headers, _body) =
        get_with_cookie(&ctx.app, "/credentials", "agtcrdn_session=!!!garbage!!!").await;

    assert_ne!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "malformed cookie must not cause a panic"
    );
    assert_redirects_to_login(status, &headers, "GET /credentials with malformed cookie");
}

/// Hit all page routes unauthenticated — every one must return a redirect, not 500.
#[tokio::test]
async fn test_all_page_routes_handle_missing_user_gracefully() {
    let ctx = TestAppBuilder::new().with_admin().build().await;

    let routes = [
        "/dashboard",
        "/credentials",
        "/workspaces",
        "/security",
        "/audit",
        "/settings",
        "/mcp-servers",
    ];

    for route in &routes {
        let (status, headers, _body) = get_unauthed(&ctx.app, route).await;

        assert_ne!(
            status,
            StatusCode::INTERNAL_SERVER_ERROR,
            "unauthenticated GET {} returned 500 — likely .unwrap() panic",
            route,
        );
        assert_redirects_to_login(status, &headers, &format!("GET {} unauthenticated", route));
    }
}

// ===========================================================================
// 2E. Security
// ===========================================================================

/// Verify that unauthenticated page responses do not leak user data.
#[tokio::test]
async fn test_page_auth_failure_does_not_leak_data() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let _user = common::create_test_user(
        &*ctx.store,
        "secret-user",
        common::TEST_PASSWORD,
        UserRole::Admin,
    )
    .await;

    let (status, _headers, body) = get_unauthed(&ctx.app, "/credentials").await;

    // Should be a redirect, not a page with data
    assert_ne!(status, StatusCode::INTERNAL_SERVER_ERROR);

    // The redirect body (if any) should not contain user-specific data
    assert!(
        !body.contains("secret-user"),
        "redirect response body must not contain username"
    );
    assert!(
        !body.contains("agtcrdn_session"),
        "redirect response body must not contain session tokens"
    );
}
