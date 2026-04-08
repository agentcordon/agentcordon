//! Integration tests — v1.9.0 Feature 1: Askama Template Infrastructure.
//!
//! Verifies that server-side Askama templates render correctly with
//! base layout, nav, scoped Alpine.js, CSRF tokens, HTML escaping,
//! and proper error pages.

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

/// Send a GET request with a session cookie and return (status, content-type, body).
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

/// Send an unauthenticated GET request and return (status, content-type, body).
async fn get_raw(app: &axum::Router, uri: &str) -> (StatusCode, String, String) {
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

// ===========================================================================
// 1A. Happy Path
// ===========================================================================

#[tokio::test]
async fn test_dashboard_returns_html() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let user = common::create_test_user(
        &*ctx.store,
        "tmpl-user",
        common::TEST_PASSWORD,
        UserRole::Admin,
    )
    .await;
    let cookie = common::login_user_combined(&ctx.app, &user.username, common::TEST_PASSWORD).await;

    let (status, content_type, body) = get_authed(&ctx.app, "/dashboard", &cookie).await;

    assert_eq!(status, StatusCode::OK);
    assert!(
        content_type.contains("text/html"),
        "expected text/html, got: {}",
        content_type
    );
    assert!(
        body.contains("<!DOCTYPE html>"),
        "body must contain DOCTYPE"
    );
    assert!(
        body.contains("Dashboard"),
        "body must contain Dashboard heading"
    );
}

#[tokio::test]
async fn test_base_layout_present() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let user = common::create_test_user(
        &*ctx.store,
        "layout-user",
        common::TEST_PASSWORD,
        UserRole::Admin,
    )
    .await;
    let cookie = common::login_user_combined(&ctx.app, &user.username, common::TEST_PASSWORD).await;

    let (_, _, body) = get_authed(&ctx.app, "/dashboard", &cookie).await;

    // Base layout includes nav, Alpine.js, and toast container
    assert!(body.contains("<nav"), "must contain nav element");
    assert!(
        body.contains("alpinejs") || body.contains("alpine"),
        "must include Alpine.js script"
    );
    assert!(body.contains("toast"), "must include toast container");
}

#[tokio::test]
async fn test_nav_links_present() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let user = common::create_test_user(
        &*ctx.store,
        "nav-user",
        common::TEST_PASSWORD,
        UserRole::Admin,
    )
    .await;
    let cookie = common::login_user_combined(&ctx.app, &user.username, common::TEST_PASSWORD).await;

    let (_, _, body) = get_authed(&ctx.app, "/dashboard", &cookie).await;

    // Nav must contain links to all major pages
    // Core nav links (always visible)
    let core_links = ["/dashboard", "/credentials", "/settings"];
    for link in &core_links {
        assert!(
            body.contains(&format!("href=\"{}\"", link)),
            "nav must contain link to {}",
            link,
        );
    }

    // Additional nav links
    let advanced_links = ["/workspaces", "/security", "/mcp-servers", "/audit"];
    for link in &advanced_links {
        assert!(
            body.contains(&format!("href=\"{}\"", link)),
            "nav must contain link to {} (advanced)",
            link,
        );
    }
}

#[tokio::test]
async fn test_page_includes_scoped_alpine() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let user = common::create_test_user(
        &*ctx.store,
        "alpine-user",
        common::TEST_PASSWORD,
        UserRole::Admin,
    )
    .await;
    let cookie = common::login_user_combined(&ctx.app, &user.username, common::TEST_PASSWORD).await;

    let (_, _, body) = get_authed(&ctx.app, "/credentials", &cookie).await;

    // Page should have scoped x-data attribute (not the monolith 180-prop state)
    assert!(
        body.contains("x-data"),
        "page must contain x-data attribute for scoped Alpine.js"
    );
}

#[tokio::test]
async fn test_page_includes_csrf_token() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let user = common::create_test_user(
        &*ctx.store,
        "csrf-user",
        common::TEST_PASSWORD,
        UserRole::Admin,
    )
    .await;
    let cookie = common::login_user_combined(&ctx.app, &user.username, common::TEST_PASSWORD).await;

    let (_, _, body) = get_authed(&ctx.app, "/dashboard", &cookie).await;

    // CSRF token should be present somewhere in the page (in forms or JS)
    assert!(
        body.contains("csrf") || body.contains("_csrf"),
        "page must include CSRF token reference",
    );
}

// ===========================================================================
// 1B. Retry/Idempotency
// ===========================================================================

#[tokio::test]
async fn test_page_render_idempotent() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let user = common::create_test_user(
        &*ctx.store,
        "idem-user",
        common::TEST_PASSWORD,
        UserRole::Admin,
    )
    .await;
    let cookie = common::login_user_combined(&ctx.app, &user.username, common::TEST_PASSWORD).await;

    let (s1, _, b1) = get_authed(&ctx.app, "/dashboard", &cookie).await;
    let (s2, _, b2) = get_authed(&ctx.app, "/dashboard", &cookie).await;

    assert_eq!(s1, StatusCode::OK);
    assert_eq!(s2, StatusCode::OK);
    // Both renders should produce the same HTML structure
    // (exact match may differ by CSRF token, so check structural elements)
    assert!(b1.contains("<!DOCTYPE html>") && b2.contains("<!DOCTYPE html>"));
    assert!(b1.contains("Dashboard") && b2.contains("Dashboard"));
}

// ===========================================================================
// 1C. Error Handling
// ===========================================================================

#[tokio::test]
async fn test_404_page_renders_html() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let user = common::create_test_user(
        &*ctx.store,
        "err-user",
        common::TEST_PASSWORD,
        UserRole::Admin,
    )
    .await;
    let cookie = common::login_user_combined(&ctx.app, &user.username, common::TEST_PASSWORD).await;

    let (status, content_type, body) = get_authed(&ctx.app, "/nonexistent-page", &cookie).await;

    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(
        content_type.contains("text/html"),
        "404 should return HTML, got: {}",
        content_type
    );
    assert!(
        body.contains("404") || body.contains("Not Found") || body.contains("not found"),
        "404 page must indicate not found",
    );
}

// ===========================================================================
// 1D. Cross-Feature
// ===========================================================================

#[tokio::test]
async fn test_api_routes_still_return_json() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let user = common::create_test_user(
        &*ctx.store,
        "api-user",
        common::TEST_PASSWORD,
        UserRole::Admin,
    )
    .await;
    let cookie = common::login_user_combined(&ctx.app, &user.username, common::TEST_PASSWORD).await;

    let (status, _) = common::send_json_auto_csrf(
        &ctx.app,
        Method::GET,
        "/api/v1/credentials",
        None,
        Some(&cookie),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::OK, "API route should return 200");
}

#[tokio::test]
async fn test_health_endpoint_unaffected() {
    let ctx = TestAppBuilder::new().with_admin().build().await;

    let (status, content_type, body) = get_raw(&ctx.app, "/health").await;

    assert_eq!(status, StatusCode::OK);
    assert!(
        content_type.contains("application/json"),
        "health must be JSON, got: {}",
        content_type
    );

    let parsed: serde_json::Value = serde_json::from_str(&body).expect("health must be valid JSON");
    assert_eq!(parsed["status"], "ok");
}

// ===========================================================================
// 1E. Security
// ===========================================================================

#[tokio::test]
async fn test_template_html_escaping() {
    let ctx = TestAppBuilder::new().with_admin().build().await;

    // Create an agent with XSS attempt in the name
    let xss_name = "<script>alert('xss')</script>";
    common::create_agent_in_db(&*ctx.store, xss_name, vec!["test"], true, None).await;

    let user = common::create_test_user(
        &*ctx.store,
        "xss-user",
        common::TEST_PASSWORD,
        UserRole::Admin,
    )
    .await;
    let cookie = common::login_user_combined(&ctx.app, &user.username, common::TEST_PASSWORD).await;

    // The agents page fetches data via API + Alpine.js, so the template itself
    // won't contain the agent name directly. But if it does (server-rendered),
    // it must be escaped. Check that raw <script> is not in the page HTML.
    let (_, _, body) = get_authed(&ctx.app, "/agents", &cookie).await;
    assert!(
        !body.contains("<script>alert('xss')</script>"),
        "template must not contain unescaped XSS payload",
    );
}

#[tokio::test]
async fn test_template_no_secrets_in_html() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let user = common::create_test_user(
        &*ctx.store,
        "secret-user",
        common::TEST_PASSWORD,
        UserRole::Admin,
    )
    .await;
    let cookie = common::login_user_combined(&ctx.app, &user.username, common::TEST_PASSWORD).await;

    // Credentials list page should not contain secret values in HTML
    let (_, _, body) = get_authed(&ctx.app, "/credentials", &cookie).await;

    assert!(
        !body.contains("encrypted_value"),
        "page must not expose encrypted_value"
    );
    assert!(
        !body.contains("secret_value"),
        "page must not expose secret_value"
    );
}
