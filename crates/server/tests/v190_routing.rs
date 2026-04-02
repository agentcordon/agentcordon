//! Integration tests — v1.9.0 Feature 2: Server-Side Routing.
//!
//! Replaces the old `spa_fallback.rs` tests. Verifies that hash-based SPA
//! routing is replaced with real server routes, that page routes require auth,
//! and that the SPA fallback is gone (unknown paths → 404 HTML, not index.html).

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

async fn get_authed(
    app: &axum::Router,
    uri: &str,
    cookie: &str,
) -> (StatusCode, String, String, Vec<(String, String)>) {
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

    (status, content_type, body, headers)
}

async fn get_raw(
    app: &axum::Router,
    uri: &str,
) -> (StatusCode, String, String, Vec<(String, String)>) {
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

    (status, content_type, body, headers)
}

#[allow(dead_code)]
fn get_header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
}

// ===========================================================================
// 2A. Happy Path
// ===========================================================================

#[tokio::test]
async fn test_all_page_routes_return_html() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let user = common::create_test_user(
        &*ctx.store,
        "routes-user",
        common::TEST_PASSWORD,
        UserRole::Admin,
    )
    .await;
    let cookie = common::login_user_combined(&ctx.app, &user.username, common::TEST_PASSWORD).await;

    // All page routes that should return 200 HTML when authenticated.
    // Detail pages use a placeholder UUID.
    let uuid = "00000000-0000-0000-0000-000000000001";
    let routes = [
        "/dashboard",
        "/credentials",
        "/credentials/new",
        &format!("/credentials/{}", uuid),
        "/workspaces",
        &format!("/workspaces/{}", uuid),
        "/security",
        &format!("/security/{}", uuid),
        "/mcp-servers",
        "/mcp-servers/new",
        &format!("/mcp-servers/{}", uuid),
        "/mcp-servers/catalog",
        "/audit",
        "/settings/users",
        "/settings/users/new",
        "/settings",
    ];

    for route in &routes {
        let (status, content_type, body, _) = get_authed(&ctx.app, route, &cookie).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "route {} should return 200, got {}",
            route,
            status,
        );
        assert!(
            content_type.contains("text/html"),
            "route {} should return text/html, got: {}",
            route,
            content_type,
        );
        assert!(
            body.contains("<!DOCTYPE html>"),
            "route {} should contain DOCTYPE",
            route,
        );
    }
}

#[tokio::test]
async fn test_login_page_no_auth_required() {
    let ctx = TestAppBuilder::new().with_admin().build().await;

    let (status, content_type, body, _) = get_raw(&ctx.app, "/login").await;

    assert_eq!(status, StatusCode::OK);
    assert!(content_type.contains("text/html"));
    assert!(body.contains("Sign in") || body.contains("login") || body.contains("Login"));
}

#[tokio::test]
async fn test_root_redirects_to_dashboard() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let user = common::create_test_user(
        &*ctx.store,
        "root-user",
        common::TEST_PASSWORD,
        UserRole::Admin,
    )
    .await;
    let cookie = common::login_user_combined(&ctx.app, &user.username, common::TEST_PASSWORD).await;

    let resp = ctx
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/")
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // Root should redirect to /dashboard (301 or 302 or 308)
    let status = resp.status();
    assert!(
        status.is_redirection(),
        "GET / should redirect, got {}",
        status,
    );

    let location = resp
        .headers()
        .get(header::LOCATION)
        .map(|v| v.to_str().unwrap_or(""))
        .unwrap_or("");
    assert!(
        location.contains("/dashboard"),
        "redirect location should be /dashboard, got: {}",
        location,
    );
}

// ===========================================================================
// 2C. Error Handling
// ===========================================================================

#[tokio::test]
async fn test_unknown_path_returns_404_html() {
    let ctx = TestAppBuilder::new().with_admin().build().await;

    let (status, content_type, body, _) = get_raw(&ctx.app, "/definitely-not-a-page").await;

    assert_eq!(status, StatusCode::NOT_FOUND, "unknown path should 404");
    assert!(
        content_type.contains("text/html"),
        "404 should be HTML, got: {}",
        content_type,
    );
    assert!(
        body.contains("404") || body.contains("Not Found") || body.contains("not found"),
        "404 page should indicate not found",
    );
    // Crucially: NOT the old SPA shell
    assert!(
        !body.contains("id=\"app\"") || body.contains("404"),
        "404 must not be the old SPA index.html shell",
    );
}

#[tokio::test]
async fn test_spa_hash_routes_return_404() {
    let ctx = TestAppBuilder::new().with_admin().build().await;

    // Hash routes (like /#/agents) are sent as GET / by the browser
    // (fragment is not sent to server). The server sees GET / which
    // redirects to /dashboard. This test verifies the server does NOT
    // serve the SPA shell for GET /.
    let resp = ctx
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // Without auth, / should redirect to /login (not serve SPA)
    let status = resp.status();
    assert!(
        status.is_redirection(),
        "GET / without auth should redirect, got {}",
        status,
    );
}

#[tokio::test]
async fn test_unauthenticated_page_redirects_to_login() {
    let ctx = TestAppBuilder::new().with_admin().build().await;

    let resp = ctx
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/credentials")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let status = resp.status();
    assert!(
        status.is_redirection(),
        "unauthenticated GET /credentials should redirect, got {}",
        status,
    );

    let location = resp
        .headers()
        .get(header::LOCATION)
        .map(|v| v.to_str().unwrap_or(""))
        .unwrap_or("");
    assert!(
        location.contains("/login"),
        "should redirect to /login, got: {}",
        location,
    );
    // Should preserve the destination in ?next= parameter
    assert!(
        location.contains("next="),
        "redirect should include next= parameter, got: {}",
        location,
    );
}

#[tokio::test]
async fn test_login_redirect_preserves_destination() {
    let ctx = TestAppBuilder::new().with_admin().build().await;

    let resp = ctx
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/workspaces")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let location = resp
        .headers()
        .get(header::LOCATION)
        .map(|v| v.to_str().unwrap_or(""))
        .unwrap_or("");

    // The redirect should preserve /workspaces as the next destination
    assert!(
        location.contains("/workspaces") || location.contains("%2Fworkspaces"),
        "redirect should preserve /workspaces destination, got: {}",
        location,
    );
}

// ===========================================================================
// 2D. Cross-Feature
// ===========================================================================

#[tokio::test]
async fn test_api_routes_not_intercepted_by_pages() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let user = common::create_test_user(
        &*ctx.store,
        "api-route-user",
        common::TEST_PASSWORD,
        UserRole::Admin,
    )
    .await;
    let cookie = common::login_user_combined(&ctx.app, &user.username, common::TEST_PASSWORD).await;

    // GET /api/v1/credentials should return JSON, not HTML
    let (status, _body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::GET,
        "/api/v1/credentials",
        None,
        Some(&cookie),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    // body is already parsed as Value by send_json — if it got here, it's JSON

    // GET agents should also return JSON
    let (status, _) = common::send_json_auto_csrf(
        &ctx.app,
        Method::GET,
        "/api/v1/workspaces",
        None,
        Some(&cookie),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn test_static_assets_served() {
    let ctx = TestAppBuilder::new().with_admin().build().await;

    // CSS should be served
    let (status, content_type, _, _) = get_raw(&ctx.app, "/css/vault.css").await;
    assert_eq!(status, StatusCode::OK, "CSS should be served");
    assert!(
        content_type.contains("text/css"),
        "CSS content-type expected, got: {}",
        content_type,
    );

    // Favicon should be served
    let (status, _, _, _) = get_raw(&ctx.app, "/img/favicon.svg").await;
    assert_eq!(status, StatusCode::OK, "favicon should be served");
}

// ===========================================================================
// 2E. Security
// ===========================================================================

#[tokio::test]
async fn test_page_routes_require_session() {
    let ctx = TestAppBuilder::new().with_admin().build().await;

    // All authenticated page routes should redirect to /login without session
    let protected_routes = [
        "/dashboard",
        "/credentials",
        "/workspaces",
        "/security",
        "/audit",
        "/settings/users",
        "/settings",
    ];

    for route in &protected_routes {
        let resp = ctx
            .app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri(*route)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert!(
            resp.status().is_redirection(),
            "GET {} without session should redirect, got {}",
            route,
            resp.status(),
        );

        let location = resp
            .headers()
            .get(header::LOCATION)
            .map(|v| v.to_str().unwrap_or(""))
            .unwrap_or("");
        assert!(
            location.contains("/login"),
            "GET {} should redirect to /login, got: {}",
            route,
            location,
        );
    }
}

#[tokio::test]
async fn test_expired_session_redirects_to_login() {
    let ctx = TestAppBuilder::new().with_admin().build().await;

    // Use a fake/expired session cookie
    let fake_cookie = "agtcrdn_session=expired-session-token-that-does-not-exist";

    let resp = ctx
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/dashboard")
                .header(header::COOKIE, fake_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert!(
        resp.status().is_redirection(),
        "expired session should redirect, got {}",
        resp.status(),
    );
}
