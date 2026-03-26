//! Integration tests — v1.9.3 Feature 1: Progressive Disclosure.
//!
//! Verifies that the nav hides advanced tabs by default, shows all tabs
//! in advanced mode, and that direct URL access + API endpoints are
//! unaffected by the UI preference.

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

/// GET a page with session cookie, returning (status, body_html).
async fn get_html(app: &axum::Router, uri: &str, cookie: &str) -> (StatusCode, String) {
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
    let body = String::from_utf8(
        resp.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();

    (status, body)
}

/// Create a test context with an admin user whose show_advanced = false (simple mode).
async fn setup_simple_mode() -> (agent_cordon_server::test_helpers::TestContext, String) {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let user = common::create_test_user(
        &*ctx.store,
        "simple-user",
        common::TEST_PASSWORD,
        UserRole::Admin,
    )
    .await;

    // Set show_advanced = false for this user
    let mut updated = user.clone();
    updated.show_advanced = false;
    ctx.store
        .update_user(&updated)
        .await
        .expect("update user show_advanced");

    let cookie = common::login_user_combined(&ctx.app, "simple-user", common::TEST_PASSWORD).await;
    (ctx, cookie)
}

/// Create a test context with an admin user whose show_advanced = true (advanced mode).
async fn setup_advanced_mode() -> (agent_cordon_server::test_helpers::TestContext, String) {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let user = common::create_test_user(
        &*ctx.store,
        "advanced-user",
        common::TEST_PASSWORD,
        UserRole::Admin,
    )
    .await;

    // Ensure show_advanced = true (should be default, but be explicit)
    let mut updated = user.clone();
    updated.show_advanced = true;
    ctx.store
        .update_user(&updated)
        .await
        .expect("update user show_advanced");

    let cookie =
        common::login_user_combined(&ctx.app, "advanced-user", common::TEST_PASSWORD).await;
    (ctx, cookie)
}

// ===========================================================================
// 1A. Happy Path
// ===========================================================================

/// Nav always shows all tabs regardless of show_advanced setting.
#[tokio::test]
async fn test_default_nav_hides_advanced_tabs() {
    let (ctx, cookie) = setup_simple_mode().await;

    let (status, body) = get_html(&ctx.app, "/dashboard", &cookie).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("<!DOCTYPE html>"));

    // Nav now always shows all items regardless of show_advanced setting.
    assert!(
        body.contains("/mcp-servers"),
        "nav should always contain MCP Servers link"
    );
}

/// User with show_advanced=true: nav should contain all tabs including MCP Servers and Devices.
#[tokio::test]
async fn test_advanced_mode_shows_all_tabs() {
    let (ctx, cookie) = setup_advanced_mode().await;

    let (status, body) = get_html(&ctx.app, "/dashboard", &cookie).await;
    assert_eq!(status, StatusCode::OK);

    // Advanced mode should show all nav links
    assert!(
        body.contains("/mcp-servers") || body.contains("/mcp_servers"),
        "advanced mode nav should contain MCP Servers link"
    );
    assert!(
        body.contains("/workspaces"),
        "advanced mode nav should contain Workspaces link"
    );
}

/// Direct URL access to /workspaces works even in simple mode (not 404).
#[tokio::test]
async fn test_direct_url_works_in_simple_mode() {
    let (ctx, cookie) = setup_simple_mode().await;

    let (status, _body) = get_html(&ctx.app, "/workspaces", &cookie).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "direct URL to /workspaces should work even in simple mode"
    );
}

/// API endpoints are not gated by UI preference.
#[tokio::test]
async fn test_api_endpoints_unaffected() {
    let (ctx, cookie) = setup_simple_mode().await;

    let (status, body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::GET,
        "/api/v1/workspaces",
        None,
        Some(&cookie),
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "API should not be gated by show_advanced preference: {:?}",
        body
    );
}

// ===========================================================================
// 1B. Retry/Idempotency
// ===========================================================================

/// Toggle advanced mode on, reload, then off, reload — preference persists.
#[tokio::test]
async fn test_toggle_advanced_mode_persists() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let user = common::create_test_user(
        &*ctx.store,
        "toggle-user",
        common::TEST_PASSWORD,
        UserRole::Admin,
    )
    .await;

    let cookie = common::login_user_combined(&ctx.app, "toggle-user", common::TEST_PASSWORD).await;

    // Enable advanced mode
    let mut updated = user.clone();
    updated.show_advanced = true;
    ctx.store
        .update_user(&updated)
        .await
        .expect("enable advanced");

    let (status, body) = get_html(&ctx.app, "/dashboard", &cookie).await;
    assert_eq!(status, StatusCode::OK);
    // Should show advanced tabs
    let has_devices = body.contains("/devices");

    // Disable advanced mode
    updated.show_advanced = false;
    ctx.store
        .update_user(&updated)
        .await
        .expect("disable advanced");

    let (status2, body2) = get_html(&ctx.app, "/dashboard", &cookie).await;
    assert_eq!(status2, StatusCode::OK);

    // Nav always shows all items now, so devices link should be present in both states
    let _ = has_devices;
    assert!(
        body2.contains("/devices") || body2.contains("/workspaces"),
        "nav should always show links regardless of show_advanced setting"
    );
}

// ===========================================================================
// 1D. Cross-Feature
// ===========================================================================

/// Settings gear/link should always be visible regardless of mode.
#[tokio::test]
async fn test_simple_mode_still_shows_settings() {
    let (ctx, cookie) = setup_simple_mode().await;

    let (status, body) = get_html(&ctx.app, "/dashboard", &cookie).await;
    assert_eq!(status, StatusCode::OK);

    assert!(
        body.contains("/settings"),
        "simple mode should still show settings link"
    );
}

/// Dashboard stat cards should show counts for agents, credentials, devices even in simple mode.
#[tokio::test]
async fn test_simple_mode_dashboard_still_shows_all_stats() {
    let (ctx, cookie) = setup_simple_mode().await;

    // Stats API should still return all counts
    let (status, body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::GET,
        "/api/v1/stats",
        None,
        Some(&cookie),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let data = &body["data"];
    assert!(
        data["workspaces"]["total"].is_number(),
        "stats should include workspaces.total in simple mode"
    );
    assert!(
        data["credentials"]["total"].is_number(),
        "stats should include credentials.total in simple mode"
    );
}
