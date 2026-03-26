//! Integration tests — Advanced Mode Toggle regression tests.
//!
//! Verifies that the advanced mode toggle uses only the database as the
//! source of truth. No localStorage or client-side persistence should
//! be involved. The API endpoint is the only way to change the setting,
//! and a page reload after success is the sync mechanism.

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

/// Create a test context with an admin user (show_advanced defaults to true).
async fn setup() -> (
    agent_cordon_server::test_helpers::TestContext,
    String,
    agent_cordon_core::domain::user::User,
) {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let user = common::create_test_user(
        &*ctx.store,
        "toggle-test-user",
        common::TEST_PASSWORD,
        UserRole::Admin,
    )
    .await;

    let cookie =
        common::login_user_combined(&ctx.app, "toggle-test-user", common::TEST_PASSWORD).await;
    (ctx, cookie, user)
}

// ===========================================================================
// Toggle ON → DB reflects → page re-render shows advanced nav items
// ===========================================================================

#[tokio::test]
async fn test_toggle_on_updates_db_and_renders_advanced() {
    let (ctx, cookie, _user) = setup().await;

    // Toggle ON via API
    let (status, body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::PUT,
        "/api/v1/settings/advanced-mode",
        None,
        Some(&cookie),
        Some(serde_json::json!({ "enabled": true })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "toggle ON should succeed: {:?}",
        body
    );
    assert_eq!(body["data"]["show_advanced"], true);

    // Verify DB state via settings page render (show_advanced is injected as template var)
    let (status, html) = get_html(&ctx.app, "/settings", &cookie).await;
    assert_eq!(status, StatusCode::OK);
    // The template renders `advancedMode: {{ user.show_advanced }}` — should be `true`
    assert!(
        html.contains("advancedMode: true"),
        "settings page should render advancedMode: true after toggle ON"
    );
}

// ===========================================================================
// Toggle OFF → DB reflects → page re-render hides advanced nav items
// ===========================================================================

#[tokio::test]
async fn test_toggle_off_updates_db_and_renders_simple() {
    let (ctx, cookie, mut user) = setup().await;

    // First set to ON in DB directly
    user.show_advanced = true;
    ctx.store
        .update_user(&user)
        .await
        .expect("set show_advanced=true");

    // Toggle OFF via API
    let (status, body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::PUT,
        "/api/v1/settings/advanced-mode",
        None,
        Some(&cookie),
        Some(serde_json::json!({ "enabled": false })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "toggle OFF should succeed: {:?}",
        body
    );
    assert_eq!(body["data"]["show_advanced"], false);

    // Verify DB state via settings page render
    let (status, html) = get_html(&ctx.app, "/settings", &cookie).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        html.contains("advancedMode: false"),
        "settings page should render advancedMode: false after toggle OFF"
    );
}

// ===========================================================================
// Idempotent re-toggle (toggle twice = back to start)
// ===========================================================================

#[tokio::test]
async fn test_toggle_idempotent_roundtrip() {
    let (ctx, cookie, mut user) = setup().await;

    // Start with OFF
    user.show_advanced = false;
    ctx.store
        .update_user(&user)
        .await
        .expect("set show_advanced=false");

    // Toggle ON
    let (s1, _) = common::send_json_auto_csrf(
        &ctx.app,
        Method::PUT,
        "/api/v1/settings/advanced-mode",
        None,
        Some(&cookie),
        Some(serde_json::json!({ "enabled": true })),
    )
    .await;
    assert_eq!(s1, StatusCode::OK);

    // Verify ON
    let (_, html) = get_html(&ctx.app, "/settings", &cookie).await;
    assert!(
        html.contains("advancedMode: true"),
        "should be ON after first toggle"
    );

    // Toggle OFF
    let (s2, _) = common::send_json_auto_csrf(
        &ctx.app,
        Method::PUT,
        "/api/v1/settings/advanced-mode",
        None,
        Some(&cookie),
        Some(serde_json::json!({ "enabled": false })),
    )
    .await;
    assert_eq!(s2, StatusCode::OK);

    // Verify OFF (back to start)
    let (_, html2) = get_html(&ctx.app, "/settings", &cookie).await;
    assert!(
        html2.contains("advancedMode: false"),
        "should be OFF after second toggle (back to start)"
    );
}

// ===========================================================================
// Idempotent: setting the same value twice is a no-op
// ===========================================================================

#[tokio::test]
async fn test_toggle_same_value_twice_is_noop() {
    let (ctx, cookie, mut user) = setup().await;

    // Start with ON
    user.show_advanced = true;
    ctx.store
        .update_user(&user)
        .await
        .expect("set show_advanced=true");

    // Toggle ON again (already ON)
    let (status, body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::PUT,
        "/api/v1/settings/advanced-mode",
        None,
        Some(&cookie),
        Some(serde_json::json!({ "enabled": true })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "setting same value should still succeed: {:?}",
        body
    );
    assert_eq!(body["data"]["show_advanced"], true);

    // Verify still ON
    let (_, html) = get_html(&ctx.app, "/settings", &cookie).await;
    assert!(html.contains("advancedMode: true"), "should still be ON");
}

// ===========================================================================
// No advanced-mode localStorage reference in settings page
// ===========================================================================

#[tokio::test]
async fn test_settings_page_has_no_advanced_mode_localstorage() {
    let (ctx, cookie, _user) = setup().await;

    let (status, html) = get_html(&ctx.app, "/settings", &cookie).await;
    assert_eq!(status, StatusCode::OK);
    // The settings page must not use localStorage for advanced mode state.
    // (base.html uses localStorage for theme — that's fine and unrelated.)
    assert!(
        !html.contains("ac_advanced_mode"),
        "settings page must not contain ac_advanced_mode localStorage references — \
         advanced mode state lives only in the database"
    );
}
