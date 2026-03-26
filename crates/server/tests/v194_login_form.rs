//! v1.9.4 — Login Form Name Attribute Tests (Item #15)
//!
//! Verifies that login form inputs have `name` attributes for browser
//! autofill compatibility, and that the login flow still works correctly.

use crate::common;

use agent_cordon_core::domain::user::UserRole;
use agent_cordon_server::test_helpers::TestAppBuilder;
use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::json;
use tower::ServiceExt;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// GET a page without auth (login page is public).
async fn get_html_raw(app: &axum::Router, uri: &str) -> (StatusCode, String) {
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

// ===========================================================================
// 15A. Happy Path
// ===========================================================================

/// Login HTML has `name="username"` on the username input.
#[tokio::test]
async fn test_login_username_has_name_attr() {
    let ctx = TestAppBuilder::new().with_admin().build().await;

    let (status, body) = get_html_raw(&ctx.app, "/login").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains(r#"name="username"#),
        "login form should have name=\"username\" attribute for browser autofill"
    );
}

/// Login HTML has `name="password"` on the password input.
#[tokio::test]
async fn test_login_password_has_name_attr() {
    let ctx = TestAppBuilder::new().with_admin().build().await;

    let (status, body) = get_html_raw(&ctx.app, "/login").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains(r#"name="password"#),
        "login form should have name=\"password\" attribute for browser autofill"
    );
}

// ===========================================================================
// 15D. Cross-Feature
// ===========================================================================

/// Login still works via JSON API (adding name attrs doesn't break Alpine.js).
#[tokio::test]
async fn test_login_still_works_with_name_attrs() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let _user = common::create_test_user(
        &*ctx.store,
        "login-form-user",
        common::TEST_PASSWORD,
        UserRole::Admin,
    )
    .await;

    // Login via JSON API (the same path Alpine.js uses)
    let (status, body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        "/api/v1/auth/login",
        None,
        None,
        Some(json!({
            "username": "login-form-user",
            "password": common::TEST_PASSWORD,
        })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "login via JSON API should still work: {:?}",
        body
    );
    assert!(
        body["data"]["csrf_token"].is_string(),
        "login response should include csrf_token"
    );
}

// ===========================================================================
// 15E. Security
// ===========================================================================

/// Username input has `autocomplete="username"`, password has `autocomplete="current-password"`.
#[tokio::test]
async fn test_login_autocomplete_attributes() {
    let ctx = TestAppBuilder::new().with_admin().build().await;

    let (status, body) = get_html_raw(&ctx.app, "/login").await;
    assert_eq!(status, StatusCode::OK);

    assert!(
        body.contains(r#"autocomplete="username"#),
        "username input should have autocomplete=\"username\" for password managers"
    );
    assert!(
        body.contains(r#"autocomplete="current-password"#),
        "password input should have autocomplete=\"current-password\" for password managers"
    );
}
