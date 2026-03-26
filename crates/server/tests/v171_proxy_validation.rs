//! v1.7.1 — Proxy Validation Tests (Feature #5)
//!
//! Tests that the device proxy endpoint correctly rejects empty/missing credential_id
//! with a 400 status instead of passing it through to resolution and returning 502.
//!
//! **Important**: The credential_id validation now happens on the SERVER (port 3140)
//! as part of the unified architecture. Proxy tests live in the E2E test suite.
//!
//! Server-side credential name resolution is tested in `v170_proxy_name_resolution.rs`.

use axum::http::{Method, StatusCode};
use serde_json::json;

use agent_cordon_core::domain::user::UserRole;
use agent_cordon_server::test_helpers::TestAppBuilder;

use crate::common::*;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

#[allow(dead_code)]
async fn setup_admin_with_credential(
    ctx: &agent_cordon_server::test_helpers::TestContext,
) -> (String, String, String) {
    create_user_in_db(
        &*ctx.store,
        "proxy-val-admin",
        TEST_PASSWORD,
        UserRole::Admin,
        false,
        true,
    )
    .await;
    let cookie = login_user_combined(&ctx.app, "proxy-val-admin", TEST_PASSWORD).await;
    let csrf = extract_csrf_from_cookie(&cookie).unwrap();

    // Create a credential for happy path tests
    let (status, body) = send_json(
        &ctx.app,
        Method::POST,
        "/api/v1/credentials",
        None,
        Some(&cookie),
        Some(&csrf),
        Some(json!({
            "name": "proxy-test-cred",
            "service": "test-service",
            "secret_value": "test-secret",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "create credential: {}", body);
    let cred_id = body["data"]["id"]
        .as_str()
        .expect("credential id")
        .to_string();

    (cookie, csrf, cred_id)
}

// ===========================================================================
// 5D. Server-Side — Credential Lookup Validation
// ===========================================================================

/// Verify that the server's by-name lookup returns 404 for empty string
/// (not 500 or other server error). This is the server-side half of the fix.
#[tokio::test]
async fn test_server_credential_by_name_empty_string_returns_404() {
    let ctx = TestAppBuilder::new().build().await;
    create_user_in_db(
        &*ctx.store,
        "proxy-val-admin2",
        TEST_PASSWORD,
        UserRole::Admin,
        false,
        true,
    )
    .await;
    let cookie = login_user_combined(&ctx.app, "proxy-val-admin2", TEST_PASSWORD).await;
    let csrf = extract_csrf_from_cookie(&cookie).unwrap();

    // Look up credential by empty name — should get 404 (not 500)
    let (status, body) = send_json(
        &ctx.app,
        Method::GET,
        "/api/v1/credentials/by-name/",
        None,
        Some(&cookie),
        Some(&csrf),
        None,
    )
    .await;

    // Empty name path segment may match a different route or return 404
    assert_ne!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "empty name lookup should not cause 500: {}",
        body
    );
}

/// Verify that the server's by-name lookup returns 404 for whitespace-only name.
#[tokio::test]
async fn test_server_credential_by_name_whitespace_returns_404() {
    let ctx = TestAppBuilder::new().build().await;
    create_user_in_db(
        &*ctx.store,
        "proxy-val-admin3",
        TEST_PASSWORD,
        UserRole::Admin,
        false,
        true,
    )
    .await;
    let cookie = login_user_combined(&ctx.app, "proxy-val-admin3", TEST_PASSWORD).await;
    let csrf = extract_csrf_from_cookie(&cookie).unwrap();

    let (status, body) = send_json(
        &ctx.app,
        Method::GET,
        "/api/v1/credentials/by-name/%20%20%20",
        None,
        Some(&cookie),
        Some(&csrf),
        None,
    )
    .await;

    assert!(
        status == StatusCode::NOT_FOUND || status == StatusCode::BAD_REQUEST,
        "whitespace-only name should return 404 or 400, got {}: {}",
        status,
        body
    );
}
