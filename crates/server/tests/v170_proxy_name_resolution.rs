//! v1.7.0 — Proxy Name Resolution Tests (Feature 1)
//!
//! Tests for the server-side `GET /api/v1/credentials/by-name/{name}` endpoint.
//! Validates that credentials can be looked up by name (the primary CLI flow),
//! as well as error handling, policy enforcement, and consistency with UUID lookups.
//!
//! Proxy-specific tests (device-side credential name in proxy body) are marked
//! Device-side proxy tests live in the E2E test suite.

use axum::http::{Method, StatusCode};
use serde_json::json;

use agent_cordon_core::domain::user::UserRole;
use agent_cordon_core::storage::Store;

use agent_cordon_server::test_helpers::TestAppBuilder;

use crate::common::*;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Create a credential directly in the store via the API (admin user).
async fn create_credential_via_api(
    app: &axum::Router,
    cookie: &str,
    csrf: &str,
    name: &str,
    service: &str,
    secret: &str,
) -> serde_json::Value {
    let (status, body) = send_json(
        app,
        Method::POST,
        "/api/v1/credentials",
        None,
        Some(cookie),
        Some(csrf),
        Some(json!({
            "name": name,
            "service": service,
            "secret_value": secret,
        })),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "create credential '{}' failed: {}",
        name,
        body
    );
    body
}

async fn setup_admin(app: &axum::Router, store: &(dyn Store + Send + Sync)) -> (String, String) {
    create_user_in_db(
        store,
        "proxy-name-admin",
        TEST_PASSWORD,
        UserRole::Admin,
        false,
        true,
    )
    .await;
    let cookie = login_user_combined(app, "proxy-name-admin", TEST_PASSWORD).await;
    let csrf = extract_csrf_from_cookie(&cookie).unwrap();
    (cookie, csrf)
}

// ===========================================================================
// 1A. Happy Path — Server-Side By-Name Endpoint
// ===========================================================================

#[tokio::test]
async fn test_get_credential_by_name() {
    let ctx = TestAppBuilder::new().build().await;
    let (cookie, csrf) = setup_admin(&ctx.app, &*ctx.store).await;

    // Create credential via API
    create_credential_via_api(
        &ctx.app,
        &cookie,
        &csrf,
        "mock-api-key",
        "mock-service",
        "secret-123",
    )
    .await;

    // Fetch by name
    let (status, body) = send_json(
        &ctx.app,
        Method::GET,
        "/api/v1/credentials/by-name/mock-api-key",
        None,
        Some(&cookie),
        Some(&csrf),
        None,
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "get by name should succeed: {}",
        body
    );
    assert_eq!(
        body["data"]["name"].as_str(),
        Some("mock-api-key"),
        "returned credential should have the correct name"
    );
}

#[tokio::test]
async fn test_get_credential_by_name_not_found() {
    let ctx = TestAppBuilder::new().build().await;
    let (cookie, csrf) = setup_admin(&ctx.app, &*ctx.store).await;

    let (status, body) = send_json(
        &ctx.app,
        Method::GET,
        "/api/v1/credentials/by-name/nonexistent-cred",
        None,
        Some(&cookie),
        Some(&csrf),
        None,
    )
    .await;

    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "nonexistent name should 404: {}",
        body
    );
}

#[tokio::test]
async fn test_get_credential_by_name_matches_get_by_id() {
    let ctx = TestAppBuilder::new().build().await;
    let (cookie, csrf) = setup_admin(&ctx.app, &*ctx.store).await;

    // Create credential
    let create_body = create_credential_via_api(
        &ctx.app,
        &cookie,
        &csrf,
        "match-test-cred",
        "test-service",
        "secret-val",
    )
    .await;
    let cred_id = create_body["data"]["id"].as_str().expect("credential id");

    // Fetch by name
    let (status_name, body_name) = send_json(
        &ctx.app,
        Method::GET,
        "/api/v1/credentials/by-name/match-test-cred",
        None,
        Some(&cookie),
        Some(&csrf),
        None,
    )
    .await;
    assert_eq!(status_name, StatusCode::OK);

    // Fetch by UUID
    let (status_id, body_id) = send_json(
        &ctx.app,
        Method::GET,
        &format!("/api/v1/credentials/{}", cred_id),
        None,
        Some(&cookie),
        Some(&csrf),
        None,
    )
    .await;
    assert_eq!(status_id, StatusCode::OK);

    // Compare core fields
    assert_eq!(
        body_name["data"]["id"], body_id["data"]["id"],
        "by-name and by-id should return the same credential ID"
    );
    assert_eq!(
        body_name["data"]["name"], body_id["data"]["name"],
        "by-name and by-id should return the same name"
    );
    assert_eq!(
        body_name["data"]["service"], body_id["data"]["service"],
        "by-name and by-id should return the same service"
    );
}

// ===========================================================================
// 1C. Error Handling — Server-Side
// ===========================================================================

#[tokio::test]
async fn test_get_credential_by_name_special_chars() {
    let ctx = TestAppBuilder::new().build().await;
    let (cookie, csrf) = setup_admin(&ctx.app, &*ctx.store).await;

    // Path traversal attempt — should not cause a 500
    let (status, _body) = send_json(
        &ctx.app,
        Method::GET,
        "/api/v1/credentials/by-name/my-cred%2F..%2F..%2Fetc",
        None,
        Some(&cookie),
        Some(&csrf),
        None,
    )
    .await;

    assert!(
        status == StatusCode::NOT_FOUND || status == StatusCode::BAD_REQUEST,
        "special chars should return 404 or 400, got {}",
        status
    );
}

// ===========================================================================
// 1E. Security — Policy Enforcement
// ===========================================================================

#[tokio::test]
async fn test_get_credential_by_name_requires_auth() {
    let ctx = TestAppBuilder::new().build().await;
    let (cookie, csrf) = setup_admin(&ctx.app, &*ctx.store).await;

    // Create a credential first
    create_credential_via_api(&ctx.app, &cookie, &csrf, "auth-test-cred", "svc", "secret").await;

    // Try without auth
    let (status, _body) = send_json(
        &ctx.app,
        Method::GET,
        "/api/v1/credentials/by-name/auth-test-cred",
        None,
        None,
        None,
        None,
    )
    .await;

    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "unauthenticated request should get 401"
    );
}

#[tokio::test]
async fn test_get_credential_by_name_policy_check() {
    // Use a restrictive policy that denies non-admin access to credentials
    let ctx = TestAppBuilder::new()
        .with_policy(
            r#"
            permit(
              principal is AgentCordon::User,
              action,
              resource
            ) when {
              principal.role == "admin"
            };
            "#,
        )
        .build()
        .await;
    let (cookie, csrf) = setup_admin(&ctx.app, &*ctx.store).await;

    // Create credential as admin
    create_credential_via_api(&ctx.app, &cookie, &csrf, "policy-cred", "svc", "secret").await;

    // Create a viewer user
    create_user_in_db(
        &*ctx.store,
        "proxy-viewer",
        TEST_PASSWORD,
        UserRole::Viewer,
        false,
        true,
    )
    .await;
    let viewer_cookie = login_user_combined(&ctx.app, "proxy-viewer", TEST_PASSWORD).await;
    let viewer_csrf = extract_csrf_from_cookie(&viewer_cookie).unwrap();

    // Viewer should be denied
    let (status, _body) = send_json(
        &ctx.app,
        Method::GET,
        "/api/v1/credentials/by-name/policy-cred",
        None,
        Some(&viewer_cookie),
        Some(&viewer_csrf),
        None,
    )
    .await;

    // Cedar-filtered by-name returns 404 (not 403) to avoid revealing
    // credential existence to unauthorized users.
    assert!(
        status == StatusCode::NOT_FOUND || status == StatusCode::FORBIDDEN,
        "viewer should be denied: got {status}"
    );
}
