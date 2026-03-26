//! Integration tests — v1.9.2 Feature 2: Try It Button API.
//!
//! Verifies the /api/v1/try-it endpoint returns a curl command, requires auth,
//! handles missing demo data, and doesn't expose long-lived secrets.

use crate::common;

use agent_cordon_core::domain::user::UserRole;
use agent_cordon_server::test_helpers::TestAppBuilder;
use axum::http::{Method, StatusCode};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Setup with demo seed data for Try It tests.
async fn setup_with_seed() -> (agent_cordon_server::test_helpers::TestContext, String) {
    // NOTE: Do NOT use .with_admin() here — it creates an agent in the DB,
    // which causes seed_demo_data() to skip seeding (it checks list_agents().is_empty()).
    let ctx = TestAppBuilder::new()
        .with_config(|c| {
            c.seed_demo = true;
        })
        .build()
        .await;

    agent_cordon_server::seed::seed_demo_data(
        &ctx.store,
        &ctx.encryptor,
        &ctx.state.config,
        &ctx.jwt_issuer,
    )
    .await
    .expect("seed demo data");

    let _user = common::create_test_user(
        &*ctx.store,
        "tryit-user",
        common::TEST_PASSWORD,
        UserRole::Admin,
    )
    .await;
    let cookie = common::login_user_combined(&ctx.app, "tryit-user", common::TEST_PASSWORD).await;
    (ctx, cookie)
}

/// Setup WITHOUT demo seed data.
async fn setup_no_seed() -> (agent_cordon_server::test_helpers::TestContext, String) {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let _user = common::create_test_user(
        &*ctx.store,
        "tryit-noseed-user",
        common::TEST_PASSWORD,
        UserRole::Admin,
    )
    .await;
    let cookie =
        common::login_user_combined(&ctx.app, "tryit-noseed-user", common::TEST_PASSWORD).await;
    (ctx, cookie)
}

// ===========================================================================
// 2A. Happy Path
// ===========================================================================

#[tokio::test]
async fn test_try_it_endpoint_returns_curl_command() {
    let (ctx, cookie) = setup_with_seed().await;

    let (status, body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::GET,
        "/api/v1/demo/try-it",
        None,
        Some(&cookie),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "try-it endpoint: {:?}", body);

    let data = &body["data"];
    assert!(
        data["curl_command"].is_string(),
        "response should contain curl_command field, got: {:?}",
        data
    );

    let curl = data["curl_command"].as_str().unwrap();
    assert!(
        curl.contains("curl"),
        "curl_command should contain 'curl', got: {}",
        curl
    );
}

// ===========================================================================
// 2B. Retry/Idempotency
// ===========================================================================

#[tokio::test]
async fn test_try_it_endpoint_stable_across_calls() {
    let (ctx, cookie) = setup_with_seed().await;

    let (status1, body1) = common::send_json_auto_csrf(
        &ctx.app,
        Method::GET,
        "/api/v1/demo/try-it",
        None,
        Some(&cookie),
        None,
    )
    .await;

    let (status2, body2) = common::send_json_auto_csrf(
        &ctx.app,
        Method::GET,
        "/api/v1/demo/try-it",
        None,
        Some(&cookie),
        None,
    )
    .await;

    assert_eq!(status1, StatusCode::OK);
    assert_eq!(status2, StatusCode::OK);

    // Each call mints a fresh JWT, so the full command differs.
    // Verify that the structural parts (URL, method, credential name) are stable.
    let cmd1 = body1["data"]["curl_command"].as_str().unwrap_or("");
    let cmd2 = body2["data"]["curl_command"].as_str().unwrap_or("");
    assert!(
        cmd1.contains("httpbin.org"),
        "call 1 should target httpbin.org"
    );
    assert!(
        cmd2.contains("httpbin.org"),
        "call 2 should target httpbin.org"
    );
    assert_eq!(
        body1["data"]["demo_agent_name"], body2["data"]["demo_agent_name"],
        "demo_agent_name should be stable across calls"
    );
    assert_eq!(
        body1["data"]["demo_credential_name"], body2["data"]["demo_credential_name"],
        "demo_credential_name should be stable across calls"
    );
}

// ===========================================================================
// 2C. Error Handling
// ===========================================================================

#[tokio::test]
async fn test_try_it_without_demo_data() {
    let (ctx, cookie) = setup_no_seed().await;

    let (status, body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::GET,
        "/api/v1/demo/try-it",
        None,
        Some(&cookie),
        None,
    )
    .await;

    // Should return 404 or meaningful error, not 500
    assert!(
        status == StatusCode::NOT_FOUND || status == StatusCode::BAD_REQUEST,
        "try-it without demo data should return 404 or 400, got {} body={:?}",
        status,
        body
    );
}

// ===========================================================================
// 2E. Security
// ===========================================================================

#[tokio::test]
async fn test_try_it_no_long_lived_secrets() {
    let (ctx, cookie) = setup_with_seed().await;

    let (status, body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::GET,
        "/api/v1/demo/try-it",
        None,
        Some(&cookie),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let curl = body["data"]["curl_command"].as_str().unwrap_or("");

    // The curl command should NOT contain raw credential secrets.
    // It may reference the credential by name (e.g. in the proxy URL path),
    // but the actual secret value must never appear.
    assert!(
        !curl.contains("demo-token-not-real"),
        "curl command should not contain the raw credential secret value"
    );
}

#[tokio::test]
async fn test_try_it_requires_auth() {
    let ctx = TestAppBuilder::new()
        .with_config(|c| {
            c.seed_demo = true;
        })
        .build()
        .await;

    // Try without any auth
    let (status, _body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::GET,
        "/api/v1/demo/try-it",
        None,
        None, // no cookie
        None,
    )
    .await;

    assert!(
        status == StatusCode::UNAUTHORIZED
            || status == StatusCode::FORBIDDEN
            || status == StatusCode::FOUND, // redirect to login
        "try-it without auth should return 401/403/302, got {}",
        status
    );
}
