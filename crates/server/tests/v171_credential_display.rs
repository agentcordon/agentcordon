//! v1.7.1 — Credential Display Tests (Feature #3)
//!
//! Tests that the `expired` flag on credential API responses is computed correctly:
//! - Credentials without `expires_at` should NOT be marked expired.
//! - Credentials with a future `expires_at` should NOT be marked expired.
//! - Credentials with a past `expires_at` SHOULD be marked expired.
//!
//! Bug: server was setting `expired: true` for credentials with no expiration date.

use axum::http::{Method, StatusCode};
use serde_json::json;

use agent_cordon_core::domain::user::UserRole;
use agent_cordon_server::test_helpers::TestAppBuilder;

use crate::common::*;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async fn setup_admin(
    app: &axum::Router,
    store: &(dyn agent_cordon_core::storage::Store + Send + Sync),
) -> (String, String) {
    create_user_in_db(
        store,
        "cred-display-admin",
        TEST_PASSWORD,
        UserRole::Admin,
        false,
        true,
    )
    .await;
    let cookie = login_user_combined(app, "cred-display-admin", TEST_PASSWORD).await;
    let csrf = extract_csrf_from_cookie(&cookie).unwrap();
    (cookie, csrf)
}

async fn create_credential(
    app: &axum::Router,
    cookie: &str,
    csrf: &str,
    name: &str,
    expires_at: Option<&str>,
) -> serde_json::Value {
    let mut payload = json!({
        "name": name,
        "service": "test-service",
        "secret_value": "test-secret-value",
    });
    if let Some(exp) = expires_at {
        payload["expires_at"] = json!(exp);
    }
    let (status, body) = send_json(
        app,
        Method::POST,
        "/api/v1/credentials",
        None,
        Some(cookie),
        Some(csrf),
        Some(payload),
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

// ===========================================================================
// 3A. Happy Path
// ===========================================================================

/// Test #1: Credential with no `expires_at` should NOT be marked expired.
#[tokio::test]
async fn test_credential_without_expiry_not_expired() {
    let ctx = TestAppBuilder::new().build().await;
    let (cookie, csrf) = setup_admin(&ctx.app, &*ctx.store).await;

    let body = create_credential(&ctx.app, &cookie, &csrf, "no-expiry-cred", None).await;
    let cred_id = body["data"]["id"].as_str().expect("credential id");

    // GET the credential
    let (status, body) = send_json(
        &ctx.app,
        Method::GET,
        &format!("/api/v1/credentials/{}", cred_id),
        None,
        Some(&cookie),
        Some(&csrf),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::OK, "get credential: {}", body);
    // expired should be false (or absent) for credentials with no expiry
    let expired = body["data"]["expired"].as_bool().unwrap_or(false);
    assert!(
        !expired,
        "credential without expires_at should NOT be marked expired"
    );
}

/// Test #2: Credential with future `expires_at` should NOT be marked expired.
#[tokio::test]
async fn test_credential_with_future_expiry_not_expired() {
    let ctx = TestAppBuilder::new().build().await;
    let (cookie, csrf) = setup_admin(&ctx.app, &*ctx.store).await;

    let future = (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339();
    let body = create_credential(
        &ctx.app,
        &cookie,
        &csrf,
        "future-expiry-cred",
        Some(&future),
    )
    .await;
    let cred_id = body["data"]["id"].as_str().expect("credential id");

    let (status, body) = send_json(
        &ctx.app,
        Method::GET,
        &format!("/api/v1/credentials/{}", cred_id),
        None,
        Some(&cookie),
        Some(&csrf),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::OK, "get credential: {}", body);
    let expired = body["data"]["expired"].as_bool().unwrap_or(false);
    assert!(
        !expired,
        "credential with future expires_at should NOT be marked expired"
    );
}

/// Test #3: Credential with past `expires_at` SHOULD be marked expired.
#[tokio::test]
async fn test_credential_with_past_expiry_is_expired() {
    let ctx = TestAppBuilder::new().build().await;
    let (cookie, csrf) = setup_admin(&ctx.app, &*ctx.store).await;

    let past = (chrono::Utc::now() - chrono::Duration::hours(1)).to_rfc3339();
    let body = create_credential(&ctx.app, &cookie, &csrf, "past-expiry-cred", Some(&past)).await;
    let cred_id = body["data"]["id"].as_str().expect("credential id");

    let (status, body) = send_json(
        &ctx.app,
        Method::GET,
        &format!("/api/v1/credentials/{}", cred_id),
        None,
        Some(&cookie),
        Some(&csrf),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::OK, "get credential: {}", body);
    let expired = body["data"]["expired"].as_bool().unwrap_or(false);
    assert!(
        expired,
        "credential with past expires_at SHOULD be marked expired"
    );
}

// ===========================================================================
// 3B. Edge Cases
// ===========================================================================

/// Test #4: Credential with `expires_at` = now (boundary). Should not crash.
#[tokio::test]
async fn test_credential_expiry_boundary() {
    let ctx = TestAppBuilder::new().build().await;
    let (cookie, csrf) = setup_admin(&ctx.app, &*ctx.store).await;

    let now = chrono::Utc::now().to_rfc3339();
    let body = create_credential(&ctx.app, &cookie, &csrf, "boundary-cred", Some(&now)).await;
    let cred_id = body["data"]["id"].as_str().expect("credential id");

    let (status, body) = send_json(
        &ctx.app,
        Method::GET,
        &format!("/api/v1/credentials/{}", cred_id),
        None,
        Some(&cookie),
        Some(&csrf),
        None,
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "get credential at boundary: {}",
        body
    );
    // Just assert it returns a boolean and doesn't crash
    assert!(
        body["data"]["expired"].is_boolean(),
        "expired field should be a boolean at boundary, got: {:?}",
        body["data"]["expired"]
    );
}

/// Test #5: List endpoint with mixed expiry states. Only past-expiry should be expired.
#[tokio::test]
async fn test_credential_list_mixed_expiry() {
    let ctx = TestAppBuilder::new().build().await;
    let (cookie, csrf) = setup_admin(&ctx.app, &*ctx.store).await;

    // Create 3 credentials with different expiry states
    let future = (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339();
    let past = (chrono::Utc::now() - chrono::Duration::hours(1)).to_rfc3339();

    create_credential(&ctx.app, &cookie, &csrf, "mix-no-expiry", None).await;
    create_credential(&ctx.app, &cookie, &csrf, "mix-future-expiry", Some(&future)).await;
    create_credential(&ctx.app, &cookie, &csrf, "mix-past-expiry", Some(&past)).await;

    // GET list
    let (status, body) = send_json(
        &ctx.app,
        Method::GET,
        "/api/v1/credentials",
        None,
        Some(&cookie),
        Some(&csrf),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::OK, "list credentials: {}", body);

    let creds = body["data"].as_array().expect("data should be an array");
    assert!(
        creds.len() >= 3,
        "should have at least 3 credentials, got {}",
        creds.len()
    );

    for cred in creds {
        let name = cred["name"].as_str().unwrap_or("");
        let expired = cred["expired"].as_bool().unwrap_or(false);
        match name {
            "mix-no-expiry" => assert!(!expired, "no-expiry cred should not be expired"),
            "mix-future-expiry" => assert!(!expired, "future-expiry cred should not be expired"),
            "mix-past-expiry" => assert!(expired, "past-expiry cred SHOULD be expired"),
            _ => {} // ignore other credentials
        }
    }
}
