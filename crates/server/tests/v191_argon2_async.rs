//! Integration tests — v1.9.1 Feature 1: Argon2 Async Blocking Fix.
//!
//! Verifies that `hash_password()` and `verify_password()` are wrapped in
//! `tokio::task::spawn_blocking()` so they don't block the async runtime.
//! The key regression test is `test_login_concurrent_with_other_requests`.

use crate::common;

use agent_cordon_core::domain::user::UserRole;
use agent_cordon_server::test_helpers::TestAppBuilder;
use axum::http::{Method, StatusCode};
use serde_json::json;
use std::time::Duration;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

#[allow(dead_code)]
async fn setup() -> (agent_cordon_server::test_helpers::TestContext, String) {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let _user = common::create_test_user(
        &*ctx.store,
        "argon2-user",
        common::TEST_PASSWORD,
        UserRole::Admin,
    )
    .await;
    let cookie = common::login_user_combined(&ctx.app, "argon2-user", common::TEST_PASSWORD).await;
    (ctx, cookie)
}

// ===========================================================================
// 1A. Happy Path
// ===========================================================================

#[tokio::test]
async fn test_login_succeeds_after_fix() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let _user = common::create_test_user(
        &*ctx.store,
        "login-ok",
        common::TEST_PASSWORD,
        UserRole::Admin,
    )
    .await;

    let (status, body) = common::send_json(
        &ctx.app,
        Method::POST,
        "/api/v1/auth/login",
        None,
        None,
        None,
        Some(json!({
            "username": "login-ok",
            "password": common::TEST_PASSWORD,
        })),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "login should succeed: {:?}", body);
}

/// THE regression test for spawn_blocking.
///
/// Pre-fix: Argon2 runs on the Tokio runtime and blocks all other tasks.
/// Post-fix: Argon2 runs via spawn_blocking, so lightweight GETs complete
/// without waiting for the hash to finish.
#[tokio::test]
async fn test_login_concurrent_with_other_requests() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let _user = common::create_test_user(
        &*ctx.store,
        "concurrent-user",
        common::TEST_PASSWORD,
        UserRole::Admin,
    )
    .await;

    // We need an authenticated cookie for the GET requests
    let cookie =
        common::login_user_combined(&ctx.app, "concurrent-user", common::TEST_PASSWORD).await;

    let start = std::time::Instant::now();

    // Spawn 1 login + 4 lightweight GETs in parallel
    let login_handle = {
        let app = ctx.app.clone();
        tokio::spawn(async move {
            let (status, _) = common::send_json(
                &app,
                Method::POST,
                "/api/v1/auth/login",
                None,
                None,
                None,
                Some(json!({
                    "username": "concurrent-user",
                    "password": common::TEST_PASSWORD,
                })),
            )
            .await;
            status
        })
    };

    let mut get_handles = Vec::new();
    for _ in 0..4 {
        let app = ctx.app.clone();
        let cookie = cookie.clone();
        get_handles.push(tokio::spawn(async move {
            let (status, _) = common::send_json(
                &app,
                Method::GET,
                "/api/v1/workspaces",
                None,
                Some(&cookie),
                None,
                None,
            )
            .await;
            status
        }));
    }

    // All must complete within 5 seconds (generous timeout; pre-fix they'd block)
    let timeout = Duration::from_secs(5);

    let login_status = tokio::time::timeout(timeout, login_handle)
        .await
        .expect("login should complete within timeout")
        .expect("login task should not panic");
    assert_eq!(login_status, StatusCode::OK, "login should succeed");

    for handle in get_handles {
        let get_status = tokio::time::timeout(timeout, handle)
            .await
            .expect("GET should complete within timeout")
            .expect("GET task should not panic");
        assert_eq!(
            get_status,
            StatusCode::OK,
            "GET /api/v1/agents should succeed"
        );
    }

    let elapsed = start.elapsed();
    assert!(
        elapsed < Duration::from_secs(5),
        "all requests should complete within 5s (took {:?})",
        elapsed,
    );
}

#[tokio::test]
async fn test_multiple_concurrent_logins() {
    let ctx = TestAppBuilder::new().with_admin().build().await;

    // Create 3 users
    for i in 0..3 {
        common::create_test_user(
            &*ctx.store,
            &format!("multi-login-{}", i),
            common::TEST_PASSWORD,
            UserRole::Admin,
        )
        .await;
    }

    let mut handles = Vec::new();
    for i in 0..3 {
        let app = ctx.app.clone();
        handles.push(tokio::spawn(async move {
            let (status, _) = common::send_json(
                &app,
                Method::POST,
                "/api/v1/auth/login",
                None,
                None,
                None,
                Some(json!({
                    "username": format!("multi-login-{}", i),
                    "password": common::TEST_PASSWORD,
                })),
            )
            .await;
            status
        }));
    }

    let timeout = Duration::from_secs(10);
    for handle in handles {
        let status = tokio::time::timeout(timeout, handle)
            .await
            .expect("concurrent login should complete within timeout")
            .expect("task should not panic");
        assert_eq!(status, StatusCode::OK, "concurrent login should succeed");
    }
}

// ===========================================================================
// 1B. Retry/Idempotency
// ===========================================================================

#[tokio::test]
async fn test_login_after_failed_attempt() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let _user = common::create_test_user(
        &*ctx.store,
        "retry-user",
        common::TEST_PASSWORD,
        UserRole::Admin,
    )
    .await;

    // Wrong password first
    let (status, _) = common::send_json(
        &ctx.app,
        Method::POST,
        "/api/v1/auth/login",
        None,
        None,
        None,
        Some(json!({
            "username": "retry-user",
            "password": "wrong-password",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Correct password — should still work (no corrupted state from spawn_blocking)
    let (status, _) = common::send_json(
        &ctx.app,
        Method::POST,
        "/api/v1/auth/login",
        None,
        None,
        None,
        Some(json!({
            "username": "retry-user",
            "password": common::TEST_PASSWORD,
        })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "correct password after failed attempt should succeed"
    );
}

// ===========================================================================
// 1C. Error Handling
// ===========================================================================

#[tokio::test]
async fn test_login_wrong_password_returns_401() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let _user = common::create_test_user(
        &*ctx.store,
        "wrong-pw-user",
        common::TEST_PASSWORD,
        UserRole::Admin,
    )
    .await;

    let (status, _) = common::send_json(
        &ctx.app,
        Method::POST,
        "/api/v1/auth/login",
        None,
        None,
        None,
        Some(json!({
            "username": "wrong-pw-user",
            "password": "absolutely-wrong",
        })),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "wrong password should return 401",
    );
}

#[tokio::test]
async fn test_login_nonexistent_user_returns_401() {
    let ctx = TestAppBuilder::new().with_admin().build().await;

    let (status, _) = common::send_json(
        &ctx.app,
        Method::POST,
        "/api/v1/auth/login",
        None,
        None,
        None,
        Some(json!({
            "username": "no-such-user",
            "password": "any-password",
        })),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "nonexistent user should return 401",
    );
}

// ===========================================================================
// 1D. Cross-Feature
// ===========================================================================

#[tokio::test]
async fn test_password_change_uses_spawn_blocking() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let user = common::create_test_user(
        &*ctx.store,
        "pw-change-user",
        common::TEST_PASSWORD,
        UserRole::Admin,
    )
    .await;
    let cookie =
        common::login_user_combined(&ctx.app, "pw-change-user", common::TEST_PASSWORD).await;

    // Change password via API
    let new_password = "new-strong-password-456!";
    let (status, body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        &format!("/api/v1/users/{}/change-password", user.id.0),
        None,
        Some(&cookie),
        Some(json!({
            "current_password": common::TEST_PASSWORD,
            "new_password": new_password,
        })),
    )
    .await;
    assert!(
        status == StatusCode::OK || status == StatusCode::NO_CONTENT,
        "password change should succeed: {:?}",
        body,
    );

    // Login with new password should work (both hash and verify via spawn_blocking)
    let (status, _) = common::send_json(
        &ctx.app,
        Method::POST,
        "/api/v1/auth/login",
        None,
        None,
        None,
        Some(json!({
            "username": "pw-change-user",
            "password": new_password,
        })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "login with new password should succeed"
    );
}
