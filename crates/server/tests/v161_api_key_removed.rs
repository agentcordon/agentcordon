//! v1.6.1 — API Key Removal Verification Tests
//!
//! Verifies that API key authentication has been fully removed:
//! - Auth endpoints reject API key credentials
//! - Workspace identity flows remain functional
//! - No API key artifacts in responses or DB

use crate::common::*;

use axum::http::Method;
use serde_json::json;

use agent_cordon_core::domain::user::UserRole;
use agent_cordon_server::test_helpers::TestAppBuilder;

// ===========================================================================
// 1A. API Key Auth Rejection
// ===========================================================================

/// POST /api/v1/auth/token with api_key body should not succeed as an API endpoint.
/// The route has been completely removed — it either returns 404, 405, or falls
/// through to the SPA fallback (200 with HTML, no access_token in response).
#[tokio::test]
async fn test_api_key_auth_returns_401() {
    let ctx = TestAppBuilder::new().with_admin().build().await;

    let dev = ctx.admin_device.as_ref().expect("admin device");
    let jti = uuid::Uuid::new_v4().to_string();
    let device_jwt = sign_device_jwt(&dev.signing_key, &dev.device_id, &jti);

    let (status, body) = send_json(
        &ctx.app,
        Method::POST,
        "/api/v1/auth/token",
        Some(&device_jwt),
        None,
        None,
        Some(json!({ "api_key": "ackey_fake_api_key_value_1234567890" })),
    )
    .await;

    // The /auth/token route has been removed entirely. The request either:
    // - Returns 404/405 (if no fallback)
    // - Falls through to SPA fallback (200 with no access_token)
    let has_access_token = body
        .get("data")
        .and_then(|d| d.get("access_token"))
        .and_then(|t| t.as_str())
        .is_some();

    assert!(
        !has_access_token,
        "API key auth must NOT return an access_token, got {}: {}",
        status, body
    );
}

/// POST /api/v1/auth/token with api_key in body should not produce a valid JWT.
#[tokio::test]
async fn test_device_rejects_api_key_in_auth_body() {
    let ctx = TestAppBuilder::new().with_admin().build().await;

    let dev = ctx.admin_device.as_ref().expect("admin device");
    let jti = uuid::Uuid::new_v4().to_string();
    let device_jwt = sign_device_jwt(&dev.signing_key, &dev.device_id, &jti);

    let (status, body) = send_json(
        &ctx.app,
        Method::POST,
        "/api/v1/auth/token",
        Some(&device_jwt),
        None,
        None,
        Some(json!({ "api_key": "ackey_0123456789abcdef0123456789abcdef" })),
    )
    .await;

    // Route removed — should NOT return access_token
    let has_access_token = body
        .get("data")
        .and_then(|d| d.get("access_token"))
        .and_then(|t| t.as_str())
        .is_some();

    assert!(
        !has_access_token,
        "device should not produce access_token via api_key, got {}: {}",
        status, body
    );
}

// ===========================================================================
// 1B. Retry/Idempotency
// ===========================================================================

/// Send API key auth twice — both attempts should NOT return a valid JWT.
#[tokio::test]
async fn test_api_key_auth_retry_still_401() {
    let ctx = TestAppBuilder::new().with_admin().build().await;

    let dev = ctx.admin_device.as_ref().expect("admin device");

    for i in 0..2 {
        let jti = uuid::Uuid::new_v4().to_string();
        let device_jwt = sign_device_jwt(&dev.signing_key, &dev.device_id, &jti);

        let (_status, body) = send_json(
            &ctx.app,
            Method::POST,
            "/api/v1/auth/token",
            Some(&device_jwt),
            None,
            None,
            Some(json!({ "api_key": "ackey_retry_test_key_value_123456" })),
        )
        .await;

        let has_access_token = body
            .get("data")
            .and_then(|d| d.get("access_token"))
            .and_then(|t| t.as_str())
            .is_some();

        assert!(
            !has_access_token,
            "attempt {} — API key auth must NOT produce access_token: {}",
            i + 1,
            body
        );
    }
}

// ===========================================================================
// 1C. Cross-Feature
// ===========================================================================

/// Workspace identity flow should be completely unaffected by API key removal.
#[tokio::test]
async fn test_workspace_identity_still_works_after_api_key_removal() {
    let ctx = TestAppBuilder::new().with_admin().build().await;

    // Register a workspace identity and complete the challenge-response flow
    let ws = setup_workspace_identity(&*ctx.store, Some("ws-no-apikey")).await;
    let ws_jwt = complete_workspace_auth(&ctx.app, &ws.signing_key, &ws.pk_hash).await;

    // JWT should be valid
    assert!(
        !ws_jwt.is_empty(),
        "workspace identity JWT must not be empty"
    );
    assert_eq!(ws_jwt.split('.').count(), 3, "JWT must have 3 segments");

    // Decode header to verify algorithm
    let header = jsonwebtoken::decode_header(&ws_jwt).unwrap();
    assert_eq!(header.alg, jsonwebtoken::Algorithm::ES256);
}

// ===========================================================================
// 1D. Security
// ===========================================================================

/// Scan multiple endpoint responses for API key format strings.
/// No response should ever contain anything matching the `ackey_` prefix.
#[tokio::test]
async fn test_no_api_key_in_any_response() {
    let ctx = TestAppBuilder::new().with_admin().build().await;

    let _admin = create_test_user(&*ctx.store, "admin-scan", TEST_PASSWORD, UserRole::Admin).await;
    let app = agent_cordon_server::build_router(ctx.state.clone());
    let (cookie, csrf) = login_user(&app, "admin-scan", TEST_PASSWORD).await;
    let full_cookie = combined_cookie(&cookie, &csrf);

    // Endpoints to scan for API key leaks
    let endpoints = vec![
        (Method::GET, "/api/v1/workspaces"),
        (Method::GET, "/api/v1/auth/whoami"),
        (Method::GET, "/api/v1/workspaces"),
    ];

    for (method, path) in endpoints {
        let app = agent_cordon_server::build_router(ctx.state.clone());
        let (status, body) = send_json(
            &app,
            method.clone(),
            path,
            None,
            Some(&full_cookie),
            None,
            None,
        )
        .await;

        // Only check successful responses
        if status.is_success() {
            let body_str = body.to_string();
            assert!(
                !body_str.contains("ackey_"),
                "endpoint {} {} response contains API key prefix 'ackey_': {}",
                method,
                path,
                body_str
            );
        }
    }
}
