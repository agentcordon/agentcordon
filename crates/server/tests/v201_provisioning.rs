//! v2.0.1 — Provisioning token (CI/CD workspace enrollment) integration tests.
//!
//! Tests the provisioning token flow: admin creates a token via
//! `POST /api/v1/workspaces/provision`, unauthenticated client redeems via
//! `POST /api/v1/workspaces/provision/complete`.

use axum::http::{Method, StatusCode};
use serde_json::{json, Value};

use crate::common::*;
use agent_cordon_server::test_helpers::TestAppBuilder;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Set up an admin user, login, and return (combined_cookie, csrf_token).
async fn admin_login(ctx: &agent_cordon_server::test_helpers::TestContext) -> (String, String) {
    let _user = create_user_in_db(
        &*ctx.store,
        "prov-admin",
        TEST_PASSWORD,
        agent_cordon_core::domain::user::UserRole::Admin,
        true,
        true,
    )
    .await;
    let cookie = login_user_combined(&ctx.app, "prov-admin", TEST_PASSWORD).await;
    let csrf = extract_csrf_from_cookie(&cookie).unwrap();
    (cookie, csrf)
}

/// Create a provisioning token via admin API. Returns the raw token string.
async fn create_provisioning_token(
    app: &axum::Router,
    cookie: &str,
    csrf: &str,
    name: &str,
) -> String {
    let (status, body) = send_json(
        app,
        Method::POST,
        "/api/v1/workspaces/provision",
        None,
        Some(cookie),
        Some(csrf),
        Some(json!({ "name": name })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "create provisioning token: {body}");
    body["data"]["token"]
        .as_str()
        .expect("token in response")
        .to_string()
}

/// Complete provisioning with a token and Ed25519 public key hex.
/// Returns (status, body).
async fn complete_provisioning(
    app: &axum::Router,
    token: &str,
    pubkey_hex: &str,
    name: &str,
) -> (StatusCode, Value) {
    send_json(
        app,
        Method::POST,
        "/api/v1/workspaces/provision/complete",
        None,
        None,
        None,
        Some(json!({
            "token": token,
            "public_key": pubkey_hex,
            "name": name,
        })),
    )
    .await
}

// ===========================================================================
// Tests
// ===========================================================================

#[tokio::test]
async fn test_provision_happy_path() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let (cookie, csrf) = admin_login(&ctx).await;

    // Admin creates provisioning token
    let token = create_provisioning_token(&ctx.app, &cookie, &csrf, "ci-workspace").await;
    assert!(!token.is_empty(), "token should not be empty");

    // Unauthenticated client redeems token with Ed25519 pubkey
    let (_signing_key, verifying_key) = generate_ed25519_keypair();
    let pubkey_hex = hex::encode(verifying_key.as_bytes());

    let (status, body) = complete_provisioning(&ctx.app, &token, &pubkey_hex, "ci-workspace").await;
    assert_eq!(status, StatusCode::OK, "complete provisioning: {body}");

    let workspace_id = body["data"]["workspace_id"]
        .as_str()
        .expect("workspace_id in response");
    let identity_jwt = body["data"]["identity_jwt"]
        .as_str()
        .expect("identity_jwt in response");
    assert!(!workspace_id.is_empty());
    assert!(!identity_jwt.is_empty());

    // Verify workspace exists in store
    let ws_id = agent_cordon_core::domain::workspace::WorkspaceId(
        uuid::Uuid::parse_str(workspace_id).expect("parse UUID"),
    );
    let ws = ctx
        .store
        .get_workspace(&ws_id)
        .await
        .expect("get workspace")
        .expect("workspace should exist");
    assert_eq!(ws.name, "ci-workspace");
    assert_eq!(
        ws.status,
        agent_cordon_core::domain::workspace::WorkspaceStatus::Active
    );
}

#[tokio::test]
async fn test_provision_expired_token() {
    use agent_cordon_core::domain::workspace::{hash_provisioning_token, ProvisioningToken};

    let ctx = TestAppBuilder::new().with_admin().build().await;

    // Create a token directly in the store with expired timestamp
    let raw_token = "expired-test-token-abc123";
    let token_hash = hash_provisioning_token(raw_token);
    let now = chrono::Utc::now();
    let token = ProvisioningToken {
        token_hash,
        name: "expired-ws".to_string(),
        expires_at: now - chrono::Duration::hours(1), // expired
        used: false,
        created_at: now - chrono::Duration::hours(2),
    };
    ctx.store
        .create_provisioning_token(&token)
        .await
        .expect("create expired token");

    let (_sk, vk) = generate_ed25519_keypair();
    let pubkey_hex = hex::encode(vk.as_bytes());

    let (status, _body) =
        complete_provisioning(&ctx.app, raw_token, &pubkey_hex, "expired-ws").await;
    assert_eq!(status, StatusCode::GONE, "expired token should return 410");
}

#[tokio::test]
async fn test_provision_replay_rejected() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let (cookie, csrf) = admin_login(&ctx).await;

    let token = create_provisioning_token(&ctx.app, &cookie, &csrf, "replay-ws").await;

    // First redemption — success
    let (_sk1, vk1) = generate_ed25519_keypair();
    let (status1, _) =
        complete_provisioning(&ctx.app, &token, &hex::encode(vk1.as_bytes()), "replay-ws").await;
    assert_eq!(status1, StatusCode::OK, "first redemption should succeed");

    // Second redemption — must be rejected
    let (_sk2, vk2) = generate_ed25519_keypair();
    let (status2, _) = complete_provisioning(
        &ctx.app,
        &token,
        &hex::encode(vk2.as_bytes()),
        "replay-ws-2",
    )
    .await;
    assert_eq!(
        status2,
        StatusCode::CONFLICT,
        "replay should return 409 Conflict"
    );
}

#[tokio::test]
async fn test_provision_invalid_token() {
    let ctx = TestAppBuilder::new().with_admin().build().await;

    let (_sk, vk) = generate_ed25519_keypair();
    let pubkey_hex = hex::encode(vk.as_bytes());

    let (status, _body) = complete_provisioning(
        &ctx.app,
        "0000000000000000deadbeef",
        &pubkey_hex,
        "invalid-ws",
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "invalid token should return 401"
    );
}

#[tokio::test]
async fn test_provision_name_validation() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let (cookie, csrf) = admin_login(&ctx).await;

    // Empty name
    let (status_empty, _) = send_json(
        &ctx.app,
        Method::POST,
        "/api/v1/workspaces/provision",
        None,
        Some(&cookie),
        Some(&csrf),
        Some(json!({ "name": "" })),
    )
    .await;
    assert_eq!(
        status_empty,
        StatusCode::BAD_REQUEST,
        "empty name should be rejected"
    );

    // Name too long (129 chars)
    let long_name = "a".repeat(129);
    let (status_long, _) = send_json(
        &ctx.app,
        Method::POST,
        "/api/v1/workspaces/provision",
        None,
        Some(&cookie),
        Some(&csrf),
        Some(json!({ "name": long_name })),
    )
    .await;
    assert_eq!(
        status_long,
        StatusCode::BAD_REQUEST,
        "129-char name should be rejected"
    );
}

#[tokio::test]
async fn test_provision_requires_auth() {
    let ctx = TestAppBuilder::new().with_admin().build().await;

    // Attempt to create provisioning token without session cookie
    let (status, _body) = send_json(
        &ctx.app,
        Method::POST,
        "/api/v1/workspaces/provision",
        None,
        None,
        None,
        Some(json!({ "name": "unauth-ws" })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "no-auth should return 401"
    );
}
