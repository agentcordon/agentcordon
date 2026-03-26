//! v1.6 — Key Rotation + Revocation Tests (Wave 3)
//!
//! Tests workspace key rotation and admin revocation:
//! - Self-service rotation (auth with old key, swap to new)
//! - Revocation (admin deletes, SSE push, device rejects)
//! - Error cases and security properties

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use common::*;
use serde_json::json;

use agent_cordon_core::domain::user::UserRole;
use agent_cordon_server::test_helpers::TestAppBuilder;

use crate::common;

// ===========================================================================
// Wave 3.1: Key Rotation — Happy Path
// ===========================================================================

#[tokio::test]
async fn test_key_rotation_success() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let ws = setup_workspace_identity(&*ctx.store, Some("rotation-ws")).await;

    // Auth with old key
    let identity_jwt = complete_workspace_auth(&ctx.app, &ws.signing_key, &ws.pk_hash).await;
    assert!(!identity_jwt.is_empty());

    // Generate new keypair
    let (new_signing_key, new_verifying_key) = generate_ed25519_keypair();
    let new_pk_hash = compute_workspace_pk_hash(&new_verifying_key);

    // Call rotation endpoint
    let (status, body) = send_json(
        &ctx.app,
        axum::http::Method::POST,
        "/api/v1/agents/identity/rotate",
        Some(&identity_jwt),
        None,
        None,
        Some(json!({
            "new_public_key": URL_SAFE_NO_PAD.encode(new_verifying_key.as_bytes()),
        })),
    )
    .await;

    assert_eq!(
        status,
        axum::http::StatusCode::OK,
        "rotation should succeed: {}",
        body
    );

    // Old key should no longer work
    let (status, _) = send_json(
        &ctx.app,
        axum::http::Method::POST,
        "/api/v1/agents/identify",
        None,
        None,
        None,
        Some(json!({ "public_key_hash": ws.pk_hash })),
    )
    .await;
    assert!(
        status != axum::http::StatusCode::OK || status == axum::http::StatusCode::NOT_FOUND,
        "old key hash should be rejected after rotation"
    );

    // New key should work
    let new_jwt = complete_workspace_auth(&ctx.app, &new_signing_key, &new_pk_hash).await;
    assert!(
        !new_jwt.is_empty(),
        "new key should authenticate successfully"
    );
}

#[tokio::test]
async fn test_key_rotation_updates_wkt() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let ws = setup_workspace_identity(&*ctx.store, Some("wkt-ws")).await;

    let identity_jwt = complete_workspace_auth(&ctx.app, &ws.signing_key, &ws.pk_hash).await;

    // Rotate key
    let (new_signing_key, new_verifying_key) = generate_ed25519_keypair();
    let new_pk_hash = compute_workspace_pk_hash(&new_verifying_key);

    let (status, _) = send_json(
        &ctx.app,
        axum::http::Method::POST,
        "/api/v1/agents/identity/rotate",
        Some(&identity_jwt),
        None,
        None,
        Some(json!({
            "new_public_key": URL_SAFE_NO_PAD.encode(new_verifying_key.as_bytes()),
        })),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK);

    // Auth with new key
    let new_jwt = complete_workspace_auth(&ctx.app, &new_signing_key, &new_pk_hash).await;

    // Decode and check wkt
    let token_data = jsonwebtoken::decode::<serde_json::Value>(
        &new_jwt,
        &jsonwebtoken::DecodingKey::from_secret(b"ignored"),
        &{
            let mut v = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::ES256);
            v.insecure_disable_signature_validation();
            v.validate_aud = false;
            v
        },
    )
    .expect("decode JWT");

    assert_eq!(
        token_data.claims["wkt"].as_str().unwrap(),
        new_pk_hash,
        "wkt should reflect new key"
    );
}

#[tokio::test]
async fn test_key_rotation_no_admin_needed() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let ws = setup_workspace_identity(&*ctx.store, Some("self-service-ws")).await;

    // Auth with workspace key (no admin session)
    let identity_jwt = complete_workspace_auth(&ctx.app, &ws.signing_key, &ws.pk_hash).await;

    let (_, new_vk) = generate_ed25519_keypair();

    // Rotation uses the identity JWT, not admin session
    let (status, _) = send_json(
        &ctx.app,
        axum::http::Method::POST,
        "/api/v1/agents/identity/rotate",
        Some(&identity_jwt),
        None,
        None,
        Some(json!({
            "new_public_key": URL_SAFE_NO_PAD.encode(new_vk.as_bytes()),
        })),
    )
    .await;

    assert_eq!(
        status,
        axum::http::StatusCode::OK,
        "rotation should not require admin"
    );
}

// ===========================================================================
// Wave 3.1: Key Rotation — Error Cases
// ===========================================================================

#[tokio::test]
async fn test_key_rotation_same_key() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let ws = setup_workspace_identity(&*ctx.store, Some("same-key-ws")).await;

    let identity_jwt = complete_workspace_auth(&ctx.app, &ws.signing_key, &ws.pk_hash).await;

    // Try to "rotate" to the same key
    let (status, _) = send_json(
        &ctx.app,
        axum::http::Method::POST,
        "/api/v1/agents/identity/rotate",
        Some(&identity_jwt),
        None,
        None,
        Some(json!({
            "new_public_key": URL_SAFE_NO_PAD.encode(ws.verifying_key.as_bytes()),
        })),
    )
    .await;

    // Should error or no-op
    assert!(
        status == axum::http::StatusCode::BAD_REQUEST || status == axum::http::StatusCode::CONFLICT,
        "rotating to same key should be rejected, got {}",
        status
    );
}

// ===========================================================================
// Wave 3.2: Revocation — Happy Path
// ===========================================================================

#[tokio::test]
async fn test_admin_revoke_workspace() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let ws = setup_workspace_identity(&*ctx.store, Some("revoke-ws")).await;

    // Verify workspace can auth
    let jwt = complete_workspace_auth(&ctx.app, &ws.signing_key, &ws.pk_hash).await;
    assert!(!jwt.is_empty());

    // Admin revokes the workspace
    create_user_in_db(
        &*ctx.store,
        "test-admin",
        TEST_PASSWORD,
        UserRole::Admin,
        false,
        true,
    )
    .await;
    let cookie = login_user_combined(&ctx.app, "test-admin", TEST_PASSWORD).await;
    let _csrf = extract_csrf_from_cookie(&cookie).unwrap();

    let (status, _) = send_json_auto_csrf(
        &ctx.app,
        axum::http::Method::DELETE,
        &format!("/api/v1/workspace-identities/{}", ws.workspace_id),
        None,
        Some(&cookie),
        None,
    )
    .await;

    assert!(
        status == axum::http::StatusCode::OK || status == axum::http::StatusCode::NO_CONTENT,
        "admin revocation should succeed, got {}",
        status
    );

    // Workspace should no longer be able to authenticate
    let (status, _) = send_json(
        &ctx.app,
        axum::http::Method::POST,
        "/api/v1/agents/identify",
        None,
        None,
        None,
        Some(json!({ "public_key_hash": ws.pk_hash })),
    )
    .await;

    assert!(
        status == axum::http::StatusCode::NOT_FOUND
            || status == axum::http::StatusCode::UNAUTHORIZED
            || status == axum::http::StatusCode::FORBIDDEN,
        "revoked workspace should not get challenges, got {}",
        status
    );
}

// ===========================================================================
// Wave 3.2: Revocation — Error Cases
// ===========================================================================

#[tokio::test]
async fn test_revoke_nonexistent_workspace() {
    let ctx = TestAppBuilder::new().with_admin().build().await;

    create_user_in_db(
        &*ctx.store,
        "test-admin",
        TEST_PASSWORD,
        UserRole::Admin,
        false,
        true,
    )
    .await;
    let cookie = login_user_combined(&ctx.app, "test-admin", TEST_PASSWORD).await;
    let _csrf = extract_csrf_from_cookie(&cookie).unwrap();

    let fake_id = uuid::Uuid::new_v4();
    let (status, _) = send_json_auto_csrf(
        &ctx.app,
        axum::http::Method::DELETE,
        &format!("/api/v1/workspace-identities/{}", fake_id),
        None,
        Some(&cookie),
        None,
    )
    .await;

    assert_eq!(status, axum::http::StatusCode::NOT_FOUND);
}

// ===========================================================================
// Wave 3.2: Revocation — Security
// ===========================================================================

#[tokio::test]
async fn test_old_key_rejected_after_rotation() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let ws = setup_workspace_identity(&*ctx.store, Some("old-key-ws")).await;

    let identity_jwt = complete_workspace_auth(&ctx.app, &ws.signing_key, &ws.pk_hash).await;

    // Rotate to new key
    let (_new_sk, new_vk) = generate_ed25519_keypair();
    let (status, _) = send_json(
        &ctx.app,
        axum::http::Method::POST,
        "/api/v1/agents/identity/rotate",
        Some(&identity_jwt),
        None,
        None,
        Some(json!({
            "new_public_key": URL_SAFE_NO_PAD.encode(new_vk.as_bytes()),
        })),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK);

    // Old key should fail
    let (status, _) = send_json(
        &ctx.app,
        axum::http::Method::POST,
        "/api/v1/agents/identify",
        None,
        None,
        None,
        Some(json!({ "public_key_hash": ws.pk_hash })),
    )
    .await;

    assert!(
        status != axum::http::StatusCode::OK,
        "old key should be rejected after rotation, got {}",
        status
    );
}
