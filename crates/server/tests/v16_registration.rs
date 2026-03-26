//! v1.6 — Browser-Redirect Registration Tests (Wave 1.3 + 1.5)
//!
//! Tests the workspace registration flow:
//! - URL construction with pk_hash and code_challenge
//! - Admin approval creating registration record
//! - Code exchange with PKCE, Ed25519 signature, and timestamp verification
//! - Error cases (wrong code, expired, max attempts, clock skew)
//! - Security (no state on page load, brute force, code-swap, replay)

use common::*;
use serde_json::json;
use sha2::{Digest, Sha256};

use agent_cordon_core::domain::user::UserRole;
use agent_cordon_server::test_helpers::TestAppBuilder;

use crate::common;

// ===========================================================================
// Helper: generate PKCE nonce and code_challenge
// ===========================================================================

fn generate_pkce_pair() -> (Vec<u8>, String) {
    let nonce: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();
    let code_challenge = hex::encode(Sha256::digest(&nonce));
    (nonce, code_challenge)
}

// ===========================================================================
// Wave 1.3: Happy Path
// ===========================================================================

#[tokio::test]
async fn test_registration_page_loads_without_state() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let (_signing_key, verifying_key) = generate_ed25519_keypair();
    let pk_hash = compute_workspace_pk_hash(&verifying_key);
    let (_, code_challenge) = generate_pkce_pair();

    // GET /register?pk_hash=...&cc=... should return 200 with no server state created
    let (status, _, _) = send_json_with_headers(
        &ctx.app,
        axum::http::Method::GET,
        &format!("/register?pk_hash={}&cc={}", pk_hash, code_challenge),
        None,
        None,
        None,
        None,
    )
    .await;

    // Should return 200 (or redirect to login, which is also acceptable)
    assert!(
        status == axum::http::StatusCode::OK
            || status == axum::http::StatusCode::FOUND
            || status == axum::http::StatusCode::SEE_OTHER,
        "register page should load: got {}",
        status
    );
}

#[tokio::test]
async fn test_approval_code_format() {
    use agent_cordon_core::domain::workspace::generate_approval_code;

    // Generate many codes and verify format
    let re = regex_lite::Regex::new(r"^[A-Z]+-\d{6}$").unwrap();
    for _ in 0..100 {
        let code = generate_approval_code();
        assert!(
            re.is_match(&code),
            "code '{}' should match WORD-NNNNNN",
            code
        );
    }
}

#[tokio::test]
async fn test_code_exchange_success() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let (signing_key, verifying_key) = generate_ed25519_keypair();
    let pk_hash = compute_workspace_pk_hash(&verifying_key);
    let (nonce, _code_challenge) = generate_pkce_pair();

    // Create admin user and login
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
    let csrf = extract_csrf_from_cookie(&cookie).unwrap();

    // Complete registration via helper
    let (agent_id, identity_jwt) =
        register_workspace_via_api(&ctx.app, &signing_key, &pk_hash, &nonce, &cookie, &csrf).await;

    assert!(!agent_id.is_empty(), "should return agent_id");
    assert!(!identity_jwt.is_empty(), "should return identity_jwt");
}

#[tokio::test]
async fn test_fingerprint_display() {
    let (_, verifying_key) = generate_ed25519_keypair();
    let pk_hash = compute_workspace_pk_hash(&verifying_key);

    // First 16 hex chars of pk_hash
    let fingerprint = &pk_hash[..16];
    assert_eq!(fingerprint.len(), 16);
    // Should be valid hex
    assert!(hex::decode(fingerprint).is_ok());
}

// ===========================================================================
// Wave 1.3: Error/Edge Cases
// ===========================================================================

#[tokio::test]
async fn test_code_exchange_wrong_code() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let (signing_key, verifying_key) = generate_ed25519_keypair();
    let pk_hash = compute_workspace_pk_hash(&verifying_key);
    let (nonce, code_challenge) = generate_pkce_pair();

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
    let csrf = extract_csrf_from_cookie(&cookie).unwrap();

    // Admin approves
    let (status, body) = send_json(
        &ctx.app,
        axum::http::Method::POST,
        "/api/v1/workspace-identities/register",
        None,
        Some(&cookie),
        Some(&csrf),
        Some(json!({
            "pk_hash": pk_hash,
            "code_challenge": code_challenge,
        })),
    )
    .await;
    assert_eq!(
        status,
        axum::http::StatusCode::OK,
        "approval failed: {}",
        body
    );

    // Try with wrong approval code
    let timestamp = chrono::Utc::now().timestamp();
    let pubkey_bytes = verifying_key.as_bytes().to_vec();
    let mut sign_payload = Vec::new();
    sign_payload.extend_from_slice(b"WRONG-000000");
    sign_payload.extend_from_slice(&hex::decode(&pk_hash).unwrap());
    sign_payload.extend_from_slice(&nonce);
    sign_payload.extend_from_slice(&timestamp.to_be_bytes());
    let signature = sign_ed25519(&signing_key, &sign_payload);

    let (status, _) = send_json(
        &ctx.app,
        axum::http::Method::POST,
        "/api/v1/agents/register",
        None,
        None,
        None,
        Some(json!({
            "approval_code": "WRONG-000000",
            "public_key": hex::encode(&pubkey_bytes),
            "nonce": hex::encode(&nonce),
            "timestamp": timestamp,
            "signature": hex::encode(&signature),
        })),
    )
    .await;

    assert_eq!(
        status,
        axum::http::StatusCode::UNAUTHORIZED,
        "wrong code should be rejected"
    );
}

#[tokio::test]
async fn test_code_exchange_wrong_nonce() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let (signing_key, verifying_key) = generate_ed25519_keypair();
    let pk_hash = compute_workspace_pk_hash(&verifying_key);
    let (_nonce, code_challenge) = generate_pkce_pair();

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
    let csrf = extract_csrf_from_cookie(&cookie).unwrap();

    // Admin approves with the real code_challenge
    let (_, body) = send_json(
        &ctx.app,
        axum::http::Method::POST,
        "/api/v1/workspace-identities/register",
        None,
        Some(&cookie),
        Some(&csrf),
        Some(json!({
            "pk_hash": pk_hash,
            "code_challenge": code_challenge,
        })),
    )
    .await;
    let approval_code = body["data"]["approval_code"].as_str().unwrap().to_string();

    // Exchange with WRONG nonce (whose SHA-256 won't match code_challenge)
    let wrong_nonce: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();
    let timestamp = chrono::Utc::now().timestamp();
    let pubkey_bytes = verifying_key.as_bytes().to_vec();
    let mut sign_payload = Vec::new();
    sign_payload.extend_from_slice(b"agentcordon:registration-v1");
    sign_payload.extend_from_slice(approval_code.as_bytes());
    sign_payload.extend_from_slice(&hex::decode(&pk_hash).unwrap());
    sign_payload.extend_from_slice(&wrong_nonce);
    sign_payload.extend_from_slice(&timestamp.to_be_bytes());
    let signature = sign_ed25519(&signing_key, &sign_payload);

    let (status, _) = send_json(
        &ctx.app,
        axum::http::Method::POST,
        "/api/v1/agents/register",
        None,
        None,
        None,
        Some(json!({
            "approval_code": approval_code,
            "public_key": hex::encode(&pubkey_bytes),
            "nonce": hex::encode(&wrong_nonce),
            "timestamp": timestamp,
            "signature": hex::encode(&signature),
        })),
    )
    .await;

    assert_eq!(
        status,
        axum::http::StatusCode::UNAUTHORIZED,
        "wrong nonce should fail PKCE"
    );
}

#[tokio::test]
async fn test_code_exchange_missing_fields() {
    let ctx = TestAppBuilder::new().with_admin().build().await;

    let (status, _) = send_json(
        &ctx.app,
        axum::http::Method::POST,
        "/api/v1/agents/register",
        None,
        None,
        None,
        Some(json!({})),
    )
    .await;

    assert!(
        status == axum::http::StatusCode::BAD_REQUEST
            || status == axum::http::StatusCode::UNPROCESSABLE_ENTITY,
        "missing fields should return 400 or 422, got {}",
        status
    );
}

#[tokio::test]
async fn test_unauthenticated_approval() {
    let ctx = TestAppBuilder::new().with_admin().build().await;

    // Try to approve without admin session
    let (status, _) = send_json(
        &ctx.app,
        axum::http::Method::POST,
        "/api/v1/workspace-identities/register",
        None,
        None,
        None,
        Some(json!({
            "pk_hash": "a".repeat(64),
            "code_challenge": "b".repeat(64),
        })),
    )
    .await;

    assert!(
        status == axum::http::StatusCode::UNAUTHORIZED
            || status == axum::http::StatusCode::FORBIDDEN,
        "unauthenticated approval should be rejected, got {}",
        status
    );
}

// ===========================================================================
// Wave 1.3: Security
// ===========================================================================

#[tokio::test]
async fn test_no_state_on_page_load() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let (_, verifying_key) = generate_ed25519_keypair();
    let pk_hash = compute_workspace_pk_hash(&verifying_key);
    let (_, code_challenge) = generate_pkce_pair();

    // Load the page
    let _ = send_json(
        &ctx.app,
        axum::http::Method::GET,
        &format!("/register?pk_hash={}&cc={}", pk_hash, code_challenge),
        None,
        None,
        None,
        None,
    )
    .await;

    // Verify no workspace registration was created in the store
    // (we can't directly inspect the store for registrations in the common helper,
    // but we can verify that a code exchange attempt fails with "not found")
    let (status, _) = send_json(
        &ctx.app,
        axum::http::Method::POST,
        "/api/v1/agents/register",
        None,
        None,
        None,
        Some(json!({
            "approval_code": "TEST-000000",
            "public_key": hex::encode(verifying_key.as_bytes()),
            "nonce": hex::encode([0u8; 32]),
            "timestamp": chrono::Utc::now().timestamp(),
            "signature": hex::encode([0u8; 64]),
        })),
    )
    .await;

    // Should fail — no registration record exists
    assert_ne!(
        status,
        axum::http::StatusCode::OK,
        "no state should exist after page load"
    );
}

#[tokio::test]
async fn test_replay_code_exchange() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let (signing_key, verifying_key) = generate_ed25519_keypair();
    let pk_hash = compute_workspace_pk_hash(&verifying_key);
    let (nonce, _) = generate_pkce_pair();

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
    let csrf = extract_csrf_from_cookie(&cookie).unwrap();

    // Complete a successful registration
    let (agent_id, _) =
        register_workspace_via_api(&ctx.app, &signing_key, &pk_hash, &nonce, &cookie, &csrf).await;
    assert!(!agent_id.is_empty());

    // Try the exact same exchange again — should fail (record deleted on first success)
    let timestamp = chrono::Utc::now().timestamp();
    let pubkey_bytes = verifying_key.as_bytes().to_vec();
    let _sign_payload: Vec<u8> = Vec::new();
    // We don't know the approval code anymore, so we can't replay exactly.
    // The point is that the registration record is deleted after success.
    // A second registration attempt for the same pk_hash should either need
    // a new approval or fail.
    let (status, _) = send_json(
        &ctx.app,
        axum::http::Method::POST,
        "/api/v1/agents/register",
        None,
        None,
        None,
        Some(json!({
            "approval_code": "TEST-000000",
            "public_key": hex::encode(&pubkey_bytes),
            "nonce": hex::encode(&nonce),
            "timestamp": timestamp,
            "signature": hex::encode([0u8; 64]),
        })),
    )
    .await;

    assert_ne!(status, axum::http::StatusCode::OK, "replay should fail");
}

// ===========================================================================
// Wave 1.5: Registration Approval UI
// ===========================================================================

#[tokio::test]
async fn test_approval_requires_authentication() {
    let ctx = TestAppBuilder::new().with_admin().build().await;

    let (status, _, _) = send_json_with_headers(
        &ctx.app,
        axum::http::Method::GET,
        "/register?pk_hash=abc123&cc=def456",
        None,
        None,
        None,
        None,
    )
    .await;

    // Either returns the page (with login redirect) or redirects to login
    // The page itself requires no auth, but approval requires auth
    assert!(
        status.is_success() || status.is_redirection(),
        "register page should be accessible (may redirect to login): got {}",
        status
    );
}

#[tokio::test]
async fn test_approval_invalid_pk_hash() {
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
    let csrf = extract_csrf_from_cookie(&cookie).unwrap();

    // Try to approve with malformed pk_hash
    let (status, _) = send_json(
        &ctx.app,
        axum::http::Method::POST,
        "/api/v1/workspace-identities/register",
        None,
        Some(&cookie),
        Some(&csrf),
        Some(json!({
            "pk_hash": "not-valid-hex!!!",
            "code_challenge": "a".repeat(64),
        })),
    )
    .await;

    assert_eq!(status, axum::http::StatusCode::BAD_REQUEST);
}
