//! v1.6.2 — Agent Name Control Tests
//!
//! Tests the `name` field in workspace identity code exchange:
//! - Name is passed through to Agent and WorkspaceIdentity
//! - Default name used when name is omitted or empty
//! - Validation (length, special chars)
//! - Name appears in identity list and audit events
//! - Name is cosmetic, not used for auth decisions

use axum::http::{Method, StatusCode};
use serde_json::json;
use sha2::{Digest, Sha256};

use agent_cordon_core::domain::user::UserRole;
use agent_cordon_core::storage::Store;
use agent_cordon_server::test_helpers::TestAppBuilder;

use crate::common::*;

// ===========================================================================
// Helper: register workspace with optional name
// ===========================================================================

/// Like `register_workspace_via_api` but includes an optional `name` field.
async fn register_workspace_with_name(
    app: &axum::Router,
    signing_key: &ed25519_dalek::SigningKey,
    pk_hash: &str,
    nonce: &[u8],
    admin_cookie: &str,
    csrf_token: &str,
    name: Option<&str>,
) -> (StatusCode, serde_json::Value) {
    let code_challenge = hex::encode(Sha256::digest(nonce));

    // Admin approves registration
    let (status, body) = send_json(
        app,
        Method::POST,
        "/api/v1/workspace-identities/register",
        None,
        Some(admin_cookie),
        Some(csrf_token),
        Some(json!({
            "pk_hash": pk_hash,
            "code_challenge": code_challenge,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "approval failed: {}", body);
    let approval_code = body["data"]["approval_code"]
        .as_str()
        .expect("approval_code")
        .to_string();

    // Build signature over (domain_separator || approval_code || pk_hash || nonce || timestamp)
    let timestamp = chrono::Utc::now().timestamp();
    let pubkey_bytes = signing_key.verifying_key().as_bytes().to_vec();

    let mut sign_payload = Vec::new();
    sign_payload.extend_from_slice(b"agentcordon:registration-v1");
    sign_payload.extend_from_slice(approval_code.as_bytes());
    sign_payload.extend_from_slice(&hex::decode(pk_hash).expect("decode pk_hash"));
    sign_payload.extend_from_slice(nonce);
    sign_payload.extend_from_slice(&timestamp.to_be_bytes());
    let signature = sign_ed25519(signing_key, &sign_payload);

    // Build request body with optional name
    let mut body_json = json!({
        "approval_code": approval_code,
        "public_key": hex::encode(&pubkey_bytes),
        "nonce": hex::encode(nonce),
        "timestamp": timestamp,
        "signature": hex::encode(&signature),
    });
    if let Some(n) = name {
        body_json["name"] = json!(n);
    }

    send_json(
        app,
        Method::POST,
        "/api/v1/agents/register",
        None,
        None,
        None,
        Some(body_json),
    )
    .await
}

/// Setup admin context: create admin user, login, return (cookie, csrf).
async fn setup_admin(app: &axum::Router, store: &(dyn Store + Send + Sync)) -> (String, String) {
    create_user_in_db(
        store,
        "test-admin",
        TEST_PASSWORD,
        UserRole::Admin,
        false,
        true,
    )
    .await;
    let cookie = login_user_combined(app, "test-admin", TEST_PASSWORD).await;
    let csrf = extract_csrf_from_cookie(&cookie).unwrap();
    (cookie, csrf)
}

// ===========================================================================
// 2A. Happy Path
// ===========================================================================

#[tokio::test]
async fn test_code_exchange_with_name() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let (cookie, csrf) = setup_admin(&ctx.app, &*ctx.store).await;

    let (signing_key, verifying_key) = generate_ed25519_keypair();
    let pk_hash = compute_workspace_pk_hash(&verifying_key);
    let nonce: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();

    let (status, body) = register_workspace_with_name(
        &ctx.app,
        &signing_key,
        &pk_hash,
        &nonce,
        &cookie,
        &csrf,
        Some("my-agent"),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "code exchange with name failed: {}",
        body
    );
    assert_eq!(body["data"]["name"].as_str(), Some("my-agent"));
    // v2.0: response may use "workspace_id" or "agent_id"
    let has_id = body["data"]["agent_id"].as_str().is_some()
        || body["data"]["workspace_id"].as_str().is_some();
    assert!(
        has_id,
        "response should have agent_id or workspace_id: {}",
        body
    );
    assert!(body["data"]["identity_jwt"].as_str().is_some());

    // Verify WorkspaceIdentity was created with name
    let identity = ctx
        .store
        .get_workspace_by_pk_hash(&pk_hash)
        .await
        .expect("query identity")
        .expect("identity should exist");
    assert_eq!(identity.name, "my-agent");
}

#[tokio::test]
async fn test_code_exchange_without_name_uses_default() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let (cookie, csrf) = setup_admin(&ctx.app, &*ctx.store).await;

    let (signing_key, verifying_key) = generate_ed25519_keypair();
    let pk_hash = compute_workspace_pk_hash(&verifying_key);
    let nonce: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();

    let (status, body) = register_workspace_with_name(
        &ctx.app,
        &signing_key,
        &pk_hash,
        &nonce,
        &cookie,
        &csrf,
        None,
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "code exchange without name failed: {}",
        body
    );

    // Default name should be workspace:<first 8 chars of pk_hash>
    let expected_default = format!("workspace:{}", &pk_hash[..8]);
    assert_eq!(
        body["data"]["name"].as_str(),
        Some(expected_default.as_str()),
        "should use default name when none provided"
    );
}

#[tokio::test]
async fn test_name_appears_in_identity_list() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let (cookie, csrf) = setup_admin(&ctx.app, &*ctx.store).await;

    let (signing_key, verifying_key) = generate_ed25519_keypair();
    let pk_hash = compute_workspace_pk_hash(&verifying_key);
    let nonce: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();

    let (status, _) = register_workspace_with_name(
        &ctx.app,
        &signing_key,
        &pk_hash,
        &nonce,
        &cookie,
        &csrf,
        Some("listed-agent"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // List workspace identities
    let (status, body) = send_json(
        &ctx.app,
        Method::GET,
        "/api/v1/workspace-identities",
        None,
        Some(&cookie),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "list identities failed: {}", body);

    let identities = body["data"]
        .as_array()
        .expect("identities should be an array");
    let found = identities
        .iter()
        .any(|i| i["name"].as_str() == Some("listed-agent"));
    assert!(
        found,
        "registered agent name should appear in identity list"
    );
}

// ===========================================================================
// 2B. Retry/Idempotency
// ===========================================================================

#[tokio::test]
async fn test_register_same_name_different_keys() {
    // FINDING: agents.name has a UNIQUE constraint in the DB schema (001_init.sql).
    // Two agents cannot share the same name. The code_exchange handler returns 500
    // when the second agent creation hits the unique constraint, rather than a
    // user-friendly 409 Conflict. This test documents the current behavior.
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let (cookie, csrf) = setup_admin(&ctx.app, &*ctx.store).await;

    // First agent
    let (signing_key1, verifying_key1) = generate_ed25519_keypair();
    let pk_hash1 = compute_workspace_pk_hash(&verifying_key1);
    let nonce1: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();

    let (status1, body1) = register_workspace_with_name(
        &ctx.app,
        &signing_key1,
        &pk_hash1,
        &nonce1,
        &cookie,
        &csrf,
        Some("shared-name"),
    )
    .await;
    assert_eq!(
        status1,
        StatusCode::OK,
        "first registration failed: {}",
        body1
    );

    // Second agent with same name, different keys — should fail due to UNIQUE constraint
    let (signing_key2, verifying_key2) = generate_ed25519_keypair();
    let pk_hash2 = compute_workspace_pk_hash(&verifying_key2);
    let nonce2: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();

    let (status2, _body2) = register_workspace_with_name(
        &ctx.app,
        &signing_key2,
        &pk_hash2,
        &nonce2,
        &cookie,
        &csrf,
        Some("shared-name"),
    )
    .await;

    // After migration 037 removed the UNIQUE constraint on agents.name,
    // duplicate names are allowed — pk_hash is the real unique key.
    assert_eq!(
        status2,
        StatusCode::OK,
        "duplicate agent names should be allowed after migration 037: got {}",
        status2
    );
}

// ===========================================================================
// 2C. Error Handling
// ===========================================================================

#[tokio::test]
async fn test_code_exchange_empty_name_treated_as_none() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let (cookie, csrf) = setup_admin(&ctx.app, &*ctx.store).await;

    let (signing_key, verifying_key) = generate_ed25519_keypair();
    let pk_hash = compute_workspace_pk_hash(&verifying_key);
    let nonce: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();

    let (status, body) = register_workspace_with_name(
        &ctx.app,
        &signing_key,
        &pk_hash,
        &nonce,
        &cookie,
        &csrf,
        Some(""), // empty name
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "empty name should succeed: {}",
        body
    );

    // Empty name should be treated as omitted → default name
    let expected_default = format!("workspace:{}", &pk_hash[..8]);
    assert_eq!(
        body["data"]["name"].as_str(),
        Some(expected_default.as_str()),
        "empty name should use default"
    );
}

#[tokio::test]
async fn test_code_exchange_name_too_long() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let (cookie, csrf) = setup_admin(&ctx.app, &*ctx.store).await;

    let (signing_key, verifying_key) = generate_ed25519_keypair();
    let pk_hash = compute_workspace_pk_hash(&verifying_key);
    let nonce: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();

    let long_name = "x".repeat(500);
    let (status, body) = register_workspace_with_name(
        &ctx.app,
        &signing_key,
        &pk_hash,
        &nonce,
        &cookie,
        &csrf,
        Some(&long_name),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "500-char name should be rejected: {}",
        body
    );
}

#[tokio::test]
async fn test_code_exchange_name_with_special_chars() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let (cookie, csrf) = setup_admin(&ctx.app, &*ctx.store).await;

    let (signing_key, verifying_key) = generate_ed25519_keypair();
    let pk_hash = compute_workspace_pk_hash(&verifying_key);
    let nonce: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();

    let xss_name = "<script>alert(1)</script>";
    let (status, body) = register_workspace_with_name(
        &ctx.app,
        &signing_key,
        &pk_hash,
        &nonce,
        &cookie,
        &csrf,
        Some(xss_name),
    )
    .await;

    // Server-side validation now rejects names with <, >, &, ", ' characters.
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "names with HTML/script chars should be rejected: {}",
        body
    );
}

// ===========================================================================
// 2D. Cross-Feature
// ===========================================================================

#[tokio::test]
async fn test_named_agent_appears_in_audit() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let (cookie, csrf) = setup_admin(&ctx.app, &*ctx.store).await;

    let (signing_key, verifying_key) = generate_ed25519_keypair();
    let pk_hash = compute_workspace_pk_hash(&verifying_key);
    let nonce: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();

    let (status, _) = register_workspace_with_name(
        &ctx.app,
        &signing_key,
        &pk_hash,
        &nonce,
        &cookie,
        &csrf,
        Some("audit-visible-agent"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Check audit events for a registration event with this pk_hash
    let events = ctx
        .store
        .list_audit_events(50, 0)
        .await
        .expect("list audit events");

    let registration_event = events.iter().find(|e| {
        e.action == "workspace_register"
            && e.metadata.get("pk_hash").and_then(|v| v.as_str()) == Some(&pk_hash)
    });

    assert!(
        registration_event.is_some(),
        "audit should contain registration event for pk_hash {}",
        pk_hash
    );
}

// ===========================================================================
// 2E. Security
// ===========================================================================

#[tokio::test]
async fn test_name_not_used_for_auth_decisions() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let (cookie, csrf) = setup_admin(&ctx.app, &*ctx.store).await;

    // Register two agents with different names but check that the auth flow
    // depends on the key, not the name.
    let (signing_key, verifying_key) = generate_ed25519_keypair();
    let pk_hash = compute_workspace_pk_hash(&verifying_key);
    let nonce: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();

    let (status, body) = register_workspace_with_name(
        &ctx.app,
        &signing_key,
        &pk_hash,
        &nonce,
        &cookie,
        &csrf,
        Some("auth-test-agent"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Verify the identity JWT doesn't contain the name in claims
    // (it should only have sub, wkt, exp, iss, aud, iat, jti)
    let jwt = body["data"]["identity_jwt"].as_str().expect("identity_jwt");
    let parts: Vec<&str> = jwt.split('.').collect();
    assert_eq!(parts.len(), 3, "JWT should have 3 parts");

    // Decode payload (base64url)
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    let payload_bytes = URL_SAFE_NO_PAD
        .decode(parts[1])
        .expect("decode JWT payload");
    let payload: serde_json::Value =
        serde_json::from_slice(&payload_bytes).expect("parse JWT payload");

    // JWT claims should not contain the name — name is cosmetic, not in auth tokens
    assert!(
        payload.get("name").is_none(),
        "agent name should NOT be in JWT claims: {:?}",
        payload
    );
    // Sub should be the agent/identity UUID, not the name
    let sub = payload["sub"].as_str().unwrap();
    assert_ne!(sub, "auth-test-agent", "sub should be UUID, not agent name");

    // Challenge-response auth should work based on the key, not the name
    let identity_jwt = complete_workspace_auth(&ctx.app, &signing_key, &pk_hash).await;
    assert!(
        !identity_jwt.is_empty(),
        "auth should succeed based on key, not name"
    );
}
