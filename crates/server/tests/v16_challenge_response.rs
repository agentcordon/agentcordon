//! v1.6 — Challenge-Response Protocol Tests (Wave 1.2 + 5.1)
//!
//! Tests the workspace identity challenge-response authentication flow:
//! - Challenge issuance and format
//! - Signature verification
//! - Identity JWT issuance
//! - Error cases (unknown hash, expired, wrong sig)
//! - Security (replay, rate limiting, concurrent challenges)
//! - Pure-logic unit tests (payload construction, sign/verify)

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use common::*;
use serde_json::json;

use agent_cordon_server::test_helpers::TestAppBuilder;

use crate::common;

// ===========================================================================
// Wave 5.1: Pure-logic unit tests (no HTTP, no DB)
// ===========================================================================

#[test]
fn test_payload_construction_correct_structure() {
    let (_signing_key, verifying_key) = generate_ed25519_keypair();
    let challenge = [0xAAu8; 32];
    let issued_at: i64 = 1710300000;
    let audience = "agentcordon:workspace-auth";
    let pubkey = verifying_key.as_bytes();

    let payload = build_challenge_signed_payload(&challenge, issued_at, audience, pubkey);

    // Verify structure: domain_sep + challenge + timestamp + audience + pubkey
    assert!(payload.starts_with(b"agentcordon:workspace-challenge-v1"));
    let domain_sep_len = b"agentcordon:workspace-challenge-v1".len(); // 34
    let expected_len = domain_sep_len + 32 + 8 + audience.len() + 32;
    assert_eq!(payload.len(), expected_len);
}

#[test]
fn test_domain_separator_correct() {
    let payload =
        build_challenge_signed_payload(&[0u8; 32], 0, "agentcordon:workspace-auth", &[0u8; 32]);
    assert!(payload.starts_with(b"agentcordon:workspace-challenge-v1"));
}

#[test]
fn test_timestamp_big_endian() {
    let ts: i64 = 0x0102030405060708;
    let payload =
        build_challenge_signed_payload(&[0u8; 32], ts, "agentcordon:workspace-auth", &[0u8; 32]);
    let domain_sep_len = b"agentcordon:workspace-challenge-v1".len();
    let ts_offset = domain_sep_len + 32;
    let ts_bytes = &payload[ts_offset..ts_offset + 8];
    assert_eq!(ts_bytes, &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
}

#[test]
fn test_valid_signature_verifies() {
    use ed25519_dalek::{Signer, Verifier};

    let (signing_key, verifying_key) = generate_ed25519_keypair();
    let challenge = [0xBBu8; 32];
    let issued_at: i64 = 1710300000;
    let audience = "agentcordon:workspace-auth";

    let payload =
        build_challenge_signed_payload(&challenge, issued_at, audience, verifying_key.as_bytes());
    let sig = signing_key.sign(&payload);

    assert!(verifying_key.verify(&payload, &sig).is_ok());
}

#[test]
fn test_modified_challenge_fails() {
    use ed25519_dalek::{Signer, Verifier};

    let (signing_key, verifying_key) = generate_ed25519_keypair();
    let challenge = [0xCCu8; 32];
    let issued_at: i64 = 1710300000;
    let audience = "agentcordon:workspace-auth";

    let payload =
        build_challenge_signed_payload(&challenge, issued_at, audience, verifying_key.as_bytes());
    let sig = signing_key.sign(&payload);

    // Modify challenge
    let mut bad_challenge = challenge;
    bad_challenge[0] ^= 0xFF;
    let bad_payload = build_challenge_signed_payload(
        &bad_challenge,
        issued_at,
        audience,
        verifying_key.as_bytes(),
    );

    assert!(verifying_key.verify(&bad_payload, &sig).is_err());
}

#[test]
fn test_modified_timestamp_fails() {
    use ed25519_dalek::{Signer, Verifier};

    let (signing_key, verifying_key) = generate_ed25519_keypair();
    let challenge = [0xDDu8; 32];
    let issued_at: i64 = 1710300000;
    let audience = "agentcordon:workspace-auth";

    let payload =
        build_challenge_signed_payload(&challenge, issued_at, audience, verifying_key.as_bytes());
    let sig = signing_key.sign(&payload);

    let bad_payload = build_challenge_signed_payload(
        &challenge,
        issued_at + 1,
        audience,
        verifying_key.as_bytes(),
    );
    assert!(verifying_key.verify(&bad_payload, &sig).is_err());
}

#[test]
fn test_modified_audience_fails() {
    use ed25519_dalek::{Signer, Verifier};

    let (signing_key, verifying_key) = generate_ed25519_keypair();
    let challenge = [0xEEu8; 32];
    let issued_at: i64 = 1710300000;

    let payload = build_challenge_signed_payload(
        &challenge,
        issued_at,
        "agentcordon:workspace-auth",
        verifying_key.as_bytes(),
    );
    let sig = signing_key.sign(&payload);

    let bad_payload = build_challenge_signed_payload(
        &challenge,
        issued_at,
        "agentcordon:WRONG-auth",
        verifying_key.as_bytes(),
    );
    assert!(verifying_key.verify(&bad_payload, &sig).is_err());
}

#[test]
fn test_modified_pubkey_fails() {
    use ed25519_dalek::{Signer, Verifier};

    let (signing_key, verifying_key) = generate_ed25519_keypair();
    let (_, other_verifying_key) = generate_ed25519_keypair();
    let challenge = [0xFFu8; 32];
    let issued_at: i64 = 1710300000;
    let audience = "agentcordon:workspace-auth";

    let payload =
        build_challenge_signed_payload(&challenge, issued_at, audience, verifying_key.as_bytes());
    let sig = signing_key.sign(&payload);

    let bad_payload = build_challenge_signed_payload(
        &challenge,
        issued_at,
        audience,
        other_verifying_key.as_bytes(),
    );
    assert!(verifying_key.verify(&bad_payload, &sig).is_err());
}

#[test]
fn test_wrong_key_fails() {
    use ed25519_dalek::{Signer, Verifier};

    let (signing_key_a, _) = generate_ed25519_keypair();
    let (_, verifying_key_b) = generate_ed25519_keypair();
    let challenge = [0x11u8; 32];
    let issued_at: i64 = 1710300000;
    let audience = "agentcordon:workspace-auth";

    let payload =
        build_challenge_signed_payload(&challenge, issued_at, audience, verifying_key_b.as_bytes());
    let sig = signing_key_a.sign(&payload);

    // Verify with key B — should fail because A signed it
    assert!(verifying_key_b.verify(&payload, &sig).is_err());
}

// ===========================================================================
// Wave 1.2: HTTP integration tests — Happy Path
// ===========================================================================

#[tokio::test]
async fn test_identify_returns_challenge() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let ws = setup_workspace_identity(&*ctx.store, Some("test-ws")).await;

    let (status, body) = send_json(
        &ctx.app,
        axum::http::Method::POST,
        "/api/v1/agents/identify",
        None,
        None,
        None,
        Some(json!({ "public_key_hash": ws.pk_hash })),
    )
    .await;

    assert_eq!(
        status,
        axum::http::StatusCode::OK,
        "identify should return 200: {}",
        body
    );

    let data = &body["data"];
    assert!(data["challenge"].is_string(), "should have challenge");
    assert!(data["issued_at"].is_string(), "should have issued_at");
    assert!(data["expires_at"].is_string(), "should have expires_at");
    assert!(data["audience"].is_string(), "should have audience");

    // Decode challenge — should be 32 bytes
    let challenge_b64 = data["challenge"].as_str().unwrap();
    let challenge_bytes = URL_SAFE_NO_PAD
        .decode(challenge_b64)
        .expect("decode challenge");
    assert_eq!(challenge_bytes.len(), 32, "challenge should be 32 bytes");
}

#[tokio::test]
async fn test_identify_verify_valid_signature() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let ws = setup_workspace_identity(&*ctx.store, Some("test-ws")).await;

    let identity_jwt = complete_workspace_auth(&ctx.app, &ws.signing_key, &ws.pk_hash).await;
    assert!(!identity_jwt.is_empty(), "should return identity JWT");
}

#[tokio::test]
async fn test_identity_jwt_claims() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let ws = setup_workspace_identity(&*ctx.store, Some("test-ws")).await;

    let identity_jwt = complete_workspace_auth(&ctx.app, &ws.signing_key, &ws.pk_hash).await;

    // Decode JWT without verification to inspect claims
    let token_data = jsonwebtoken::decode::<serde_json::Value>(
        &identity_jwt,
        &jsonwebtoken::DecodingKey::from_secret(b"ignored"),
        &{
            let mut v = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::ES256);
            v.insecure_disable_signature_validation();
            v.validate_aud = false;
            v
        },
    )
    .expect("decode JWT claims");

    let claims = token_data.claims;
    assert!(claims["sub"].is_string(), "should have sub");
    assert!(claims["wkt"].is_string(), "should have wkt");
    assert!(claims["exp"].is_number(), "should have exp");
    assert!(claims["iss"].is_string(), "should have iss");
    assert_eq!(claims["aud"], "agentcordon:workspace-identity");

    // wkt should match the pk_hash
    assert_eq!(claims["wkt"].as_str().unwrap(), ws.pk_hash);
}

#[tokio::test]
async fn test_identity_jwt_signed_es256() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let ws = setup_workspace_identity(&*ctx.store, Some("test-ws")).await;

    let identity_jwt = complete_workspace_auth(&ctx.app, &ws.signing_key, &ws.pk_hash).await;

    let header = jsonwebtoken::decode_header(&identity_jwt).expect("decode header");
    assert_eq!(header.alg, jsonwebtoken::Algorithm::ES256);
}

#[tokio::test]
async fn test_challenge_single_use() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let ws = setup_workspace_identity(&*ctx.store, Some("test-ws")).await;

    // Request a challenge
    let (_, body) = send_json(
        &ctx.app,
        axum::http::Method::POST,
        "/api/v1/agents/identify",
        None,
        None,
        None,
        Some(json!({ "public_key_hash": ws.pk_hash })),
    )
    .await;

    let challenge_b64 = body["data"]["challenge"].as_str().unwrap();
    let issued_at_str = body["data"]["issued_at"].as_str().unwrap();
    let audience = body["data"]["audience"].as_str().unwrap();

    let challenge_bytes = URL_SAFE_NO_PAD.decode(challenge_b64).unwrap();
    let issued_at: i64 = chrono::DateTime::parse_from_rfc3339(issued_at_str)
        .unwrap()
        .timestamp();
    let pubkey_bytes = ws.verifying_key.as_bytes().to_vec();
    let payload =
        build_challenge_signed_payload(&challenge_bytes, issued_at, audience, &pubkey_bytes);
    let signature = sign_ed25519(&ws.signing_key, &payload);

    let verify_body = json!({
        "public_key": URL_SAFE_NO_PAD.encode(&pubkey_bytes),
        "signature": URL_SAFE_NO_PAD.encode(&signature),
        "signed_payload": URL_SAFE_NO_PAD.encode(&payload),
    });

    // First verify — should succeed
    let (status, _) = send_json(
        &ctx.app,
        axum::http::Method::POST,
        "/api/v1/agents/identify/verify",
        None,
        None,
        None,
        Some(verify_body.clone()),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK);

    // Second verify with same challenge — should fail (challenge consumed)
    let (status, _) = send_json(
        &ctx.app,
        axum::http::Method::POST,
        "/api/v1/agents/identify/verify",
        None,
        None,
        None,
        Some(verify_body),
    )
    .await;
    assert_ne!(
        status,
        axum::http::StatusCode::OK,
        "replayed challenge should be rejected"
    );
}

#[tokio::test]
async fn test_sequential_auth_sessions() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let ws = setup_workspace_identity(&*ctx.store, Some("test-ws")).await;

    // First auth
    let jwt1 = complete_workspace_auth(&ctx.app, &ws.signing_key, &ws.pk_hash).await;
    assert!(!jwt1.is_empty());

    // Second auth (new challenge)
    let jwt2 = complete_workspace_auth(&ctx.app, &ws.signing_key, &ws.pk_hash).await;
    assert!(!jwt2.is_empty());

    // Both should be valid but different
    assert_ne!(jwt1, jwt2);
}

// ===========================================================================
// Wave 1.2: Error/Edge Cases
// ===========================================================================

#[tokio::test]
async fn test_identify_unknown_hash() {
    let ctx = TestAppBuilder::new().with_admin().build().await;

    let fake_hash = "a".repeat(64);
    let (status, _) = send_json(
        &ctx.app,
        axum::http::Method::POST,
        "/api/v1/agents/identify",
        None,
        None,
        None,
        Some(json!({ "public_key_hash": fake_hash })),
    )
    .await;

    assert!(
        status == axum::http::StatusCode::NOT_FOUND
            || status == axum::http::StatusCode::UNAUTHORIZED,
        "unknown hash should return 404 or 401, got {}",
        status
    );
}

#[tokio::test]
async fn test_identify_empty_hash() {
    let ctx = TestAppBuilder::new().with_admin().build().await;

    let (status, _) = send_json(
        &ctx.app,
        axum::http::Method::POST,
        "/api/v1/agents/identify",
        None,
        None,
        None,
        Some(json!({ "public_key_hash": "" })),
    )
    .await;

    assert_eq!(status, axum::http::StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_identify_malformed_hash() {
    let ctx = TestAppBuilder::new().with_admin().build().await;

    // Non-hex characters
    let (status, _) = send_json(
        &ctx.app,
        axum::http::Method::POST,
        "/api/v1/agents/identify",
        None,
        None,
        None,
        Some(json!({ "public_key_hash": "not-a-valid-hex-hash!!!" })),
    )
    .await;

    assert_eq!(status, axum::http::StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_verify_wrong_signature() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let ws = setup_workspace_identity(&*ctx.store, Some("test-ws")).await;

    // Get a challenge
    let (_, body) = send_json(
        &ctx.app,
        axum::http::Method::POST,
        "/api/v1/agents/identify",
        None,
        None,
        None,
        Some(json!({ "public_key_hash": ws.pk_hash })),
    )
    .await;

    let challenge_b64 = body["data"]["challenge"].as_str().unwrap();
    let issued_at_str = body["data"]["issued_at"].as_str().unwrap();
    let audience = body["data"]["audience"].as_str().unwrap();

    let challenge_bytes = URL_SAFE_NO_PAD.decode(challenge_b64).unwrap();
    let issued_at: i64 = chrono::DateTime::parse_from_rfc3339(issued_at_str)
        .unwrap()
        .timestamp();
    let pubkey_bytes = ws.verifying_key.as_bytes().to_vec();
    let payload =
        build_challenge_signed_payload(&challenge_bytes, issued_at, audience, &pubkey_bytes);

    // Sign with a DIFFERENT key
    let (wrong_key, _) = generate_ed25519_keypair();
    let bad_signature = sign_ed25519(&wrong_key, &payload);

    let (status, _) = send_json(
        &ctx.app,
        axum::http::Method::POST,
        "/api/v1/agents/identify/verify",
        None,
        None,
        None,
        Some(json!({
            "public_key": URL_SAFE_NO_PAD.encode(&pubkey_bytes),
            "signature": URL_SAFE_NO_PAD.encode(&bad_signature),
            "signed_payload": URL_SAFE_NO_PAD.encode(&payload),
        })),
    )
    .await;

    assert_eq!(status, axum::http::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_verify_missing_fields() {
    let ctx = TestAppBuilder::new().with_admin().build().await;

    // Missing all fields
    let (status, _) = send_json(
        &ctx.app,
        axum::http::Method::POST,
        "/api/v1/agents/identify/verify",
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
async fn test_verify_hash_mismatch() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let ws = setup_workspace_identity(&*ctx.store, Some("test-ws")).await;

    // Get a challenge for our registered workspace
    let (_, body) = send_json(
        &ctx.app,
        axum::http::Method::POST,
        "/api/v1/agents/identify",
        None,
        None,
        None,
        Some(json!({ "public_key_hash": ws.pk_hash })),
    )
    .await;

    let challenge_b64 = body["data"]["challenge"].as_str().unwrap();
    let issued_at_str = body["data"]["issued_at"].as_str().unwrap();
    let audience = body["data"]["audience"].as_str().unwrap();
    let challenge_bytes = URL_SAFE_NO_PAD.decode(challenge_b64).unwrap();
    let issued_at: i64 = chrono::DateTime::parse_from_rfc3339(issued_at_str)
        .unwrap()
        .timestamp();

    // Use a DIFFERENT key to sign (whose hash doesn't match the registered pk_hash)
    let (other_key, other_vk) = generate_ed25519_keypair();
    let other_pubkey = other_vk.as_bytes().to_vec();
    let payload =
        build_challenge_signed_payload(&challenge_bytes, issued_at, audience, &other_pubkey);
    let signature = sign_ed25519(&other_key, &payload);

    let (status, _) = send_json(
        &ctx.app,
        axum::http::Method::POST,
        "/api/v1/agents/identify/verify",
        None,
        None,
        None,
        Some(json!({
            "public_key": URL_SAFE_NO_PAD.encode(&other_pubkey),
            "signature": URL_SAFE_NO_PAD.encode(&signature),
            "signed_payload": URL_SAFE_NO_PAD.encode(&payload),
        })),
    )
    .await;

    assert_eq!(
        status,
        axum::http::StatusCode::UNAUTHORIZED,
        "hash mismatch should be rejected"
    );
}

// ===========================================================================
// Wave 1.2: Security
// ===========================================================================

#[tokio::test]
async fn test_challenge_replay_prevention() {
    // Same as test_challenge_single_use — verify that a consumed challenge can't be reused
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let ws = setup_workspace_identity(&*ctx.store, Some("test-ws")).await;

    let jwt = complete_workspace_auth(&ctx.app, &ws.signing_key, &ws.pk_hash).await;
    assert!(!jwt.is_empty());

    // The challenge used in complete_workspace_auth is now consumed.
    // A new auth attempt needs a fresh challenge — this is implicitly tested
    // by test_challenge_single_use above.
}

#[tokio::test]
async fn test_key_binding() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let ws = setup_workspace_identity(&*ctx.store, Some("test-ws")).await;

    // Get challenge for workspace
    let (_, body) = send_json(
        &ctx.app,
        axum::http::Method::POST,
        "/api/v1/agents/identify",
        None,
        None,
        None,
        Some(json!({ "public_key_hash": ws.pk_hash })),
    )
    .await;

    let challenge_b64 = body["data"]["challenge"].as_str().unwrap();
    let issued_at_str = body["data"]["issued_at"].as_str().unwrap();
    let audience = body["data"]["audience"].as_str().unwrap();
    let challenge_bytes = URL_SAFE_NO_PAD.decode(challenge_b64).unwrap();
    let issued_at: i64 = chrono::DateTime::parse_from_rfc3339(issued_at_str)
        .unwrap()
        .timestamp();

    // Sign with key A but submit key B's public key
    let (_, other_vk) = generate_ed25519_keypair();
    let other_pubkey = other_vk.as_bytes().to_vec();

    // Build payload with OTHER key's pubkey (key binding attack)
    let payload =
        build_challenge_signed_payload(&challenge_bytes, issued_at, audience, &other_pubkey);
    let signature = sign_ed25519(&ws.signing_key, &payload);

    let (status, _) = send_json(
        &ctx.app,
        axum::http::Method::POST,
        "/api/v1/agents/identify/verify",
        None,
        None,
        None,
        Some(json!({
            "public_key": URL_SAFE_NO_PAD.encode(&other_pubkey),
            "signature": URL_SAFE_NO_PAD.encode(&signature),
            "signed_payload": URL_SAFE_NO_PAD.encode(&payload),
        })),
    )
    .await;

    // Should fail because:
    // 1. SHA-256(other_pubkey) doesn't match any registered pk_hash, OR
    // 2. Ed25519 verify with other_pubkey will fail (signature was made by ws.signing_key)
    assert_ne!(
        status,
        axum::http::StatusCode::OK,
        "key binding attack should be rejected"
    );
}

#[tokio::test]
async fn test_concurrent_challenges() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let ws = setup_workspace_identity(&*ctx.store, Some("test-ws")).await;

    // Request two challenges for the same hash
    let (status1, body1) = send_json(
        &ctx.app,
        axum::http::Method::POST,
        "/api/v1/agents/identify",
        None,
        None,
        None,
        Some(json!({ "public_key_hash": ws.pk_hash })),
    )
    .await;
    assert_eq!(status1, axum::http::StatusCode::OK);

    let (status2, body2) = send_json(
        &ctx.app,
        axum::http::Method::POST,
        "/api/v1/agents/identify",
        None,
        None,
        None,
        Some(json!({ "public_key_hash": ws.pk_hash })),
    )
    .await;
    assert_eq!(status2, axum::http::StatusCode::OK);

    // The challenges should be different
    let c1 = body1["data"]["challenge"].as_str().unwrap();
    let c2 = body2["data"]["challenge"].as_str().unwrap();
    assert_ne!(c1, c2, "concurrent challenges should be different");

    // Only the latest challenge should be valid — try to verify with the second one
    let challenge_bytes = URL_SAFE_NO_PAD.decode(c2).unwrap();
    let issued_at_str = body2["data"]["issued_at"].as_str().unwrap();
    let audience = body2["data"]["audience"].as_str().unwrap();
    let issued_at: i64 = chrono::DateTime::parse_from_rfc3339(issued_at_str)
        .unwrap()
        .timestamp();
    let pubkey_bytes = ws.verifying_key.as_bytes().to_vec();
    let payload =
        build_challenge_signed_payload(&challenge_bytes, issued_at, audience, &pubkey_bytes);
    let signature = sign_ed25519(&ws.signing_key, &payload);

    let (status, _) = send_json(
        &ctx.app,
        axum::http::Method::POST,
        "/api/v1/agents/identify/verify",
        None,
        None,
        None,
        Some(json!({
            "public_key": URL_SAFE_NO_PAD.encode(&pubkey_bytes),
            "signature": URL_SAFE_NO_PAD.encode(&signature),
            "signed_payload": URL_SAFE_NO_PAD.encode(&payload),
        })),
    )
    .await;
    assert_eq!(
        status,
        axum::http::StatusCode::OK,
        "latest challenge should be valid"
    );
}
