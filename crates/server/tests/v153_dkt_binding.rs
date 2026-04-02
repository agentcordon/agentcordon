//! v1.5.3 DKT (Device Key Thumbprint) Binding Tests
//!
//! Tests for cryptographic agent-device binding via the `dkt` claim
//! (RFC 7638 JWK thumbprint of the device's P-256 signing key).
//!
//! The `dkt` claim is embedded in agent JWTs issued for device-bound agents
//! and validated when those JWTs are presented through the MCP proxy.

use crate::common::*;

use serde_json::Value;

use agent_cordon_core::auth::jwt::{base64_url_encode, compute_p256_thumbprint};
use agent_cordon_core::domain::user::UserRole;

use agent_cordon_server::test_helpers::TestAppBuilder;

const TEST_PASSWORD: &str = "strong-test-password-123!";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Decode a JWT's payload without verifying the signature.
fn decode_jwt_payload(jwt: &str) -> Value {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;

    let parts: Vec<&str> = jwt.split('.').collect();
    assert_eq!(parts.len(), 3, "JWT must have 3 parts");
    let payload_bytes = URL_SAFE_NO_PAD
        .decode(parts[1])
        .expect("base64 decode JWT payload");
    serde_json::from_slice(&payload_bytes).expect("parse JWT payload JSON")
}

/// Get a device-bound JWT: issue JWT directly for agent bound to device.
/// API key exchange has been removed in v1.6.1.
async fn get_device_bound_jwt(
    state: &agent_cordon_server::state::AppState,
    _device_key: &p256::ecdsa::SigningKey,
    device_id: &str,
    _api_key: &str,
) -> String {
    get_jwt_via_device(state, _device_key, device_id, _api_key).await
}

/// Compute the expected thumbprint from a JWK value (the signing key).
fn compute_thumbprint_from_jwk(jwk: &Value) -> String {
    let x = jwk["x"].as_str().expect("JWK must have x");
    let y = jwk["y"].as_str().expect("JWK must have y");
    compute_p256_thumbprint(x, y)
}

// ===========================================================================
// Test 1: dkt claim present in device-issued JWT
// ===========================================================================

#[tokio::test]
#[ignore = "REMOVED: v2.0 has no device endpoints — devices unified into workspaces"]
async fn test_dkt_claim_present_in_device_issued_jwt() {
    let ctx = TestAppBuilder::new()
        .with_admin()
        .build()
        .await;
    let _admin = create_test_user(&*ctx.store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let app = agent_cordon_server::build_router(ctx.state.clone());
    let (cookie, csrf) = login_user(&app, "admin", TEST_PASSWORD).await;
    let full_cookie = combined_cookie(&cookie, &csrf);

    let dac = setup_full_device_agent(&ctx.state, &full_cookie, &csrf).await;

    let payload = decode_jwt_payload(&dac.agent_jwt);
    assert!(
        payload.get("dkt").is_some(),
        "device-bound JWT must contain dkt claim"
    );
    assert!(
        !payload["dkt"].as_str().unwrap().is_empty(),
        "dkt claim must be non-empty"
    );
}

// ===========================================================================
// Test 2: dkt claim matches device signing key thumbprint
// ===========================================================================

#[tokio::test]
#[ignore = "REMOVED: v2.0 has no device endpoints — devices unified into workspaces"]
async fn test_dkt_claim_matches_device_signing_key_thumbprint() {
    let ctx = TestAppBuilder::new()
        .with_admin()
        .build()
        .await;
    let _admin = create_test_user(&*ctx.store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let app = agent_cordon_server::build_router(ctx.state.clone());
    let (cookie, csrf) = login_user(&app, "admin", TEST_PASSWORD).await;
    let full_cookie = combined_cookie(&cookie, &csrf);

    // Generate dual keypairs manually so we can compute expected thumbprint
    let (sig_key, sig_jwk, _enc_key, enc_jwk) = generate_dual_p256_keypairs_jwk();

    // Create + enroll device
    let (device_id, bootstrap_token) =
        create_device_via_api(&ctx.state, &full_cookie, &csrf, "dkt-test-device").await;
    enroll_device(&ctx.state, &bootstrap_token, &sig_jwk, &enc_jwk).await;

    // Enroll agent through device
    let (session_token, approval_ref) =
        enroll_agent_through_device(&ctx.state, &sig_key, &device_id, "dkt-test-agent").await;

    // Approve and get API key
    let (_agent_id, api_key) = approve_and_get_api_key(
        &ctx.state,
        &full_cookie,
        &csrf,
        &session_token,
        &approval_ref,
    )
    .await;

    // Get JWT through device
    let jwt = get_device_bound_jwt(&ctx.state, &sig_key, &device_id, &api_key).await;

    let payload = decode_jwt_payload(&jwt);
    let actual_dkt = payload["dkt"].as_str().expect("dkt must be present");

    // Compute expected thumbprint from the signing key JWK
    let expected_dkt = compute_thumbprint_from_jwk(&sig_jwk);

    assert_eq!(
        actual_dkt, expected_dkt,
        "dkt must match RFC 7638 thumbprint of device signing key"
    );
}

// ===========================================================================
// Test 3: dkt claim absent for direct agent JWT
// ===========================================================================

// ===========================================================================
// Test 4: dkt claim deterministic across issuances
// ===========================================================================

#[tokio::test]
#[ignore = "REMOVED: v2.0 has no device endpoints — devices unified into workspaces"]
async fn test_dkt_claim_deterministic_across_issuances() {
    let ctx = TestAppBuilder::new()
        .with_admin()
        .build()
        .await;
    let _admin = create_test_user(&*ctx.store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let app = agent_cordon_server::build_router(ctx.state.clone());
    let (cookie, csrf) = login_user(&app, "admin", TEST_PASSWORD).await;
    let full_cookie = combined_cookie(&cookie, &csrf);

    let (sig_key, sig_jwk, _enc_key, enc_jwk) = generate_dual_p256_keypairs_jwk();
    let (device_id, bootstrap_token) =
        create_device_via_api(&ctx.state, &full_cookie, &csrf, "dkt-det-device").await;
    enroll_device(&ctx.state, &bootstrap_token, &sig_jwk, &enc_jwk).await;

    let (session_token, approval_ref) =
        enroll_agent_through_device(&ctx.state, &sig_key, &device_id, "dkt-det-agent").await;
    let (_agent_id, api_key) = approve_and_get_api_key(
        &ctx.state,
        &full_cookie,
        &csrf,
        &session_token,
        &approval_ref,
    )
    .await;

    // Issue two JWTs
    let jwt1 = get_device_bound_jwt(&ctx.state, &sig_key, &device_id, &api_key).await;
    let jwt2 = get_device_bound_jwt(&ctx.state, &sig_key, &device_id, &api_key).await;

    let dkt1 = decode_jwt_payload(&jwt1)["dkt"]
        .as_str()
        .unwrap()
        .to_string();
    let dkt2 = decode_jwt_payload(&jwt2)["dkt"]
        .as_str()
        .unwrap()
        .to_string();

    assert_eq!(
        dkt1, dkt2,
        "dkt must be deterministic across issuances for same device"
    );
}

// ===========================================================================
// Test 5: dkt claim differs between devices
// ===========================================================================

#[tokio::test]
#[ignore = "REMOVED: v2.0 has no device endpoints — devices unified into workspaces"]
async fn test_dkt_claim_differs_between_devices() {
    let ctx = TestAppBuilder::new()
        .with_admin()
        .build()
        .await;
    let _admin = create_test_user(&*ctx.store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let app = agent_cordon_server::build_router(ctx.state.clone());
    let (cookie, csrf) = login_user(&app, "admin", TEST_PASSWORD).await;
    let full_cookie = combined_cookie(&cookie, &csrf);

    // Device A
    let dac_a = setup_full_device_agent(&ctx.state, &full_cookie, &csrf).await;
    let dkt_a = decode_jwt_payload(&dac_a.agent_jwt)["dkt"]
        .as_str()
        .unwrap()
        .to_string();

    // Device B — create a second device+agent
    let (sig_key_b, sig_jwk_b, _enc_key_b, enc_jwk_b) = generate_dual_p256_keypairs_jwk();
    let (device_id_b, bootstrap_token_b) =
        create_device_via_api(&ctx.state, &full_cookie, &csrf, "dkt-diff-device-b").await;
    enroll_device(&ctx.state, &bootstrap_token_b, &sig_jwk_b, &enc_jwk_b).await;

    let (session_token_b, approval_ref_b) =
        enroll_agent_through_device(&ctx.state, &sig_key_b, &device_id_b, "dkt-diff-agent-b").await;
    let (_agent_id_b, api_key_b) = approve_and_get_api_key(
        &ctx.state,
        &full_cookie,
        &csrf,
        &session_token_b,
        &approval_ref_b,
    )
    .await;
    let jwt_b = get_device_bound_jwt(&ctx.state, &sig_key_b, &device_id_b, &api_key_b).await;
    let dkt_b = decode_jwt_payload(&jwt_b)["dkt"]
        .as_str()
        .unwrap()
        .to_string();

    assert_ne!(
        dkt_a, dkt_b,
        "different devices must produce different dkt values"
    );
}

// Tests 6-7 removed — DKT validation was in the AuthenticatedAgent extractor which
// now uses workspace identity JWTs (no DKT claims). DKT generation tests (1-5) above
// remain valid as they test claim generation and thumbprint computation.

// Tests 8-9 removed — they tested direct auth paths on the now-deprecated MCP proxy endpoint.
// Direct agent auth path has been removed; all requests require dual auth via the device.

// ===========================================================================
// Test 10: RFC 7638 thumbprint canonical JSON
// ===========================================================================

#[test]
fn test_rfc7638_thumbprint_canonical_json() {
    // Use known x/y values and verify the thumbprint is computed from
    // the canonical JSON form: {"crv":"P-256","kty":"EC","x":"...","y":"..."}
    use sha2::{Digest, Sha256};

    let x = "test_x_value_base64url";
    let y = "test_y_value_base64url";

    let thumbprint = compute_p256_thumbprint(x, y);

    // Recompute manually
    let canonical = format!(r#"{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}}"#, x, y);
    let hash = Sha256::digest(canonical.as_bytes());
    let expected = base64_url_encode(&hash);

    assert_eq!(
        thumbprint, expected,
        "thumbprint must match canonical JSON hash"
    );

    // Verify alphabetical order: crv < kty < x < y
    assert!(canonical.find("crv").unwrap() < canonical.find("kty").unwrap());
    assert!(canonical.find("kty").unwrap() < canonical.find(r#""x""#).unwrap());
    assert!(canonical.find(r#""x""#).unwrap() < canonical.find(r#""y""#).unwrap());
}

// ===========================================================================
// Test 11: RFC 7638 thumbprint base64url no padding
// ===========================================================================

#[test]
fn test_rfc7638_thumbprint_base64url_no_padding() {
    // A SHA-256 hash is 32 bytes. Base64url of 32 bytes = ceil(32*4/3) = 43 chars, no padding.
    let x = "WbbaSStuffedBase64UrlEncodedXCoordinate";
    let y = "AnotherBase64UrlEncodedYCoordinateValue";

    let thumbprint = compute_p256_thumbprint(x, y);

    // SHA-256 output is 32 bytes -> base64url no padding = 43 characters
    assert_eq!(
        thumbprint.len(),
        43,
        "base64url(SHA-256) must be exactly 43 chars, got {}",
        thumbprint.len()
    );
    assert!(
        !thumbprint.contains('='),
        "base64url must not contain padding '='"
    );
    assert!(!thumbprint.contains('+'), "base64url must not contain '+'");
    assert!(!thumbprint.contains('/'), "base64url must not contain '/'");
}
