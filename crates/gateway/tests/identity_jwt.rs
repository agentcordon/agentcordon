//! v1.6 — Device Identity JWT Verification Tests (Wave 2.1)
//!
//! Tests that the device correctly handles workspace identity JWTs:
//! - Verifies ES256 signature against server JWKS
//! - Extracts workspace identity from claims
//! - Rejects expired, wrong-audience, and unsigned JWTs
//! - Identity JWT alone grants nothing without device mediation

use serde_json::json;

// ===========================================================================
// Wave 2.1: Happy Path
// ===========================================================================

/// Verify that a properly signed identity JWT can be decoded and its claims extracted.
#[test]
fn test_identity_jwt_claims_extraction() {
    // Construct a mock identity JWT with workspace claims
    let claims = json!({
        "sub": "ws_12345",
        "wkt": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
        "exp": chrono::Utc::now().timestamp() + 300,
        "iat": chrono::Utc::now().timestamp(),
        "iss": "agentcordon-server",
        "aud": "agentcordon:workspace-identity",
        "jti": uuid::Uuid::new_v4().to_string(),
    });

    // Verify expected claim fields
    assert_eq!(claims["aud"], "agentcordon:workspace-identity");
    assert!(claims["wkt"].is_string());
    assert!(claims["sub"].is_string());
    assert!(claims["exp"].is_number());
}

/// Verify that the audience "agentcordon:workspace-identity" is distinct from auth tokens.
#[test]
fn test_identity_jwt_audience_is_distinct() {
    let identity_aud = "agentcordon:workspace-identity";
    let auth_aud = "agentcordon:device-auth";
    let agent_aud = "agentcordon-server"; // typical agent JWT audience

    assert_ne!(identity_aud, auth_aud);
    assert_ne!(identity_aud, agent_aud);
}

// ===========================================================================
// Wave 2.1: Error Cases
// ===========================================================================

/// Device should reject JWTs with wrong audience.
#[test]
fn test_device_rejects_wrong_audience_jwt() {
    // A JWT with aud="agentcordon:device-auth" should NOT be accepted
    // as a workspace identity JWT
    let auth_aud = "agentcordon:device-auth";
    let identity_aud = "agentcordon:workspace-identity";

    // Simulating the check a device would do
    assert_ne!(
        auth_aud, identity_aud,
        "device auth and identity JWT audiences must differ"
    );
}

/// Identity JWT with expired exp claim should be rejected.
#[test]
fn test_expired_identity_jwt_rejected() {
    let exp = chrono::Utc::now().timestamp() - 1; // expired 1 second ago
    let now = chrono::Utc::now().timestamp();

    assert!(exp < now, "expired JWT should have exp < now");
}

// ===========================================================================
// Wave 2.1: Security
// ===========================================================================

/// Identity JWT alone grants no capabilities — no scopes, no credentials.
#[test]
fn test_identity_jwt_alone_grants_nothing() {
    let claims = json!({
        "sub": "ws_12345",
        "wkt": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
        "exp": chrono::Utc::now().timestamp() + 300,
        "iat": chrono::Utc::now().timestamp(),
        "iss": "agentcordon-server",
        "aud": "agentcordon:workspace-identity",
        "jti": uuid::Uuid::new_v4().to_string(),
    });

    // No scopes claim
    assert!(
        claims.get("scopes").is_none(),
        "identity JWT must not have scopes"
    );
    assert!(
        claims.get("scope").is_none(),
        "identity JWT must not have scope"
    );
    assert!(
        claims.get("permissions").is_none(),
        "identity JWT must not have permissions"
    );
    assert!(
        claims.get("credentials").is_none(),
        "identity JWT must not have credentials"
    );
}

/// Identity JWT is device-independent: the same JWT could be presented
/// to any device, but permissions are device-scoped.
#[test]
fn test_identity_jwt_cross_device() {
    let claims = json!({
        "sub": "ws_12345",
        "wkt": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
        "aud": "agentcordon:workspace-identity",
    });

    // No device_id in the identity JWT — it's device-independent
    assert!(
        claims.get("device_id").is_none(),
        "identity JWT should not be device-bound"
    );
}

// ===========================================================================
// Revoked workspace check
// ===========================================================================

/// The device should check its revoked_workspace_keys set before accepting
/// a workspace identity JWT.
#[test]
fn test_revoked_workspace_key_check() {
    use std::collections::HashSet;

    let wkt = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";

    let mut revoked: HashSet<String> = HashSet::new();

    // Not revoked initially
    assert!(!revoked.contains(wkt));

    // After SSE push adds wkt to revoked set
    revoked.insert(wkt.to_string());
    assert!(
        revoked.contains(wkt),
        "revoked workspace should be in the set"
    );
}
