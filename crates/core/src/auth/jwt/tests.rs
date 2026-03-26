use super::*;
use crate::crypto::key_derivation::derive_jwt_signing_keypair;

fn test_keypair() -> (SigningKey, VerifyingKey) {
    derive_jwt_signing_keypair("test-secret-for-jwt", b"test-salt-value!")
        .expect("derive test keypair")
}

fn test_issuer() -> JwtIssuer {
    let (sk, vk) = test_keypair();
    JwtIssuer::new(&sk, &vk, super::ISSUER.to_string(), 900)
}

#[test]
fn kid_is_deterministic() {
    let (sk, vk) = test_keypair();
    let issuer1 = JwtIssuer::new(&sk, &vk, super::ISSUER.to_string(), 900);
    let issuer2 = JwtIssuer::new(&sk, &vk, super::ISSUER.to_string(), 900);
    assert_eq!(issuer1.public_key.kid, issuer2.public_key.kid);
}

#[test]
fn mcp_permissions_roundtrip() {
    let issuer = test_issuer();
    let agent_id = Uuid::new_v4().to_string();
    let device_id = Uuid::new_v4().to_string();
    let scopes = vec![
        "my-device.github.create_issue".to_string(),
        "my-device.slack.*".to_string(),
    ];

    let (token, original) = issuer
        .issue_mcp_permissions_token(&agent_id, &device_id, scopes.clone(), 300)
        .unwrap();

    let validated = issuer.validate_mcp_permissions(&token).unwrap();

    assert_eq!(validated.sub, agent_id);
    assert_eq!(validated.aud, AUDIENCE_MCP_PERMISSIONS);
    assert_eq!(validated.iss, super::ISSUER);
    assert_eq!(validated.scopes, scopes);
    assert_eq!(validated.device_id, device_id);
    assert_eq!(validated.jti, original.jti);
}

#[test]
fn mcp_permissions_expired_rejected() {
    let issuer = test_issuer();
    let agent_id = Uuid::new_v4().to_string();
    let device_id = Uuid::new_v4().to_string();

    // Manually build expired claims
    let now = Utc::now();
    let claims = McpPermissionsClaims {
        iss: super::ISSUER.to_string(),
        sub: agent_id,
        aud: AUDIENCE_MCP_PERMISSIONS.to_string(),
        exp: (now - Duration::seconds(120)).timestamp(),
        iat: (now - Duration::seconds(120)).timestamp(),
        nbf: (now - Duration::seconds(120)).timestamp(),
        jti: Uuid::new_v4().to_string(),
        scopes: vec!["dev.github.*".to_string()],
        device_id,
    };

    let token = issuer.sign_custom_claims(&claims).unwrap();
    let result = issuer.validate_mcp_permissions(&token);
    assert!(
        result.is_err(),
        "expired MCP permissions token should be rejected"
    );
}

#[test]
fn mcp_permissions_wrong_audience() {
    let issuer = test_issuer();

    // Issue a workspace identity token and try to validate as MCP permissions
    let now = Utc::now();
    let claims = JwtClaims {
        iss: super::ISSUER.to_string(),
        sub: Uuid::new_v4().to_string(),
        aud: AUDIENCE_WORKSPACE_IDENTITY.to_string(),
        exp: (now + Duration::seconds(300)).timestamp(),
        iat: now.timestamp(),
        nbf: now.timestamp(),
        jti: Uuid::new_v4().to_string(),
        roles: vec!["reader".to_string()],
    };
    let token = issuer.sign_custom_claims(&claims).unwrap();
    let result = issuer.validate_mcp_permissions(&token);
    assert!(
        result.is_err(),
        "workspace identity token should be rejected as MCP permissions token"
    );
}

#[test]
fn mcp_permissions_wrong_signer() {
    let issuer = test_issuer();
    let agent_id = Uuid::new_v4().to_string();
    let device_id = Uuid::new_v4().to_string();

    let (token, _) = issuer
        .issue_mcp_permissions_token(&agent_id, &device_id, vec![], 300)
        .unwrap();

    // Validate with a different key pair
    let (sk2, vk2) = derive_jwt_signing_keypair("different-secret", b"different-salt")
        .expect("derive different keypair");
    let wrong_issuer = JwtIssuer::new(&sk2, &vk2, super::ISSUER.to_string(), 900);
    let result = wrong_issuer.validate_mcp_permissions(&token);
    assert!(
        result.is_err(),
        "token signed by different key should be rejected"
    );
}

// --- P-256 Thumbprint tests ---

#[test]
fn test_p256_thumbprint_deterministic() {
    let (_, vk) = test_keypair();
    let point = vk.to_encoded_point(false);
    let x_b64 = base64_url_encode(point.x().unwrap());
    let y_b64 = base64_url_encode(point.y().unwrap());

    let t1 = compute_p256_thumbprint(&x_b64, &y_b64);
    let t2 = compute_p256_thumbprint(&x_b64, &y_b64);
    assert_eq!(t1, t2, "same coordinates must produce the same thumbprint");
}

#[test]
fn test_p256_thumbprint_format() {
    let (_, vk) = test_keypair();
    let point = vk.to_encoded_point(false);
    let x_b64 = base64_url_encode(point.x().unwrap());
    let y_b64 = base64_url_encode(point.y().unwrap());

    let thumbprint = compute_p256_thumbprint(&x_b64, &y_b64);
    // SHA-256 = 32 bytes, base64url = ceil(32*4/3) = 43 chars (no padding)
    assert_eq!(thumbprint.len(), 43, "base64url SHA-256 must be 43 chars");
    assert!(
        !thumbprint.contains('='),
        "base64url must not contain padding"
    );
    assert!(!thumbprint.contains('+'), "base64url must not contain +");
    assert!(!thumbprint.contains('/'), "base64url must not contain /");
}

#[test]
fn test_p256_thumbprint_different_keys() {
    let (_, vk1) = derive_jwt_signing_keypair("secret-a", b"salt-a").unwrap();
    let (_, vk2) = derive_jwt_signing_keypair("secret-b", b"salt-b").unwrap();

    let p1 = vk1.to_encoded_point(false);
    let p2 = vk2.to_encoded_point(false);

    let t1 = compute_p256_thumbprint(
        &base64_url_encode(p1.x().unwrap()),
        &base64_url_encode(p1.y().unwrap()),
    );
    let t2 = compute_p256_thumbprint(
        &base64_url_encode(p2.x().unwrap()),
        &base64_url_encode(p2.y().unwrap()),
    );

    assert_ne!(t1, t2, "different keys must produce different thumbprints");
}

#[test]
fn test_p256_thumbprint_known_vector() {
    // Manually compute RFC 7638 thumbprint for a known key:
    // Build the canonical JSON, SHA-256 it, base64url encode.
    let (_, vk) = test_keypair();
    let point = vk.to_encoded_point(false);
    let x_b64 = base64_url_encode(point.x().unwrap());
    let y_b64 = base64_url_encode(point.y().unwrap());

    // Manual computation matching compute_p256_thumbprint
    let canonical_json = format!(
        r#"{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}}"#,
        x_b64, y_b64
    );
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(canonical_json.as_bytes());
    let expected = base64_url_encode(&hash);

    let actual = compute_p256_thumbprint(&x_b64, &y_b64);
    assert_eq!(
        actual, expected,
        "thumbprint must match manual RFC 7638 computation"
    );
}

// --- sign_custom_claims with ekt ---

#[test]
fn test_sign_custom_claims_with_ekt() {
    use crate::domain::workspace::WorkspaceIdentityClaims;

    let issuer = test_issuer();
    let claims = WorkspaceIdentityClaims {
        sub: "ws-1".to_string(),
        wkt: "wkt-hash".to_string(),
        ekt: Some("my-ekt-thumbprint".to_string()),
        exp: (Utc::now() + Duration::seconds(300)).timestamp(),
        iss: super::ISSUER.to_string(),
        aud: AUDIENCE_WORKSPACE_IDENTITY.to_string(),
        iat: Utc::now().timestamp(),
        nbf: Utc::now().timestamp(),
        jti: Uuid::new_v4().to_string(),
    };

    let token = issuer.sign_custom_claims(&claims).unwrap();

    // Decode the payload without verification to check ekt presence
    let parts: Vec<&str> = token.split('.').collect();
    assert_eq!(parts.len(), 3, "JWT must have 3 parts");
    let payload_bytes = {
        use base64::Engine;
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(parts[1])
            .unwrap()
    };
    let payload: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();
    assert_eq!(
        payload["ekt"], "my-ekt-thumbprint",
        "ekt must be present in JWT payload"
    );
}

#[test]
fn test_sign_custom_claims_without_ekt() {
    use crate::domain::workspace::WorkspaceIdentityClaims;

    let issuer = test_issuer();
    let claims = WorkspaceIdentityClaims {
        sub: "ws-1".to_string(),
        wkt: "wkt-hash".to_string(),
        ekt: None,
        exp: (Utc::now() + Duration::seconds(300)).timestamp(),
        iss: super::ISSUER.to_string(),
        aud: AUDIENCE_WORKSPACE_IDENTITY.to_string(),
        iat: Utc::now().timestamp(),
        nbf: Utc::now().timestamp(),
        jti: Uuid::new_v4().to_string(),
    };

    let token = issuer.sign_custom_claims(&claims).unwrap();

    let parts: Vec<&str> = token.split('.').collect();
    let payload_bytes = {
        use base64::Engine;
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(parts[1])
            .unwrap()
    };
    let payload: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();
    assert!(
        payload.get("ekt").is_none(),
        "ekt must be absent when None (skip_serializing_if)"
    );
}

// --- validate_custom_audience ---

#[test]
fn test_validate_custom_audience_roundtrip() {
    let issuer = test_issuer();
    let now = Utc::now();
    let custom_audience = "agentcordon:test-custom";

    let claims = serde_json::json!({
        "iss": super::ISSUER,
        "sub": "test-subject",
        "aud": custom_audience,
        "exp": (now + Duration::seconds(300)).timestamp(),
        "iat": now.timestamp(),
        "nbf": now.timestamp(),
        "jti": Uuid::new_v4().to_string(),
    });

    let token = issuer.sign_custom_claims(&claims).unwrap();
    let validated = issuer.validate_custom_audience(&token, custom_audience);
    assert!(
        validated.is_ok(),
        "sign+validate with same audience must succeed: {:?}",
        validated.err()
    );
    let v = validated.unwrap();
    assert_eq!(v["sub"], "test-subject");
}

#[test]
fn test_validate_custom_audience_wrong_audience() {
    let issuer = test_issuer();
    let now = Utc::now();

    let claims = serde_json::json!({
        "iss": super::ISSUER,
        "sub": "test-subject",
        "aud": "agentcordon:audience-a",
        "exp": (now + Duration::seconds(300)).timestamp(),
        "iat": now.timestamp(),
        "nbf": now.timestamp(),
        "jti": Uuid::new_v4().to_string(),
    });

    let token = issuer.sign_custom_claims(&claims).unwrap();
    let result = issuer.validate_custom_audience(&token, "agentcordon:audience-b");
    assert!(result.is_err(), "wrong audience must be rejected");
}

#[test]
fn test_validate_custom_audience_expired() {
    let issuer = test_issuer();
    let now = Utc::now();

    let claims = serde_json::json!({
        "iss": super::ISSUER,
        "sub": "test-subject",
        "aud": "agentcordon:test",
        "exp": (now - Duration::seconds(120)).timestamp(),
        "iat": (now - Duration::seconds(300)).timestamp(),
        "nbf": (now - Duration::seconds(300)).timestamp(),
        "jti": Uuid::new_v4().to_string(),
    });

    let token = issuer.sign_custom_claims(&claims).unwrap();
    let result = issuer.validate_custom_audience(&token, "agentcordon:test");
    assert!(result.is_err(), "expired JWT must be rejected");
}

#[test]
fn test_validate_custom_audience_future_nbf() {
    let issuer = test_issuer();
    let now = Utc::now();

    // nbf is 10 minutes in the future (well beyond 30s leeway)
    let claims = serde_json::json!({
        "iss": super::ISSUER,
        "sub": "test-subject",
        "aud": "agentcordon:test",
        "exp": (now + Duration::seconds(600)).timestamp(),
        "iat": now.timestamp(),
        "nbf": (now + Duration::seconds(600)).timestamp(),
        "jti": Uuid::new_v4().to_string(),
    });

    let token = issuer.sign_custom_claims(&claims).unwrap();
    let result = issuer.validate_custom_audience(&token, "agentcordon:test");
    assert!(
        result.is_err(),
        "future nbf (beyond leeway) must be rejected"
    );
}

// --- base64_url_encode ---

#[test]
fn test_base64_url_encode_no_padding() {
    // Test various lengths to ensure no padding appears
    for len in 1..=50 {
        let data: Vec<u8> = (0..len).map(|i| i as u8).collect();
        let encoded = base64_url_encode(&data);
        assert!(
            !encoded.contains('='),
            "base64url must not contain padding for {}-byte input",
            len
        );
    }
}

// --- ekt + ECIES key correlation ---

#[test]
fn test_ekt_thumbprint_matches_ecies_keypair() {
    use crate::crypto::key_derivation::derive_p256_keypair;

    // Derive an ECIES P-256 keypair (as a device would)
    let (_, ecies_vk) =
        derive_p256_keypair("device-secret", b"device-salt", b"agentcordon:ecies-enc-v1")
            .expect("derive ECIES keypair");

    let point = ecies_vk.to_encoded_point(false);
    let x_b64 = base64_url_encode(point.x().unwrap());
    let y_b64 = base64_url_encode(point.y().unwrap());

    let thumbprint = compute_p256_thumbprint(&x_b64, &y_b64);

    // Now derive the same key again and compute thumbprint — must match
    let (_, ecies_vk2) =
        derive_p256_keypair("device-secret", b"device-salt", b"agentcordon:ecies-enc-v1")
            .expect("derive ECIES keypair 2");
    let point2 = ecies_vk2.to_encoded_point(false);
    let x_b64_2 = base64_url_encode(point2.x().unwrap());
    let y_b64_2 = base64_url_encode(point2.y().unwrap());
    let thumbprint2 = compute_p256_thumbprint(&x_b64_2, &y_b64_2);

    assert_eq!(
        thumbprint, thumbprint2,
        "same ECIES key must produce same ekt thumbprint"
    );

    // Different ECIES key must produce different thumbprint
    let (_, ecies_vk_other) =
        derive_p256_keypair("other-secret", b"other-salt", b"agentcordon:ecies-enc-v1")
            .expect("derive other ECIES keypair");
    let point3 = ecies_vk_other.to_encoded_point(false);
    let x_b64_3 = base64_url_encode(point3.x().unwrap());
    let y_b64_3 = base64_url_encode(point3.y().unwrap());
    let thumbprint3 = compute_p256_thumbprint(&x_b64_3, &y_b64_3);

    assert_ne!(
        thumbprint, thumbprint3,
        "different ECIES keys must produce different ekt thumbprints"
    );
}

// --- Canonical JSON key order ---

#[test]
fn test_thumbprint_canonical_json_order() {
    // RFC 7638 requires JSON keys in alphabetical order for EC keys:
    // crv, kty, x, y
    let (_, vk) = test_keypair();
    let point = vk.to_encoded_point(false);
    let x_b64 = base64_url_encode(point.x().unwrap());
    let y_b64 = base64_url_encode(point.y().unwrap());

    // Build the expected canonical JSON string
    let expected_json = format!(
        r#"{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}}"#,
        x_b64, y_b64
    );

    // Verify key order is: crv < kty < x < y (alphabetical)
    // Parse the JSON string tokens: {"crv":"P-256","kty":"EC","x":"...","y":"..."}
    // Splitting by '"' gives: [{, crv, :, P-256, ,, kty, :, EC, ,, x, :, <xval>, ,, y, :, <yval>, }]
    // Keys are at odd indices: 1, 5, 9, 13
    let tokens: Vec<&str> = expected_json.split('"').collect();
    let keys = vec![tokens[1], tokens[5], tokens[9], tokens[13]];
    assert_eq!(
        keys,
        vec!["crv", "kty", "x", "y"],
        "JSON keys must be in alphabetical order: crv, kty, x, y"
    );

    // Confirm thumbprint matches manual hash of this exact JSON
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(expected_json.as_bytes());
    let manual_thumbprint = base64_url_encode(&hash);
    let computed = compute_p256_thumbprint(&x_b64, &y_b64);
    assert_eq!(
        computed, manual_thumbprint,
        "thumbprint must use canonical alphabetical key order"
    );
}
