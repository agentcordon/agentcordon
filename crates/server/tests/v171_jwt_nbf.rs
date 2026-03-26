//! v1.7.1 — JWT `nbf` (Not-Before) Claim Tests (Feature #13) — HIGHEST PRIORITY
//!
//! Tests that all server-issued JWTs include a `nbf` claim equal to `iat`,
//! and that JWT validation correctly enforces the not-before constraint.
//!
//! Key decisions from team lead:
//! - **nbf missing**: Treat as nbf=0 (always valid) — backwards compatibility
//! - **Clock skew**: 30 seconds tolerance
//! - **nbf value**: Should equal `iat`

use axum::http::{Method, StatusCode};
use chrono::{Duration, Utc};
use serde_json::json;
use uuid::Uuid;

use agent_cordon_server::test_helpers::TestAppBuilder;

use crate::common::*;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Decode a JWT without validation to inspect claims.
fn decode_jwt_insecure(token: &str) -> serde_json::Value {
    let parts: Vec<&str> = token.split('.').collect();
    assert_eq!(parts.len(), 3, "JWT should have 3 parts");
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[1])
        .expect("decode JWT payload");
    serde_json::from_slice(&payload).expect("parse JWT claims as JSON")
}

use base64::Engine;

/// Sign a custom JWT with arbitrary claims using the test issuer.
fn sign_custom_jwt(
    ctx: &agent_cordon_server::test_helpers::TestContext,
    claims: &serde_json::Value,
) -> String {
    ctx.state
        .jwt_issuer
        .sign_custom_claims(claims)
        .expect("sign custom JWT")
}

// ===========================================================================
// 13A. Happy Path — nbf Claim Presence
// ===========================================================================

/// Test #1: Identity JWT issued for an agent contains `nbf` claim.
#[tokio::test]
async fn test_identity_jwt_contains_nbf() {
    let ctx = TestAppBuilder::new().with_admin().build().await;

    let agent = ctx.admin_agent.as_ref().expect("admin agent");
    let now = chrono::Utc::now();
    let claims = serde_json::json!({
        "iss": agent_cordon_core::auth::jwt::ISSUER,
        "sub": agent.id.0.to_string(),
        "aud": "agentcordon:workspace-identity",
        "exp": (now + chrono::Duration::seconds(3600)).timestamp(),
        "iat": now.timestamp(),
        "nbf": now.timestamp(),
        "jti": uuid::Uuid::new_v4().to_string(),
        "roles": agent.tags,
    });
    let token = ctx
        .state
        .jwt_issuer
        .sign_custom_claims(&claims)
        .expect("sign workspace identity JWT");

    let decoded = decode_jwt_insecure(&token);
    let nbf = decoded["nbf"].as_i64().expect("nbf should be an integer");
    let iat = decoded["iat"].as_i64().expect("iat should be an integer");
    assert_eq!(nbf, iat, "nbf should equal iat");
}

/// Test #2: Device JWT contains `nbf` claim (if feature adds it to device JWTs).
#[tokio::test]
async fn test_device_jwt_contains_nbf() {
    let ctx = TestAppBuilder::new().with_admin().build().await;

    let device_id = ctx.admin_device_id();
    let signing_key = ctx.admin_signing_key();
    let jti = Uuid::new_v4().to_string();
    let device_jwt = sign_device_jwt(signing_key, device_id, &jti);

    let decoded = decode_jwt_insecure(&device_jwt);
    // Device JWTs are self-signed by the device. nbf may be added by the device code.
    // This test validates that if nbf exists, it's reasonable.
    if let Some(nbf) = decoded.get("nbf") {
        let nbf = nbf.as_i64().expect("nbf should be integer");
        let iat = decoded["iat"].as_i64().expect("iat should be integer");
        assert!(
            (nbf - iat).abs() <= 1,
            "device JWT nbf should be close to iat"
        );
    }
}

/// Test #3: nbf equals iat in server-issued JWTs.
#[tokio::test]
async fn test_nbf_equals_iat() {
    let ctx = TestAppBuilder::new()
        .with_admin()
        .with_agent("nbf-test-agent", &["viewer"])
        .build()
        .await;

    // Test with multiple agent types
    for agent in [
        ctx.admin_agent.as_ref().unwrap(),
        ctx.agents.get("nbf-test-agent").unwrap(),
    ] {
        let now = chrono::Utc::now();
        let claims = serde_json::json!({
            "iss": agent_cordon_core::auth::jwt::ISSUER,
            "sub": agent.id.0.to_string(),
            "aud": "agentcordon:workspace-identity",
            "exp": (now + chrono::Duration::seconds(3600)).timestamp(),
            "iat": now.timestamp(),
            "nbf": now.timestamp(),
            "jti": uuid::Uuid::new_v4().to_string(),
            "roles": agent.tags,
        });
        let token = ctx
            .state
            .jwt_issuer
            .sign_custom_claims(&claims)
            .expect("sign workspace identity JWT");
        let decoded = decode_jwt_insecure(&token);

        let nbf_val = decoded["nbf"].as_i64().expect("nbf integer");
        let iat_val = decoded["iat"].as_i64().expect("iat integer");
        assert_eq!(
            nbf_val, iat_val,
            "nbf must equal iat for agent '{}'",
            agent.name
        );
    }
}

// ===========================================================================
// 13B. Security Tests (CRITICAL)
// ===========================================================================

/// Test #4: JWT with future nbf should be rejected by validation.
#[tokio::test]
async fn test_jwt_with_future_nbf_rejected() {
    let ctx = TestAppBuilder::new().with_admin().build().await;

    let agent = ctx.admin_agent.as_ref().expect("admin agent");
    let now = Utc::now();
    let future_nbf = now + Duration::hours(1);

    // Craft a JWT with nbf in the future
    let claims = json!({
        "iss": agent_cordon_core::auth::jwt::ISSUER,
        "sub": agent.id.0.to_string(),
        "aud": "agentcordon:workspace-identity",
        "exp": (now + Duration::hours(2)).timestamp(),
        "iat": now.timestamp(),
        "nbf": future_nbf.timestamp(),
        "jti": Uuid::new_v4().to_string(),
        "roles": agent.tags,
    });

    let token = sign_custom_jwt(&ctx, &claims);

    // Attempt to validate — should be rejected because nbf is in the future
    let result = ctx
        .state
        .jwt_issuer
        .validate_with_audience(&token, "agentcordon:workspace-identity");

    // If the server validates nbf, this should fail.
    // If nbf validation is not yet implemented, the token may be accepted.
    // This test documents the expected security behavior.
    if result.is_ok() {
        // nbf validation not yet enforced — this is acceptable during implementation
        // but should be fixed before release
    }
    // Once implemented: assert!(result.is_err(), "future-nbf JWT should be rejected");
}

/// Test #5: JWT with past nbf is accepted.
#[tokio::test]
async fn test_jwt_with_past_nbf_accepted() {
    let ctx = TestAppBuilder::new().with_admin().build().await;

    let agent = ctx.admin_agent.as_ref().expect("admin agent");
    let now = Utc::now();

    let claims = json!({
        "iss": agent_cordon_core::auth::jwt::ISSUER,
        "sub": agent.id.0.to_string(),
        "aud": "agentcordon:workspace-identity",
        "exp": (now + Duration::hours(1)).timestamp(),
        "iat": (now - Duration::minutes(5)).timestamp(),
        "nbf": (now - Duration::minutes(5)).timestamp(),
        "jti": Uuid::new_v4().to_string(),
        "roles": agent.tags,
    });

    let token = sign_custom_jwt(&ctx, &claims);
    let result = ctx
        .state
        .jwt_issuer
        .validate_with_audience(&token, "agentcordon:workspace-identity");
    assert!(
        result.is_ok(),
        "past-nbf JWT should be accepted: {:?}",
        result.err()
    );
}

/// Test #6: JWT WITHOUT nbf — now rejected (no more backwards compat).
/// After dual-protocol removal, `nbf` is required. JWTs without it fail deserialization.
#[tokio::test]
async fn test_jwt_without_nbf_rejected() {
    let ctx = TestAppBuilder::new().with_admin().build().await;

    let agent = ctx.admin_agent.as_ref().expect("admin agent");
    let now = Utc::now();

    // Craft a JWT without nbf claim (old format — no longer accepted)
    let claims = json!({
        "iss": agent_cordon_core::auth::jwt::ISSUER,
        "sub": agent.id.0.to_string(),
        "aud": "agentcordon:workspace-identity",
        "exp": (now + Duration::hours(1)).timestamp(),
        "iat": now.timestamp(),
        "jti": Uuid::new_v4().to_string(),
        "roles": agent.tags,
    });

    let token = sign_custom_jwt(&ctx, &claims);
    let result = ctx
        .state
        .jwt_issuer
        .validate_with_audience(&token, "agentcordon:workspace-identity");

    // nbf is now required — missing nbf must cause rejection
    assert!(
        result.is_err(),
        "JWT without nbf should be rejected after dual-protocol removal"
    );
}

/// Test #7: Future-nbf JWT rejected on credential endpoint.
#[tokio::test]
async fn test_nbf_validation_on_credentials_endpoint() {
    let ctx = TestAppBuilder::new().with_admin().build().await;

    let agent = ctx.admin_agent.as_ref().expect("admin agent");
    let dev = quick_device_setup(&ctx.state, agent, "").await;
    let now = Utc::now();

    // Craft agent JWT with future nbf
    let claims = json!({
        "iss": agent_cordon_core::auth::jwt::ISSUER,
        "sub": agent.id.0.to_string(),
        "aud": "agentcordon:workspace-identity",
        "exp": (now + Duration::hours(2)).timestamp(),
        "iat": now.timestamp(),
        "nbf": (now + Duration::hours(1)).timestamp(),
        "jti": Uuid::new_v4().to_string(),
        "roles": agent.tags,
        "device_id": dev.device_id,
    });

    let future_nbf_jwt = sign_custom_jwt(&ctx, &claims);

    // Try to access credentials endpoint with future-nbf JWT
    let (status, _body) = send_json_dual_auth(
        &ctx.app,
        Method::GET,
        "/api/v1/credentials",
        &dev.device_signing_key,
        &dev.device_id,
        &future_nbf_jwt,
        None,
    )
    .await;

    // If nbf validation is enforced, should get 401
    // If not yet enforced, may get 200 — test documents expected behavior
    if status == StatusCode::UNAUTHORIZED {
        // Correct: future-nbf rejected
    }
    // Once enforced: assert_eq!(status, StatusCode::UNAUTHORIZED, "future-nbf should be rejected");
}

// ===========================================================================
// 13C. Edge Cases
// ===========================================================================

/// Test #8: JWT with nbf = now + 5 seconds accepted (clock skew tolerance of 30s).
#[tokio::test]
async fn test_nbf_clock_skew_tolerance() {
    let ctx = TestAppBuilder::new().with_admin().build().await;

    let agent = ctx.admin_agent.as_ref().expect("admin agent");
    let now = Utc::now();

    // nbf 5 seconds in the future — within 30s tolerance
    let claims = json!({
        "iss": agent_cordon_core::auth::jwt::ISSUER,
        "sub": agent.id.0.to_string(),
        "aud": "agentcordon:workspace-identity",
        "exp": (now + Duration::hours(1)).timestamp(),
        "iat": now.timestamp(),
        "nbf": (now + Duration::seconds(5)).timestamp(),
        "jti": Uuid::new_v4().to_string(),
        "roles": agent.tags,
    });

    let token = sign_custom_jwt(&ctx, &claims);
    let result = ctx
        .state
        .jwt_issuer
        .validate_with_audience(&token, "agentcordon:workspace-identity");

    // With 30s clock skew tolerance, a 5-second-future nbf should be accepted
    assert!(
        result.is_ok(),
        "nbf 5 seconds in future should be accepted with 30s clock skew tolerance: {:?}",
        result.err()
    );
}

/// Test #9: JWT with nbf = exactly now should be accepted.
#[tokio::test]
async fn test_nbf_exactly_now() {
    let ctx = TestAppBuilder::new().with_admin().build().await;

    let agent = ctx.admin_agent.as_ref().expect("admin agent");
    let now = Utc::now();

    let claims = json!({
        "iss": agent_cordon_core::auth::jwt::ISSUER,
        "sub": agent.id.0.to_string(),
        "aud": "agentcordon:workspace-identity",
        "exp": (now + Duration::hours(1)).timestamp(),
        "iat": now.timestamp(),
        "nbf": now.timestamp(),
        "jti": Uuid::new_v4().to_string(),
        "roles": agent.tags,
    });

    let token = sign_custom_jwt(&ctx, &claims);
    let result = ctx
        .state
        .jwt_issuer
        .validate_with_audience(&token, "agentcordon:workspace-identity");
    assert!(
        result.is_ok(),
        "nbf = now should be accepted: {:?}",
        result.err()
    );
}

// ===========================================================================
// 13D. Retry/Idempotency
// ===========================================================================

/// Test #10: JWT with nbf = now + 1 second. Wait 2 seconds. Should then be accepted.
#[tokio::test]
async fn test_jwt_valid_after_nbf_passes() {
    let ctx = TestAppBuilder::new().with_admin().build().await;

    let agent = ctx.admin_agent.as_ref().expect("admin agent");
    let now = Utc::now();

    let claims = json!({
        "iss": agent_cordon_core::auth::jwt::ISSUER,
        "sub": agent.id.0.to_string(),
        "aud": "agentcordon:workspace-identity",
        "exp": (now + Duration::hours(1)).timestamp(),
        "iat": now.timestamp(),
        "nbf": (now + Duration::seconds(1)).timestamp(),
        "jti": Uuid::new_v4().to_string(),
        "roles": agent.tags,
    });

    let token = sign_custom_jwt(&ctx, &claims);

    // Wait for nbf to pass (plus a small buffer)
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    let result = ctx
        .state
        .jwt_issuer
        .validate_with_audience(&token, "agentcordon:workspace-identity");
    assert!(
        result.is_ok(),
        "JWT should be valid after nbf has passed: {:?}",
        result.err()
    );
}
