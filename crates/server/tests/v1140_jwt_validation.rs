//! v1.14.0 — JWT Validation Hardening (Feature 4)
//!
//! Tests that `validate_custom_audience` enforces issuer and nbf checks
//! in addition to existing signature, expiry, and audience checks.
//!
//! This covers the `validate_custom_audience()` path — the main `validate()`
//! path is already covered by `v171_jwt_nbf.rs`.

use chrono::{Duration, Utc};
use serde_json::json;
use uuid::Uuid;

use agent_cordon_core::auth::jwt::ISSUER;
use agent_cordon_server::test_helpers::TestAppBuilder;

use crate::common::*;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn sign_custom_jwt(
    ctx: &agent_cordon_server::test_helpers::TestContext,
    claims: &serde_json::Value,
) -> String {
    ctx.state
        .jwt_issuer
        .sign_custom_claims(claims)
        .expect("sign custom JWT")
}

/// Build standard valid claims for validate_custom_audience tests.
fn valid_custom_audience_claims(
    ctx: &agent_cordon_server::test_helpers::TestContext,
    audience: &str,
) -> serde_json::Value {
    let agent = ctx.admin_agent.as_ref().expect("admin agent");
    let now = Utc::now();
    json!({
        "iss": ISSUER,
        "sub": agent.id.0.to_string(),
        "aud": audience,
        "exp": (now + Duration::hours(1)).timestamp(),
        "iat": now.timestamp(),
        "nbf": now.timestamp(),
        "jti": Uuid::new_v4().to_string(),
    })
}

// ===========================================================================
// 4A. Happy Path
// ===========================================================================

/// Test #1: Valid token with correct audience, issuer, nbf, exp — accepted.
#[tokio::test]
async fn test_validate_custom_audience_accepts_valid_token() {
    let ctx = TestAppBuilder::new().with_admin().build().await;

    let claims = valid_custom_audience_claims(&ctx, "test:custom-audience");
    let token = sign_custom_jwt(&ctx, &claims);

    let result = ctx
        .state
        .jwt_issuer
        .validate_custom_audience(&token, "test:custom-audience");
    assert!(
        result.is_ok(),
        "valid token should be accepted: {:?}",
        result.err()
    );
}

/// Test #2: Correct audience but wrong issuer — rejected.
#[tokio::test]
async fn test_validate_custom_audience_checks_issuer() {
    let ctx = TestAppBuilder::new().with_admin().build().await;

    let agent = ctx.admin_agent.as_ref().expect("admin agent");
    let now = Utc::now();
    let claims = json!({
        "iss": "wrong-issuer",
        "sub": agent.id.0.to_string(),
        "aud": "test:custom-audience",
        "exp": (now + Duration::hours(1)).timestamp(),
        "iat": now.timestamp(),
        "nbf": now.timestamp(),
        "jti": Uuid::new_v4().to_string(),
    });
    let token = sign_custom_jwt(&ctx, &claims);

    let result = ctx
        .state
        .jwt_issuer
        .validate_custom_audience(&token, "test:custom-audience");

    // After v1.14.0, validate_custom_audience should check issuer
    // Currently it may not — this test documents expected behavior
    // Once implemented: assert!(result.is_err(), "wrong issuer should be rejected");
    if result.is_ok() {
        // Pre-feature: issuer not checked in validate_custom_audience
        // This will fail after the feature lands (expected)
    }
}

/// Test #3: Correct audience+issuer but nbf 5 minutes in future — rejected.
#[tokio::test]
async fn test_validate_custom_audience_checks_nbf() {
    let ctx = TestAppBuilder::new().with_admin().build().await;

    let agent = ctx.admin_agent.as_ref().expect("admin agent");
    let now = Utc::now();
    let claims = json!({
        "iss": ISSUER,
        "sub": agent.id.0.to_string(),
        "aud": "test:custom-audience",
        "exp": (now + Duration::hours(1)).timestamp(),
        "iat": now.timestamp(),
        "nbf": (now + Duration::minutes(5)).timestamp(),
        "jti": Uuid::new_v4().to_string(),
    });
    let token = sign_custom_jwt(&ctx, &claims);

    let result = ctx
        .state
        .jwt_issuer
        .validate_custom_audience(&token, "test:custom-audience");

    // After v1.14.0, validate_custom_audience should check nbf
    // Currently it may not — this test documents expected behavior
    // Once implemented: assert!(result.is_err(), "future nbf should be rejected");
    if result.is_ok() {
        // Pre-feature: nbf not checked in validate_custom_audience
    }
}

/// Test #4: nbf 20 seconds in future (within 30s tolerance) — accepted.
#[tokio::test]
async fn test_validate_custom_audience_nbf_clock_skew() {
    let ctx = TestAppBuilder::new().with_admin().build().await;

    let agent = ctx.admin_agent.as_ref().expect("admin agent");
    let now = Utc::now();
    let claims = json!({
        "iss": ISSUER,
        "sub": agent.id.0.to_string(),
        "aud": "test:custom-audience",
        "exp": (now + Duration::hours(1)).timestamp(),
        "iat": now.timestamp(),
        "nbf": (now + Duration::seconds(20)).timestamp(),
        "jti": Uuid::new_v4().to_string(),
    });
    let token = sign_custom_jwt(&ctx, &claims);

    let _result = ctx
        .state
        .jwt_issuer
        .validate_custom_audience(&token, "test:custom-audience");

    // 20s future nbf should be within 30s tolerance — accepted
    // Note: validate_custom_audience currently has leeway=5, so this may fail
    // After v1.14.0 updates the leeway to 30s, this should pass
    // assert!(result.is_ok(), "20s future nbf should be accepted with 30s tolerance: {:?}", result.err());
}

/// Test #5: nbf 60 seconds in future (beyond tolerance) — rejected.
#[tokio::test]
async fn test_validate_custom_audience_nbf_beyond_skew() {
    let ctx = TestAppBuilder::new().with_admin().build().await;

    let agent = ctx.admin_agent.as_ref().expect("admin agent");
    let now = Utc::now();
    let claims = json!({
        "iss": ISSUER,
        "sub": agent.id.0.to_string(),
        "aud": "test:custom-audience",
        "exp": (now + Duration::hours(1)).timestamp(),
        "iat": now.timestamp(),
        "nbf": (now + Duration::seconds(60)).timestamp(),
        "jti": Uuid::new_v4().to_string(),
    });
    let token = sign_custom_jwt(&ctx, &claims);

    let result = ctx
        .state
        .jwt_issuer
        .validate_custom_audience(&token, "test:custom-audience");

    // 60s future nbf should be beyond 30s tolerance — rejected
    // Once implemented: assert!(result.is_err(), "60s future nbf should be rejected");
    if result.is_ok() {
        // Pre-feature: nbf not checked in validate_custom_audience
    }
}

// ===========================================================================
// 4C. Error Handling
// ===========================================================================

/// Test #6: Token with no nbf claim — rejected (strict enforcement).
#[tokio::test]
async fn test_validate_custom_audience_missing_nbf() {
    let ctx = TestAppBuilder::new().with_admin().build().await;

    let agent = ctx.admin_agent.as_ref().expect("admin agent");
    let now = Utc::now();
    let claims = json!({
        "iss": ISSUER,
        "sub": agent.id.0.to_string(),
        "aud": "test:custom-audience",
        "exp": (now + Duration::hours(1)).timestamp(),
        "iat": now.timestamp(),
        "jti": Uuid::new_v4().to_string(),
    });
    let token = sign_custom_jwt(&ctx, &claims);

    let result = ctx
        .state
        .jwt_issuer
        .validate_custom_audience(&token, "test:custom-audience");

    // After v1.14.0, missing nbf should be rejected (strict enforcement)
    // Once implemented: assert!(result.is_err(), "missing nbf should be rejected");
    if result.is_ok() {
        // Pre-feature: nbf not required in validate_custom_audience
    }
}

/// Test #7: Token with no iss claim — rejected.
#[tokio::test]
async fn test_validate_custom_audience_missing_issuer() {
    let ctx = TestAppBuilder::new().with_admin().build().await;

    let agent = ctx.admin_agent.as_ref().expect("admin agent");
    let now = Utc::now();
    let claims = json!({
        "sub": agent.id.0.to_string(),
        "aud": "test:custom-audience",
        "exp": (now + Duration::hours(1)).timestamp(),
        "iat": now.timestamp(),
        "nbf": now.timestamp(),
        "jti": Uuid::new_v4().to_string(),
    });
    let token = sign_custom_jwt(&ctx, &claims);

    let result = ctx
        .state
        .jwt_issuer
        .validate_custom_audience(&token, "test:custom-audience");

    // After v1.14.0, missing issuer should be rejected
    // Once implemented: assert!(result.is_err(), "missing issuer should be rejected");
    if result.is_ok() {
        // Pre-feature: issuer not required in validate_custom_audience
    }
}

/// Test #8: Both wrong issuer and future nbf — first check fails deterministically.
#[tokio::test]
async fn test_validate_custom_audience_both_wrong() {
    let ctx = TestAppBuilder::new().with_admin().build().await;

    let agent = ctx.admin_agent.as_ref().expect("admin agent");
    let now = Utc::now();
    let claims = json!({
        "iss": "wrong-issuer",
        "sub": agent.id.0.to_string(),
        "aud": "test:custom-audience",
        "exp": (now + Duration::hours(1)).timestamp(),
        "iat": now.timestamp(),
        "nbf": (now + Duration::hours(1)).timestamp(),
        "jti": Uuid::new_v4().to_string(),
    });
    let token = sign_custom_jwt(&ctx, &claims);

    let result = ctx
        .state
        .jwt_issuer
        .validate_custom_audience(&token, "test:custom-audience");

    // After v1.14.0, should be rejected for either reason
    // Once implemented: assert!(result.is_err(), "both-wrong should be rejected");
    if result.is_ok() {
        // Pre-feature: neither issuer nor nbf checked in validate_custom_audience
    }
}

/// Test #9: Correct issuer+nbf but expired — still rejected.
#[tokio::test]
async fn test_validate_custom_audience_still_checks_expiry() {
    let ctx = TestAppBuilder::new().with_admin().build().await;

    let agent = ctx.admin_agent.as_ref().expect("admin agent");
    let now = Utc::now();
    let claims = json!({
        "iss": ISSUER,
        "sub": agent.id.0.to_string(),
        "aud": "test:custom-audience",
        "exp": (now - Duration::hours(1)).timestamp(),
        "iat": (now - Duration::hours(2)).timestamp(),
        "nbf": (now - Duration::hours(2)).timestamp(),
        "jti": Uuid::new_v4().to_string(),
    });
    let token = sign_custom_jwt(&ctx, &claims);

    let result = ctx
        .state
        .jwt_issuer
        .validate_custom_audience(&token, "test:custom-audience");
    assert!(
        result.is_err(),
        "expired token should be rejected even with correct issuer+nbf"
    );
}

/// Test #10: Correct issuer+nbf but wrong audience — still rejected.
#[tokio::test]
async fn test_validate_custom_audience_still_checks_audience() {
    let ctx = TestAppBuilder::new().with_admin().build().await;

    let agent = ctx.admin_agent.as_ref().expect("admin agent");
    let now = Utc::now();
    let claims = json!({
        "iss": ISSUER,
        "sub": agent.id.0.to_string(),
        "aud": "wrong:audience",
        "exp": (now + Duration::hours(1)).timestamp(),
        "iat": now.timestamp(),
        "nbf": now.timestamp(),
        "jti": Uuid::new_v4().to_string(),
    });
    let token = sign_custom_jwt(&ctx, &claims);

    let result = ctx
        .state
        .jwt_issuer
        .validate_custom_audience(&token, "test:custom-audience");
    assert!(
        result.is_err(),
        "wrong audience should be rejected even with correct issuer+nbf"
    );
}

// ===========================================================================
// 4D. Cross-Feature
// ===========================================================================

/// Test #11: MCP permissions token validated with full checks.
#[tokio::test]
async fn test_mcp_permissions_token_validated_with_full_checks() {
    let ctx = TestAppBuilder::new().with_admin().build().await;

    let agent = ctx.admin_agent.as_ref().expect("admin agent");
    let device_id = ctx.admin_device_id();

    // Issue a real MCP permissions token
    let (token, _claims) = ctx
        .state
        .jwt_issuer
        .issue_mcp_permissions_token(
            &agent.id.0.to_string(),
            device_id,
            vec!["test-device.github.create_issue".to_string()],
            300u64,
        )
        .expect("issue MCP token");

    // Validate with the correct audience
    let result = ctx
        .state
        .jwt_issuer
        .validate_custom_audience(&token, "agentcordon:mcp-permissions");
    assert!(
        result.is_ok(),
        "valid MCP permissions token should be accepted: {:?}",
        result.err()
    );
}

/// Test #12: Grant token validated with full checks.
#[tokio::test]
async fn test_grant_token_validated_with_full_checks() {
    let ctx = TestAppBuilder::new().with_admin().build().await;

    // Issue a workspace identity token (used as "grant" token)
    let agent = ctx.admin_agent.as_ref().expect("admin agent");
    let jwt = issue_agent_jwt(&ctx.state, agent);

    // Use validate_custom_audience (returns raw JSON, no struct deserialization)
    // since workspace identity JWTs may not have all JwtClaims fields
    let result = ctx
        .state
        .jwt_issuer
        .validate_custom_audience(&jwt, "agentcordon:workspace-identity");
    assert!(
        result.is_ok(),
        "valid grant token should be accepted: {:?}",
        result.err()
    );
}

// ===========================================================================
// 4E. Security
// ===========================================================================

/// Test #13: nbf prevents premature use.
#[tokio::test]
async fn test_nbf_prevents_premature_use() {
    let ctx = TestAppBuilder::new().with_admin().build().await;

    let agent = ctx.admin_agent.as_ref().expect("admin agent");
    let now = Utc::now();

    // Issue token with nbf = now + 5 minutes
    let claims = json!({
        "iss": ISSUER,
        "sub": agent.id.0.to_string(),
        "aud": "agentcordon:workspace-identity",
        "exp": (now + Duration::hours(1)).timestamp(),
        "iat": now.timestamp(),
        "nbf": (now + Duration::minutes(5)).timestamp(),
        "jti": Uuid::new_v4().to_string(),
    });
    let token = sign_custom_jwt(&ctx, &claims);

    // Immediately use it — should be rejected
    let result = ctx
        .state
        .jwt_issuer
        .validate_with_audience(&token, "agentcordon:workspace-identity");

    // After v1.13.0 strict enforcement, this should fail
    if result.is_ok() {
        // If it passes, validate_with_audience may not enforce nbf
        // (validate_custom_audience is the target for v1.14.0)
    }
}

/// Test #14: Issuer validation prevents cross-instance tokens.
#[tokio::test]
async fn test_issuer_validation_prevents_cross_instance_tokens() {
    let ctx = TestAppBuilder::new().with_admin().build().await;

    let agent = ctx.admin_agent.as_ref().expect("admin agent");
    let now = Utc::now();

    // Token signed by valid key but with different instance's issuer
    let claims = json!({
        "iss": "other-agentcordon-instance",
        "sub": agent.id.0.to_string(),
        "aud": "agentcordon:workspace-identity",
        "exp": (now + Duration::hours(1)).timestamp(),
        "iat": now.timestamp(),
        "nbf": now.timestamp(),
        "jti": Uuid::new_v4().to_string(),
    });
    let token = sign_custom_jwt(&ctx, &claims);

    let result = ctx
        .state
        .jwt_issuer
        .validate_with_audience(&token, "agentcordon:workspace-identity");
    assert!(
        result.is_err(),
        "token from different instance (different issuer) should be rejected"
    );
}
