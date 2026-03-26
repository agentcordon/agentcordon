//! v1.6 — Identity JWT Issuance Tests (Wave 1.4)
//!
//! Tests properties of the workspace identity JWT:
//! - Minimal claims (sub, wkt, exp, iss, aud — no scopes, no credentials)
//! - 5-minute TTL
//! - Audience restriction
//! - Security: identity JWT cannot be used as auth token

use common::*;

use agent_cordon_server::test_helpers::TestAppBuilder;

use crate::common;

// ===========================================================================
// Happy Path
// ===========================================================================

#[tokio::test]
async fn test_identity_jwt_minimal_claims() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let ws = setup_workspace_identity(&*ctx.store, Some("test-ws")).await;

    let identity_jwt = complete_workspace_auth(&ctx.app, &ws.signing_key, &ws.pk_hash).await;

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
    .expect("decode JWT");

    let claims = &token_data.claims;

    // Must have these
    assert!(claims["sub"].is_string(), "must have sub");
    assert!(claims["wkt"].is_string(), "must have wkt");
    assert!(claims["exp"].is_number(), "must have exp");
    assert!(claims["iss"].is_string(), "must have iss");
    assert!(claims["aud"].is_string(), "must have aud");

    // Must NOT have scopes or credential-related claims
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
        claims.get("roles").is_none()
            || claims["roles"]
                .as_array()
                .map(|a| a.is_empty())
                .unwrap_or(true),
        "identity JWT must not have roles"
    );
    assert!(
        claims.get("credential").is_none(),
        "identity JWT must not have credential claims"
    );
    assert!(
        claims.get("api_key").is_none(),
        "identity JWT must not have api_key"
    );
}

#[tokio::test]
async fn test_identity_jwt_5min_ttl() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let ws = setup_workspace_identity(&*ctx.store, Some("test-ws")).await;

    let identity_jwt = complete_workspace_auth(&ctx.app, &ws.signing_key, &ws.pk_hash).await;

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
    .expect("decode JWT");

    let exp = token_data.claims["exp"].as_i64().unwrap();
    let iat = token_data.claims["iat"].as_i64().unwrap();

    let ttl = exp - iat;
    assert_eq!(
        ttl, 300,
        "identity JWT TTL should be 300 seconds (5 minutes)"
    );
}

#[tokio::test]
async fn test_identity_jwt_audience() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let ws = setup_workspace_identity(&*ctx.store, Some("test-ws")).await;

    let identity_jwt = complete_workspace_auth(&ctx.app, &ws.signing_key, &ws.pk_hash).await;

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
    .expect("decode JWT");

    let aud = &token_data.claims["aud"];
    // aud can be a string or array
    let aud_str = if aud.is_string() {
        aud.as_str().unwrap().to_string()
    } else if let Some(arr) = aud.as_array() {
        arr[0].as_str().unwrap().to_string()
    } else {
        panic!("aud should be string or array");
    };
    assert_eq!(aud_str, "agentcordon:workspace-identity");
}

#[tokio::test]
async fn test_identity_jwt_wkt_matches_pubkey() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let ws = setup_workspace_identity(&*ctx.store, Some("test-ws")).await;

    let identity_jwt = complete_workspace_auth(&ctx.app, &ws.signing_key, &ws.pk_hash).await;

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
    .expect("decode JWT");

    let wkt = token_data.claims["wkt"].as_str().unwrap();
    assert_eq!(wkt, ws.pk_hash, "wkt claim should match workspace pk_hash");
}

// ===========================================================================
// Security
// ===========================================================================

#[tokio::test]
async fn test_identity_jwt_no_scopes() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let ws = setup_workspace_identity(&*ctx.store, Some("test-ws")).await;

    let identity_jwt = complete_workspace_auth(&ctx.app, &ws.signing_key, &ws.pk_hash).await;

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
    .expect("decode JWT");

    assert!(token_data.claims.get("scopes").is_none(), "no scopes claim");
    assert!(token_data.claims.get("scope").is_none(), "no scope claim");
}

#[tokio::test]
async fn test_identity_jwt_no_credentials() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let ws = setup_workspace_identity(&*ctx.store, Some("test-ws")).await;

    let identity_jwt = complete_workspace_auth(&ctx.app, &ws.signing_key, &ws.pk_hash).await;

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
    .expect("decode JWT");

    let claims = &token_data.claims;
    for key in ["credential", "credentials", "api_key", "secret", "token"] {
        assert!(
            claims.get(key).is_none(),
            "identity JWT must not contain '{}'",
            key
        );
    }
}

#[tokio::test]
async fn test_identity_jwt_not_usable_as_auth_token() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let ws = setup_workspace_identity(&*ctx.store, Some("test-ws")).await;

    let identity_jwt = complete_workspace_auth(&ctx.app, &ws.signing_key, &ws.pk_hash).await;

    // Try to use identity JWT as a bearer token on an agent endpoint
    let (status, _) = send_json(
        &ctx.app,
        axum::http::Method::GET,
        "/api/v1/workspaces",
        Some(&identity_jwt),
        None,
        None,
        None,
    )
    .await;

    // Should be rejected — wrong audience or wrong JWT type
    assert!(
        status == axum::http::StatusCode::UNAUTHORIZED
            || status == axum::http::StatusCode::FORBIDDEN,
        "identity JWT should not work as auth token, got {}",
        status
    );
}
