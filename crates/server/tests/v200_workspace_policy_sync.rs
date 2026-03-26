//! v2.0 — Workspace policy sync endpoint tests.
//!
//! Tests the `GET /api/v1/workspaces/policies` endpoint which allows
//! authenticated workspaces to sync Cedar policies.

use axum::http::{Method, StatusCode};
use serde_json::json;
use uuid::Uuid;

use agent_cordon_core::domain::policy::{PolicyId, StoredPolicy};

use crate::common::*;
use agent_cordon_server::test_helpers::TestAppBuilder;

// ===========================================================================
// 1. Happy path: authenticated workspace fetches enabled policies
// ===========================================================================

#[tokio::test]
async fn test_workspace_policy_sync_happy_path() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let jwt = ctx_admin_jwt(&ctx).await;

    let (status, body) = send_json(
        &ctx.app,
        Method::GET,
        "/api/v1/workspaces/policies",
        Some(&jwt),
        None,
        None,
        None,
    )
    .await;

    assert_eq!(status, StatusCode::OK, "policy sync: {}", body);
    let policies = &body["data"]["policies"];
    assert!(policies.is_array(), "policies should be an array");
    // The test harness seeds at least one default policy
    assert!(
        !policies.as_array().unwrap().is_empty(),
        "should have at least the default policy"
    );

    // Each policy should have id, name, cedar_policy
    let first = &policies[0];
    assert!(first["id"].is_string(), "policy should have id");
    assert!(first["name"].is_string(), "policy should have name");
    assert!(
        first["cedar_policy"].is_string(),
        "policy should have cedar_policy"
    );
}

// ===========================================================================
// 2. Unauthenticated request -> 401
// ===========================================================================

#[tokio::test]
async fn test_workspace_policy_sync_unauthenticated_rejected() {
    let ctx = TestAppBuilder::new().with_admin().build().await;

    let (status, _body) = send_json(
        &ctx.app,
        Method::GET,
        "/api/v1/workspaces/policies",
        None, // no bearer
        None,
        None,
        None,
    )
    .await;

    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "unauthenticated policy sync should be 401"
    );
}

// ===========================================================================
// 3. Expired JWT -> 401
// ===========================================================================

#[tokio::test]
async fn test_workspace_policy_sync_expired_jwt_rejected() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let admin = ctx.admin_agent.as_ref().unwrap();

    // Issue a JWT that is already expired
    let now = chrono::Utc::now();
    let expired_claims = json!({
        "sub": admin.id.0.to_string(),
        "aud": "agentcordon:workspace-identity",
        "iss": agent_cordon_core::auth::jwt::ISSUER,
        "exp": (now - chrono::Duration::seconds(300)).timestamp(),
        "iat": (now - chrono::Duration::seconds(600)).timestamp(),
        "nbf": (now - chrono::Duration::seconds(600)).timestamp(),
        "jti": Uuid::new_v4().to_string(),
        "wkt": "test-workspace-key-thumbprint",
    });
    let expired_jwt = ctx
        .state
        .jwt_issuer
        .sign_custom_claims(&expired_claims)
        .expect("sign expired JWT");

    let (status, _body) = send_json(
        &ctx.app,
        Method::GET,
        "/api/v1/workspaces/policies",
        Some(&expired_jwt),
        None,
        None,
        None,
    )
    .await;

    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "expired JWT should be rejected for policy sync"
    );
}

// ===========================================================================
// 4. Only enabled policies returned
// ===========================================================================

#[tokio::test]
async fn test_workspace_policy_sync_only_enabled_returned() {
    let ctx = TestAppBuilder::new().with_admin().build().await;

    // Store a disabled policy
    let now = chrono::Utc::now();
    let disabled_policy = StoredPolicy {
        id: PolicyId(Uuid::new_v4()),
        name: "disabled-test-policy".to_string(),
        description: Some("This policy is disabled".to_string()),
        cedar_policy: "forbid(principal, action, resource);".to_string(),
        enabled: false,
        is_system: false,
        created_at: now,
        updated_at: now,
    };
    ctx.store
        .store_policy(&disabled_policy)
        .await
        .expect("store disabled policy");

    let jwt = ctx_admin_jwt(&ctx).await;

    let (status, body) = send_json(
        &ctx.app,
        Method::GET,
        "/api/v1/workspaces/policies",
        Some(&jwt),
        None,
        None,
        None,
    )
    .await;

    assert_eq!(status, StatusCode::OK, "policy sync: {}", body);
    let policies = body["data"]["policies"].as_array().unwrap();

    // The disabled policy should not appear
    let disabled_found = policies
        .iter()
        .any(|p| p["name"].as_str() == Some("disabled-test-policy"));
    assert!(
        !disabled_found,
        "disabled policy should not be returned in sync"
    );
}

// ===========================================================================
// 5. Empty policies -> empty array with correct schema
// ===========================================================================

#[tokio::test]
async fn test_workspace_policy_sync_empty_policies() {
    // Use a custom policy that is the bare minimum, then disable it
    let ctx = TestAppBuilder::new()
        .with_admin()
        .with_policy("// empty policy set\npermit(principal, action, resource);")
        .build()
        .await;

    // Disable all policies in the store
    let all_policies = ctx
        .store
        .get_all_enabled_policies()
        .await
        .expect("list policies");
    for policy in all_policies {
        let mut updated = policy.clone();
        updated.enabled = false;
        ctx.store
            .update_policy(&updated)
            .await
            .expect("disable policy");
    }

    let jwt = ctx_admin_jwt(&ctx).await;

    let (status, body) = send_json(
        &ctx.app,
        Method::GET,
        "/api/v1/workspaces/policies",
        Some(&jwt),
        None,
        None,
        None,
    )
    .await;

    assert_eq!(status, StatusCode::OK, "empty policy sync: {}", body);
    let policies = &body["data"]["policies"];
    assert!(policies.is_array(), "should still return an array");
    assert_eq!(
        policies.as_array().unwrap().len(),
        0,
        "all policies disabled -> empty array"
    );
}
