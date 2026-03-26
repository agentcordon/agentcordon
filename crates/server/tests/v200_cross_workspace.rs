//! v2.0 — Cross-workspace credential isolation tests (SECURITY CRITICAL).
//!
//! Validates that workspaces cannot access each other's credentials without
//! explicit Cedar policy grants, and that grant revocation is enforced.

use axum::http::{Method, StatusCode};
use serde_json::json;
use uuid::Uuid;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use agent_cordon_core::crypto::SecretEncryptor;
use agent_cordon_core::domain::credential::{CredentialId, StoredCredential};
use agent_cordon_core::domain::workspace::Workspace;

use crate::common::*;
use agent_cordon_server::test_helpers::TestAppBuilder;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async fn store_credential_for_owner(
    state: &agent_cordon_server::state::AppState,
    owner: &Workspace,
    name: &str,
    secret: &str,
) -> CredentialId {
    let now = chrono::Utc::now();
    let cred_id = CredentialId(Uuid::new_v4());
    let (encrypted, nonce) = state
        .encryptor
        .encrypt(secret.as_bytes(), cred_id.0.to_string().as_bytes())
        .expect("encrypt");
    let cred = StoredCredential {
        id: cred_id.clone(),
        name: name.to_string(),
        service: "test-service".to_string(),
        encrypted_value: encrypted,
        nonce,
        scopes: vec!["read".to_string()],
        metadata: json!({}),
        created_by: Some(owner.id.clone()),
        created_by_user: None,
        created_at: now,
        updated_at: now,
        allowed_url_pattern: None,
        expires_at: None,
        transform_script: None,
        transform_name: None,
        vault: "default".to_string(),
        credential_type: "generic".to_string(),
        tags: vec![],
        key_version: 1,
    };
    state
        .store
        .store_credential(&cred)
        .await
        .expect("store credential");

    // Grant owner full permissions
    for perm in &["read", "write", "delete", "delegated_use"] {
        grant_cedar_permission(state, &cred_id, &owner.id, perm).await;
    }

    cred_id
}

// ===========================================================================
// 1. Workspace cannot access another workspace's credentials (isolation)
// ===========================================================================

#[tokio::test]
async fn test_workspace_cannot_access_others_credentials() {
    // WS-A (admin) owns a credential. WS-B has no grants. WS-B proxy -> denied.
    let ctx = TestAppBuilder::new()
        .with_admin()
        .with_agent("ws-b", &[])
        .build()
        .await;

    let ws_a = ctx.admin_agent.as_ref().unwrap();
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/data"))
        .respond_with(ResponseTemplate::new(200).set_body_string("should-not-reach"))
        .mount(&mock_server)
        .await;

    let _cred_id =
        store_credential_for_owner(&ctx.state, ws_a, "ws-a-secret", "super_secret_value_12345")
            .await;

    // WS-B tries to proxy using WS-A's credential
    let ws_b_jwt = ctx_agent_jwt(&ctx, "ws-b").await;
    let upstream_url = format!("{}/api/data", mock_server.uri());

    let (status, body) = ctx_agent_send(
        &ctx,
        "ws-b",
        Method::POST,
        "/api/v1/proxy/execute",
        &ws_b_jwt,
        Some(json!({
            "method": "GET",
            "url": upstream_url,
            "headers": {"Authorization": "Bearer {{ws-a-secret}}"}
        })),
    )
    .await;

    // WS-B has no Cedar grants for ws-a-secret -> must be denied
    assert!(
        status == StatusCode::FORBIDDEN || status == StatusCode::NOT_FOUND,
        "cross-workspace access without grant must be denied, got {} body: {}",
        status,
        body
    );
}

// ===========================================================================
// 2. Cross-workspace Cedar grant enables access
// ===========================================================================

#[tokio::test]
async fn test_cross_workspace_grant_enables_access() {
    let ctx = TestAppBuilder::new()
        .with_admin()
        .with_agent("ws-b", &[])
        .build()
        .await;

    let ws_a = ctx.admin_agent.as_ref().unwrap();
    let ws_b = ctx.agents.get("ws-b").unwrap();
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/granted"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"granted": true})))
        .mount(&mock_server)
        .await;

    let cred_id =
        store_credential_for_owner(&ctx.state, ws_a, "shared-cred", "shared_secret_value_xyz")
            .await;

    // Grant WS-B vend_credential on WS-A's credential via Cedar
    grant_cedar_permission(&ctx.state, &cred_id, &ws_b.id, "delegated_use").await;
    grant_cedar_permission(&ctx.state, &cred_id, &ws_b.id, "read").await;

    let ws_b_jwt = ctx_agent_jwt(&ctx, "ws-b").await;
    let upstream_url = format!("{}/api/granted", mock_server.uri());

    let (status, body) = ctx_agent_send(
        &ctx,
        "ws-b",
        Method::POST,
        "/api/v1/proxy/execute",
        &ws_b_jwt,
        Some(json!({
            "method": "GET",
            "url": upstream_url,
            "headers": {"Authorization": "Bearer {{shared-cred}}"}
        })),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "cross-workspace grant should allow proxy access: {}",
        body
    );
    assert_eq!(body["data"]["status_code"], 200);
}

// ===========================================================================
// 3. Cross-workspace grant revocation denies previously-granted access
// ===========================================================================

#[tokio::test]
async fn test_cross_workspace_grant_revocation() {
    let ctx = TestAppBuilder::new()
        .with_admin()
        .with_agent("ws-b", &[])
        .build()
        .await;

    let ws_a = ctx.admin_agent.as_ref().unwrap();
    let ws_b = ctx.agents.get("ws-b").unwrap();
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/revoke-test"))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .mount(&mock_server)
        .await;

    let cred_id =
        store_credential_for_owner(&ctx.state, ws_a, "revocable-cred", "revocable_secret_abc")
            .await;

    // Grant WS-B access
    grant_cedar_permission(&ctx.state, &cred_id, &ws_b.id, "delegated_use").await;
    grant_cedar_permission(&ctx.state, &cred_id, &ws_b.id, "read").await;

    let ws_b_jwt = ctx_agent_jwt(&ctx, "ws-b").await;
    let upstream_url = format!("{}/api/revoke-test", mock_server.uri());

    // Verify access works
    let (status, body) = ctx_agent_send(
        &ctx,
        "ws-b",
        Method::POST,
        "/api/v1/proxy/execute",
        &ws_b_jwt,
        Some(json!({
            "method": "GET",
            "url": &upstream_url,
            "headers": {"Authorization": "Bearer {{revocable-cred}}"}
        })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "access should work before revocation: {}",
        body
    );

    // Revoke access
    revoke_cedar_permission(&ctx.state, &cred_id, &ws_b.id, "delegated_use").await;

    // Get fresh JWT and retry
    let ws_b_jwt2 = ctx_agent_jwt(&ctx, "ws-b").await;

    let (status, body) = ctx_agent_send(
        &ctx,
        "ws-b",
        Method::POST,
        "/api/v1/proxy/execute",
        &ws_b_jwt2,
        Some(json!({
            "method": "GET",
            "url": &upstream_url,
            "headers": {"Authorization": "Bearer {{revocable-cred}}"}
        })),
    )
    .await;

    assert!(
        status == StatusCode::FORBIDDEN || status == StatusCode::NOT_FOUND,
        "access must be denied after revocation, got {} body: {}",
        status,
        body
    );
}
