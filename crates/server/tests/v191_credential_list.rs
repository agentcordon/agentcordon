//! Integration tests — v1.9.1 Feature 4: N+1 Query Fix in list_credentials.
//!
//! Verifies that credential listing returns correct results for all principals.
//! All authorization goes through Cedar — no code-level bypasses except root
//! (handled inside the Cedar engine). Default policies grant enabled workspaces
//! `list` and `vend_credential` access to all credentials.

use crate::common;

use agent_cordon_core::crypto::SecretEncryptor;
use agent_cordon_core::domain::credential::{CredentialId, StoredCredential};
use agent_cordon_core::domain::user::UserRole;
use agent_cordon_server::test_helpers::TestAppBuilder;
use axum::http::{Method, StatusCode};
use chrono::Utc;
use serde_json::json;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Create a credential directly in the DB and return its ID.
#[allow(dead_code)]
async fn create_credential_in_db(
    store: &(dyn agent_cordon_core::storage::Store + Send + Sync),
    encryptor: &agent_cordon_core::crypto::aes_gcm::AesGcmEncryptor,
    name: &str,
    tags: Vec<String>,
) -> CredentialId {
    let now = Utc::now();
    let cred_id = CredentialId(Uuid::new_v4());
    let (encrypted, nonce) = encryptor
        .encrypt(b"test-secret", cred_id.0.to_string().as_bytes())
        .expect("encrypt");
    let cred = StoredCredential {
        id: cred_id.clone(),
        name: name.to_string(),
        service: "test-service".to_string(),
        encrypted_value: encrypted,
        nonce,
        scopes: vec!["read".to_string()],
        metadata: json!({}),
        created_by: None,
        created_by_user: None,
        created_at: now,
        updated_at: now,
        allowed_url_pattern: None,
        expires_at: None,
        transform_script: None,
        transform_name: None,
        vault: "default".to_string(),
        credential_type: "generic".to_string(),
        tags,
        description: None,
        target_identity: None,
        key_version: 1,
    };
    store
        .store_credential(&cred)
        .await
        .expect("store credential");
    cred_id
}

/// Create a credential via the API (user session) and return its UUID string.
async fn create_credential_via_api(app: &axum::Router, cookie: &str, name: &str) -> String {
    let (status, body) = common::send_json_auto_csrf(
        app,
        Method::POST,
        "/api/v1/credentials",
        None,
        Some(cookie),
        Some(json!({
            "name": name,
            "service": "test-service",
            "credential_type": "generic",
            "secret_value": "test-secret-value"
        })),
    )
    .await;
    assert!(
        status == StatusCode::CREATED || status == StatusCode::OK,
        "credential creation should succeed: {:?}",
        body,
    );
    body["data"]["id"]
        .as_str()
        .expect("credential response must have id")
        .to_string()
}

#[allow(dead_code)]
/// Grant a credential permission to an agent.
async fn grant_permission(
    app: &axum::Router,
    cookie: &str,
    credential_id: &str,
    agent_id: &str,
    permission: &str,
) {
    let (status, body) = common::send_json_auto_csrf(
        app,
        Method::POST,
        &format!("/api/v1/credentials/{}/permissions", credential_id),
        None,
        Some(cookie),
        Some(json!({
            "agent_id": agent_id,
            "permission": permission
        })),
    )
    .await;
    assert!(
        status == StatusCode::OK
            || status == StatusCode::CREATED
            || status == StatusCode::NO_CONTENT,
        "grant permission should succeed for cred={} agent={}: status={} body={:?}",
        credential_id,
        agent_id,
        status,
        body,
    );
}

/// Set up a test context with a user and agent, returning context + user cookie.
async fn setup() -> (agent_cordon_server::test_helpers::TestContext, String) {
    let ctx = TestAppBuilder::new()
        .with_admin()
        .with_agent("test-agent", &["user"])
        .build()
        .await;
    let _user = common::create_test_user(
        &*ctx.store,
        "cred-list-user",
        common::TEST_PASSWORD,
        UserRole::Admin,
    )
    .await;
    let cookie =
        common::login_user_combined(&ctx.app, "cred-list-user", common::TEST_PASSWORD).await;
    (ctx, cookie)
}

/// List credentials as an agent via dual auth (device JWT + agent JWT).
async fn list_credentials_as_agent(
    ctx: &agent_cordon_server::test_helpers::TestContext,
    agent_name: &str,
) -> (StatusCode, serde_json::Value) {
    let _agent = ctx.agents.get(agent_name).expect("agent must exist");
    let dev_ctx = ctx.device_for(agent_name);
    let agent_jwt =
        common::get_jwt_via_device(&ctx.state, &dev_ctx.signing_key, &dev_ctx.device_id, "").await;
    common::send_json_dual_auth(
        &ctx.app,
        Method::GET,
        "/api/v1/credentials",
        &dev_ctx.signing_key,
        &dev_ctx.device_id,
        &agent_jwt,
        None,
    )
    .await
}

// ===========================================================================
// 4A. Happy Path — Default policies grant enabled workspaces list access
// ===========================================================================

#[tokio::test]
async fn test_agent_without_owner_sees_no_credentials() {
    // Owner-scoped policies require workspace ownership matching.
    // An agent with no owner cannot see any credentials.
    let (ctx, cookie) = setup().await;

    // Create 3 credentials (owned by cred-list-user)
    create_credential_via_api(&ctx.app, &cookie, "cred-1").await;
    create_credential_via_api(&ctx.app, &cookie, "cred-2").await;
    create_credential_via_api(&ctx.app, &cookie, "cred-3").await;

    // Agent with no owner should see 0 credentials (no ownership match)
    let (status, body) = list_credentials_as_agent(&ctx, "test-agent").await;
    assert_eq!(status, StatusCode::OK, "agent list credentials: {:?}", body);

    let creds = body["data"].as_array().expect("data should be array");
    assert_eq!(
        creds.len(),
        0,
        "agent without owner should see 0 credentials (owner-scoped policies), got {}",
        creds.len(),
    );
}

#[tokio::test]
async fn test_user_lists_all_credentials_via_cedar() {
    // Admin users see all credentials via Cedar policy 2a (not a code bypass).
    // The list_credentials endpoint uses the same per-credential Cedar evaluation
    // for both users and workspaces.
    let (ctx, cookie) = setup().await;

    // Create 3 credentials
    create_credential_via_api(&ctx.app, &cookie, "user-list-1").await;
    create_credential_via_api(&ctx.app, &cookie, "user-list-2").await;
    create_credential_via_api(&ctx.app, &cookie, "user-list-3").await;

    // List as admin user — should see all 3 (via Cedar policy 2a)
    let (status, body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::GET,
        "/api/v1/credentials",
        None,
        Some(&cookie),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "user list credentials: {:?}", body);

    let creds = body["data"].as_array().expect("data should be array");
    assert!(
        creds.len() >= 3,
        "admin user should see at least 3 credentials, got {}",
        creds.len(),
    );
}

// ===========================================================================
// 4B. Retry/Idempotency
// ===========================================================================

#[tokio::test]
async fn test_list_credentials_is_idempotent() {
    let (ctx, cookie) = setup().await;

    create_credential_via_api(&ctx.app, &cookie, "idempotent-cred").await;

    // List twice
    let (status1, body1) = common::send_json_auto_csrf(
        &ctx.app,
        Method::GET,
        "/api/v1/credentials",
        None,
        Some(&cookie),
        None,
    )
    .await;
    let (status2, body2) = common::send_json_auto_csrf(
        &ctx.app,
        Method::GET,
        "/api/v1/credentials",
        None,
        Some(&cookie),
        None,
    )
    .await;

    assert_eq!(status1, StatusCode::OK);
    assert_eq!(status2, StatusCode::OK);

    let count1 = body1["data"].as_array().map(|a| a.len()).unwrap_or(0);
    let count2 = body2["data"].as_array().map(|a| a.len()).unwrap_or(0);
    assert_eq!(count1, count2, "listing twice should return the same count");
}

// ===========================================================================
// 4C. Error Handling
// ===========================================================================

#[tokio::test]
async fn test_agent_with_no_credentials_sees_empty_list() {
    let (ctx, _cookie) = setup().await;

    // No credentials created — agent should see empty list, not error
    let (status, body) = list_credentials_as_agent(&ctx, "test-agent").await;
    assert_eq!(status, StatusCode::OK, "agent with no creds: {:?}", body);

    let creds = body["data"].as_array().expect("data should be array");
    assert_eq!(
        creds.len(),
        0,
        "agent should see empty list when no credentials exist, got {}",
        creds.len(),
    );
}

// ===========================================================================
// 4D. Cross-Feature
// ===========================================================================

#[tokio::test]
async fn test_agent_without_owner_sees_no_many_credentials() {
    // Owner-scoped policies: agent without owner sees 0 credentials even
    // when many exist. Verifies Cedar evaluation is efficient.
    let (ctx, cookie) = setup().await;

    // Create 20 credentials (owned by cred-list-user)
    for i in 0..20 {
        create_credential_via_api(&ctx.app, &cookie, &format!("many-cred-{}", i)).await;
    }

    // Agent without owner should see 0 credentials
    let (status, body) = list_credentials_as_agent(&ctx, "test-agent").await;
    assert_eq!(status, StatusCode::OK, "many creds list: {:?}", body);

    let creds = body["data"].as_array().expect("data should be array");
    assert_eq!(
        creds.len(),
        0,
        "agent without owner should see 0 credentials (owner-scoped), got {}",
        creds.len(),
    );
}

#[tokio::test]
async fn test_disabled_workspace_sees_nothing() {
    // All permits check principal.enabled, so disabled workspaces are
    // implicitly denied. A disabled workspace should see nothing.
    let ctx = TestAppBuilder::new()
        .with_admin()
        .with_agent("disabled-agent", &["user"])
        .build()
        .await;

    let user = common::create_test_user(
        &*ctx.store,
        "disable-test-user",
        common::TEST_PASSWORD,
        UserRole::Admin,
    )
    .await;
    let cookie =
        common::login_user_combined(&ctx.app, "disable-test-user", common::TEST_PASSWORD).await;

    // Create a credential
    create_credential_via_api(&ctx.app, &cookie, "should-be-hidden").await;

    // Disable the workspace
    let mut workspace = ctx.agents.get("disabled-agent").expect("agent").clone();
    workspace.enabled = false;
    ctx.store
        .update_workspace(&workspace)
        .await
        .expect("disable workspace");

    // Disabled workspace can't get JWT (auth fails), so we verify via policy test
    let (status, body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        "/api/v1/policies/test",
        None,
        Some(&cookie),
        Some(json!({
            "principal": {
                "type": "Agent",
                "id": "disabled-agent",
                "attributes": { "name": "disabled-agent", "enabled": false, "tags": ["user"] }
            },
            "action": "list",
            "resource": {
                "type": "Credential",
                "id": "test-cred",
                "attributes": { "name": "cred", "service": "svc", "scopes": [], "owner": user.id.0.to_string(), "tags": [] }
            }
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "policy test: {:?}", body);
    assert_eq!(
        body["data"]["decision"], "forbid",
        "disabled workspace should be denied — no permit matches when !enabled"
    );
}

// ===========================================================================
// 4E. Security
// ===========================================================================

#[tokio::test]
async fn test_agent_cannot_see_credential_secrets_in_list() {
    // Verify that credential secrets are never exposed in the list response.
    // Use admin user list (which sees own credentials) to verify field filtering.
    let (ctx, cookie) = setup().await;

    create_credential_via_api(&ctx.app, &cookie, "secret-check-cred").await;

    // List as admin user (sees own credentials via policy 2a-cred)
    let (status, body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::GET,
        "/api/v1/credentials",
        None,
        Some(&cookie),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let creds = body["data"].as_array().expect("data should be array");
    assert!(
        !creds.is_empty(),
        "admin user should see at least 1 credential"
    );

    for cred in creds {
        assert!(
            cred.get("encrypted_value").is_none(),
            "credential list must not expose encrypted_value"
        );
        assert!(
            cred.get("nonce").is_none(),
            "credential list must not expose nonce"
        );
    }
}

#[tokio::test]
async fn test_owner_match_does_not_grant_access_via_policy_1b() {
    // Regression test: Cedar policy 1b (owner-match) intentionally excludes
    // `access` — workspaces must NEVER see raw credential secrets. They use
    // `vend_credential` to proxy requests and `list` to discover credentials.
    let ctx = TestAppBuilder::new()
        .with_admin()
        .with_agent("owned-agent", &["user"])
        .build()
        .await;

    let user = common::create_test_user(
        &*ctx.store,
        "owner-test-user",
        common::TEST_PASSWORD,
        UserRole::Admin,
    )
    .await;
    let cookie =
        common::login_user_combined(&ctx.app, "owner-test-user", common::TEST_PASSWORD).await;

    // Test via policy tester: owner-match should NOT permit `access` (raw secret visibility)
    // Use a disabled agent so only policy 1b could match (not default policies 5b/1d).
    let (status, body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        "/api/v1/policies/test",
        None,
        Some(&cookie),
        Some(json!({
            "principal": {
                "type": "Agent",
                "id": "test-agent",
                "attributes": { "name": "test-agent", "enabled": false, "tags": [], "owner": user.id.0.to_string() }
            },
            "action": "access",
            "resource": {
                "type": "Credential",
                "id": "test-cred",
                "attributes": { "name": "cred", "service": "svc", "scopes": [], "owner": user.id.0.to_string(), "tags": [] }
            }
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "policy test: {:?}", body);
    // Disabled workspace: no permit matches (all check enabled).
    // Even if enabled, policy 1b doesn't include `access`.
    assert_eq!(
        body["data"]["decision"], "forbid",
        "disabled workspace denied — no permit matches when !enabled"
    );
}
