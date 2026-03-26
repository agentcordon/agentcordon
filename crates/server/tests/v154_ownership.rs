//! Integration tests for Feature 1: Owner-Based Credential Access.
//!
//! Tests that the Cedar ownership rule `resource.owner == principal.owner`
//! correctly scopes credential listing, vending, detail access, and updates.
//! Validates admin override, disabled agent forbid, delegated_use grants,
//! and audit events.

use crate::common::*;

use axum::http::{Method, StatusCode};
use serde_json::json;

use agent_cordon_core::domain::user::UserRole;
use agent_cordon_server::test_helpers::TestAppBuilder;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Create a user, an agent owned by that user, bind agent to a device, get JWT.
/// Returns (user, agent, api_key, device_id, device_signing_key, agent_jwt).
async fn setup_user_agent(
    state: &agent_cordon_server::state::AppState,
    username: &str,
) -> (
    agent_cordon_core::domain::user::User,
    agent_cordon_core::domain::agent::Agent,
    String,
    String,
    p256::ecdsa::SigningKey,
    String,
) {
    let user = create_test_user(&*state.store, username, TEST_PASSWORD, UserRole::Admin).await;
    // Generate encryption keypair so vend_credential can ECIES-encrypt to this workspace
    let (_enc_key, enc_jwk) = generate_p256_keypair_jwk();
    let enc_jwk_str = serde_json::to_string(&enc_jwk).unwrap();
    let now = chrono::Utc::now();
    let agent = agent_cordon_core::domain::agent::Agent {
        id: agent_cordon_core::domain::workspace::WorkspaceId(uuid::Uuid::new_v4()),
        name: format!("{}-agent", username),
        enabled: true,
        status: agent_cordon_core::domain::workspace::WorkspaceStatus::Active,
        pk_hash: None,
        encryption_public_key: Some(enc_jwk_str),
        tags: vec![],
        owner_id: Some(user.id.clone()),
        parent_id: None,
        tool_name: None,
        created_at: now,
        updated_at: now,
    };
    state
        .store
        .create_workspace(&agent)
        .await
        .expect("create workspace");
    let api_key = String::new();
    let (device_id, sig_key) = create_device_and_bind_agent(state, &agent).await;
    let jwt = get_jwt_via_device(state, &sig_key, &device_id, &api_key).await;
    (user, agent, api_key, device_id, sig_key, jwt)
}

/// Create a credential via admin session auth. Returns credential id.
async fn create_credential_via_session(
    app: &axum::Router,
    cookie: &str,
    csrf: &str,
    name: &str,
    service: &str,
) -> String {
    let (status, body) = send_json(
        app,
        Method::POST,
        "/api/v1/credentials",
        None,
        Some(cookie),
        Some(csrf),
        Some(json!({
            "name": name,
            "service": service,
            "secret_value": "test-secret-value"
        })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "create credential '{}': {}",
        name,
        body
    );
    body["data"]["id"].as_str().unwrap().to_string()
}

// ===========================================================================
// 1A. Owner-Scoped Credential Listing
// ===========================================================================

#[tokio::test]
async fn test_agent_can_list_own_credentials() {
    // Default Cedar policy 5b grants all enabled workspaces `list` access.
    // Agent sees credentials via default policy, not owner-match (policy 1b
    // intentionally excludes `list`).
    let ctx = TestAppBuilder::new().build().await;
    let (_u1, _a1, _key1, dev1_id, dev1_key, jwt1) = setup_user_agent(&ctx.state, "u1").await;

    // U1 creates a credential via session
    let (cookie, csrf) = login_user(&ctx.app, "u1", TEST_PASSWORD).await;
    let full_cookie = combined_cookie(&cookie, &csrf);
    let cred_id =
        create_credential_via_session(&ctx.app, &full_cookie, &csrf, "u1-cred", "svc1").await;

    // A1 lists credentials — should see credential via default policy 5b
    let (status, body) = send_json_dual_auth(
        &ctx.app,
        Method::GET,
        "/api/v1/credentials",
        &dev1_key,
        &dev1_id,
        &jwt1,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "list: {}", body);
    let creds = body["data"].as_array().expect("data must be array");
    assert!(
        creds.iter().any(|c| c["id"].as_str() == Some(&cred_id)),
        "A1 should see credential via default policy"
    );
}

#[tokio::test]
async fn test_agent_cannot_list_other_owners_credentials() {
    // Owner-scoped policies prevent agents from seeing other users' credentials.
    // A1 (owned by U1) should NOT see credentials created by U2.
    let ctx = TestAppBuilder::new().build().await;
    let (_u1, _a1, _key1, dev1_id, dev1_key, jwt1) = setup_user_agent(&ctx.state, "u1-list").await;
    let (_u2, _a2, _key2, _dev2_id, _dev2_key, _jwt2) =
        setup_user_agent(&ctx.state, "u2-list").await;

    // U2 creates a credential
    let (cookie2, csrf2) = login_user(&ctx.app, "u2-list", TEST_PASSWORD).await;
    let full_cookie2 = combined_cookie(&cookie2, &csrf2);
    let _cred_id =
        create_credential_via_session(&ctx.app, &full_cookie2, &csrf2, "u2-cred", "svc2").await;

    // A1 should NOT see U2's credential (owner-scoped policies)
    let (status, body) = send_json_dual_auth(
        &ctx.app,
        Method::GET,
        "/api/v1/credentials",
        &dev1_key,
        &dev1_id,
        &jwt1,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "list: {}", body);
    let creds = body["data"].as_array().expect("data must be array");
    assert!(
        !creds.iter().any(|c| c["id"].as_str() == Some(&_cred_id)),
        "agent should NOT see other owner's credential (owner-scoped policies)"
    );
}

#[tokio::test]
async fn test_agents_only_see_own_owners_credentials() {
    // Owner-scoped policies: each agent only sees credentials belonging to its owner.
    // A1 (owned by U1) sees only C1, A2 (owned by U2) sees only C2.
    let ctx = TestAppBuilder::new().build().await;
    let (_u1, _a1, _key1, dev1_id, dev1_key, jwt1) = setup_user_agent(&ctx.state, "u1-mix").await;
    let (_u2, _a2, _key2, dev2_id, dev2_key, jwt2) = setup_user_agent(&ctx.state, "u2-mix").await;

    // U1 creates C1, U2 creates C2
    let (cookie1, csrf1) = login_user(&ctx.app, "u1-mix", TEST_PASSWORD).await;
    let full_cookie1 = combined_cookie(&cookie1, &csrf1);
    let c1_id =
        create_credential_via_session(&ctx.app, &full_cookie1, &csrf1, "c1-mix", "svc1").await;

    let (cookie2, csrf2) = login_user(&ctx.app, "u2-mix", TEST_PASSWORD).await;
    let full_cookie2 = combined_cookie(&cookie2, &csrf2);
    let c2_id =
        create_credential_via_session(&ctx.app, &full_cookie2, &csrf2, "c2-mix", "svc2").await;

    // A1 lists — sees only C1 (owned by U1), NOT C2
    let (status, body) = send_json_dual_auth(
        &ctx.app,
        Method::GET,
        "/api/v1/credentials",
        &dev1_key,
        &dev1_id,
        &jwt1,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let creds = body["data"].as_array().unwrap();
    assert!(
        creds.iter().any(|c| c["id"].as_str() == Some(&c1_id)),
        "A1 sees own C1"
    );
    assert!(
        !creds.iter().any(|c| c["id"].as_str() == Some(&c2_id)),
        "A1 does NOT see C2"
    );

    // A2 lists — sees only C2 (owned by U2), NOT C1
    let (status, body) = send_json_dual_auth(
        &ctx.app,
        Method::GET,
        "/api/v1/credentials",
        &dev2_key,
        &dev2_id,
        &jwt2,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let creds = body["data"].as_array().unwrap();
    assert!(
        creds.iter().any(|c| c["id"].as_str() == Some(&c2_id)),
        "A2 sees own C2"
    );
    assert!(
        !creds.iter().any(|c| c["id"].as_str() == Some(&c1_id)),
        "A2 does NOT see C1"
    );
}

#[tokio::test]
async fn test_agent_with_no_owner_sees_empty_credential_list() {
    // Owner-scoped policies require workspace ownership matching.
    // An agent with no owner cannot see any credentials.
    let ctx = TestAppBuilder::new().build().await;

    // Create a user who creates a credential
    let _user = create_test_user(&*ctx.store, "owner-user", TEST_PASSWORD, UserRole::Admin).await;
    let (cookie, csrf) = login_user(&ctx.app, "owner-user", TEST_PASSWORD).await;
    let full_cookie = combined_cookie(&cookie, &csrf);
    let _cred_id =
        create_credential_via_session(&ctx.app, &full_cookie, &csrf, "owned-cred", "svc").await;

    // Create an agent with NO owner
    let (agent, api_key) =
        create_agent_in_db(&*ctx.store, "no-owner-agent", vec![], true, None).await;
    let (dev_id, dev_key) = create_device_and_bind_agent(&ctx.state, &agent).await;
    let jwt = get_jwt_via_device(&ctx.state, &dev_key, &dev_id, &api_key).await;

    // Ownerless agent should see empty credential list
    let (status, body) = send_json_dual_auth(
        &ctx.app,
        Method::GET,
        "/api/v1/credentials",
        &dev_key,
        &dev_id,
        &jwt,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let creds = body["data"].as_array().unwrap();
    assert!(
        creds.is_empty(),
        "ownerless agent should see empty credential list (owner-scoped policies)"
    );
}

// ===========================================================================
// 1B. Owner-Scoped Credential Vending
// ===========================================================================

#[tokio::test]
async fn test_agent_can_vend_own_credential() {
    let ctx = TestAppBuilder::new().build().await;
    let (_u1, _a1, _key1, dev1_id, dev1_key, jwt1) = setup_user_agent(&ctx.state, "u1-vend").await;

    // U1 creates credential
    let (cookie, csrf) = login_user(&ctx.app, "u1-vend", TEST_PASSWORD).await;
    let full_cookie = combined_cookie(&cookie, &csrf);
    let cred_id =
        create_credential_via_session(&ctx.app, &full_cookie, &csrf, "vend-cred", "svc1").await;

    // A1 vends own credential — should succeed
    let (status, body) = send_json_dual_auth(
        &ctx.app,
        Method::POST,
        &format!("/api/v1/credentials/{}/vend", cred_id),
        &dev1_key,
        &dev1_id,
        &jwt1,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "vend own credential: {}", body);
}

#[tokio::test]
async fn test_agent_cannot_vend_other_owners_credential() {
    let ctx = TestAppBuilder::new().build().await;
    let (_u1, _a1, _key1, dev1_id, dev1_key, jwt1) =
        setup_user_agent(&ctx.state, "u1-novend").await;
    let (_u2, _a2, _key2, _dev2_id, _dev2_key, _jwt2) =
        setup_user_agent(&ctx.state, "u2-novend").await;

    // U2 creates credential
    let (cookie2, csrf2) = login_user(&ctx.app, "u2-novend", TEST_PASSWORD).await;
    let full_cookie2 = combined_cookie(&cookie2, &csrf2);
    let cred_id =
        create_credential_via_session(&ctx.app, &full_cookie2, &csrf2, "u2-vend-cred", "svc2")
            .await;

    // v1.15.0: vend_credential requires explicit grants or ownership match.
    // Cross-owner vend without grants → deny.
    let (status, body) = send_json_dual_auth(
        &ctx.app,
        Method::POST,
        &format!("/api/v1/credentials/{}/vend", cred_id),
        &dev1_key,
        &dev1_id,
        &jwt1,
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "cross-owner vend without grants should be denied: {}",
        body
    );
}

#[tokio::test]
async fn test_admin_agent_can_vend_any_credential() {
    let ctx = TestAppBuilder::new().build().await;
    let (_u2, _a2, _key2, _dev2_id, _dev2_key, _jwt2) =
        setup_user_agent(&ctx.state, "u2-admin-vend").await;

    // U2 creates credential
    let (cookie2, csrf2) = login_user(&ctx.app, "u2-admin-vend", TEST_PASSWORD).await;
    let full_cookie2 = combined_cookie(&cookie2, &csrf2);
    let cred_id =
        create_credential_via_session(&ctx.app, &full_cookie2, &csrf2, "any-vend-cred", "svc2")
            .await;

    // Create admin agent (tags: ["admin"]) with encryption key — should bypass ownership
    let (_enc_key_admin, enc_jwk_admin) = generate_p256_keypair_jwk();
    let enc_jwk_admin_str = serde_json::to_string(&enc_jwk_admin).unwrap();
    let now_admin = chrono::Utc::now();
    let admin_agent = agent_cordon_core::domain::workspace::Workspace {
        id: agent_cordon_core::domain::workspace::WorkspaceId(uuid::Uuid::new_v4()),
        name: "admin-vend-agent".to_string(),
        enabled: true,
        status: agent_cordon_core::domain::workspace::WorkspaceStatus::Active,
        pk_hash: None,
        encryption_public_key: Some(enc_jwk_admin_str),
        tags: vec!["admin".to_string()],
        owner_id: None,
        parent_id: None,
        tool_name: None,
        created_at: now_admin,
        updated_at: now_admin,
    };
    ctx.store
        .create_workspace(&admin_agent)
        .await
        .expect("create admin workspace");
    let (admin_dev_id, admin_dev_key) =
        create_device_and_bind_agent(&ctx.state, &admin_agent).await;
    let admin_jwt = get_jwt_via_device(&ctx.state, &admin_dev_key, &admin_dev_id, "").await;

    let (status, body) = send_json_dual_auth(
        &ctx.app,
        Method::POST,
        &format!("/api/v1/credentials/{}/vend", cred_id),
        &admin_dev_key,
        &admin_dev_id,
        &admin_jwt,
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "admin agent should vend any credential: {}",
        body
    );
}

// ===========================================================================
// 1C. Cedar Policy Evaluation for Ownership
// ===========================================================================

#[tokio::test]
async fn test_owner_match_grants_vend_and_list() {
    let ctx = TestAppBuilder::new().build().await;
    let admin = create_test_user(&*ctx.store, "admin-policy", TEST_PASSWORD, UserRole::Admin).await;
    let (cookie, csrf) = login_user(&ctx.app, "admin-policy", TEST_PASSWORD).await;
    let full_cookie = combined_cookie(&cookie, &csrf);

    let user_id = admin.id.0.to_string();

    // Test vend_credential with owner match
    let (status, body) = send_json(
        &ctx.app,
        Method::POST,
        "/api/v1/policies/test",
        None,
        Some(&full_cookie),
        Some(&csrf),
        Some(json!({
            "principal": {
                "type": "Agent",
                "id": "test-owner-agent",
                "attributes": { "name": "owner-agent", "enabled": true, "tags": [], "owner": user_id }
            },
            "action": "vend_credential",
            "resource": {
                "type": "Credential",
                "id": "test-cred",
                "attributes": { "name": "cred", "service": "svc", "scopes": [], "owner": user_id, "tags": [] }
            }
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "policy test: {}", body);
    assert_eq!(
        body["data"]["decision"], "permit",
        "owner match should permit vend_credential"
    );

    // Test list with owner match — permitted via default policy 5b (not owner-match 1b)
    let (status, body) = send_json(
        &ctx.app,
        Method::POST,
        "/api/v1/policies/test",
        None,
        Some(&full_cookie),
        Some(&csrf),
        Some(json!({
            "principal": {
                "type": "Agent",
                "id": "test-owner-agent",
                "attributes": { "name": "owner-agent", "enabled": true, "tags": [], "owner": user_id }
            },
            "action": "list",
            "resource": {
                "type": "Credential",
                "id": "test-cred",
                "attributes": { "name": "cred", "service": "svc", "scopes": [], "owner": user_id, "tags": [] }
            }
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "policy test: {}", body);
    assert_eq!(
        body["data"]["decision"], "permit",
        "enabled workspace should be allowed to list via default policy 5b"
    );
}

#[tokio::test]
async fn test_owner_mismatch_denies_vend_and_list() {
    let ctx = TestAppBuilder::new().build().await;
    let _admin = create_test_user(
        &*ctx.store,
        "admin-mismatch",
        TEST_PASSWORD,
        UserRole::Admin,
    )
    .await;
    let (cookie, csrf) = login_user(&ctx.app, "admin-mismatch", TEST_PASSWORD).await;
    let full_cookie = combined_cookie(&cookie, &csrf);

    let (status, body) = send_json(
        &ctx.app,
        Method::POST,
        "/api/v1/policies/test",
        None,
        Some(&full_cookie),
        Some(&csrf),
        Some(json!({
            "principal": {
                "type": "Agent",
                "id": "agent-a",
                "attributes": { "name": "a", "enabled": true, "tags": [], "owner": "user-1" }
            },
            "action": "vend_credential",
            "resource": {
                "type": "Credential",
                "id": "cred-b",
                "attributes": { "name": "b", "service": "svc", "scopes": [], "owner": "user-2", "tags": [] }
            }
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "policy test: {}", body);
    // v1.15.0: vend_credential requires explicit grants or ownership match.
    assert_eq!(
        body["data"]["decision"], "deny",
        "vend with ownership mismatch and no grants should deny"
    );

    let (status, body) = send_json(
        &ctx.app,
        Method::POST,
        "/api/v1/policies/test",
        None,
        Some(&full_cookie),
        Some(&csrf),
        Some(json!({
            "principal": {
                "type": "Agent",
                "id": "agent-a",
                "attributes": { "name": "a", "enabled": true, "tags": [], "owner": "user-1" }
            },
            "action": "list",
            "resource": {
                "type": "Credential",
                "id": "cred-b",
                "attributes": { "name": "b", "service": "svc", "scopes": [], "owner": "user-2", "tags": [] }
            }
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "policy test: {}", body);
    // Without blanket policy 5b, ownership mismatch denies list too.
    assert_eq!(
        body["data"]["decision"], "deny",
        "ownership mismatch without grants should deny list"
    );
}

#[tokio::test]
async fn test_forbid_disabled_agent_overrides_ownership() {
    let ctx = TestAppBuilder::new().build().await;
    let user = create_test_user(&*ctx.store, "u1-disabled", TEST_PASSWORD, UserRole::Admin).await;

    // Create disabled agent with owner
    let (agent, _api_key) = create_agent_in_db(
        &*ctx.store,
        "disabled-owner-agent",
        vec![],
        false, // disabled
        Some(user.id.clone()),
    )
    .await;
    let (_dev_id, _dev_key) = create_device_and_bind_agent(&ctx.state, &agent).await;

    // Create credential owned by same user
    let (cookie, csrf) = login_user(&ctx.app, "u1-disabled", TEST_PASSWORD).await;
    let full_cookie = combined_cookie(&cookie, &csrf);
    let cred_id =
        create_credential_via_session(&ctx.app, &full_cookie, &csrf, "disabled-cred", "svc").await;

    // Disabled agent can't get JWT (token exchange should fail or vend should fail)
    // The agent is disabled, so token exchange may reject it.
    // Let's test via the policy test endpoint instead.
    let (status, body) = send_json(
        &ctx.app,
        Method::POST,
        "/api/v1/policies/test",
        None,
        Some(&full_cookie),
        Some(&csrf),
        Some(json!({
            "principal": {
                "type": "Agent",
                "id": "disabled-agent",
                "attributes": { "name": "disabled", "enabled": false, "tags": [], "owner": user.id.0.to_string() }
            },
            "action": "vend_credential",
            "resource": {
                "type": "Credential",
                "id": &cred_id,
                "attributes": { "name": "disabled-cred", "service": "svc", "scopes": [], "owner": user.id.0.to_string(), "tags": [] }
            }
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "policy test: {}", body);
    assert_eq!(
        body["data"]["decision"], "forbid",
        "disabled agent should be forbidden even with owner match"
    );
}

#[tokio::test]
async fn test_explicit_delegated_use_grant_overrides_ownership() {
    let ctx = TestAppBuilder::new().build().await;
    let (_u1, a1, _key1, dev1_id, dev1_key, jwt1) = setup_user_agent(&ctx.state, "u1-deleg").await;
    let (_u2, _a2, _key2, _dev2_id, _dev2_key, _jwt2) =
        setup_user_agent(&ctx.state, "u2-deleg").await;

    // U2 creates credential
    let (cookie2, csrf2) = login_user(&ctx.app, "u2-deleg", TEST_PASSWORD).await;
    let full_cookie2 = combined_cookie(&cookie2, &csrf2);
    let cred_id =
        create_credential_via_session(&ctx.app, &full_cookie2, &csrf2, "deleg-cred", "svc").await;

    // Grant A1 delegated_use on U2's credential via Cedar grant policy
    let cred_uuid = uuid::Uuid::parse_str(&cred_id).unwrap();
    grant_cedar_permission(
        &ctx.state,
        &agent_cordon_core::domain::credential::CredentialId(cred_uuid),
        &a1.id,
        "delegated_use",
    )
    .await;

    // A1 vends U2's credential — should succeed via delegated_use grant
    let (status, body) = send_json_dual_auth(
        &ctx.app,
        Method::POST,
        &format!("/api/v1/credentials/{}/vend", cred_id),
        &dev1_key,
        &dev1_id,
        &jwt1,
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "delegated_use should override ownership: {}",
        body
    );
}

// ===========================================================================
// 1D. Credential Detail and Update Scoping
// ===========================================================================

#[tokio::test]
async fn test_agent_can_get_detail_of_own_credential() {
    // Default Cedar policy 5b grants `list` (which also controls detail view).
    // Enabled workspaces can view credential details for all credentials.
    let ctx = TestAppBuilder::new().build().await;
    let (_u1, _a1, _key1, dev1_id, dev1_key, jwt1) =
        setup_user_agent(&ctx.state, "u1-detail").await;

    let (cookie, csrf) = login_user(&ctx.app, "u1-detail", TEST_PASSWORD).await;
    let full_cookie = combined_cookie(&cookie, &csrf);
    let cred_id =
        create_credential_via_session(&ctx.app, &full_cookie, &csrf, "detail-cred", "svc").await;

    let (status, body) = send_json_dual_auth(
        &ctx.app,
        Method::GET,
        &format!("/api/v1/credentials/{}", cred_id),
        &dev1_key,
        &dev1_id,
        &jwt1,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "get credential detail: {}", body);
    assert_eq!(body["data"]["id"].as_str(), Some(cred_id.as_str()));
}

#[tokio::test]
async fn test_agent_cannot_get_detail_of_other_owners_credential() {
    // Owner-scoped policies prevent agents from viewing other users' credential details.
    let ctx = TestAppBuilder::new().build().await;
    let (_u1, _a1, _key1, dev1_id, dev1_key, jwt1) =
        setup_user_agent(&ctx.state, "u1-nodetail").await;
    let (_u2, _a2, _key2, _dev2_id, _dev2_key, _jwt2) =
        setup_user_agent(&ctx.state, "u2-nodetail").await;

    let (cookie2, csrf2) = login_user(&ctx.app, "u2-nodetail", TEST_PASSWORD).await;
    let full_cookie2 = combined_cookie(&cookie2, &csrf2);
    let cred_id =
        create_credential_via_session(&ctx.app, &full_cookie2, &csrf2, "nodetail-cred", "svc")
            .await;

    let (status, _body) = send_json_dual_auth(
        &ctx.app,
        Method::GET,
        &format!("/api/v1/credentials/{}", cred_id),
        &dev1_key,
        &dev1_id,
        &jwt1,
        None,
    )
    .await;
    // Owner-scoped policies deny cross-owner credential detail access.
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "agent should NOT view other owner's credential detail"
    );
}

#[tokio::test]
async fn test_agent_can_update_own_credential() {
    let ctx = TestAppBuilder::new().build().await;
    let (_u1, _a1, _key1, dev1_id, dev1_key, jwt1) =
        setup_user_agent(&ctx.state, "u1-update").await;

    let (cookie, csrf) = login_user(&ctx.app, "u1-update", TEST_PASSWORD).await;
    let full_cookie = combined_cookie(&cookie, &csrf);
    let cred_id =
        create_credential_via_session(&ctx.app, &full_cookie, &csrf, "update-cred", "svc").await;

    let (status, body) = send_json_dual_auth(
        &ctx.app,
        Method::PUT,
        &format!("/api/v1/credentials/{}", cred_id),
        &dev1_key,
        &dev1_id,
        &jwt1,
        Some(json!({ "name": "updated-cred-name" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "update own credential: {}", body);
}

#[tokio::test]
async fn test_agent_cannot_update_other_owners_credential() {
    let ctx = TestAppBuilder::new().build().await;
    let (_u1, _a1, _key1, dev1_id, dev1_key, jwt1) =
        setup_user_agent(&ctx.state, "u1-noupdate").await;
    let (_u2, _a2, _key2, _dev2_id, _dev2_key, _jwt2) =
        setup_user_agent(&ctx.state, "u2-noupdate").await;

    let (cookie2, csrf2) = login_user(&ctx.app, "u2-noupdate", TEST_PASSWORD).await;
    let full_cookie2 = combined_cookie(&cookie2, &csrf2);
    let cred_id =
        create_credential_via_session(&ctx.app, &full_cookie2, &csrf2, "noupdate-cred", "svc")
            .await;

    let (status, _body) = send_json_dual_auth(
        &ctx.app,
        Method::PUT,
        &format!("/api/v1/credentials/{}", cred_id),
        &dev1_key,
        &dev1_id,
        &jwt1,
        Some(json!({ "name": "stolen-update" })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "should deny cross-owner update (got {})",
        status
    );
}

// ===========================================================================
// 1E. Audit Trail
// ===========================================================================

#[tokio::test]
async fn test_owner_scoped_vend_creates_audit_event() {
    let ctx = TestAppBuilder::new().build().await;
    let (_u1, _a1, _key1, dev1_id, dev1_key, jwt1) =
        setup_user_agent(&ctx.state, "u1-audit-vend").await;

    let (cookie, csrf) = login_user(&ctx.app, "u1-audit-vend", TEST_PASSWORD).await;
    let full_cookie = combined_cookie(&cookie, &csrf);
    let cred_id =
        create_credential_via_session(&ctx.app, &full_cookie, &csrf, "audit-vend-cred", "svc")
            .await;

    // A1 vends own credential
    let (status, _body) = send_json_dual_auth(
        &ctx.app,
        Method::POST,
        &format!("/api/v1/credentials/{}/vend", cred_id),
        &dev1_key,
        &dev1_id,
        &jwt1,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Check audit log
    let events = ctx
        .store
        .list_audit_events(100, 0)
        .await
        .expect("list audit events");
    let vend_event = events.iter().find(|e| {
        e.action == "vend_credential"
            && e.resource_id.as_deref() == Some(&cred_id)
            && matches!(
                e.decision,
                agent_cordon_core::domain::audit::AuditDecision::Permit
            )
    });
    assert!(
        vend_event.is_some(),
        "audit log should contain a vend_credential Allow event"
    );
}

#[tokio::test]
async fn test_cross_owner_vend_denial_creates_audit_event() {
    let ctx = TestAppBuilder::new().build().await;
    let (_u1, _a1, _key1, dev1_id, dev1_key, jwt1) =
        setup_user_agent(&ctx.state, "u1-audit-deny").await;
    let (_u2, _a2, _key2, _dev2_id, _dev2_key, _jwt2) =
        setup_user_agent(&ctx.state, "u2-audit-deny").await;

    let (cookie2, csrf2) = login_user(&ctx.app, "u2-audit-deny", TEST_PASSWORD).await;
    let full_cookie2 = combined_cookie(&cookie2, &csrf2);
    let cred_id =
        create_credential_via_session(&ctx.app, &full_cookie2, &csrf2, "audit-deny-cred", "svc")
            .await;

    // v1.15.0: vend_credential requires explicit grants or ownership match.
    // Cross-owner vend without grants → deny with audit event.
    let (status, _body) = send_json_dual_auth(
        &ctx.app,
        Method::POST,
        &format!("/api/v1/credentials/{}/vend", cred_id),
        &dev1_key,
        &dev1_id,
        &jwt1,
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "cross-owner vend without grants should be denied"
    );

    // Check audit log for deny event
    let events = ctx
        .store
        .list_audit_events(100, 0)
        .await
        .expect("list audit events");
    let vend_event = events.iter().find(|e| {
        e.action == "vend_credential"
            && e.resource_id.as_deref() == Some(&cred_id)
            && matches!(
                e.decision,
                agent_cordon_core::domain::audit::AuditDecision::Forbid
            )
    });
    assert!(
        vend_event.is_some(),
        "audit log should contain a vend_credential Deny event"
    );
}
