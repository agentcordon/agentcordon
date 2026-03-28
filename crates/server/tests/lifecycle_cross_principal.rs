//! Cross-Principal Lifecycle E2E Integration Tests
//!
//! Tests interactions across principal types (Agent, Device):
//! - Agent created -> gets JWT via device
//! - Device created and enrolled -> full audit trail across identity types
//! - Cross-principal isolation (agent A vs agent B credential access)
//! - Disabled principals across types

use crate::common::*;

use axum::http::{Method, StatusCode};
use serde_json::json;
use uuid::Uuid;

use agent_cordon_core::crypto::SecretEncryptor;
use agent_cordon_core::domain::workspace::{Workspace, WorkspaceId, WorkspaceStatus};
type Agent = Workspace;
use agent_cordon_core::domain::credential::{CredentialId, StoredCredential};
use agent_cordon_core::domain::user::UserRole;
use agent_cordon_core::storage::Store;

use agent_cordon_server::test_helpers::TestAppBuilder;

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

const TEST_PASSWORD: &str = "strong-test-password-123!";

async fn create_agent(
    store: &(dyn Store + Send + Sync),
    name: &str,
    tags: Vec<&str>,
    enabled: bool,
) -> (Agent, String) {
    let now = chrono::Utc::now();
    // Generate encryption key for vend_credential support
    let (_enc_key, enc_jwk) = generate_p256_keypair_jwk();
    let enc_jwk_str = serde_json::to_string(&enc_jwk).unwrap();
    let agent = Agent {
        id: WorkspaceId(Uuid::new_v4()),
        name: name.to_string(),
        enabled,
        status: WorkspaceStatus::Active,
        pk_hash: None,
        encryption_public_key: Some(enc_jwk_str),
        tags: tags.into_iter().map(String::from).collect(),
        owner_id: None,
        parent_id: None,
        tool_name: None,
        created_at: now,
        updated_at: now,
    };
    store.create_workspace(&agent).await.expect("create agent");
    (agent, String::new())
}

async fn store_test_credential(
    state: &agent_cordon_server::state::AppState,
    owner: &Agent,
    name: &str,
    service: &str,
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
        service: service.to_string(),
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
        description: None,
        target_identity: None,
        key_version: 1,
    };
    state
        .store
        .store_credential(&cred)
        .await
        .expect("store credential");

    for perm in &["read", "write", "delete", "delegated_use"] {
        grant_cedar_permission(state, &cred_id, &owner.id, perm).await;
    }

    cred_id
}

async fn get_jwt_da(
    state: &agent_cordon_server::state::AppState,
    agent: &Agent,
    api_key: &str,
) -> (String, String, p256::ecdsa::SigningKey) {
    let (device_id, signing_key) = create_device_and_bind_agent(state, agent).await;
    let jwt = get_jwt_via_device(state, &signing_key, &device_id, api_key).await;
    (jwt, device_id, signing_key)
}

// ===========================================================================
// Test: Golden Path — All Principals
// ===========================================================================

#[tokio::test]
#[ignore = "REMOVED: v2.0 has no device enrollment — test uses /api/v1/devices/enroll"]
async fn test_golden_path_all_principals() {
    let ctx = TestAppBuilder::new()
        .with_admin()
        .with_enrollment()
        .with_policy(&default_policy_no_auto_enroll())
        .build()
        .await;
    let _admin_user = create_test_user(&*ctx.store, "admin", TEST_PASSWORD, UserRole::Admin).await;

    let app = agent_cordon_server::build_router(ctx.state.clone());
    let (cookie, csrf) = login_user(&app, "admin", TEST_PASSWORD).await;
    let full_cookie = combined_cookie(&cookie, &csrf);

    // ---- AGENT: Create directly (enrollment flow removed in v1.13.0) ----
    let (enroll_dev_id, enroll_dev_key) = create_standalone_device(&ctx.state).await;
    let _enroll_dev_uuid: Uuid = enroll_dev_id.parse().unwrap();
    let golden_agent = Agent {
        id: WorkspaceId(Uuid::new_v4()),
        name: "golden-agent".to_string(),
        enabled: true,
        status: WorkspaceStatus::Active,
        pk_hash: None,
        encryption_public_key: None,
        tags: vec!["admin".to_string()],
        owner_id: None,
        parent_id: None,
        tool_name: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };
    ctx.store
        .create_workspace(&golden_agent)
        .await
        .expect("create golden agent");

    let agent_jwt = get_jwt_via_device(&ctx.state, &enroll_dev_key, &enroll_dev_id, "").await;
    assert_eq!(
        agent_jwt.split('.').count(),
        3,
        "agent JWT must have 3 segments"
    );

    // ---- DEVICE: Create and enroll ----
    let app = agent_cordon_server::build_router(ctx.state.clone());
    let (status, body) = send_json(
        &app,
        Method::POST,
        "/api/v1/workspaces",
        None,
        Some(&full_cookie),
        Some(&csrf),
        Some(json!({ "name": "golden-device" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "create device: {}", body);
    let device_id = body["data"]["id"].as_str().unwrap().to_string();
    let bootstrap_token = body["data"]["bootstrap_token"]
        .as_str()
        .unwrap()
        .to_string();

    let (signing_key, jwk) = generate_p256_keypair_jwk();
    let (_enc_key, enc_jwk) = generate_p256_keypair_jwk();

    let app = agent_cordon_server::build_router(ctx.state.clone());
    let (status, body) = send_json(
        &app,
        Method::POST,
        "/api/v1/devices/enroll",
        None,
        None,
        None,
        Some(json!({
            "bootstrap_token": bootstrap_token,
            "signing_key": jwk,
            "encryption_key": enc_jwk
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "enroll device: {}", body);
    assert_eq!(body["data"]["status"], "active");

    // Verify device authentication with self-signed JWT
    let jti = Uuid::new_v4().to_string();
    let device_jwt = sign_device_jwt(&signing_key, &device_id, &jti);

    let (_new_key, new_jwk) = generate_p256_keypair_jwk();
    let app = agent_cordon_server::build_router(ctx.state.clone());
    let (status, body) = send_json(
        &app,
        Method::POST,
        &format!("/api/v1/devices/{}/rotate-key", device_id),
        Some(&device_jwt),
        None,
        None,
        Some(json!({ "new_public_key": new_jwk })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "device auth: {}", body);

    // ---- Verify audit trail spans device principal type ----
    let events = ctx.store.list_audit_events(100, 0).await.unwrap();

    let device_events: Vec<_> = events
        .iter()
        .filter(|e| e.resource_type == "device")
        .collect();

    assert!(
        !device_events.is_empty(),
        "should have device-related audit events"
    );

    // Total events: device create, device enroll, key rotate
    assert!(
        events.len() >= 2,
        "should have at least 2 total audit events, got {}",
        events.len()
    );
}

// ===========================================================================
// Test: Cross-Principal Isolation
// ===========================================================================

#[tokio::test]
async fn test_cross_principal_isolation() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let admin = ctx.admin_agent.clone().unwrap();

    // Create two agents: one with permissions, one without
    let (agent_a, key_a) = create_agent(&*ctx.store, "agent-a", vec!["reader"], true).await;
    let (_agent_b, key_b) = create_agent(&*ctx.store, "agent-b", vec!["reader"], true).await;

    // Store a credential owned by admin, grant agent_a access
    let cred_id = store_test_credential(
        &ctx.state,
        &admin,
        "isolated-cred",
        "test",
        "isolated-secret",
    )
    .await;

    // Grant agent_a delegated_use + read via Cedar grant policies
    grant_cedar_permission(&ctx.state, &cred_id, &agent_a.id, "delegated_use").await;
    grant_cedar_permission(&ctx.state, &cred_id, &agent_a.id, "read").await;

    // Agent A: should be able to vend the credential (Cedar allows vend_credential)
    let (jwt_a, dev_id_a, dev_key_a) = get_jwt_da(&ctx.state, &agent_a, &key_a).await;

    let app = agent_cordon_server::build_router(ctx.state.clone());
    let (status, body) = send_json_dual_auth(
        &app,
        Method::POST,
        &format!("/api/v1/credentials/{}/vend", cred_id.0),
        &dev_key_a,
        &dev_id_a,
        &jwt_a,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "agent_a vend: {}", body);

    // Agent B: should be denied (no Cedar policy for vend_credential)
    let (jwt_b, dev_id_b, dev_key_b) = get_jwt_da(&ctx.state, &_agent_b, &key_b).await;

    let app = agent_cordon_server::build_router(ctx.state.clone());
    let (status, _body) = send_json_dual_auth(
        &app,
        Method::POST,
        &format!("/api/v1/credentials/{}/vend", cred_id.0),
        &dev_key_b,
        &dev_id_b,
        &jwt_b,
        None,
    )
    .await;
    // v1.15.0: vend_credential requires explicit grants or ownership match.
    // Agent B has no grants → vend denied.
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "agent_b without grants should be denied vend"
    );
}

// ===========================================================================
// Test: Disabled Principals Across Types
// ===========================================================================

#[tokio::test]
#[ignore = "REMOVED: v2.0 has no device enrollment — test uses /api/v1/devices/enroll"]
async fn test_disabled_principals_across_types() {
    let ctx = TestAppBuilder::new().build().await;
    let _admin_user = create_test_user(&*ctx.store, "admin", TEST_PASSWORD, UserRole::Admin).await;

    let app = agent_cordon_server::build_router(ctx.state.clone());
    let (cookie, csrf) = login_user(&app, "admin", TEST_PASSWORD).await;
    let full_cookie = combined_cookie(&cookie, &csrf);

    // ---- Agent: Create and disable ----
    let (agent, agent_key) = create_agent(&*ctx.store, "disable-agent", vec!["admin"], true).await;
    let (agent_dev_id, agent_dev_key) = create_device_and_bind_agent(&ctx.state, &agent).await;

    // Verify agent works (whoami via dual auth)
    let agent_jwt_str =
        get_jwt_via_device(&ctx.state, &agent_dev_key, &agent_dev_id, &agent_key).await;
    let app = agent_cordon_server::build_router(ctx.state.clone());
    let (status, _body) = send_json_dual_auth(
        &app,
        Method::GET,
        "/api/v1/auth/whoami",
        &agent_dev_key,
        &agent_dev_id,
        &agent_jwt_str,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "agent should work initially");

    // Disable agent
    let app = agent_cordon_server::build_router(ctx.state.clone());
    let (status, _body) = send_json(
        &app,
        Method::PUT,
        &format!("/api/v1/workspaces/{}", agent.id.0),
        None,
        Some(&full_cookie),
        Some(&csrf),
        Some(json!({ "enabled": false })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "disable agent");

    // Agent should fail (disabled)
    let app = agent_cordon_server::build_router(ctx.state.clone());
    let (status, _body) = send_json_dual_auth(
        &app,
        Method::GET,
        "/api/v1/auth/whoami",
        &agent_dev_key,
        &agent_dev_id,
        &agent_jwt_str,
        None,
    )
    .await;
    assert!(
        status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN,
        "disabled agent should fail, got: {}",
        status
    );

    // Re-enable agent
    let app = agent_cordon_server::build_router(ctx.state.clone());
    let (status, _body) = send_json(
        &app,
        Method::PUT,
        &format!("/api/v1/workspaces/{}", agent.id.0),
        None,
        Some(&full_cookie),
        Some(&csrf),
        Some(json!({ "enabled": true })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "re-enable agent");

    let new_jwt = get_jwt_via_device(&ctx.state, &agent_dev_key, &agent_dev_id, "").await;
    let app = agent_cordon_server::build_router(ctx.state.clone());
    let (status, _body) = send_json_dual_auth(
        &app,
        Method::GET,
        "/api/v1/auth/whoami",
        &agent_dev_key,
        &agent_dev_id,
        &new_jwt,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "re-enabled agent should work");

    // ---- Device: Create, enroll, disable, and test ----
    let app = agent_cordon_server::build_router(ctx.state.clone());
    let (status, body) = send_json(
        &app,
        Method::POST,
        "/api/v1/workspaces",
        None,
        Some(&full_cookie),
        Some(&csrf),
        Some(json!({ "name": "disable-device" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let device_id = body["data"]["id"].as_str().unwrap().to_string();
    let bootstrap_token = body["data"]["bootstrap_token"]
        .as_str()
        .unwrap()
        .to_string();

    let (signing_key, jwk) = generate_p256_keypair_jwk();
    let (_enc_key, enc_jwk) = generate_p256_keypair_jwk();

    let app = agent_cordon_server::build_router(ctx.state.clone());
    let (status, _body) = send_json(
        &app,
        Method::POST,
        "/api/v1/devices/enroll",
        None,
        None,
        None,
        Some(json!({
            "bootstrap_token": bootstrap_token,
            "signing_key": jwk,
            "encryption_key": enc_jwk
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "enroll device");

    // Device auth should work
    let jti = Uuid::new_v4().to_string();
    let jwt = sign_device_jwt(&signing_key, &device_id, &jti);
    let (_new_key, new_jwk) = generate_p256_keypair_jwk();

    let app = agent_cordon_server::build_router(ctx.state.clone());
    let (status, _body) = send_json(
        &app,
        Method::POST,
        &format!("/api/v1/devices/{}/rotate-key", device_id),
        Some(&jwt),
        None,
        None,
        Some(json!({ "new_public_key": new_jwk })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "device should work initially");

    // Disable device
    let app = agent_cordon_server::build_router(ctx.state.clone());
    let (status, _body) = send_json(
        &app,
        Method::PUT,
        &format!("/api/v1/workspaces/{}", device_id),
        None,
        Some(&full_cookie),
        Some(&csrf),
        Some(json!({ "enabled": false })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "disable device");

    let jti2 = Uuid::new_v4().to_string();
    // Note: _new_key is now the signing key after rotation
    let jwt2 = sign_device_jwt(&_new_key, &device_id, &jti2);
    let (_new_key2, new_jwk2) = generate_p256_keypair_jwk();

    let app = agent_cordon_server::build_router(ctx.state.clone());
    let (status, _body) = send_json(
        &app,
        Method::POST,
        &format!("/api/v1/devices/{}/rotate-key", device_id),
        Some(&jwt2),
        None,
        None,
        Some(json!({ "new_public_key": new_jwk2 })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "disabled device should fail"
    );

    // Re-enable device
    let app = agent_cordon_server::build_router(ctx.state.clone());
    let (status, _body) = send_json(
        &app,
        Method::PUT,
        &format!("/api/v1/workspaces/{}", device_id),
        None,
        Some(&full_cookie),
        Some(&csrf),
        Some(json!({ "enabled": true })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "re-enable device");

    let jti3 = Uuid::new_v4().to_string();
    let jwt3 = sign_device_jwt(&_new_key, &device_id, &jti3);
    let (_new_key3, new_jwk3) = generate_p256_keypair_jwk();

    let app = agent_cordon_server::build_router(ctx.state.clone());
    let (status, _body) = send_json(
        &app,
        Method::POST,
        &format!("/api/v1/devices/{}/rotate-key", device_id),
        Some(&jwt3),
        None,
        None,
        Some(json!({ "new_public_key": new_jwk3 })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "re-enabled device should work");
}
