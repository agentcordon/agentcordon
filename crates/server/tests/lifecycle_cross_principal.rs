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
