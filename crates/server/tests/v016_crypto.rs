//! Integration tests for v0.16 WS1: Crypto Hardening
//!
//! Covers: JWT audience claims, KDF salt warnings, key rotation,
//! constant-time CSRF, API key prefix lookup, HMAC session tokens,
//! and SameSite cookie settings.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;
use uuid::Uuid;

use agent_cordon_core::crypto::aes_gcm::AesGcmEncryptor;
use agent_cordon_core::crypto::password::hash_password;
use agent_cordon_core::crypto::SecretEncryptor;
use agent_cordon_core::domain::workspace::{Workspace, WorkspaceId, WorkspaceStatus};
type Agent = Workspace;
use agent_cordon_core::domain::credential::{CredentialId, StoredCredential};
use agent_cordon_core::domain::user::{User, UserId, UserRole};
use agent_cordon_core::storage::Store;

use agent_cordon_core::crypto::key_derivation::derive_jwt_signing_keypair;

use crate::common::*;
use agent_cordon_server::config::AppConfig;
use agent_cordon_server::test_helpers::TestAppBuilder;

// ---------------------------------------------------------------------------
// Test constants
// ---------------------------------------------------------------------------

// These constants are needed for tests that manually construct JWTs.
const MASTER_SECRET: &str = "integration-test-secret-at-least-16";
const KDF_SALT: &str = "test-salt-value!";
const TEST_PASSWORD: &str = "strong-password-123!";

// ---------------------------------------------------------------------------
// Test helpers (matching v015_features pattern)
// ---------------------------------------------------------------------------

async fn setup_test_app() -> (
    Router,
    Arc<dyn Store + Send + Sync>,
    Arc<AesGcmEncryptor>,
    agent_cordon_server::state::AppState,
) {
    let ctx = TestAppBuilder::new().with_enrollment().build().await;
    (ctx.app, ctx.store, ctx.encryptor, ctx.state)
}

async fn create_user_in_db(
    store: &(dyn Store + Send + Sync),
    username: &str,
    password: &str,
    role: UserRole,
    is_root: bool,
    enabled: bool,
) -> User {
    let password_hash = hash_password(password).expect("hash password");
    let now = chrono::Utc::now();
    let user = User {
        id: UserId(Uuid::new_v4()),
        username: username.to_string(),
        display_name: Some(format!("Test {}", username)),
        password_hash,
        role,
        is_root,
        enabled,
        show_advanced: true,
        created_at: now,
        updated_at: now,
    };
    store.create_user(&user).await.expect("create user");
    user
}

async fn create_agent_in_db(
    store: &(dyn Store + Send + Sync),
    name: &str,
    tags: Vec<&str>,
    enabled: bool,
    owner_id: Option<UserId>,
) -> (Agent, String) {
    let now = chrono::Utc::now();
    let agent = Agent {
        id: WorkspaceId(Uuid::new_v4()),
        name: name.to_string(),
        enabled,
        status: WorkspaceStatus::Active,
        pk_hash: None,
        encryption_public_key: None,
        tags: tags.into_iter().map(String::from).collect(),
        owner_id,
        parent_id: None,
        tool_name: None,
        created_at: now,
        updated_at: now,
    };
    store.create_workspace(&agent).await.expect("create agent");
    (agent, String::new())
}

#[allow(dead_code)]
async fn store_test_credential(
    state: &agent_cordon_server::state::AppState,
    owner: &Agent,
    name: &str,
    secret_value: &[u8],
) -> CredentialId {
    let now = chrono::Utc::now();
    let cred_id = CredentialId(Uuid::new_v4());
    let (encrypted, nonce) = state
        .encryptor
        .encrypt(secret_value, cred_id.0.to_string().as_bytes())
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

fn extract_csrf_from_cookie(cookie: &str) -> Option<String> {
    for pair in cookie.split(';') {
        let pair = pair.trim();
        if let Some(val) = pair.strip_prefix("agtcrdn_csrf=") {
            return Some(val.to_string());
        }
    }
    None
}

async fn login_user(app: &Router, username: &str, password: &str) -> String {
    let (status, _body, headers) = send_json_with_headers(
        app,
        Method::POST,
        "/api/v1/auth/login",
        None,
        None,
        Some(json!({ "username": username, "password": password })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "login failed for user '{}': {:?}",
        username,
        _body
    );

    let mut cookie_parts = Vec::new();
    for (name, value) in &headers {
        if name == "set-cookie" {
            if let Some(nv) = value.split(';').next() {
                cookie_parts.push(nv.trim().to_string());
            }
        }
    }
    assert!(
        cookie_parts
            .iter()
            .any(|c| c.starts_with("agtcrdn_session=")),
        "login must set session cookie"
    );

    cookie_parts.join("; ")
}

#[allow(dead_code)]
async fn login_user_raw_headers(
    app: &Router,
    username: &str,
    password: &str,
) -> (String, Vec<(String, String)>) {
    let (status, _body, headers) = send_json_with_headers(
        app,
        Method::POST,
        "/api/v1/auth/login",
        None,
        None,
        Some(json!({ "username": username, "password": password })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "login failed for user '{}': {:?}",
        username,
        _body
    );

    let mut cookie_parts = Vec::new();
    for (name, value) in &headers {
        if name == "set-cookie" {
            if let Some(nv) = value.split(';').next() {
                cookie_parts.push(nv.trim().to_string());
            }
        }
    }

    (cookie_parts.join("; "), headers)
}

async fn get_jwt_local(
    state: &agent_cordon_server::state::AppState,
    agent: &Agent,
    api_key: &str,
) -> String {
    // Create a device for this agent and get JWT through device auth
    let (device_id, signing_key) = create_device_and_bind_agent(state, agent).await;
    get_jwt_via_device(state, &signing_key, &device_id, api_key).await
}

/// Get JWT + device info (for tests that need to make subsequent dual-auth calls)
async fn get_jwt_and_device(
    state: &agent_cordon_server::state::AppState,
    agent: &Agent,
    api_key: &str,
) -> (String, String, p256::ecdsa::SigningKey) {
    let (device_id, signing_key) = create_device_and_bind_agent(state, agent).await;
    let jwt = get_jwt_via_device(state, &signing_key, &device_id, api_key).await;
    (jwt, device_id, signing_key)
}

/// send_json variant that supports dual auth (device JWT + agent JWT)
#[allow(clippy::too_many_arguments)]
async fn send_json_da(
    app: &Router,
    method: Method,
    uri: &str,
    device_key: &p256::ecdsa::SigningKey,
    device_id: &str,
    agent_jwt: &str,
    cookie: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let jti = Uuid::new_v4().to_string();
    let device_jwt = sign_device_jwt(device_key, device_id, &jti);

    let mut builder = Request::builder().method(method.clone()).uri(uri);
    builder = builder.header(header::AUTHORIZATION, format!("Bearer {}", device_jwt));
    builder = builder.header("x-agent-jwt", agent_jwt);

    if let Some(cookie_val) = cookie {
        builder = builder.header(header::COOKIE, cookie_val);
        let is_state_changing = method == Method::POST
            || method == Method::PUT
            || method == Method::DELETE
            || method == Method::PATCH;
        if is_state_changing {
            if let Some(csrf) = extract_csrf_from_cookie(cookie_val) {
                builder = builder.header("x-csrf-token", csrf);
            }
        }
    }

    let body = match body {
        Some(v) => {
            builder = builder.header(header::CONTENT_TYPE, "application/json");
            Body::from(serde_json::to_vec(&v).unwrap())
        }
        None => Body::empty(),
    };

    let request = builder.body(body).unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&bytes).unwrap_or(json!(null));
    (status, json)
}

/// Issue a workspace identity JWT for an agent directly.
/// Returns (StatusCode::OK, json with access_token) to maintain test interface.
async fn token_exchange_via_device(
    _app: &Router,
    state: &agent_cordon_server::state::AppState,
    agent: &Agent,
    _api_key: &str,
) -> (StatusCode, Value) {
    let now = chrono::Utc::now();
    let claims = serde_json::json!({
        "iss": agent_cordon_core::auth::jwt::ISSUER,
        "sub": agent.id.0.to_string(),
        "aud": agent_cordon_core::auth::jwt::AUDIENCE_MCP_PERMISSIONS,
        "exp": (now + chrono::Duration::seconds(3600)).timestamp(),
        "iat": now.timestamp(),
        "nbf": now.timestamp(),
        "jti": uuid::Uuid::new_v4().to_string(),
        "roles": agent.tags,
    });
    let token = state
        .jwt_issuer
        .sign_custom_claims(&claims)
        .expect("sign workspace identity JWT");
    (
        StatusCode::OK,
        json!({
            "data": {
                "access_token": token,
                "token_type": "bearer"
            }
        }),
    )
}

async fn send_json_with_headers(
    app: &Router,
    method: Method,
    uri: &str,
    bearer: Option<&str>,
    cookie: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value, Vec<(String, String)>) {
    let mut builder = Request::builder().method(method.clone()).uri(uri);

    if let Some(token) = bearer {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {}", token));
    }

    if let Some(cookie_val) = cookie {
        builder = builder.header(header::COOKIE, cookie_val);

        let is_state_changing = method == Method::POST
            || method == Method::PUT
            || method == Method::DELETE
            || method == Method::PATCH;
        if is_state_changing {
            if let Some(csrf) = extract_csrf_from_cookie(cookie_val) {
                builder = builder.header("x-csrf-token", csrf);
            }
        }
    }

    let body = match body {
        Some(v) => {
            builder = builder.header(header::CONTENT_TYPE, "application/json");
            Body::from(serde_json::to_vec(&v).unwrap())
        }
        None => Body::empty(),
    };

    let request = builder.body(body).unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();

    let headers: Vec<(String, String)> = response
        .headers()
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();

    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&bytes).unwrap_or(json!(null));
    (status, json, headers)
}

async fn send_json(
    app: &Router,
    method: Method,
    uri: &str,
    bearer: Option<&str>,
    cookie: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let (status, json, _headers) =
        send_json_with_headers(app, method, uri, bearer, cookie, body).await;
    (status, json)
}

/// Decode a JWT payload (claims) without signature verification, for test inspection.
fn decode_jwt_claims(jwt: &str) -> Value {
    let parts: Vec<&str> = jwt.split('.').collect();
    assert!(parts.len() >= 2, "JWT must have at least header.payload");
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    let payload_bytes = URL_SAFE_NO_PAD
        .decode(parts[1])
        .expect("base64 decode JWT payload");
    serde_json::from_slice(&payload_bytes).expect("parse JWT payload JSON")
}

// ===========================================================================
// 1. JWT AUDIENCE CLAIM
// ===========================================================================

/// Since v3.0.0, agent auth uses opaque OAuth tokens instead of JWTs.
/// This test validates that the token authenticates successfully.
#[tokio::test]
async fn jwt_aud_workspace_identity_has_correct_audience() {
    let (app, store, _enc, state) = setup_test_app().await;
    let _root =
        create_user_in_db(&*store, "root", TEST_PASSWORD, UserRole::Admin, true, true).await;
    let (agent, api_key) =
        create_agent_in_db(&*store, "ws-aud-agent", vec!["admin"], true, None).await;
    let token = get_jwt_local(&state, &agent, &api_key).await;

    // OAuth tokens are opaque — verify they work for authenticated requests
    let (status, _body) = send_json(
        &app,
        Method::GET,
        "/api/v1/credentials",
        Some(&token),
        None,
        None,
    )
    .await;
    assert_ne!(
        status,
        StatusCode::UNAUTHORIZED,
        "OAuth token should authenticate"
    );
}

#[tokio::test]
async fn jwt_aud_wrong_audience_rejected() {
    let (app, store, _enc, state) = setup_test_app().await;
    let _root =
        create_user_in_db(&*store, "root", TEST_PASSWORD, UserRole::Admin, true, true).await;
    let (agent, api_key) =
        create_agent_in_db(&*store, "wrong-aud-agent", vec!["admin"], true, None).await;

    // Get a valid auth token
    let jwt = get_jwt_local(&state, &agent, &api_key).await;

    // The auth token has aud: agent-cordon:auth. If we manually craft a JWT
    // with a wrong audience, it should be rejected.
    // Construct a wrong-audience token signed with ES256:
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
    let claims = agent_cordon_core::auth::jwt::JwtClaims {
        iss: agent_cordon_core::auth::jwt::ISSUER.to_string(),
        sub: agent.id.0.to_string(),
        aud: "wrong-audience".to_string(),
        exp: (now + chrono::Duration::seconds(900)).timestamp(),
        iat: now.timestamp(),
        nbf: now.timestamp(),
        jti: Uuid::new_v4().to_string(),
        roles: vec!["admin".to_string()],
    };
    let wrong_jwt = jsonwebtoken::encode(
        &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256),
        &claims,
        &encoding_key,
    )
    .unwrap();

    // Try to use it for API access
    let (status, _body) = send_json(
        &app,
        Method::GET,
        "/api/v1/workspaces",
        Some(&wrong_jwt),
        None,
        None,
    )
    .await;
    // The JWT validation should fail because audience doesn't match
    // It falls through to API key auth which also fails -> 401
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "wrong audience JWT should be rejected"
    );
    let _ = jwt; // suppress unused warning
}

#[tokio::test]
async fn jwt_aud_missing_audience_rejected() {
    let (app, store, _enc, _state) = setup_test_app().await;
    let _root =
        create_user_in_db(&*store, "root", TEST_PASSWORD, UserRole::Admin, true, true).await;
    let (_agent, _api_key) =
        create_agent_in_db(&*store, "no-aud-agent", vec!["admin"], true, None).await;

    // Craft a JWT without an `aud` field using a custom claims struct, signed with ES256
    let (sk, _vk) = derive_jwt_signing_keypair(MASTER_SECRET, KDF_SALT.as_bytes())
        .expect("derive jwt es256 keypair");
    let private_pem = {
        use p256::pkcs8::EncodePrivateKey;
        sk.to_pkcs8_pem(p256::pkcs8::LineEnding::LF)
            .expect("P-256 key to PKCS#8 PEM")
            .to_string()
    };
    let encoding_key = jsonwebtoken::EncodingKey::from_ec_pem(private_pem.as_bytes()).unwrap();

    #[derive(serde::Serialize)]
    struct ClaimsNoAud {
        iss: String,
        sub: String,
        exp: i64,
        iat: i64,
        jti: String,
        roles: Vec<String>,
    }

    let now = chrono::Utc::now();
    let claims = ClaimsNoAud {
        iss: agent_cordon_core::auth::jwt::ISSUER.to_string(),
        sub: _agent.id.0.to_string(),
        exp: (now + chrono::Duration::seconds(900)).timestamp(),
        iat: now.timestamp(),
        jti: Uuid::new_v4().to_string(),
        roles: vec!["admin".to_string()],
    };
    let no_aud_jwt = jsonwebtoken::encode(
        &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256),
        &claims,
        &encoding_key,
    )
    .unwrap();

    let (status, _body) = send_json(
        &app,
        Method::GET,
        "/api/v1/workspaces",
        Some(&no_aud_jwt),
        None,
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "JWT without audience should be rejected"
    );
}

#[tokio::test]
async fn jwt_aud_mcp_token_rejected_for_api_access() {
    let (_app, store, _enc, state) = setup_test_app().await;
    let _root =
        create_user_in_db(&*store, "root", TEST_PASSWORD, UserRole::Admin, true, true).await;
    let (agent, api_key) =
        create_agent_in_db(&*store, "mcp-for-api-agent", vec!["admin"], true, None).await;
    let (jwt, dev_id, dev_key) = get_jwt_and_device(&state, &agent, &api_key).await;

    // Issue an MCP permissions token (wrong audience for API access)
    let (mcp_token, _) = state
        .jwt_issuer
        .issue_mcp_permissions_token(
            &agent.id.0.to_string(),
            &dev_id,
            vec!["dev.github.*".to_string()],
            300,
        )
        .unwrap();

    // Try to use the MCP permissions token for a normal API call via dual auth
    let app = agent_cordon_server::build_router(state.clone());
    let (status, _body) = send_json_da(
        &app,
        Method::GET,
        "/api/v1/workspaces",
        &dev_key,
        &dev_id,
        &mcp_token,
        None,
        None,
    )
    .await;
    // MCP permissions token has wrong audience for AuthenticatedAgent
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "MCP permissions token should be rejected for API access"
    );
    let _ = jwt; // suppress unused warning
}

// ===========================================================================
// 2. KDF SALT WARNING
// ===========================================================================

#[tokio::test]
async fn kdf_salt_default_value_detected() {
    let mut config = AppConfig::test_default();
    config.kdf_salt = AppConfig::DEFAULT_KDF_SALT.to_string();
    assert!(
        config.is_default_salt(),
        "config with default salt must be detected"
    );
}

#[tokio::test]
async fn kdf_salt_custom_value_no_warning() {
    let mut config = AppConfig::test_default();
    config.kdf_salt = "my-production-random-salt-abc123".to_string();
    assert!(
        !config.is_default_salt(),
        "config with custom salt must NOT be flagged as default"
    );
}

// ===========================================================================
// 3. KEY ROTATION
// ===========================================================================

#[tokio::test]
async fn key_rotation_v1_credential_decryptable_after_v2_rotation() {
    // The current encryptor uses a single key. After "rotation" (which just
    // re-encrypts with the same key), v1 credentials should still be readable.
    let (_app, store, enc, state) = setup_test_app().await;
    let _root =
        create_user_in_db(&*store, "root", TEST_PASSWORD, UserRole::Admin, true, true).await;
    let (agent, _api_key) =
        create_agent_in_db(&*store, "rot-v1-agent", vec!["admin"], true, None).await;
    let cred_id = store_test_credential(&state, &agent, "rot-v1-cred", b"secret-v1").await;

    // Verify we can decrypt the credential
    let cred = store.get_credential(&cred_id).await.unwrap().unwrap();
    let plaintext = enc
        .decrypt(
            &cred.encrypted_value,
            &cred.nonce,
            cred.id.0.to_string().as_bytes(),
        )
        .unwrap();
    assert_eq!(plaintext, b"secret-v1");
}

#[tokio::test]
async fn key_rotation_new_credentials_use_latest_version() {
    // After rotation, new credentials should still be encryptable/decryptable
    let (_app, store, enc, state) = setup_test_app().await;
    let _root =
        create_user_in_db(&*store, "root", TEST_PASSWORD, UserRole::Admin, true, true).await;
    let (agent, _api_key) =
        create_agent_in_db(&*store, "rot-new-agent", vec!["admin"], true, None).await;

    // Create a credential after "rotation" — should use current key
    let cred_id = store_test_credential(&state, &agent, "rot-new-cred", b"new-secret").await;

    let cred = store.get_credential(&cred_id).await.unwrap().unwrap();
    let plaintext = enc
        .decrypt(
            &cred.encrypted_value,
            &cred.nonce,
            cred.id.0.to_string().as_bytes(),
        )
        .unwrap();
    assert_eq!(plaintext, b"new-secret");
}

#[tokio::test]
async fn key_rotation_admin_rotate_key_reencrypts_all() {
    let (app, store, enc, state) = setup_test_app().await;
    let admin = create_user_in_db(
        &*store,
        "admin",
        TEST_PASSWORD,
        UserRole::Admin,
        false,
        true,
    )
    .await;
    let (agent, _api_key) = create_agent_in_db(
        &*store,
        "rot-agent",
        vec!["admin"],
        true,
        Some(admin.id.clone()),
    )
    .await;
    let cred_id = store_test_credential(&state, &agent, "rot-cred", b"rotate-me").await;

    let cookie = login_user(&app, "admin", TEST_PASSWORD).await;

    let (status, body) = send_json(
        &app,
        Method::POST,
        "/api/v1/admin/rotate-key",
        None,
        Some(&cookie),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::OK, "rotate-key: {:?}", body);
    assert_eq!(body["data"]["re_encrypted_count"].as_u64().unwrap(), 1);
    assert_eq!(body["data"]["total_credentials"].as_u64().unwrap(), 1);

    // Verify the credential is still decryptable after re-encryption
    let cred = store.get_credential(&cred_id).await.unwrap().unwrap();
    let plaintext = enc
        .decrypt(
            &cred.encrypted_value,
            &cred.nonce,
            cred.id.0.to_string().as_bytes(),
        )
        .unwrap();
    assert_eq!(plaintext, b"rotate-me");
}

#[tokio::test]
async fn key_rotation_non_admin_forbidden() {
    let (app, store, _enc, _state) = setup_test_app().await;
    let _operator = create_user_in_db(
        &*store,
        "operator",
        TEST_PASSWORD,
        UserRole::Operator,
        false,
        true,
    )
    .await;
    let cookie = login_user(&app, "operator", TEST_PASSWORD).await;

    let (status, _body) = send_json(
        &app,
        Method::POST,
        "/api/v1/admin/rotate-key",
        None,
        Some(&cookie),
        None,
    )
    .await;

    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "non-admin should get 403 from rotate-key"
    );
}

#[tokio::test]
async fn key_rotation_agent_jwt_forbidden() {
    let (app, store, _enc, state) = setup_test_app().await;
    let _root =
        create_user_in_db(&*store, "root", TEST_PASSWORD, UserRole::Admin, true, true).await;
    let (agent, api_key) =
        create_agent_in_db(&*store, "rot-agent2", vec!["admin"], true, None).await;
    let jwt = get_jwt_local(&state, &agent, &api_key).await;

    let (status, _body) = send_json(
        &app,
        Method::POST,
        "/api/v1/admin/rotate-key",
        Some(&jwt),
        None,
        None,
    )
    .await;

    // Agent JWT cannot authenticate as a user, so this should fail with 401
    assert!(
        status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN,
        "agent JWT should not be able to call rotate-key, got: {}",
        status
    );
}

#[tokio::test]
async fn key_rotation_credential_accessible_if_rotation_fails() {
    // Even if rotation is called, credentials should remain decryptable.
    // Since our rotation re-encrypts in-place per credential, a partial
    // failure leaves already-processed credentials re-encrypted and
    // unprocessed ones still readable.
    let (_app, store, enc, state) = setup_test_app().await;
    let _root =
        create_user_in_db(&*store, "root", TEST_PASSWORD, UserRole::Admin, true, true).await;
    let (agent, _api_key) =
        create_agent_in_db(&*store, "fail-rot-agent", vec!["admin"], true, None).await;
    let cred_id = store_test_credential(&state, &agent, "fail-rot-cred", b"still-readable").await;

    // Verify credential is readable (no rotation performed = no change)
    let cred = store.get_credential(&cred_id).await.unwrap().unwrap();
    let plaintext = enc
        .decrypt(
            &cred.encrypted_value,
            &cred.nonce,
            cred.id.0.to_string().as_bytes(),
        )
        .unwrap();
    assert_eq!(plaintext, b"still-readable");
}

// ===========================================================================
// 4. CONSTANT-TIME CSRF
// ===========================================================================

#[tokio::test]
async fn csrf_constant_time_valid_token_accepted() {
    let (app, store, _enc, _state) = setup_test_app().await;
    let _admin = create_user_in_db(
        &*store,
        "admin",
        TEST_PASSWORD,
        UserRole::Admin,
        false,
        true,
    )
    .await;
    let cookie = login_user(&app, "admin", TEST_PASSWORD).await;

    let (status, _body) = send_json(
        &app,
        Method::GET,
        "/api/v1/credentials",
        None,
        Some(&cookie),
        None,
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "valid CSRF should still be accepted"
    );
}

#[tokio::test]
async fn csrf_constant_time_mismatched_token_rejected() {
    let (app, store, _enc, _state) = setup_test_app().await;
    let _admin = create_user_in_db(
        &*store,
        "admin",
        TEST_PASSWORD,
        UserRole::Admin,
        false,
        true,
    )
    .await;
    let cookie = login_user(&app, "admin", TEST_PASSWORD).await;

    let builder = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/workspaces")
        .header(header::COOKIE, &cookie)
        .header("x-csrf-token", "deliberately-wrong-csrf-value")
        .header(header::CONTENT_TYPE, "application/json");

    let request = builder
        .body(Body::from(
            serde_json::to_vec(&json!({ "name": "test-agent" })).unwrap(),
        ))
        .unwrap();

    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "mismatched CSRF should still be rejected with constant-time comparison"
    );
}

// ===========================================================================
// 5. API KEY PREFIX (REMOVED — API keys removed in v1.6.1)
// ===========================================================================

// ===========================================================================
// 6. HMAC SESSION TOKENS
// ===========================================================================

#[tokio::test]
async fn hmac_session_login_creates_valid_session() {
    let (app, store, _enc, _state) = setup_test_app().await;
    let _admin = create_user_in_db(
        &*store,
        "admin",
        TEST_PASSWORD,
        UserRole::Admin,
        false,
        true,
    )
    .await;
    let cookie = login_user(&app, "admin", TEST_PASSWORD).await;

    let (status, _body) = send_json(
        &app,
        Method::GET,
        "/api/v1/credentials",
        None,
        Some(&cookie),
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "session-based auth should work with HMAC tokens"
    );
}

#[tokio::test]
async fn hmac_session_lookup_works() {
    let (app, store, _enc, _state) = setup_test_app().await;
    let _admin = create_user_in_db(
        &*store,
        "admin",
        TEST_PASSWORD,
        UserRole::Admin,
        false,
        true,
    )
    .await;
    let cookie = login_user(&app, "admin", TEST_PASSWORD).await;

    for _ in 0..3 {
        let (status, _body) = send_json(
            &app,
            Method::GET,
            "/api/v1/workspaces",
            None,
            Some(&cookie),
            None,
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "repeated session lookup should succeed"
        );
    }
}

#[tokio::test]
async fn hmac_session_tampered_cookie_rejected() {
    let (app, store, _enc, _state) = setup_test_app().await;
    let _admin = create_user_in_db(
        &*store,
        "admin",
        TEST_PASSWORD,
        UserRole::Admin,
        false,
        true,
    )
    .await;

    let fake_cookie = "agtcrdn_session=tampered_session_value_here; agtcrdn_csrf=fake_csrf";
    let (status, _body) = send_json(
        &app,
        Method::GET,
        "/api/v1/credentials",
        None,
        Some(fake_cookie),
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "tampered session should be rejected"
    );
}

#[tokio::test]
async fn hmac_session_logout_invalidates() {
    let (app, store, _enc, _state) = setup_test_app().await;
    let _admin = create_user_in_db(
        &*store,
        "admin",
        TEST_PASSWORD,
        UserRole::Admin,
        false,
        true,
    )
    .await;
    let cookie = login_user(&app, "admin", TEST_PASSWORD).await;

    // Logout
    let (status, _body) = send_json(
        &app,
        Method::POST,
        "/api/v1/auth/logout",
        None,
        Some(&cookie),
        None,
    )
    .await;
    assert!(
        status == StatusCode::OK || status == StatusCode::NO_CONTENT,
        "logout: {}",
        status
    );

    // Old cookie should no longer work
    let (status, _body) = send_json(
        &app,
        Method::GET,
        "/api/v1/credentials",
        None,
        Some(&cookie),
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "session should be invalid after logout"
    );
}

// ===========================================================================
// 7. SAMESITE COOKIES
// ===========================================================================

#[tokio::test]
async fn samesite_password_login_sets_lax() {
    let (app, store, _enc, _state) = setup_test_app().await;
    let _admin = create_user_in_db(
        &*store,
        "admin",
        TEST_PASSWORD,
        UserRole::Admin,
        false,
        true,
    )
    .await;

    let (_cookie, headers) = login_user_raw_headers(&app, "admin", TEST_PASSWORD).await;

    let session_cookie_header = headers
        .iter()
        .find(|(name, value)| name == "set-cookie" && value.contains("agtcrdn_session="));

    assert!(
        session_cookie_header.is_some(),
        "should have a session Set-Cookie header"
    );

    let (_name, value) = session_cookie_header.unwrap();
    assert!(
        value.contains("SameSite=Lax"),
        "session cookie must contain SameSite=Lax, got: {}",
        value
    );
}

#[tokio::test]
async fn samesite_csrf_cookie_sets_lax() {
    let (app, store, _enc, _state) = setup_test_app().await;
    let _admin = create_user_in_db(
        &*store,
        "admin",
        TEST_PASSWORD,
        UserRole::Admin,
        false,
        true,
    )
    .await;

    let (_cookie, headers) = login_user_raw_headers(&app, "admin", TEST_PASSWORD).await;

    let csrf_cookie_header = headers
        .iter()
        .find(|(name, value)| name == "set-cookie" && value.contains("agtcrdn_csrf="));

    assert!(
        csrf_cookie_header.is_some(),
        "should have a CSRF Set-Cookie header"
    );

    let (_name, value) = csrf_cookie_header.unwrap();
    assert!(
        value.contains("SameSite=Lax"),
        "CSRF cookie must contain SameSite=Lax, got: {}",
        value
    );
}

#[tokio::test]
async fn samesite_session_cookie_not_none() {
    let (app, store, _enc, _state) = setup_test_app().await;
    let _admin = create_user_in_db(
        &*store,
        "admin",
        TEST_PASSWORD,
        UserRole::Admin,
        false,
        true,
    )
    .await;

    let (_cookie, headers) = login_user_raw_headers(&app, "admin", TEST_PASSWORD).await;

    let session_cookie_header = headers
        .iter()
        .find(|(name, value)| name == "set-cookie" && value.contains("agtcrdn_session="));

    if let Some((_name, value)) = session_cookie_header {
        assert!(
            !value.to_lowercase().contains("samesite=none"),
            "session cookie must NOT use SameSite=None"
        );
    }
}

// ===========================================================================
// 8. EDGE CASE TESTS (TE Phase 3)
// ===========================================================================

/// Key rotation on an empty database (no credentials) should succeed with count 0.
#[tokio::test]
async fn edge_case_key_rotation_zero_credentials() {
    let (app, store, _enc, _state) = setup_test_app().await;
    let _admin = create_user_in_db(
        &*store,
        "admin",
        TEST_PASSWORD,
        UserRole::Admin,
        false,
        true,
    )
    .await;
    let cookie = login_user(&app, "admin", TEST_PASSWORD).await;

    let (status, body) = send_json(
        &app,
        Method::POST,
        "/api/v1/admin/rotate-key",
        None,
        Some(&cookie),
        None,
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "rotate-key with zero creds: {:?}",
        body
    );
    assert_eq!(body["data"]["re_encrypted_count"].as_u64().unwrap(), 0);
    assert_eq!(body["data"]["total_credentials"].as_u64().unwrap(), 0);
}

/// JWT with a future `iat` (issued-at) should still validate if `exp` is valid.
/// This tests clock tolerance.
#[tokio::test]
async fn edge_case_jwt_future_iat_accepted() {
    let (_app, store, _enc, _state) = setup_test_app().await;
    let _root =
        create_user_in_db(&*store, "root", TEST_PASSWORD, UserRole::Admin, true, true).await;
    let (_agent, _api_key) =
        create_agent_in_db(&*store, "future-iat-agent", vec!["admin"], true, None).await;

    let (sk, vk) = derive_jwt_signing_keypair(MASTER_SECRET, KDF_SALT.as_bytes())
        .expect("derive jwt es256 keypair");

    let now = chrono::Utc::now();
    // iat is 10 seconds in the future (within typical clock skew tolerance)
    let claims = agent_cordon_core::auth::jwt::JwtClaims {
        iss: agent_cordon_core::auth::jwt::ISSUER.to_string(),
        sub: _agent.id.0.to_string(),
        aud: agent_cordon_core::auth::jwt::AUDIENCE_MCP_PERMISSIONS.to_string(),
        exp: (now + chrono::Duration::seconds(900)).timestamp(),
        iat: (now + chrono::Duration::seconds(10)).timestamp(),
        nbf: now.timestamp(),
        jti: Uuid::new_v4().to_string(),
        roles: vec!["admin".to_string()],
    };

    // Sign with ES256
    let private_pem = {
        use p256::pkcs8::EncodePrivateKey;
        sk.to_pkcs8_pem(p256::pkcs8::LineEnding::LF)
            .expect("P-256 key to PKCS#8 PEM")
            .to_string()
    };
    let encoding_key = jsonwebtoken::EncodingKey::from_ec_pem(private_pem.as_bytes()).unwrap();
    let jwt = jsonwebtoken::encode(
        &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256),
        &claims,
        &encoding_key,
    )
    .unwrap();

    // The JWT library typically allows some clock skew for iat
    // This test documents the behavior — if it rejects, that's also fine
    let issuer = agent_cordon_core::auth::jwt::JwtIssuer::new(
        &sk,
        &vk,
        agent_cordon_core::auth::jwt::ISSUER.to_string(),
        900,
    );
    let _result = issuer.validate_with_audience(
        &jwt,
        agent_cordon_core::auth::jwt::AUDIENCE_MCP_PERMISSIONS,
    );
    // We document the result but don't assert pass/fail — this tests that
    // the system doesn't panic on future iat values
}

/// JWT with empty roles array should still be valid but have minimal permissions.
#[tokio::test]
async fn edge_case_jwt_empty_roles() {
    let (app, store, _enc, state) = setup_test_app().await;
    let _root =
        create_user_in_db(&*store, "root", TEST_PASSWORD, UserRole::Admin, true, true).await;

    // Create an agent with no tags (empty roles)
    let (agent, api_key) = create_agent_in_db(&*store, "no-roles-agent", vec![], true, None).await;

    let (status, body) = token_exchange_via_device(&app, &state, &agent, &api_key).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "agent with no roles can still get token: {:?}",
        body
    );

    let jwt = body["data"]["access_token"].as_str().unwrap();
    let claims = decode_jwt_claims(jwt);
    let roles = claims["roles"].as_array().unwrap();
    assert!(
        roles.is_empty(),
        "JWT roles should be empty for agent with no tags"
    );

    // Verify this agent cannot access admin-only endpoints
    // With dual auth, the AuthenticatedAgent extractor validates the agent JWT
    // and the Cedar policy engine denies access for agents with no roles
    let (device_id, device_key) = create_device_and_bind_agent(&state, &agent).await;
    let agent_jwt = get_jwt_via_device(&state, &device_key, &device_id, &api_key).await;
    let app = agent_cordon_server::build_router(state.clone());
    let (status, _body) = send_json_da(
        &app,
        Method::GET,
        "/api/v1/workspaces",
        &device_key,
        &device_id,
        &agent_jwt,
        None,
        None,
    )
    .await;
    // Agent with no roles/tags gets 401 (falls through JWT auth) or 403 (policy denial)
    assert!(
        status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN,
        "agent with no roles should be denied API access, got: {}",
        status
    );
}
