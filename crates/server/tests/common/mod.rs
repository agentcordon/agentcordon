//! Shared test helpers for integration tests.
//!
//! This module provides common functions used across 20+ integration test files,
//! reducing duplication and ensuring consistent behavior.
//!
//! # Usage
//!
//! In each integration test file:
//! ```text
//! mod common;
//! use common::*;
//! ```

#![allow(dead_code)]

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;
use uuid::Uuid;

use agent_cordon_core::crypto::password::hash_password;
use agent_cordon_core::domain::user::{User, UserId, UserRole};
use agent_cordon_core::domain::workspace::{Workspace, WorkspaceId, WorkspaceStatus};
use agent_cordon_core::policy::PolicyEngine;
use agent_cordon_core::storage::Store;

// Backward-compat aliases for test code
pub type Agent = Workspace;
pub type AgentId = WorkspaceId;

// ---------------------------------------------------------------------------
// Test constants
// ---------------------------------------------------------------------------

pub const TEST_PASSWORD: &str = "strong-password-123!";

// ---------------------------------------------------------------------------
// User helpers
// ---------------------------------------------------------------------------

/// Create a user directly in the store (full parameters).
///
/// This is the most flexible version. For simpler cases, use
/// [`create_test_user`] which defaults `is_root=false` and `enabled=true`.
pub async fn create_user_in_db(
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

/// Convenience: create a normal (non-root, enabled) user.
pub async fn create_test_user(
    store: &(dyn Store + Send + Sync),
    username: &str,
    password: &str,
    role: UserRole,
) -> User {
    create_user_in_db(store, username, password, role, false, true).await
}

/// Convenience: create a root admin user (is_root=true, enabled=true).
pub async fn create_root_user(
    store: &(dyn Store + Send + Sync),
    username: &str,
    password: &str,
) -> User {
    create_user_in_db(store, username, password, UserRole::Admin, true, true).await
}

// ---------------------------------------------------------------------------
// Agent helpers
// ---------------------------------------------------------------------------

/// Create an agent directly in the store.
///
/// Returns `(Agent, String)` where the String is always empty (legacy compat).
/// API keys have been removed — agents authenticate via workspace identity.
pub async fn create_agent_in_db(
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

// ---------------------------------------------------------------------------
// Login helpers
// ---------------------------------------------------------------------------

/// Login a user and return (session_cookie, csrf_token) as separate strings.
///
/// `session_cookie` is e.g. `"agtcrdn_session=xxx"`.
/// `csrf_token` is the raw CSRF token value.
pub async fn login_user(app: &Router, username: &str, password: &str) -> (String, String) {
    let (status, body, headers) = send_json_with_headers(
        app,
        Method::POST,
        "/api/v1/auth/login",
        None,
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
        body
    );

    let session_cookie = headers
        .iter()
        .filter(|(name, _)| name == "set-cookie")
        .find(|(_, val)| val.starts_with("agtcrdn_session="))
        .expect("session Set-Cookie header must be present")
        .1
        .clone();
    let session_cookie = session_cookie
        .split(';')
        .next()
        .expect("cookie must have value")
        .trim()
        .to_string();

    let csrf_token = body["data"]["csrf_token"]
        .as_str()
        .expect("login response must include csrf_token")
        .to_string();

    (session_cookie, csrf_token)
}

/// Login a user and return the combined cookie string (session + CSRF).
///
/// Returns e.g. `"agtcrdn_session=<token>; agtcrdn_csrf=<csrf>"`.
pub async fn login_user_combined(app: &Router, username: &str, password: &str) -> String {
    let (session_cookie, csrf_token) = login_user(app, username, password).await;
    combined_cookie(&session_cookie, &csrf_token)
}

/// Combine session cookie and CSRF token into a single cookie string.
pub fn combined_cookie(session_cookie: &str, csrf_token: &str) -> String {
    format!("{}; agtcrdn_csrf={}", session_cookie, csrf_token)
}

// ---------------------------------------------------------------------------
// CSRF helpers
// ---------------------------------------------------------------------------

/// Extract the CSRF token value from a cookie string.
///
/// Parses `"agtcrdn_session=xxx; agtcrdn_csrf=yyy"` and returns `Some("yyy")`.
pub fn extract_csrf_from_cookie(cookie: &str) -> Option<String> {
    for pair in cookie.split(';') {
        let pair = pair.trim();
        if let Some(val) = pair.strip_prefix("agtcrdn_csrf=") {
            return Some(val.to_string());
        }
    }
    None
}

/// Extract the raw session token from a cookie string.
///
/// Parses `"agtcrdn_session=xxx; agtcrdn_csrf=yyy"` and returns `Some("xxx")`.
pub fn extract_session_token(cookie: &str) -> Option<String> {
    for pair in cookie.split(';') {
        let pair = pair.trim();
        if let Some(val) = pair.strip_prefix("agtcrdn_session=") {
            return Some(val.to_string());
        }
    }
    None
}

/// Compute the CSRF token for the OAuth consent form.
///
/// Mirrors the server-side HMAC computation so tests can submit valid consent forms.
pub fn compute_consent_csrf(cookie: &str, session_hash_key: &[u8; 32]) -> String {
    let session_token = extract_session_token(cookie).expect("cookie must contain agtcrdn_session");
    let csrf_input = format!("{session_token}\0csrf-oauth-consent");
    agent_cordon_core::crypto::session::hash_session_token_hmac(&csrf_input, session_hash_key)
}

// ---------------------------------------------------------------------------
// HTTP request helpers
// ---------------------------------------------------------------------------

/// Send a JSON request with fine-grained control over bearer, cookie, CSRF header, and body.
///
/// Returns (status, parsed_json_body, response_headers).
///
/// This is the canonical version used by most test files.
pub async fn send_json_with_headers(
    app: &Router,
    method: Method,
    uri: &str,
    bearer: Option<&str>,
    cookie: Option<&str>,
    csrf_token: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value, Vec<(String, String)>) {
    let mut builder = Request::builder().method(method.clone()).uri(uri);

    if let Some(token) = bearer {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {}", token));
    }
    if let Some(cookie_val) = cookie {
        builder = builder.header(header::COOKIE, cookie_val);
    }
    if let Some(csrf) = csrf_token {
        builder = builder.header("x-csrf-token", csrf);
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

/// Send a JSON request without returning response headers.
///
/// This is the most commonly used helper for simple request/response tests.
pub async fn send_json(
    app: &Router,
    method: Method,
    uri: &str,
    bearer: Option<&str>,
    cookie: Option<&str>,
    csrf_token: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let (status, json, _headers) =
        send_json_with_headers(app, method, uri, bearer, cookie, csrf_token, body).await;
    (status, json)
}

/// Send a JSON request with auto-CSRF extraction from cookie.
///
/// If the cookie string contains an `agtcrdn_csrf` value and the method is
/// state-changing (POST/PUT/DELETE/PATCH), the `X-CSRF-Token` header is
/// automatically added. This is convenient for test files that use combined
/// cookie strings.
pub async fn send_json_auto_csrf_with_headers(
    app: &Router,
    method: Method,
    uri: &str,
    bearer: Option<&str>,
    cookie: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value, Vec<(String, String)>) {
    let csrf = cookie.and_then(|c| {
        let is_state_changing = method == Method::POST
            || method == Method::PUT
            || method == Method::DELETE
            || method == Method::PATCH;
        if is_state_changing {
            extract_csrf_from_cookie(c)
        } else {
            None
        }
    });
    send_json_with_headers(app, method, uri, bearer, cookie, csrf.as_deref(), body).await
}

/// Send a JSON request with auto-CSRF extraction (no headers returned).
pub async fn send_json_auto_csrf(
    app: &Router,
    method: Method,
    uri: &str,
    bearer: Option<&str>,
    cookie: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let (status, json, _) =
        send_json_auto_csrf_with_headers(app, method, uri, bearer, cookie, body).await;
    (status, json)
}

/// Issue a test OAuth access token for an agent.
///
/// Creates an OAuth client (if one doesn't already exist for this workspace)
/// and an access token in the database, returning the raw bearer token.
/// This bypasses any auth flow and directly creates a valid token for the agent.
pub async fn issue_agent_jwt(state: &agent_cordon_server::state::AppState, agent: &Agent) -> String {
    use agent_cordon_core::oauth2::tokens::generate_access_token;
    use agent_cordon_core::oauth2::types::{OAuthAccessToken, OAuthClient, OAuthScope};
    use agent_cordon_core::domain::user::UserId;

    let now = chrono::Utc::now();

    // Ensure the workspace has a pk_hash; if not, generate one
    let pk_hash = match &agent.pk_hash {
        Some(h) => h.clone(),
        None => format!("test_pk_{}", agent.id.0),
    };

    // Ensure an OAuth client exists for this workspace
    let client_id = format!("ac_test_{}", &agent.id.0.to_string()[..8]);
    let existing = state.store.get_oauth_client_by_client_id(&client_id).await.ok().flatten();
    let test_user_id = UserId(uuid::Uuid::nil());

    if existing.is_none() {
        // If workspace has no pk_hash, ensure one exists for lookup
        if agent.pk_hash.is_none() {
            let mut updated = agent.clone();
            updated.pk_hash = Some(pk_hash.clone());
            let _ = state.store.update_workspace(&updated).await;
        }

        let client = OAuthClient {
            id: uuid::Uuid::new_v4(),
            client_id: client_id.clone(),
            client_secret_hash: None,
            workspace_name: agent.name.clone(),
            public_key_hash: pk_hash,
            redirect_uris: vec!["http://localhost:9999/callback".to_string()],
            allowed_scopes: vec![
                OAuthScope::CredentialsDiscover,
                OAuthScope::CredentialsVend,
                OAuthScope::McpInvoke,
            ],
            created_by_user: test_user_id.clone(),
            created_at: now,
            revoked_at: None,
        };
        state.store.create_oauth_client(&client).await.expect("create test OAuth client");
    }

    // Create access token
    let (raw_token, token_hash) = generate_access_token();
    let token = OAuthAccessToken {
        token_hash,
        client_id,
        user_id: test_user_id,
        scopes: vec![
            OAuthScope::CredentialsDiscover,
            OAuthScope::CredentialsVend,
            OAuthScope::McpInvoke,
        ],
        created_at: now,
        expires_at: now + chrono::Duration::hours(1),
        revoked_at: None,
    };
    state.store.create_oauth_access_token(&token).await.expect("store test OAuth token");

    raw_token
}

/// Legacy compat: obtain an OAuth access token for a workspace.
///
/// API key exchange has been removed. This now looks up the workspace by ID
/// and issues an OAuth access token. The device_key and api_key parameters
/// are ignored.
pub async fn get_jwt_via_device(
    state: &agent_cordon_server::state::AppState,
    _device_key: &p256::ecdsa::SigningKey,
    workspace_id: &str,
    _api_key: &str,
) -> String {
    let ws_uuid: uuid::Uuid = workspace_id
        .parse()
        .expect("workspace_id must be a valid UUID");
    let workspace = state
        .store
        .get_workspace(&WorkspaceId(ws_uuid))
        .await
        .expect("get workspace")
        .expect("workspace must exist");

    issue_agent_jwt(state, &workspace).await
}

/// Send a JSON request with workspace JWT auth.
///
/// Sends the workspace JWT in `Authorization: Bearer <jwt>`.
/// The device_key and device_id params are kept for backward compat but ignored.
pub async fn send_json_dual_auth(
    app: &Router,
    method: Method,
    uri: &str,
    _device_key: &p256::ecdsa::SigningKey,
    _device_id: &str,
    workspace_jwt: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut builder = Request::builder().method(method).uri(uri);
    builder = builder.header(header::AUTHORIZATION, format!("Bearer {}", workspace_jwt));

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

/// Legacy compat: "create device and bind agent" is now a no-op since
/// agents and devices are unified as Workspaces. Returns the workspace's
/// own ID and a fresh signing key.
///
/// Returns `(workspace_id_string, signing_key)`.
pub async fn create_device_and_bind_agent(
    _state: &agent_cordon_server::state::AppState,
    agent: &agent_cordon_core::domain::workspace::Workspace,
) -> (String, p256::ecdsa::SigningKey) {
    let (sig_key, _sig_jwk, _enc_key, _enc_jwk) = generate_dual_p256_keypairs_jwk();
    (agent.id.0.to_string(), sig_key)
}

/// Context for device-mediated agent auth, used by test helpers.
/// Created from existing agents (not through enrollment flow).
pub struct QuickDeviceAgent {
    pub device_id: String,
    pub device_signing_key: p256::ecdsa::SigningKey,
    pub agent_jwt: String,
}

/// Quick setup: create a device, bind an existing agent, get a JWT.
///
/// Use this for tests that create agents via `TestAppBuilder::with_agent`
/// or `create_agent_in_db` and need dual auth.
pub async fn quick_device_setup(
    state: &agent_cordon_server::state::AppState,
    agent: &agent_cordon_core::domain::workspace::Workspace,
    _api_key: &str,
) -> QuickDeviceAgent {
    let (device_id, sig_key) = create_device_and_bind_agent(state, agent).await;
    let agent_jwt = issue_agent_jwt(state, agent).await;
    QuickDeviceAgent {
        device_id,
        device_signing_key: sig_key,
        agent_jwt,
    }
}

/// Create a standalone device (not bound to any agent).
/// Useful for enrollment tests where the agent doesn't exist yet.
/// Returns `(device_id_string, signing_key)`.
pub async fn create_standalone_device(
    state: &agent_cordon_server::state::AppState,
) -> (String, p256::ecdsa::SigningKey) {
    use agent_cordon_core::domain::workspace::{Workspace, WorkspaceId, WorkspaceStatus};

    let (sig_key, _sig_jwk, _enc_key, _enc_jwk) = generate_dual_p256_keypairs_jwk();
    let workspace_id = WorkspaceId(Uuid::new_v4());
    let now = chrono::Utc::now();
    let workspace = Workspace {
        id: workspace_id.clone(),
        name: format!("standalone-workspace-{}", workspace_id.0),
        enabled: true,
        status: WorkspaceStatus::Active,
        pk_hash: None,
        encryption_public_key: None,
        tags: vec![],
        owner_id: None,
        parent_id: None,
        tool_name: None,
        created_at: now,
        updated_at: now,
    };
    state
        .store
        .create_workspace(&workspace)
        .await
        .expect("create standalone workspace");
    (workspace_id.0.to_string(), sig_key)
}

// ---------------------------------------------------------------------------
// P-256 / Device JWT helpers
// ---------------------------------------------------------------------------

/// Claims for a device self-signed JWT.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct DeviceAuthClaims {
    pub sub: String,
    pub iat: i64,
    pub exp: i64,
    pub jti: String,
    pub aud: String,
}

/// Generate a P-256 keypair and return (SigningKey, JWK public key as JSON).
pub fn generate_p256_keypair_jwk() -> (p256::ecdsa::SigningKey, Value) {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use p256::ecdsa::SigningKey;
    use p256::elliptic_curve::rand_core::OsRng;

    let signing_key = SigningKey::random(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    let point = verifying_key.to_encoded_point(false);

    let x = URL_SAFE_NO_PAD.encode(point.x().unwrap());
    let y = URL_SAFE_NO_PAD.encode(point.y().unwrap());

    let jwk = json!({
        "kty": "EC",
        "crv": "P-256",
        "x": x,
        "y": y
    });

    (signing_key, jwk)
}

/// Sign a self-signed JWT for a device using its P-256 private key.
///
/// Uses a 30-second TTL (within the 60s limit).
/// Includes `aud: "agentcordon:device-auth"` as required by the server.
pub fn sign_device_jwt(key: &p256::ecdsa::SigningKey, device_id: &str, jti: &str) -> String {
    sign_device_jwt_with_ttl(key, device_id, jti, 30)
}

/// Sign a device JWT with a custom audience claim.
///
/// Used for negative tests that verify audience validation.
pub fn sign_device_jwt_with_aud(
    key: &p256::ecdsa::SigningKey,
    device_id: &str,
    jti: &str,
    aud: &str,
) -> String {
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
    use p256::pkcs8::EncodePrivateKey;

    let now = chrono::Utc::now().timestamp();
    let claims = DeviceAuthClaims {
        sub: device_id.to_string(),
        iat: now,
        exp: now + 30,
        jti: jti.to_string(),
        aud: aud.to_string(),
    };

    let pem = key
        .to_pkcs8_pem(p256::pkcs8::LineEnding::LF)
        .expect("P-256 key to PEM");
    let encoding_key = EncodingKey::from_ec_pem(pem.as_bytes()).expect("encoding key from PEM");

    encode(&Header::new(Algorithm::ES256), &claims, &encoding_key).expect("encode device JWT")
}

/// Sign a device JWT with a custom TTL (in seconds).
pub fn sign_device_jwt_with_ttl(
    key: &p256::ecdsa::SigningKey,
    device_id: &str,
    jti: &str,
    ttl_seconds: i64,
) -> String {
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
    use p256::pkcs8::EncodePrivateKey;

    let now = chrono::Utc::now().timestamp();
    let claims = DeviceAuthClaims {
        sub: device_id.to_string(),
        iat: now,
        exp: now + ttl_seconds,
        jti: jti.to_string(),
        aud: "agentcordon:device-auth".to_string(),
    };

    let pem = key
        .to_pkcs8_pem(p256::pkcs8::LineEnding::LF)
        .expect("P-256 key to PEM");
    let encoding_key = EncodingKey::from_ec_pem(pem.as_bytes()).expect("encoding key from PEM");

    encode(&Header::new(Algorithm::ES256), &claims, &encoding_key).expect("encode device JWT")
}

// ---------------------------------------------------------------------------
// Sprint 2: Dual keypair + device-agent helpers
// ---------------------------------------------------------------------------

/// Generate two P-256 keypairs: one for signing (`use: sig`) and one for encryption (`use: enc`).
///
/// Returns `(sig_key, sig_jwk, enc_key, enc_jwk)`.
pub fn generate_dual_p256_keypairs_jwk() -> (
    p256::ecdsa::SigningKey,
    Value,
    p256::ecdsa::SigningKey,
    Value,
) {
    let (sig_key, mut sig_jwk) = generate_p256_keypair_jwk();
    sig_jwk
        .as_object_mut()
        .unwrap()
        .insert("use".to_string(), json!("sig"));

    let (enc_key, mut enc_jwk) = generate_p256_keypair_jwk();
    enc_jwk
        .as_object_mut()
        .unwrap()
        .insert("use".to_string(), json!("enc"));

    (sig_key, sig_jwk, enc_key, enc_jwk)
}

/// Create a workspace via direct store insertion, return `(workspace_id, bootstrap_token)`.
///
/// POST /api/v1/workspaces no longer exists — workspaces are created via registration.
/// This helper creates directly in the store for tests that need a workspace quickly.
/// The `bootstrap_token` is a dummy value for backward compat (enrollment is gone).
pub async fn create_device_via_api(
    state: &agent_cordon_server::state::AppState,
    _cookie: &str,
    _csrf: &str,
    name: &str,
) -> (String, String) {
    use agent_cordon_core::domain::workspace::{Workspace, WorkspaceId, WorkspaceStatus};

    let workspace_id = WorkspaceId(Uuid::new_v4());
    let now = chrono::Utc::now();
    let workspace = Workspace {
        id: workspace_id.clone(),
        name: name.to_string(),
        enabled: true,
        status: WorkspaceStatus::Active,
        pk_hash: None,
        encryption_public_key: None,
        tags: vec![],
        owner_id: None,
        parent_id: None,
        tool_name: None,
        created_at: now,
        updated_at: now,
    };
    state
        .store
        .create_workspace(&workspace)
        .await
        .unwrap_or_else(|_| panic!("create workspace '{}'", name));
    // Return workspace_id as the "bootstrap_token" — enrollment is no longer a concept.
    // The enroll_device helper reads this to return the correct ID.
    (workspace_id.0.to_string(), workspace_id.0.to_string())
}

/// Enroll a device — now a no-op since enrollment is gone.
///
/// Returns `device_id` which is the workspace ID passed as the bootstrap_token.
/// In the unified model, `create_device_via_api` stores the workspace_id in the
/// bootstrap_token field for this purpose.
pub async fn enroll_device(
    _state: &agent_cordon_server::state::AppState,
    bootstrap_token: &str,
    _sig_jwk: &Value,
    _enc_jwk: &Value,
) -> String {
    // bootstrap_token now carries the workspace_id from create_device_via_api
    bootstrap_token.to_string()
}

/// Create an agent bound to a device directly in DB.
///
/// Replaces the old device-mediated enrollment flow (removed in v1.13.0).
/// Returns `(agent_id_string, "")` — second element is empty for backwards compat.
pub async fn enroll_agent_through_device(
    state: &agent_cordon_server::state::AppState,
    _device_key: &p256::ecdsa::SigningKey,
    _device_id: &str,
    agent_name: &str,
) -> (String, String) {
    use agent_cordon_core::domain::workspace::{Workspace, WorkspaceId, WorkspaceStatus};

    let workspace_id = WorkspaceId(Uuid::new_v4());
    let now = chrono::Utc::now();

    let workspace = Workspace {
        id: workspace_id.clone(),
        name: agent_name.to_string(),
        enabled: true,
        status: WorkspaceStatus::Active,
        pk_hash: None,
        encryption_public_key: None,
        tags: vec![],
        owner_id: None,
        parent_id: None,
        tool_name: None,
        created_at: now,
        updated_at: now,
    };

    state
        .store
        .create_workspace(&workspace)
        .await
        .expect("create workspace in DB");

    (workspace_id.0.to_string(), String::new())
}

/// No-op approval — agents are now created directly.
///
/// Returns `(agent_id, "")`. The `session_token` parameter is actually the
/// agent_id from `enroll_agent_through_device`.
pub async fn approve_and_get_api_key(
    _state: &agent_cordon_server::state::AppState,
    _cookie: &str,
    _csrf: &str,
    session_token: &str,
    _approval_ref: &str,
) -> (String, String) {
    // session_token is actually the agent_id from enroll_agent_through_device
    (session_token.to_string(), String::new())
}

/// Call the credential vend endpoint.
///
/// Returns the parsed JSON response body.
pub async fn vend_credential(
    state: &agent_cordon_server::state::AppState,
    _device_key: &p256::ecdsa::SigningKey,
    _device_id: &str,
    workspace_jwt: &str,
    credential_id: &str,
) -> Value {
    let app = agent_cordon_server::build_router(state.clone());

    let request = axum::http::Request::builder()
        .method(Method::POST)
        .uri(format!("/api/v1/credentials/{}/vend", credential_id))
        .header(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {}", workspace_jwt),
        )
        .header(axum::http::header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::empty())
        .unwrap();

    let response = tower::ServiceExt::oneshot(app, request).await.unwrap();
    let status = response.status();
    let bytes = http_body_util::BodyExt::collect(response.into_body())
        .await
        .unwrap()
        .to_bytes();
    let json: Value = serde_json::from_slice(&bytes).unwrap_or(json!(null));

    assert_eq!(status, StatusCode::OK, "vend credential: {}", json);
    json
}

/// Context returned by `setup_full_device_agent` — everything needed for
/// device-mediated agent operations.
pub struct DeviceAgentContext {
    pub device_id: String,
    pub device_signing_key: p256::ecdsa::SigningKey,
    pub device_encryption_key: p256::ecdsa::SigningKey,
    pub agent_id: String,
    /// Legacy field — always empty. API keys have been removed.
    pub agent_api_key: String,
    pub agent_jwt: String,
}

/// Full convenience helper: create a workspace and issue a workspace identity JWT.
///
/// Returns a `DeviceAgentContext` with all IDs, keys, and tokens.
pub async fn setup_full_device_agent(
    state: &agent_cordon_server::state::AppState,
    cookie: &str,
    csrf: &str,
) -> DeviceAgentContext {
    // Generate dual keypairs
    let (sig_key, _sig_jwk, enc_key, _enc_jwk) = generate_dual_p256_keypairs_jwk();

    // Create workspace directly in DB
    let (device_id, _bootstrap_token) =
        create_device_via_api(state, cookie, csrf, "full-setup-workspace").await;

    // The workspace IS the agent in the unified model
    let agent_id = device_id.clone();

    // Issue workspace identity JWT
    let agent_jwt = get_jwt_via_device(state, &sig_key, &device_id, "").await;

    DeviceAgentContext {
        device_id,
        device_signing_key: sig_key,
        device_encryption_key: enc_key,
        agent_id,
        agent_api_key: String::new(),
        agent_jwt,
    }
}

// ---------------------------------------------------------------------------
// TestContext convenience helpers
// ---------------------------------------------------------------------------

use agent_cordon_server::test_helpers::TestContext;

/// Get admin JWT from a TestContext via direct JWT issuance.
pub async fn ctx_admin_jwt(ctx: &TestContext) -> String {
    let agent = ctx.admin_agent.as_ref().expect("admin agent must exist");
    issue_agent_jwt(&ctx.state, agent).await
}

/// Get a named agent's JWT from a TestContext via direct JWT issuance.
pub async fn ctx_agent_jwt(ctx: &TestContext, name: &str) -> String {
    let agent = ctx.agents.get(name).unwrap_or_else(|| {
        panic!("no agent record for '{}'", name);
    });
    issue_agent_jwt(&ctx.state, agent).await
}

/// Send a dual-auth request using the admin device from a TestContext.
pub async fn ctx_admin_send(
    ctx: &TestContext,
    method: Method,
    uri: &str,
    agent_jwt: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let dev = ctx.admin_device.as_ref().expect("admin device must exist");
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

/// Send a dual-auth request using a named agent's device from a TestContext.
pub async fn ctx_agent_send(
    ctx: &TestContext,
    name: &str,
    method: Method,
    uri: &str,
    agent_jwt: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let dev = ctx.device_contexts.get(name).unwrap_or_else(|| {
        panic!("no device context for agent '{}'", name);
    });
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

// ---------------------------------------------------------------------------
// Cedar policy helpers
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Ed25519 / Workspace Identity helpers (v1.6)
// ---------------------------------------------------------------------------

/// Generate an Ed25519 keypair for workspace identity tests.
pub fn generate_ed25519_keypair() -> (ed25519_dalek::SigningKey, ed25519_dalek::VerifyingKey) {
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let verifying_key = signing_key.verifying_key();
    (signing_key, verifying_key)
}

/// Compute the SHA-256 hex hash of an Ed25519 public key (workspace pk_hash).
pub fn compute_workspace_pk_hash(pubkey: &ed25519_dalek::VerifyingKey) -> String {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(pubkey.as_bytes());
    hex::encode(hash)
}

/// Sign a payload with an Ed25519 signing key.
pub fn sign_ed25519(key: &ed25519_dalek::SigningKey, payload: &[u8]) -> Vec<u8> {
    use ed25519_dalek::Signer;
    let signature = key.sign(payload);
    signature.to_bytes().to_vec()
}

/// Register a workspace identity directly in the store for testing.
///
/// Creates an active workspace identity with the given pk_hash.
/// Returns the workspace identity ID (UUID string).
pub async fn register_workspace_identity(
    store: &(dyn Store + Send + Sync),
    pk_hash: &str,
    name: Option<&str>,
) -> String {
    use agent_cordon_core::domain::workspace::{Workspace, WorkspaceId, WorkspaceStatus};
    let now = chrono::Utc::now();
    let workspace = Workspace {
        id: WorkspaceId(Uuid::new_v4()),
        name: name.unwrap_or("test-workspace").to_string(),
        enabled: true,
        status: WorkspaceStatus::Active,
        pk_hash: Some(pk_hash.to_string()),
        encryption_public_key: None,
        tags: vec![],
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
    workspace.id.0.to_string()
}

/// Perform a workspace registration flow via the API (admin approves, CLI exchanges code).
///
/// Returns `(agent_id, identity_jwt)`.
pub async fn register_workspace_via_api(
    app: &Router,
    signing_key: &ed25519_dalek::SigningKey,
    pk_hash: &str,
    nonce: &[u8],
    admin_cookie: &str,
    csrf_token: &str,
) -> (String, String) {
    use sha2::{Digest, Sha256};

    let code_challenge = hex::encode(Sha256::digest(nonce));

    // Admin approves registration
    let (status, body) = send_json(
        app,
        Method::POST,
        "/api/v1/workspace-identities/register",
        None,
        Some(admin_cookie),
        Some(csrf_token),
        Some(json!({
            "pk_hash": pk_hash,
            "code_challenge": code_challenge,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "approval failed: {}", body);
    let approval_code = body["data"]["approval_code"]
        .as_str()
        .expect("approval_code")
        .to_string();

    // CLI exchanges code
    let timestamp = chrono::Utc::now().timestamp();
    let pubkey_bytes = signing_key.verifying_key().as_bytes().to_vec();

    // Build signature over (domain_separator || approval_code || pk_hash || nonce || timestamp)
    let mut sign_payload = Vec::new();
    sign_payload.extend_from_slice(b"agentcordon:registration-v1");
    sign_payload.extend_from_slice(approval_code.as_bytes());
    sign_payload.extend_from_slice(&hex::decode(pk_hash).expect("decode pk_hash"));
    sign_payload.extend_from_slice(nonce);
    sign_payload.extend_from_slice(&timestamp.to_be_bytes());
    let signature = sign_ed25519(signing_key, &sign_payload);

    let (status, body) = send_json(
        app,
        Method::POST,
        "/api/v1/agents/register",
        None,
        None,
        None,
        Some(json!({
            "approval_code": approval_code,
            "public_key": hex::encode(&pubkey_bytes),
            "nonce": hex::encode(nonce),
            "timestamp": timestamp,
            "signature": hex::encode(&signature),
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "code exchange failed: {}", body);

    let agent_id = body["data"]["workspace_id"]
        .as_str()
        .expect("workspace_id")
        .to_string();
    let identity_jwt = body["data"]["identity_jwt"]
        .as_str()
        .expect("identity_jwt")
        .to_string();
    (agent_id, identity_jwt)
}

/// Context returned by `register_workspace_full_context` — everything needed for
/// workspace identity operations using the full API registration handshake.
pub struct WorkspaceRegisteredContext {
    pub signing_key: ed25519_dalek::SigningKey,
    pub verifying_key: ed25519_dalek::VerifyingKey,
    pub pk_hash: String,
    pub agent_id: String,
    pub identity_jwt: String,
    pub nonce: Vec<u8>,
}

/// Full convenience helper: generate Ed25519 keypair, register workspace via API
/// (admin approval + PKCE code exchange), return context with all keys and IDs.
///
/// This replaces `setup_workspace_identity()` for E2E tests — it goes through
/// the full multi-party registration handshake instead of inserting directly into the DB.
pub async fn register_workspace_full_context(
    app: &Router,
    admin_cookie: &str,
    csrf: &str,
) -> WorkspaceRegisteredContext {
    let (signing_key, verifying_key) = generate_ed25519_keypair();
    let pk_hash = compute_workspace_pk_hash(&verifying_key);
    let nonce: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();

    let (agent_id, identity_jwt) =
        register_workspace_via_api(app, &signing_key, &pk_hash, &nonce, admin_cookie, csrf).await;

    WorkspaceRegisteredContext {
        signing_key,
        verifying_key,
        pk_hash,
        agent_id,
        identity_jwt,
        nonce,
    }
}

/// Create Cedar grant policies for a credential permission grant.
///
/// This replaces `store.grant_credential_permission()` which writes to the DB
/// `credential_permissions` table. The production code now uses Cedar policies
/// named `grant:{cred_id}:{agent_id}:{action}` for authorization.
///
/// After creating policies, reloads the policy engine so they take effect.
pub async fn grant_cedar_permission(
    state: &agent_cordon_server::state::AppState,
    cred_id: &agent_cordon_core::domain::credential::CredentialId,
    agent_id: &agent_cordon_core::domain::workspace::WorkspaceId,
    permission: &str,
) {
    let cedar_actions: Vec<&str> = match permission {
        "delegated_use" => vec!["vend_credential"],
        "read" => vec!["list"],
        "write" => vec!["update"],
        "delete" => vec!["delete"],
        _ => panic!("unknown permission: {}", permission),
    };
    let now = chrono::Utc::now();
    for cedar_action in &cedar_actions {
        let policy_name = format!("grant:{}:{}:{}", cred_id.0, agent_id.0, cedar_action);
        let cedar_policy = format!(
            "permit(\n  principal == AgentCordon::Workspace::\"{}\",\n  action == AgentCordon::Action::\"{}\",\n  resource == AgentCordon::Credential::\"{}\"\n);",
            agent_id.0, cedar_action, cred_id.0
        );
        let stored_policy = agent_cordon_core::domain::policy::StoredPolicy {
            id: agent_cordon_core::domain::policy::PolicyId(Uuid::new_v4()),
            name: policy_name,
            description: Some(format!("Test grant {} on credential for agent", permission)),
            cedar_policy,
            enabled: true,
            is_system: true,
            created_at: now,
            updated_at: now,
        };
        state
            .store
            .store_policy(&stored_policy)
            .await
            .expect("store grant policy");
    }
    // Reload engine so Cedar picks up the new policies
    let db_policies = state
        .store
        .get_all_enabled_policies()
        .await
        .expect("get policies");
    let sources: Vec<(String, String)> = db_policies
        .into_iter()
        .map(|p| (p.id.0.to_string(), p.cedar_policy))
        .collect();
    state
        .policy_engine
        .reload_policies(sources)
        .expect("reload policy engine");
}

/// Grant credential permissions via Cedar policies using store + policy_engine directly.
///
/// Drop-in replacement for the removed `store.grant_credential_permission()`.
/// Accepts any combination of store and policy engine references.
pub async fn grant_credential_permission_via_cedar(
    store: &(dyn agent_cordon_core::storage::Store + Send + Sync),
    policy_engine: &(dyn agent_cordon_core::policy::PolicyEngine + Send + Sync),
    cred_id: &agent_cordon_core::domain::credential::CredentialId,
    agent_id: &agent_cordon_core::domain::workspace::WorkspaceId,
    permission: &str,
) {
    let cedar_actions: Vec<&str> = match permission {
        "delegated_use" => vec!["vend_credential"],
        "read" => vec!["list"],
        "write" => vec!["update"],
        "delete" => vec!["delete"],
        _ => panic!("unknown permission: {}", permission),
    };
    let now = chrono::Utc::now();
    for cedar_action in &cedar_actions {
        let policy_name = format!("grant:{}:{}:{}", cred_id.0, agent_id.0, cedar_action);
        let cedar_policy = format!(
            "permit(\n  principal == AgentCordon::Workspace::\"{}\",\n  action == AgentCordon::Action::\"{}\",\n  resource == AgentCordon::Credential::\"{}\"\n);",
            agent_id.0, cedar_action, cred_id.0
        );
        let stored_policy = agent_cordon_core::domain::policy::StoredPolicy {
            id: agent_cordon_core::domain::policy::PolicyId(Uuid::new_v4()),
            name: policy_name,
            description: Some(format!("Test grant {} on credential for agent", permission)),
            cedar_policy,
            enabled: true,
            is_system: true,
            created_at: now,
            updated_at: now,
        };
        store
            .store_policy(&stored_policy)
            .await
            .expect("store grant policy");
    }
    // Reload engine so Cedar picks up the new policies
    let db_policies = store
        .get_all_enabled_policies()
        .await
        .expect("get policies");
    let sources: Vec<(String, String)> = db_policies
        .into_iter()
        .map(|p| (p.id.0.to_string(), p.cedar_policy))
        .collect();
    policy_engine
        .reload_policies(sources)
        .expect("reload policy engine");
}

/// Revoke a Cedar grant policy for a credential permission.
///
/// This replaces `store.revoke_credential_permission()` for the Cedar-based model.
pub async fn revoke_cedar_permission(
    state: &agent_cordon_server::state::AppState,
    cred_id: &agent_cordon_core::domain::credential::CredentialId,
    agent_id: &agent_cordon_core::domain::workspace::WorkspaceId,
    permission: &str,
) {
    let cedar_actions: Vec<&str> = match permission {
        "delegated_use" => vec!["vend_credential"],
        "read" => vec!["list"],
        "write" => vec!["update"],
        "delete" => vec!["delete"],
        _ => panic!("unknown permission: {}", permission),
    };
    for cedar_action in &cedar_actions {
        let policy_name = format!("grant:{}:{}:{}", cred_id.0, agent_id.0, cedar_action);
        state
            .store
            .delete_policy_by_name(&policy_name)
            .await
            .expect("delete grant policy");
    }
    // Reload engine
    let db_policies = state
        .store
        .get_all_enabled_policies()
        .await
        .expect("get policies");
    let sources: Vec<(String, String)> = db_policies
        .into_iter()
        .map(|p| (p.id.0.to_string(), p.cedar_policy))
        .collect();
    state
        .policy_engine
        .reload_policies(sources)
        .expect("reload policy engine");
}

pub fn default_policy_no_auto_enroll() -> String {
    let default = include_str!("../../../../policies/default.cedar");
    // Remove the 6-enroll rule that auto-approves device enrollment.
    // The rule starts with "// 6-enroll." comment and ends at the closing "};".
    let mut result = String::new();
    let mut skip = false;
    for line in default.lines() {
        if line.contains("6-enroll.") {
            skip = true;
            continue;
        }
        if skip {
            if line.trim_start().starts_with("};") {
                skip = false;
                continue;
            }
            continue;
        }
        result.push_str(line);
        result.push('\n');
    }
    result
}
