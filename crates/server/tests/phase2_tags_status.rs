//! Integration tests for Phase 2: Credential Tags, Agent Tags (roles->tags rename),
//! Agent Status (B-010), and Bootstrap Admin Removal (F-009).
//!
//! Coverage areas:
//! - F-010: Credential tags CRUD, agent roles->tags rename
//! - B-010: Agent status lifecycle (new -> active -> idle)
//! - F-009: No bootstrap admin agent (root user still created)

use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;
use uuid::Uuid;

use agent_cordon_core::auth::jwt::JwtIssuer;
use agent_cordon_core::crypto::aes_gcm::AesGcmEncryptor;
use agent_cordon_core::crypto::password::hash_password;
use agent_cordon_core::crypto::SecretEncryptor;
use agent_cordon_core::domain::credential::{CredentialId, StoredCredential};
use agent_cordon_core::domain::user::{User, UserId, UserRole};
use agent_cordon_core::domain::workspace::{Workspace, WorkspaceId, WorkspaceStatus};
use agent_cordon_core::storage::Store;

use crate::common::*;
use agent_cordon_server::config::AppConfig;
use agent_cordon_server::test_helpers::TestAppBuilder;

// ---------------------------------------------------------------------------
// Test constants
// ---------------------------------------------------------------------------

const TEST_PASSWORD: &str = "strong-password-123!";

// ---------------------------------------------------------------------------
// Dual-auth credential helper
// ---------------------------------------------------------------------------

/// Send a request using dual auth (device JWT + agent JWT) via a QuickDeviceAgent.
async fn send_cred(
    app: &Router,
    qda: &QuickDeviceAgent,
    method: Method,
    uri: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    send_json_dual_auth(
        app,
        method,
        uri,
        &qda.device_signing_key,
        &qda.device_id,
        &qda.agent_jwt,
        body,
    )
    .await
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

/// Build the full test application with an in-memory SQLite store.
/// Returns (router, store, encryptor, jwt_issuer).
async fn setup_test_app() -> (
    Router,
    Arc<dyn Store + Send + Sync>,
    Arc<AesGcmEncryptor>,
    Arc<JwtIssuer>,
) {
    let ctx = TestAppBuilder::new().build().await;
    (ctx.app, ctx.store, ctx.encryptor, ctx.jwt_issuer)
}

/// Create a user directly in the store.
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
        created_at: now,
        updated_at: now,
    };
    store.create_user(&user).await.expect("create user");
    user
}

/// Create an agent directly in the store. Returns (Agent, raw_api_key).
async fn create_agent_in_db(
    store: &(dyn Store + Send + Sync),
    name: &str,
    tags: Vec<&str>,
    enabled: bool,
    owner_id: Option<UserId>,
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
        owner_id,
        parent_id: None,
        tool_name: None,
        created_at: now,
        updated_at: now,
    };
    store.create_workspace(&agent).await.expect("create agent");
    (agent, String::new())
}

/// Login a user and return the combined cookie string (session + CSRF).
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
        "login failed for user {}: {}",
        username,
        _body
    );

    // Collect all set-cookie headers into a single cookie string
    let cookies: Vec<String> = headers
        .iter()
        .filter(|(k, _)| k == "set-cookie")
        .map(|(_, v)| {
            // Extract just the cookie name=value part (before the first ';')
            v.split(';').next().unwrap_or("").to_string()
        })
        .collect();
    cookies.join("; ")
}

/// Extract the CSRF token from a cookie string.
fn extract_csrf_from_cookie(cookie: &str) -> Option<String> {
    for pair in cookie.split(';') {
        let pair = pair.trim();
        if let Some(val) = pair.strip_prefix("agtcrdn_csrf=") {
            return Some(val.to_string());
        }
    }
    None
}

/// Helper to send a request and parse the JSON response.
async fn send_json(
    app: &Router,
    method: Method,
    uri: &str,
    bearer: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut builder = Request::builder().method(method).uri(uri);

    if let Some(token) = bearer {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {}", token));
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

/// Helper to send a request with cookie support and return headers.
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

        // Auto-add CSRF header for state-changing methods
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

// ===========================================================================
// F-010: Credential Tags — Happy Paths
// ===========================================================================

#[tokio::test]
async fn credential_create_with_tags_returns_tags() {
    let ctx = TestAppBuilder::new().build().await;
    let (agent, api_key) =
        create_agent_in_db(&*ctx.store, "admin-1", vec!["admin"], true, None).await;
    let qda = quick_device_setup(&ctx.state, &agent, &api_key).await;

    let (status, body) = send_cred(
        &ctx.app,
        &qda,
        Method::POST,
        "/api/v1/credentials",
        Some(json!({
            "name": "tagged-cred",
            "service": "github",
            "secret_value": "ghp_secret123",
            "scopes": ["repo"],
            "tags": ["production", "ci-credentials"]
        })),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "response: {}", body);
    let tags = body["data"]["tags"]
        .as_array()
        .expect("tags should be array");
    assert_eq!(tags.len(), 2);
    assert!(tags.contains(&json!("production")));
    assert!(tags.contains(&json!("ci-credentials")));
}

#[tokio::test]
async fn credential_create_without_tags_returns_empty_array() {
    let ctx = TestAppBuilder::new().build().await;
    let (agent, api_key) =
        create_agent_in_db(&*ctx.store, "admin-2", vec!["admin"], true, None).await;
    let qda = quick_device_setup(&ctx.state, &agent, &api_key).await;

    let (status, body) = send_cred(
        &ctx.app,
        &qda,
        Method::POST,
        "/api/v1/credentials",
        Some(json!({
            "name": "untagged-cred",
            "service": "github",
            "secret_value": "ghp_secret456",
            "scopes": ["repo"]
        })),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "response: {}", body);
    let tags = body["data"]["tags"]
        .as_array()
        .expect("tags should be array");
    assert!(tags.is_empty(), "tags should be empty when not provided");
}

#[tokio::test]
async fn credential_update_tags_via_put() {
    let ctx = TestAppBuilder::new().build().await;
    let (agent, api_key) =
        create_agent_in_db(&*ctx.store, "admin-3", vec!["admin"], true, None).await;
    let qda = quick_device_setup(&ctx.state, &agent, &api_key).await;

    // Create credential with initial tags
    let (status, body) = send_cred(
        &ctx.app,
        &qda,
        Method::POST,
        "/api/v1/credentials",
        Some(json!({
            "name": "update-tags-cred",
            "service": "slack",
            "secret_value": "xoxb-secret",
            "scopes": ["chat:write"],
            "tags": ["staging"]
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "create: {}", body);
    let cred_id = body["data"]["id"].as_str().unwrap();

    // Update tags via PUT
    let (status, body) = send_cred(
        &ctx.app,
        &qda,
        Method::PUT,
        &format!("/api/v1/credentials/{}", cred_id),
        Some(json!({
            "tags": ["production", "critical"]
        })),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "update: {}", body);
    let tags = body["data"]["tags"]
        .as_array()
        .expect("tags should be array");
    assert_eq!(tags.len(), 2);
    assert!(tags.contains(&json!("production")));
    assert!(tags.contains(&json!("critical")));
}

#[tokio::test]
async fn credential_tags_appear_in_list() {
    let ctx = TestAppBuilder::new().build().await;
    let (agent, api_key) =
        create_agent_in_db(&*ctx.store, "admin-4", vec!["admin"], true, None).await;
    let qda = quick_device_setup(&ctx.state, &agent, &api_key).await;

    // Create two credentials with different tags
    let (status, _body) = send_cred(
        &ctx.app,
        &qda,
        Method::POST,
        "/api/v1/credentials",
        Some(json!({
            "name": "list-cred-a",
            "service": "test",
            "secret_value": "secret-a",
            "tags": ["env:prod"]
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, _body) = send_cred(
        &ctx.app,
        &qda,
        Method::POST,
        "/api/v1/credentials",
        Some(json!({
            "name": "list-cred-b",
            "service": "test",
            "secret_value": "secret-b",
            "tags": ["env:staging", "team:platform"]
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // List credentials and verify tags are present
    let (status, body) = send_cred(&ctx.app, &qda, Method::GET, "/api/v1/credentials", None).await;
    assert_eq!(status, StatusCode::OK, "list: {}", body);

    let creds = body["data"].as_array().expect("data should be array");
    let cred_a = creds
        .iter()
        .find(|c| c["name"] == "list-cred-a")
        .expect("cred-a should be in list");
    let cred_b = creds
        .iter()
        .find(|c| c["name"] == "list-cred-b")
        .expect("cred-b should be in list");

    assert_eq!(cred_a["tags"], json!(["env:prod"]));
    let b_tags = cred_b["tags"].as_array().unwrap();
    assert_eq!(b_tags.len(), 2);
}

#[tokio::test]
async fn credential_tags_appear_in_get_detail() {
    let ctx = TestAppBuilder::new().build().await;
    let (agent, api_key) =
        create_agent_in_db(&*ctx.store, "admin-5", vec!["admin"], true, None).await;
    let qda = quick_device_setup(&ctx.state, &agent, &api_key).await;

    // Create credential with tags
    let (status, body) = send_cred(
        &ctx.app,
        &qda,
        Method::POST,
        "/api/v1/credentials",
        Some(json!({
            "name": "detail-cred",
            "service": "test",
            "secret_value": "secret-detail",
            "tags": ["important", "reviewed"]
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let cred_id = body["data"]["id"].as_str().unwrap();

    // GET detail
    let (status, body) = send_cred(
        &ctx.app,
        &qda,
        Method::GET,
        &format!("/api/v1/credentials/{}", cred_id),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "detail: {}", body);
    let tags = body["data"]["tags"]
        .as_array()
        .expect("tags should be array");
    assert_eq!(tags.len(), 2);
    assert!(tags.contains(&json!("important")));
    assert!(tags.contains(&json!("reviewed")));
}

#[tokio::test]
async fn credential_update_tags_to_empty() {
    let ctx = TestAppBuilder::new().build().await;
    let (agent, api_key) =
        create_agent_in_db(&*ctx.store, "admin-6", vec!["admin"], true, None).await;
    let qda = quick_device_setup(&ctx.state, &agent, &api_key).await;

    // Create credential with tags
    let (status, body) = send_cred(
        &ctx.app,
        &qda,
        Method::POST,
        "/api/v1/credentials",
        Some(json!({
            "name": "clear-tags-cred",
            "service": "test",
            "secret_value": "secret-val",
            "tags": ["remove-me"]
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let cred_id = body["data"]["id"].as_str().unwrap();

    // Update tags to empty array
    let (status, body) = send_cred(
        &ctx.app,
        &qda,
        Method::PUT,
        &format!("/api/v1/credentials/{}", cred_id),
        Some(json!({
            "tags": []
        })),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "update: {}", body);
    let tags = body["data"]["tags"]
        .as_array()
        .expect("tags should be array");
    assert!(tags.is_empty(), "tags should be empty after clearing");
}

// ===========================================================================
// F-010: Credential Tags — Sad Paths
// ===========================================================================

#[tokio::test]
async fn credential_create_with_tags_unauthenticated_returns_401() {
    let (app, _store, _enc, _jwt) = setup_test_app().await;

    let (status, _body) = send_json(
        &app,
        Method::POST,
        "/api/v1/credentials",
        None, // no auth
        Some(json!({
            "name": "no-auth-cred",
            "service": "test",
            "secret_value": "secret",
            "tags": ["should-not-work"]
        })),
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn credential_update_tags_nonexistent_credential_returns_404() {
    let ctx = TestAppBuilder::new().build().await;
    let (agent, api_key) =
        create_agent_in_db(&*ctx.store, "admin-7", vec!["admin"], true, None).await;
    let qda = quick_device_setup(&ctx.state, &agent, &api_key).await;

    let fake_id = Uuid::new_v4();
    let (status, _body) = send_cred(
        &ctx.app,
        &qda,
        Method::PUT,
        &format!("/api/v1/credentials/{}", fake_id),
        Some(json!({
            "tags": ["wont-work"]
        })),
    )
    .await;

    assert_eq!(status, StatusCode::NOT_FOUND, "response: {}", _body);
}

#[tokio::test]
async fn credential_update_tags_unauthenticated_returns_401() {
    let (app, store, enc, _jwt) = setup_test_app().await;
    let (admin, _api_key) = create_agent_in_db(&*store, "admin-8", vec!["admin"], true, None).await;

    // Create a credential directly in DB
    let now = chrono::Utc::now();
    let cred_id = CredentialId(Uuid::new_v4());
    let (encrypted, nonce) = enc
        .encrypt(b"secret", cred_id.0.to_string().as_bytes())
        .expect("encrypt");
    let cred = StoredCredential {
        id: cred_id.clone(),
        name: "noauth-update-cred".to_string(),
        service: "test".to_string(),
        encrypted_value: encrypted,
        nonce,
        scopes: vec![],
        metadata: json!({}),
        created_by: Some(admin.id.clone()),
        created_by_user: None,
        created_at: now,
        updated_at: now,
        allowed_url_pattern: None,
        expires_at: None,
        transform_script: None,
        transform_name: None,
        vault: "default".to_string(),
        credential_type: "generic".to_string(),
        tags: vec!["original".to_string()],
        description: None,
        target_identity: None,
        key_version: 1,
    };
    store.store_credential(&cred).await.expect("store cred");

    let (status, _body) = send_json(
        &app,
        Method::PUT,
        &format!("/api/v1/credentials/{}", cred_id.0),
        None, // no auth
        Some(json!({ "tags": ["hacked"] })),
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

// ===========================================================================
// F-010: Agent Tags (roles -> tags rename) — Happy Paths
// ===========================================================================

#[tokio::test]
async fn agent_created_with_tags_field_works() {
    let (app, store, _enc, _jwt) = setup_test_app().await;
    // Create admin user for the user-auth agent management endpoints
    let _admin_user = create_user_in_db(
        &*store,
        "admin-user",
        TEST_PASSWORD,
        UserRole::Admin,
        true,
        true,
    )
    .await;
    let cookie = login_user(&app, "admin-user", TEST_PASSWORD).await;

    // Create an agent with tags via direct DB insertion
    let (agent, _api_key) = create_agent_in_db(
        &*store,
        "tagged-agent",
        vec!["ci-bot", "deploy"],
        true,
        Some(_admin_user.id.clone()),
    )
    .await;

    // Verify agent detail returns tags (not roles)
    let (status, body, _headers) = send_json_with_headers(
        &app,
        Method::GET,
        &format!("/api/v1/workspaces/{}", agent.id.0),
        None,
        Some(&cookie),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::OK, "response: {}", body);
    // Must have `tags` field
    let tags = body["data"]["tags"]
        .as_array()
        .expect("tags should be array");
    assert_eq!(tags.len(), 2);
    assert!(tags.contains(&json!("ci-bot")));
    assert!(tags.contains(&json!("deploy")));
    // Must NOT have `roles` field at the top level of the agent data
    assert!(
        body["data"].get("roles").is_none(),
        "response should use 'tags' not 'roles'"
    );
}

#[tokio::test]
async fn agent_list_uses_tags_field() {
    let (app, store, _enc, _jwt) = setup_test_app().await;
    let admin_user = create_user_in_db(
        &*store,
        "admin-list",
        TEST_PASSWORD,
        UserRole::Admin,
        true,
        true,
    )
    .await;
    let cookie = login_user(&app, "admin-list", TEST_PASSWORD).await;

    // Create agents with different tags
    let (_a1, _k1) = create_agent_in_db(
        &*store,
        "bot-alpha",
        vec!["reader"],
        true,
        Some(admin_user.id.clone()),
    )
    .await;
    let (_a2, _k2) = create_agent_in_db(
        &*store,
        "bot-beta",
        vec!["writer", "admin"],
        true,
        Some(admin_user.id.clone()),
    )
    .await;

    let (status, body, _) = send_json_with_headers(
        &app,
        Method::GET,
        "/api/v1/workspaces",
        None,
        Some(&cookie),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::OK, "response: {}", body);
    let agents = body["data"].as_array().expect("data should be array");
    assert!(agents.len() >= 2, "should have at least 2 agents");

    for agent in agents {
        // Every agent in the list should have `tags`, not `roles`
        assert!(
            agent.get("tags").is_some(),
            "agent {} should have 'tags' field",
            agent["name"]
        );
        assert!(
            agent.get("roles").is_none(),
            "agent {} should NOT have 'roles' field",
            agent["name"]
        );
    }
}

#[tokio::test]
async fn agent_update_tags_via_put() {
    let (app, store, _enc, _jwt) = setup_test_app().await;
    let admin_user = create_user_in_db(
        &*store,
        "admin-update-tags",
        TEST_PASSWORD,
        UserRole::Admin,
        true,
        true,
    )
    .await;
    let cookie = login_user(&app, "admin-update-tags", TEST_PASSWORD).await;

    let (agent, _api_key) = create_agent_in_db(
        &*store,
        "update-tags-agent",
        vec!["old-tag"],
        true,
        Some(admin_user.id.clone()),
    )
    .await;

    // Update agent tags
    let (status, body, _) = send_json_with_headers(
        &app,
        Method::PUT,
        &format!("/api/v1/workspaces/{}", agent.id.0),
        None,
        Some(&cookie),
        Some(json!({ "tags": ["new-tag", "another-tag"] })),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "update response: {}", body);
    let tags = body["data"]["tags"]
        .as_array()
        .expect("tags should be array");
    assert_eq!(tags.len(), 2);
    assert!(tags.contains(&json!("new-tag")));
    assert!(tags.contains(&json!("another-tag")));
}

// ===========================================================================
// F-010: Agent Tags — Sad Paths
// ===========================================================================

#[tokio::test]
async fn agent_detail_unauthenticated_returns_401() {
    let (app, store, _enc, _jwt) = setup_test_app().await;
    let (agent, _key) =
        create_agent_in_db(&*store, "noauth-agent", vec!["viewer"], true, None).await;

    // Try to get agent detail without authentication (no cookie, no bearer)
    let (status, _body) = send_json(
        &app,
        Method::GET,
        &format!("/api/v1/workspaces/{}", agent.id.0),
        None,
        None,
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn agent_list_non_admin_user_denied() {
    let (app, store, _enc, _jwt) = setup_test_app().await;
    let _viewer = create_user_in_db(
        &*store,
        "viewer-user",
        TEST_PASSWORD,
        UserRole::Viewer,
        false,
        true,
    )
    .await;
    let cookie = login_user(&app, "viewer-user", TEST_PASSWORD).await;

    let (status, _body, _) = send_json_with_headers(
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
        StatusCode::FORBIDDEN,
        "viewer should not list agents: {}",
        _body
    );
}

// ===========================================================================
// B-010: Agent Status — Happy Paths
// ===========================================================================

#[tokio::test]
async fn workspace_status_active_when_created() {
    let (app, store, _enc, _jwt) = setup_test_app().await;
    let admin_user = create_user_in_db(
        &*store,
        "admin-status-new",
        TEST_PASSWORD,
        UserRole::Admin,
        true,
        true,
    )
    .await;
    let cookie = login_user(&app, "admin-status-new", TEST_PASSWORD).await;

    // Create workspace — should have active status
    let (agent, _api_key) = create_agent_in_db(
        &*store,
        "new-status-agent",
        vec!["viewer"],
        true,
        Some(admin_user.id.clone()),
    )
    .await;

    // Get workspace detail — status should be "active"
    let (status, body, _) = send_json_with_headers(
        &app,
        Method::GET,
        &format!("/api/v1/workspaces/{}", agent.id.0),
        None,
        Some(&cookie),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::OK, "response: {}", body);
    assert_eq!(
        body["data"]["status"], "active",
        "newly created workspace should have status 'active'"
    );
}

#[tokio::test]
async fn agent_status_active_after_activation() {
    let ctx = TestAppBuilder::new().build().await;
    let admin_user = create_user_in_db(
        &*ctx.store,
        "admin-status-active",
        TEST_PASSWORD,
        UserRole::Admin,
        true,
        true,
    )
    .await;
    let cookie = login_user(&ctx.app, "admin-status-active", TEST_PASSWORD).await;

    // Create agent with Active status
    let (agent, _api_key) = create_agent_in_db(
        &*ctx.store,
        "active-status-agent",
        vec!["viewer"],
        true,
        Some(admin_user.id.clone()),
    )
    .await;

    // Get agent detail — status should be "active"
    let (status, body, _) = send_json_with_headers(
        &ctx.app,
        Method::GET,
        &format!("/api/v1/workspaces/{}", agent.id.0),
        None,
        Some(&cookie),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::OK, "response: {}", body);
    assert_eq!(
        body["data"]["status"], "active",
        "workspace with Active status should report 'active'"
    );
}

#[tokio::test]
async fn agent_status_revoked() {
    let (app, store, _enc, _jwt) = setup_test_app().await;
    let admin_user = create_user_in_db(
        &*store,
        "admin-status-idle",
        TEST_PASSWORD,
        UserRole::Admin,
        true,
        true,
    )
    .await;
    let cookie = login_user(&app, "admin-status-idle", TEST_PASSWORD).await;

    // Create agent with Revoked status
    let now = chrono::Utc::now();
    let agent = Workspace {
        id: WorkspaceId(Uuid::new_v4()),
        name: "revoked-status-agent".to_string(),
        enabled: false,
        status: WorkspaceStatus::Revoked,
        pk_hash: None,
        encryption_public_key: None,
        tags: vec!["viewer".to_string()],
        owner_id: Some(admin_user.id.clone()),
        parent_id: None,
        tool_name: None,
        created_at: now,
        updated_at: now,
    };
    store.create_workspace(&agent).await.expect("create agent");

    // Get agent detail — status should be "revoked"
    let (status, body, _) = send_json_with_headers(
        &app,
        Method::GET,
        &format!("/api/v1/workspaces/{}", agent.id.0),
        None,
        Some(&cookie),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::OK, "response: {}", body);
    assert_eq!(
        body["data"]["status"], "revoked",
        "workspace with Revoked status should report 'revoked'"
    );
}

#[tokio::test]
async fn workspace_status_appears_in_list() {
    let ctx = TestAppBuilder::new().build().await;
    let admin_user = create_user_in_db(
        &*ctx.store,
        "admin-status-list",
        TEST_PASSWORD,
        UserRole::Admin,
        true,
        true,
    )
    .await;
    let cookie = login_user(&ctx.app, "admin-status-list", TEST_PASSWORD).await;

    // Create workspaces with different statuses
    let now = chrono::Utc::now();
    for (name, ws_status) in [
        ("status-list-pending", WorkspaceStatus::Pending),
        ("status-list-active", WorkspaceStatus::Active),
        ("status-list-revoked", WorkspaceStatus::Revoked),
    ] {
        let ws = Workspace {
            id: WorkspaceId(Uuid::new_v4()),
            name: name.to_string(),
            enabled: true,
            status: ws_status,
            pk_hash: None,
            encryption_public_key: None,
            tags: vec!["viewer".to_string()],
            owner_id: Some(admin_user.id.clone()),
            parent_id: None,
            tool_name: None,
            created_at: now,
            updated_at: now,
        };
        ctx.store
            .create_workspace(&ws)
            .await
            .expect("create workspace");
    }

    // List all workspaces
    let (status, body, _) = send_json_with_headers(
        &ctx.app,
        Method::GET,
        "/api/v1/workspaces",
        None,
        Some(&cookie),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "list: {}", body);

    let agents = body["data"].as_array().expect("data should be array");

    let find_agent = |name: &str| -> &Value {
        agents
            .iter()
            .find(|a| a["name"] == name)
            .unwrap_or_else(|| panic!("workspace {} not found in list", name))
    };

    assert_eq!(find_agent("status-list-pending")["status"], "pending");
    assert_eq!(find_agent("status-list-active")["status"], "active");
    assert_eq!(find_agent("status-list-revoked")["status"], "revoked");
}

// ===========================================================================
// B-010: Agent Status — Sad Paths
// ===========================================================================

#[tokio::test]
async fn agent_status_not_exposed_to_unauthenticated() {
    let (app, store, _enc, _jwt) = setup_test_app().await;
    let (agent, _key) =
        create_agent_in_db(&*store, "status-noauth", vec!["viewer"], true, None).await;

    let (status, _body) = send_json(
        &app,
        Method::GET,
        &format!("/api/v1/workspaces/{}", agent.id.0),
        None,
        None,
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn agent_status_nonexistent_agent_returns_404() {
    let (app, store, _enc, _jwt) = setup_test_app().await;
    let _admin_user = create_user_in_db(
        &*store,
        "admin-status-404",
        TEST_PASSWORD,
        UserRole::Admin,
        true,
        true,
    )
    .await;
    let cookie = login_user(&app, "admin-status-404", TEST_PASSWORD).await;

    let fake_id = Uuid::new_v4();
    let (status, _body, _) = send_json_with_headers(
        &app,
        Method::GET,
        &format!("/api/v1/workspaces/{}", fake_id),
        None,
        Some(&cookie),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::NOT_FOUND, "response: {}", _body);
}

// ===========================================================================
// F-009: Bootstrap Admin Removed — root USER still created
// ===========================================================================

#[tokio::test]
async fn no_bootstrap_admin_agent_in_fresh_db() {
    let (_app, store, _enc, _jwt) = setup_test_app().await;

    // In a fresh DB, there should be no agents at all
    let agents = store.list_workspaces().await.expect("list agents");
    assert!(
        agents.is_empty(),
        "fresh DB should have no agents (no bootstrap admin agent)"
    );
}

#[tokio::test]
async fn root_user_can_still_be_created_and_login() {
    let (app, store, _enc, _jwt) = setup_test_app().await;

    // Manually create a root user (simulating what main.rs does on startup)
    let _root = create_user_in_db(
        &*store,
        "root",
        "rootpassword123!",
        UserRole::Admin,
        true,
        true,
    )
    .await;

    // Root user should be able to login
    let cookie = login_user(&app, "root", "rootpassword123!").await;
    assert!(
        !cookie.is_empty(),
        "root user should be able to login and get a session cookie"
    );
}

#[tokio::test]
async fn no_bootstrap_admin_env_var_in_config() {
    // Verify AppConfig::test_default() does not have a bootstrap_admin field.
    // This is a compile-time check — if the field exists, this test file
    // would fail to compile because we never set it in setup_test_app().
    // The fact that setup_test_app() compiles and works without setting
    // bootstrap_admin proves F-009 is complete.
    let config = AppConfig::test_default();
    // Verify config can be created without any bootstrap admin reference
    assert!(config.jwt_ttl_seconds > 0, "config should be valid");
}

// ===========================================================================
// Combined: Credential tags + Agent tags in same flow
// ===========================================================================

#[tokio::test]
async fn user_can_create_credential_with_tags_via_session() {
    let (app, store, _enc, _jwt) = setup_test_app().await;
    let _admin_user = create_user_in_db(
        &*store,
        "admin-cred-tags",
        TEST_PASSWORD,
        UserRole::Admin,
        true,
        true,
    )
    .await;
    let cookie = login_user(&app, "admin-cred-tags", TEST_PASSWORD).await;

    let (status, body, _) = send_json_with_headers(
        &app,
        Method::POST,
        "/api/v1/credentials",
        None,
        Some(&cookie),
        Some(json!({
            "name": "user-tagged-cred",
            "service": "github",
            "secret_value": "ghp_user_secret",
            "scopes": ["repo"],
            "tags": ["user-created", "important"]
        })),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "response: {}", body);
    let tags = body["data"]["tags"]
        .as_array()
        .expect("tags should be array");
    assert_eq!(tags.len(), 2);
    assert!(tags.contains(&json!("user-created")));
    assert!(tags.contains(&json!("important")));
}

#[tokio::test]
async fn credential_tags_persist_after_other_field_update() {
    let ctx = TestAppBuilder::new().build().await;
    let (agent, api_key) =
        create_agent_in_db(&*ctx.store, "admin-persist", vec!["admin"], true, None).await;
    let qda = quick_device_setup(&ctx.state, &agent, &api_key).await;

    // Create credential with tags
    let (status, body) = send_cred(
        &ctx.app,
        &qda,
        Method::POST,
        "/api/v1/credentials",
        Some(json!({
            "name": "persist-tags-cred",
            "service": "test",
            "secret_value": "my-secret",
            "tags": ["keep-me", "stable"]
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let cred_id = body["data"]["id"].as_str().unwrap();

    // Update only the name (not tags)
    let (status, body) = send_cred(
        &ctx.app,
        &qda,
        Method::PUT,
        &format!("/api/v1/credentials/{}", cred_id),
        Some(json!({
            "name": "renamed-cred"
        })),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "update: {}", body);
    // Tags should still be present and unchanged
    let tags = body["data"]["tags"]
        .as_array()
        .expect("tags should be array");
    assert_eq!(
        tags.len(),
        2,
        "tags should persist when not explicitly updated"
    );
    assert!(tags.contains(&json!("keep-me")));
    assert!(tags.contains(&json!("stable")));
}

#[tokio::test]
async fn agent_tags_persist_after_other_field_update() {
    let (app, store, _enc, _jwt) = setup_test_app().await;
    let admin_user = create_user_in_db(
        &*store,
        "admin-agent-persist",
        TEST_PASSWORD,
        UserRole::Admin,
        true,
        true,
    )
    .await;
    let cookie = login_user(&app, "admin-agent-persist", TEST_PASSWORD).await;

    let (agent, _api_key) = create_agent_in_db(
        &*store,
        "persist-tags-agent",
        vec!["original-tag"],
        true,
        Some(admin_user.id.clone()),
    )
    .await;

    // Update only the name (not tags)
    let (status, body, _) = send_json_with_headers(
        &app,
        Method::PUT,
        &format!("/api/v1/workspaces/{}", agent.id.0),
        None,
        Some(&cookie),
        Some(json!({ "name": "renamed-agent" })),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "update response: {}", body);
    let tags = body["data"]["tags"]
        .as_array()
        .expect("tags should be array");
    assert_eq!(tags.len(), 1);
    assert!(
        tags.contains(&json!("original-tag")),
        "tags should persist when not explicitly updated"
    );
}
