//! Integration tests for B-002: Permission Granting Fix.
//!
//! The bug was that users could not grant credential permissions — it failed
//! with a FK constraint error because `credential_permissions.granted_by`
//! referenced `agents(id)` and the code used `Uuid::nil()` for user grantors.
//!
//! The fix:
//!   - Added `granted_by_user TEXT` column (migration 020)
//!   - Made `granted_by` nullable
//!   - Updated `grant_credential_permission` to accept `Option<&AgentId>` and `Option<&UserId>`
//!   - When a user grants, `granted_by` is NULL and `granted_by_user` is set
//!
//! Coverage ratio: 2:1+ sad-to-happy (12 sad, 5 happy).

use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;
use uuid::Uuid;

use agent_cordon_core::crypto::password::hash_password;
use agent_cordon_core::crypto::SecretEncryptor;
use agent_cordon_core::domain::workspace::{Workspace, WorkspaceId, WorkspaceStatus};
type Agent = Workspace;
use agent_cordon_core::domain::credential::{CredentialId, StoredCredential};
use agent_cordon_core::domain::user::{User, UserId, UserRole};
use agent_cordon_core::storage::Store;

use crate::common::*;
use agent_cordon_server::test_helpers::TestAppBuilder;

// ---------------------------------------------------------------------------
// Test constants
// ---------------------------------------------------------------------------

const TEST_PASSWORD: &str = "strong-password-123!";

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

/// Build the full test application with an in-memory SQLite store.
/// Returns (router, store, state).
async fn setup_test_app() -> (
    Router,
    Arc<dyn Store + Send + Sync>,
    agent_cordon_server::state::AppState,
) {
    let ctx = TestAppBuilder::new().with_enrollment().build().await;
    (ctx.app, ctx.store, ctx.state)
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
        show_advanced: true,
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

/// Store a credential directly in the DB owned by the given agent.
/// Grants all permissions to the owner.
async fn store_test_credential(
    state: &agent_cordon_server::state::AppState,
    owner: &Agent,
    name: &str,
) -> CredentialId {
    let now = chrono::Utc::now();
    let cred_id = CredentialId(Uuid::new_v4());
    let (encrypted, nonce) = state
        .encryptor
        .encrypt(b"test-secret-value", cred_id.0.to_string().as_bytes())
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
        created_by_user: owner.owner_id.clone(),
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

    // Grant all permissions to the owner agent
    for perm in &["read", "write", "delete", "delegated_use"] {
        grant_cedar_permission(state, &cred_id, &owner.id, perm).await;
    }

    cred_id
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

/// Extract the CSRF token value from a cookie string.
fn extract_csrf_from_cookie(cookie: &str) -> Option<String> {
    for pair in cookie.split(';') {
        let pair = pair.trim();
        if let Some(val) = pair.strip_prefix("agtcrdn_csrf=") {
            return Some(val.to_string());
        }
    }
    None
}

/// Obtain a JWT for the given API key via the token exchange endpoint.
async fn get_jwt_da(
    state: &agent_cordon_server::state::AppState,
    agent: &Agent,
    api_key: &str,
) -> (String, String, p256::ecdsa::SigningKey) {
    let (device_id, signing_key) = create_device_and_bind_agent(state, agent).await;
    let jwt = get_jwt_via_device(state, &signing_key, &device_id, api_key).await;
    (jwt, device_id, signing_key)
}

/// Send a JSON request with optional bearer/cookie, returning (status, body, headers).
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

/// Convenience: send a JSON request with optional bearer and/or cookie.
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

// ===========================================================================
// HAPPY PATH 1: Root user grants read permission to an agent via HTTP API
// ===========================================================================

#[tokio::test]
async fn user_grants_read_permission_to_agent() {
    let (app, store, state) = setup_test_app().await;

    // Create root user and an admin agent that owns a credential
    let root = create_user_in_db(&*store, "root", TEST_PASSWORD, UserRole::Admin, true, true).await;
    let (admin_agent, _admin_key) = create_agent_in_db(
        &*store,
        "admin-agent",
        vec!["admin"],
        true,
        Some(root.id.clone()),
    )
    .await;
    let cred_id = store_test_credential(&state, &admin_agent, "perm-test-cred").await;

    // Create a second agent that will receive the permission
    let (target_agent, _target_key) =
        create_agent_in_db(&*store, "target-agent", vec!["viewer"], true, None).await;

    // Login as root user
    let cookie = login_user(&app, "root", TEST_PASSWORD).await;

    // Grant read permission to target agent
    let url = format!("/api/v1/credentials/{}/permissions", cred_id.0);
    let (status, body) = send_json(
        &app,
        Method::POST,
        &url,
        None,
        Some(&cookie),
        Some(json!({
            "agent_id": target_agent.id.0.to_string(),
            "permission": "read"
        })),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "grant failed: {}", body);
    assert!(
        body["data"]["granted"].is_array(),
        "expected granted to be an array: {}",
        body
    );

    // Verify the permission appears in the list.
    // "read" maps to Cedar action "list" in the grants-as-Cedar model.
    let (status, body) = send_json(&app, Method::GET, &url, None, Some(&cookie), None).await;
    assert_eq!(status, StatusCode::OK, "list permissions failed: {}", body);
    let permissions = body["data"]["permissions"].as_array().unwrap();
    let found = permissions.iter().any(|p| {
        p["agent_id"].as_str() == Some(&target_agent.id.0.to_string())
            && p["permission"].as_str() == Some("list")
    });
    assert!(
        found,
        "expected to find 'list' permission (Cedar action for 'read'), got: {:?}",
        permissions
    );
}

// ===========================================================================
// HAPPY PATH 2: User grants multiple permissions to same agent
// ===========================================================================

#[tokio::test]
async fn user_grants_multiple_permissions_to_same_agent() {
    let (app, store, state) = setup_test_app().await;

    let root = create_user_in_db(&*store, "root", TEST_PASSWORD, UserRole::Admin, true, true).await;
    let (admin_agent, _) = create_agent_in_db(
        &*store,
        "admin-agent",
        vec!["admin"],
        true,
        Some(root.id.clone()),
    )
    .await;
    let cred_id = store_test_credential(&state, &admin_agent, "multi-perm-cred").await;

    let (target_agent, _) =
        create_agent_in_db(&*store, "multi-target", vec!["viewer"], true, None).await;

    let cookie = login_user(&app, "root", TEST_PASSWORD).await;
    let url = format!("/api/v1/credentials/{}/permissions", cred_id.0);

    // Grant read, write, delegated_use
    for perm in &["read", "write", "delegated_use"] {
        let (status, body) = send_json(
            &app,
            Method::POST,
            &url,
            None,
            Some(&cookie),
            Some(json!({
                "agent_id": target_agent.id.0.to_string(),
                "permission": perm
            })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "grant '{}' failed: {}", perm, body);
    }

    // Verify all three appear
    let (status, body) = send_json(&app, Method::GET, &url, None, Some(&cookie), None).await;
    assert_eq!(status, StatusCode::OK, "list failed: {}", body);
    let permissions = body["data"]["permissions"].as_array().unwrap();

    // In the grants-as-Cedar model:
    //   "read" → "list", "write" → "update", "delegated_use" → "vend_credential"
    //   Agents should never get "access" (raw credential decryption) — only "vend_credential".
    let target_perms: Vec<&str> = permissions
        .iter()
        .filter(|p| p["agent_id"].as_str() == Some(&target_agent.id.0.to_string()))
        .filter_map(|p| p["permission"].as_str())
        .collect();

    assert!(
        target_perms.contains(&"list"),
        "missing 'list' (Cedar action for 'read')"
    );
    assert!(
        target_perms.contains(&"update"),
        "missing 'update' (Cedar action for 'write')"
    );
    assert!(
        !target_perms.contains(&"access"),
        "'access' should NOT be granted to agents via 'delegated_use'"
    );
    assert!(
        target_perms.contains(&"vend_credential"),
        "missing 'vend_credential' (Cedar action for 'delegated_use')"
    );
}

// ===========================================================================
// HAPPY PATH 3: User revokes a permission
// ===========================================================================

#[tokio::test]
async fn user_revokes_permission() {
    let (app, store, state) = setup_test_app().await;

    let root = create_user_in_db(&*store, "root", TEST_PASSWORD, UserRole::Admin, true, true).await;
    let (admin_agent, _) = create_agent_in_db(
        &*store,
        "admin-agent",
        vec!["admin"],
        true,
        Some(root.id.clone()),
    )
    .await;
    let cred_id = store_test_credential(&state, &admin_agent, "revoke-test-cred").await;

    let (target_agent, _) =
        create_agent_in_db(&*store, "revoke-target", vec!["viewer"], true, None).await;

    let cookie = login_user(&app, "root", TEST_PASSWORD).await;
    let base_url = format!("/api/v1/credentials/{}/permissions", cred_id.0);

    // Grant read
    let (status, _) = send_json(
        &app,
        Method::POST,
        &base_url,
        None,
        Some(&cookie),
        Some(json!({
            "agent_id": target_agent.id.0.to_string(),
            "permission": "read"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Revoke read
    let revoke_url = format!(
        "/api/v1/credentials/{}/permissions/{}/read",
        cred_id.0, target_agent.id.0
    );
    let (status, body) =
        send_json(&app, Method::DELETE, &revoke_url, None, Some(&cookie), None).await;
    assert_eq!(status, StatusCode::OK, "revoke failed: {}", body);
    assert_eq!(body["data"]["revoked"], true);

    // Verify it no longer appears
    let (status, body) = send_json(&app, Method::GET, &base_url, None, Some(&cookie), None).await;
    assert_eq!(status, StatusCode::OK);
    let permissions = body["data"]["permissions"].as_array().unwrap();
    let found = permissions.iter().any(|p| {
        p["agent_id"].as_str() == Some(&target_agent.id.0.to_string())
            && p["permission"].as_str() == Some("read")
    });
    assert!(!found, "read permission should have been revoked");
}

// ===========================================================================
// HAPPY PATH 4: Agent grants permission to another agent (existing flow)
// ===========================================================================

#[tokio::test]
async fn agent_grants_permission_to_another_agent() {
    let (_app, store, state) = setup_test_app().await;

    let (admin_agent, admin_key) =
        create_agent_in_db(&*store, "granting-agent", vec!["admin"], true, None).await;
    let cred_id = store_test_credential(&state, &admin_agent, "agent-grant-cred").await;

    let (target_agent, _) =
        create_agent_in_db(&*store, "receiving-agent", vec!["viewer"], true, None).await;

    let (jwt, dev_id, dev_key) = get_jwt_da(&state, &admin_agent, &admin_key).await;
    let url = format!("/api/v1/credentials/{}/permissions", cred_id.0);

    // Grant read permission via agent JWT (dual auth)
    let app2 = agent_cordon_server::build_router(state.clone());
    let (status, body) = send_json_dual_auth(
        &app2,
        Method::POST,
        &url,
        &dev_key,
        &dev_id,
        &jwt,
        Some(json!({
            "agent_id": target_agent.id.0.to_string(),
            "permission": "read"
        })),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "agent grant failed: {}", body);
    assert!(
        body["data"]["granted"].is_array(),
        "expected granted to be an array: {}",
        body
    );

    // Verify the permission appears. "read" maps to Cedar action "list".
    // In the Cedar model, granted_by is no longer tracked in the policy.
    let app3 = agent_cordon_server::build_router(state.clone());
    let (status, body) =
        send_json_dual_auth(&app3, Method::GET, &url, &dev_key, &dev_id, &jwt, None).await;
    assert_eq!(status, StatusCode::OK);
    let permissions = body["data"]["permissions"].as_array().unwrap();
    let found = permissions.iter().any(|p| {
        p["agent_id"].as_str() == Some(&target_agent.id.0.to_string())
            && p["permission"].as_str() == Some("list")
    });
    assert!(
        found,
        "expected to find 'list' permission (Cedar action for 'read'), got: {:?}",
        permissions
    );
}

// ===========================================================================
// HAPPY PATH 5: Admin (non-root) user grants permission
// ===========================================================================

#[tokio::test]
async fn admin_user_grants_permission() {
    let (app, store, state) = setup_test_app().await;

    // Create an admin user who owns the credential
    let admin = create_user_in_db(
        &*store,
        "admin-user",
        TEST_PASSWORD,
        UserRole::Admin,
        false,
        true,
    )
    .await;

    let (owner_agent, _) = create_agent_in_db(
        &*store,
        "owner-agent",
        vec!["admin"],
        true,
        Some(admin.id.clone()),
    )
    .await;
    let cred_id = store_test_credential(&state, &owner_agent, "admin-user-grant-cred").await;

    let (target_agent, _) =
        create_agent_in_db(&*store, "target-for-admin", vec!["viewer"], true, None).await;

    // Login as the admin who owns the credential
    let cookie = login_user(&app, "admin-user", TEST_PASSWORD).await;
    let url = format!("/api/v1/credentials/{}/permissions", cred_id.0);

    let (status, body) = send_json(
        &app,
        Method::POST,
        &url,
        None,
        Some(&cookie),
        Some(json!({
            "agent_id": target_agent.id.0.to_string(),
            "permission": "write"
        })),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "admin user grant failed: {}", body);
    assert!(
        body["data"]["granted"].is_array(),
        "expected granted to be an array: {}",
        body
    );
}

// ===========================================================================
// SAD PATH 5: Grant permission to nonexistent agent → 404
// ===========================================================================

#[tokio::test]
async fn grant_to_nonexistent_agent_returns_404() {
    let (app, store, state) = setup_test_app().await;

    let root = create_user_in_db(&*store, "root", TEST_PASSWORD, UserRole::Admin, true, true).await;
    let (admin_agent, _) = create_agent_in_db(
        &*store,
        "admin-agent",
        vec!["admin"],
        true,
        Some(root.id.clone()),
    )
    .await;
    let cred_id = store_test_credential(&state, &admin_agent, "no-agent-cred").await;

    let cookie = login_user(&app, "root", TEST_PASSWORD).await;
    let url = format!("/api/v1/credentials/{}/permissions", cred_id.0);

    let fake_agent_id = Uuid::new_v4();
    let (status, body) = send_json(
        &app,
        Method::POST,
        &url,
        None,
        Some(&cookie),
        Some(json!({
            "agent_id": fake_agent_id.to_string(),
            "permission": "read"
        })),
    )
    .await;

    assert_eq!(status, StatusCode::NOT_FOUND, "response: {}", body);
    let err_msg = body["error"]["message"].as_str().unwrap_or("");
    assert!(
        err_msg.contains("agent") || err_msg.contains("workspace"),
        "error should mention agent/workspace not found, got: {}",
        err_msg
    );
}

// ===========================================================================
// SAD PATH 6: Grant invalid permission type → 400
// ===========================================================================

#[tokio::test]
async fn grant_invalid_permission_type_returns_400() {
    let (app, store, state) = setup_test_app().await;

    let root = create_user_in_db(&*store, "root", TEST_PASSWORD, UserRole::Admin, true, true).await;
    let (admin_agent, _) = create_agent_in_db(
        &*store,
        "admin-agent",
        vec!["admin"],
        true,
        Some(root.id.clone()),
    )
    .await;
    let cred_id = store_test_credential(&state, &admin_agent, "bad-perm-cred").await;

    let (target_agent, _) =
        create_agent_in_db(&*store, "target-bad-perm", vec!["viewer"], true, None).await;

    let cookie = login_user(&app, "root", TEST_PASSWORD).await;
    let url = format!("/api/v1/credentials/{}/permissions", cred_id.0);

    let (status, body) = send_json(
        &app,
        Method::POST,
        &url,
        None,
        Some(&cookie),
        Some(json!({
            "agent_id": target_agent.id.0.to_string(),
            "permission": "superadmin"
        })),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "response: {}", body);
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap_or("")
            .contains("invalid permission"),
        "error should mention invalid permission, got: {}",
        body
    );
}

// ===========================================================================
// SAD PATH 7: Grant permission on nonexistent credential → 404
// ===========================================================================

#[tokio::test]
async fn grant_on_nonexistent_credential_returns_404() {
    let (app, store, _state) = setup_test_app().await;

    let root = create_user_in_db(&*store, "root", TEST_PASSWORD, UserRole::Admin, true, true).await;
    let (target_agent, _) = create_agent_in_db(
        &*store,
        "target-no-cred",
        vec!["viewer"],
        true,
        Some(root.id.clone()),
    )
    .await;

    let cookie = login_user(&app, "root", TEST_PASSWORD).await;
    let fake_cred_id = Uuid::new_v4();
    let url = format!("/api/v1/credentials/{}/permissions", fake_cred_id);

    let (status, body) = send_json(
        &app,
        Method::POST,
        &url,
        None,
        Some(&cookie),
        Some(json!({
            "agent_id": target_agent.id.0.to_string(),
            "permission": "read"
        })),
    )
    .await;

    assert_eq!(status, StatusCode::NOT_FOUND, "response: {}", body);
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap_or("")
            .contains("not found"),
        "error should mention not found, got: {}",
        body
    );
}

// ===========================================================================
// SAD PATH 8: Duplicate permission grant → handled gracefully (not 500)
// ===========================================================================

#[tokio::test]
async fn duplicate_grant_handled_gracefully() {
    let (app, store, state) = setup_test_app().await;

    let root = create_user_in_db(&*store, "root", TEST_PASSWORD, UserRole::Admin, true, true).await;
    let (admin_agent, _) = create_agent_in_db(
        &*store,
        "admin-agent",
        vec!["admin"],
        true,
        Some(root.id.clone()),
    )
    .await;
    let cred_id = store_test_credential(&state, &admin_agent, "dup-perm-cred").await;

    let (target_agent, _) =
        create_agent_in_db(&*store, "dup-target", vec!["viewer"], true, None).await;

    let cookie = login_user(&app, "root", TEST_PASSWORD).await;
    let url = format!("/api/v1/credentials/{}/permissions", cred_id.0);

    let payload = json!({
        "agent_id": target_agent.id.0.to_string(),
        "permission": "read"
    });

    // Grant first time
    let (status, body) = send_json(
        &app,
        Method::POST,
        &url,
        None,
        Some(&cookie),
        Some(payload.clone()),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "first grant failed: {}", body);

    // Grant same permission again — should NOT return 500
    let (status, body) =
        send_json(&app, Method::POST, &url, None, Some(&cookie), Some(payload)).await;

    // Should succeed (upsert behavior) or return a non-500 error
    assert_ne!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "duplicate grant should not cause 500, got: {}",
        body
    );
    // Our implementation uses ON CONFLICT ... DO UPDATE, so it should be 200
    assert_eq!(
        status,
        StatusCode::OK,
        "duplicate grant should succeed with upsert, got: {}",
        body
    );
}

// ===========================================================================
// SAD PATH 9: Unauthenticated request to grant → 401
// ===========================================================================

#[tokio::test]
async fn unauthenticated_grant_returns_401() {
    let (app, store, state) = setup_test_app().await;

    let (admin_agent, _) =
        create_agent_in_db(&*store, "admin-agent", vec!["admin"], true, None).await;
    let cred_id = store_test_credential(&state, &admin_agent, "unauth-perm-cred").await;

    let (target_agent, _) =
        create_agent_in_db(&*store, "target-unauth", vec!["viewer"], true, None).await;

    let url = format!("/api/v1/credentials/{}/permissions", cred_id.0);

    // Send without any auth
    let (status, _body) = send_json(
        &app,
        Method::POST,
        &url,
        None,
        None,
        Some(json!({
            "agent_id": target_agent.id.0.to_string(),
            "permission": "read"
        })),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "unauthenticated grant should return 401"
    );
}

// ===========================================================================
// SAD PATH 10: Viewer user tries to grant permission → 403
// ===========================================================================

#[tokio::test]
async fn viewer_user_grant_denied_by_policy() {
    let (app, store, state) = setup_test_app().await;

    // Create root for credential ownership, and a viewer user
    let root = create_user_in_db(&*store, "root", TEST_PASSWORD, UserRole::Admin, true, true).await;
    let _viewer = create_user_in_db(
        &*store,
        "viewer",
        TEST_PASSWORD,
        UserRole::Viewer,
        false,
        true,
    )
    .await;

    let (admin_agent, _) = create_agent_in_db(
        &*store,
        "admin-agent",
        vec!["admin"],
        true,
        Some(root.id.clone()),
    )
    .await;
    let cred_id = store_test_credential(&state, &admin_agent, "viewer-deny-cred").await;

    let (target_agent, _) =
        create_agent_in_db(&*store, "target-viewer-deny", vec!["viewer"], true, None).await;

    // Login as viewer
    let cookie = login_user(&app, "viewer", TEST_PASSWORD).await;
    let url = format!("/api/v1/credentials/{}/permissions", cred_id.0);

    let (status, body) = send_json(
        &app,
        Method::POST,
        &url,
        None,
        Some(&cookie),
        Some(json!({
            "agent_id": target_agent.id.0.to_string(),
            "permission": "read"
        })),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "viewer user should be denied by policy, got: {}",
        body
    );
}

// ===========================================================================
// SAD PATH 11: Grant with empty/invalid agent_id → 400 (deserialization error)
// ===========================================================================

#[tokio::test]
async fn grant_with_empty_agent_id_returns_400() {
    let (app, store, state) = setup_test_app().await;

    let root = create_user_in_db(&*store, "root", TEST_PASSWORD, UserRole::Admin, true, true).await;
    let (admin_agent, _) = create_agent_in_db(
        &*store,
        "admin-agent",
        vec!["admin"],
        true,
        Some(root.id.clone()),
    )
    .await;
    let cred_id = store_test_credential(&state, &admin_agent, "empty-agent-cred").await;

    let cookie = login_user(&app, "root", TEST_PASSWORD).await;
    let url = format!("/api/v1/credentials/{}/permissions", cred_id.0);

    // Empty string is not a valid UUID → deserialization should fail
    let (status, _body) = send_json(
        &app,
        Method::POST,
        &url,
        None,
        Some(&cookie),
        Some(json!({
            "agent_id": "",
            "permission": "read"
        })),
    )
    .await;

    // Axum returns 422 for JSON deserialization failures
    assert!(
        status == StatusCode::BAD_REQUEST || status == StatusCode::UNPROCESSABLE_ENTITY,
        "empty agent_id should return 400 or 422, got: {}",
        status
    );
}

// ===========================================================================
// SAD PATH 12: Revoke nonexistent permission → handled gracefully
// ===========================================================================

#[tokio::test]
async fn revoke_nonexistent_permission_handled_gracefully() {
    let (app, store, state) = setup_test_app().await;

    let root = create_user_in_db(&*store, "root", TEST_PASSWORD, UserRole::Admin, true, true).await;
    let (admin_agent, _) = create_agent_in_db(
        &*store,
        "admin-agent",
        vec!["admin"],
        true,
        Some(root.id.clone()),
    )
    .await;
    let cred_id = store_test_credential(&state, &admin_agent, "revoke-none-cred").await;

    let (target_agent, _) =
        create_agent_in_db(&*store, "target-revoke-none", vec!["viewer"], true, None).await;

    let cookie = login_user(&app, "root", TEST_PASSWORD).await;

    // Attempt to revoke a permission that was never granted
    let revoke_url = format!(
        "/api/v1/credentials/{}/permissions/{}/read",
        cred_id.0, target_agent.id.0
    );
    let (status, body) =
        send_json(&app, Method::DELETE, &revoke_url, None, Some(&cookie), None).await;

    // Should not return 500 — either 200 (idempotent) or 404
    assert_ne!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "revoking nonexistent perm should not cause 500, got: {}",
        body
    );
    // Most implementations treat DELETE as idempotent
    assert!(
        status == StatusCode::OK || status == StatusCode::NOT_FOUND,
        "expected 200 or 404, got: {} {}",
        status,
        body
    );
}

// ===========================================================================
// SAD PATH 13: Grant with missing permission field → 422/400
// ===========================================================================

#[tokio::test]
async fn grant_with_missing_permission_field_returns_error() {
    let (app, store, state) = setup_test_app().await;

    let root = create_user_in_db(&*store, "root", TEST_PASSWORD, UserRole::Admin, true, true).await;
    let (admin_agent, _) = create_agent_in_db(
        &*store,
        "admin-agent",
        vec!["admin"],
        true,
        Some(root.id.clone()),
    )
    .await;
    let cred_id = store_test_credential(&state, &admin_agent, "missing-perm-field-cred").await;

    let (target_agent, _) =
        create_agent_in_db(&*store, "target-missing-perm", vec!["viewer"], true, None).await;

    let cookie = login_user(&app, "root", TEST_PASSWORD).await;
    let url = format!("/api/v1/credentials/{}/permissions", cred_id.0);

    // Send without the "permission" field
    let (status, _body) = send_json(
        &app,
        Method::POST,
        &url,
        None,
        Some(&cookie),
        Some(json!({
            "agent_id": target_agent.id.0.to_string()
        })),
    )
    .await;

    assert!(
        status == StatusCode::BAD_REQUEST || status == StatusCode::UNPROCESSABLE_ENTITY,
        "missing permission field should return 400 or 422, got: {}",
        status
    );
}

// ===========================================================================
// SAD PATH 14: Revoke with invalid permission type in URL → 400
// ===========================================================================

#[tokio::test]
async fn revoke_invalid_permission_type_returns_400() {
    let (app, store, state) = setup_test_app().await;

    let root = create_user_in_db(&*store, "root", TEST_PASSWORD, UserRole::Admin, true, true).await;
    let (admin_agent, _) = create_agent_in_db(
        &*store,
        "admin-agent",
        vec!["admin"],
        true,
        Some(root.id.clone()),
    )
    .await;
    let cred_id = store_test_credential(&state, &admin_agent, "bad-revoke-perm-cred").await;

    let (target_agent, _) =
        create_agent_in_db(&*store, "target-bad-revoke", vec!["viewer"], true, None).await;

    let cookie = login_user(&app, "root", TEST_PASSWORD).await;

    // Try to revoke an invalid permission type
    let revoke_url = format!(
        "/api/v1/credentials/{}/permissions/{}/superadmin",
        cred_id.0, target_agent.id.0
    );
    let (status, body) =
        send_json(&app, Method::DELETE, &revoke_url, None, Some(&cookie), None).await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "invalid permission type in revoke should return 400, got: {} {}",
        status,
        body
    );
}

// ===========================================================================
// SAD PATH 15: Agent with viewer role cannot grant permissions → 403
// ===========================================================================

#[tokio::test]
async fn viewer_agent_cannot_grant_permissions() {
    let (_app, store, state) = setup_test_app().await;

    let (admin_agent, _) =
        create_agent_in_db(&*store, "admin-agent", vec!["admin"], true, None).await;
    let cred_id = store_test_credential(&state, &admin_agent, "viewer-agent-deny-cred").await;

    let (_viewer_agent, viewer_key) =
        create_agent_in_db(&*store, "viewer-agent", vec!["viewer"], true, None).await;
    let (target_agent, _) =
        create_agent_in_db(&*store, "target-for-viewer", vec!["viewer"], true, None).await;

    let (jwt, dev_id, dev_key) = get_jwt_da(&state, &_viewer_agent, &viewer_key).await;
    let url = format!("/api/v1/credentials/{}/permissions", cred_id.0);

    let app2 = agent_cordon_server::build_router(state.clone());
    let (status, body) = send_json_dual_auth(
        &app2,
        Method::POST,
        &url,
        &dev_key,
        &dev_id,
        &jwt,
        Some(json!({
            "agent_id": target_agent.id.0.to_string(),
            "permission": "read"
        })),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "viewer agent should be denied by policy, got: {} {}",
        status,
        body
    );
}

// ===========================================================================
// SAD PATH 16: Unauthenticated list permissions → 401
// ===========================================================================

#[tokio::test]
async fn unauthenticated_list_permissions_returns_401() {
    let (app, store, state) = setup_test_app().await;

    let (admin_agent, _) =
        create_agent_in_db(&*store, "admin-agent", vec!["admin"], true, None).await;
    let cred_id = store_test_credential(&state, &admin_agent, "unauth-list-cred").await;

    let url = format!("/api/v1/credentials/{}/permissions", cred_id.0);

    // No auth provided
    let (status, _body) = send_json(&app, Method::GET, &url, None, None, None).await;

    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "unauthenticated list should return 401"
    );
}

// ===========================================================================
// SAD PATH 17: Grant with missing agent_id field → 422/400
// ===========================================================================

#[tokio::test]
async fn grant_with_missing_agent_id_field_returns_error() {
    let (app, store, state) = setup_test_app().await;

    let root = create_user_in_db(&*store, "root", TEST_PASSWORD, UserRole::Admin, true, true).await;
    let (admin_agent, _) = create_agent_in_db(
        &*store,
        "admin-agent",
        vec!["admin"],
        true,
        Some(root.id.clone()),
    )
    .await;
    let cred_id = store_test_credential(&state, &admin_agent, "missing-agent-cred").await;

    let cookie = login_user(&app, "root", TEST_PASSWORD).await;
    let url = format!("/api/v1/credentials/{}/permissions", cred_id.0);

    // Send without the "agent_id" field
    let (status, _body) = send_json(
        &app,
        Method::POST,
        &url,
        None,
        Some(&cookie),
        Some(json!({
            "permission": "read"
        })),
    )
    .await;

    assert!(
        status == StatusCode::BAD_REQUEST || status == StatusCode::UNPROCESSABLE_ENTITY,
        "missing agent_id field should return 400 or 422, got: {}",
        status
    );
}
