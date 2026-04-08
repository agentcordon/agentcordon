//! Integration tests for F-004: User Identity Model + Role-Based Access.
//!
//! Tests cover user authentication (login/logout/me), user CRUD,
//! credential ownership, and agent management.
//!
//! These tests spin up the full Axum router with an in-memory SQLite store
//! and exercise the endpoints end-to-end using `tower::ServiceExt` (no TCP).

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
use agent_cordon_core::domain::user::{User, UserId, UserRole};
use agent_cordon_core::domain::workspace::{Workspace, WorkspaceId, WorkspaceStatus};
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

/// Build the complete test application state with an in-memory store.
/// Returns (router, store, encryptor, jwt_issuer).
async fn setup_test_app() -> (
    Router,
    Arc<dyn Store + Send + Sync>,
    Arc<AesGcmEncryptor>,
    Arc<JwtIssuer>,
    agent_cordon_server::state::AppState,
) {
    setup_test_app_with_rate_limit(5, 900).await
}

/// Build the test app with custom login rate-limit parameters.
async fn setup_test_app_with_rate_limit(
    max_attempts: u32,
    lockout_seconds: u64,
) -> (
    Router,
    Arc<dyn Store + Send + Sync>,
    Arc<AesGcmEncryptor>,
    Arc<JwtIssuer>,
    agent_cordon_server::state::AppState,
) {
    let ctx = TestAppBuilder::new()
        .with_config(move |c| {
            c.login_max_attempts = max_attempts;
            c.login_lockout_seconds = lockout_seconds;
        })
        .build()
        .await;
    (ctx.app, ctx.store, ctx.encryptor, ctx.jwt_issuer, ctx.state)
}

/// Create a user directly in the store and return the User.
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

/// Create a workspace directly in the store and return (Workspace, "").
async fn create_agent_in_db(
    store: &(dyn Store + Send + Sync),
    name: &str,
    tags: Vec<&str>,
    enabled: bool,
    owner_id: Option<UserId>,
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
        owner_id,
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

/// Login a user and return the combined cookie string (session + CSRF).
///
/// Returns e.g. `"agtcrdn_session=<token>; agtcrdn_csrf=<csrf>"`.
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

    // Extract all Set-Cookie headers and parse cookie name=value pairs
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

/// Extract the CSRF token value from a cookie string like
/// `"agtcrdn_session=xxx; agtcrdn_csrf=yyy"`.
fn extract_csrf_from_cookie(cookie: &str) -> Option<String> {
    for pair in cookie.split(';') {
        let pair = pair.trim();
        if let Some(val) = pair.strip_prefix("agtcrdn_csrf=") {
            return Some(val.to_string());
        }
    }
    None
}

/// Send a JSON request with optional cookie and bearer, and return response headers too.
///
/// If the cookie string contains an `agtcrdn_csrf` value and the method is
/// state-changing (POST/PUT/DELETE/PATCH), the `X-CSRF-Token` header is
/// automatically added.
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

    // Collect headers
    let headers: Vec<(String, String)> = response
        .headers()
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();

    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&bytes).unwrap_or(json!(null));
    (status, json, headers)
}

/// Convenience: send a JSON request with optional cookie and/or bearer.
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
// Tests: User Auth Flow (login/logout/me)
// ===========================================================================

#[tokio::test]
async fn test_login_valid_credentials_returns_session_cookie() {
    let (app, store, _enc, _jwt, _state) = setup_test_app().await;
    let _user = create_user_in_db(
        &*store,
        "alice",
        TEST_PASSWORD,
        UserRole::Admin,
        false,
        true,
    )
    .await;

    let (status, body, headers) = send_json_with_headers(
        &app,
        Method::POST,
        "/api/v1/auth/login",
        None,
        None,
        Some(json!({ "username": "alice", "password": TEST_PASSWORD })),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "response: {}", body);

    // Verify response body contains user info
    let data = &body["data"];
    assert_eq!(data["user"]["username"], "alice");
    assert!(data["expires_at"].is_string(), "must contain expires_at");

    // Verify Set-Cookie header is present with session cookie
    let set_cookie = headers
        .iter()
        .find(|(name, _)| name == "set-cookie")
        .expect("Set-Cookie header must be present");

    assert!(
        set_cookie.1.contains("agtcrdn_session="),
        "cookie must contain agtcrdn_session"
    );
    assert!(set_cookie.1.contains("HttpOnly"), "cookie must be HttpOnly");
    assert!(
        set_cookie.1.contains("SameSite=Lax"),
        "cookie must be SameSite=Lax (changed from Strict in v0.16)"
    );
}

#[tokio::test]
async fn test_login_invalid_password_returns_401() {
    let (app, store, _enc, _jwt, _state) = setup_test_app().await;
    let _user = create_user_in_db(
        &*store,
        "alice",
        TEST_PASSWORD,
        UserRole::Admin,
        false,
        true,
    )
    .await;

    let (status, body) = send_json(
        &app,
        Method::POST,
        "/api/v1/auth/login",
        None,
        None,
        Some(json!({ "username": "alice", "password": "wrong-password-123" })),
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED, "response: {}", body);
}

#[tokio::test]
async fn test_login_nonexistent_user_returns_401() {
    let (app, _store, _enc, _jwt, _state) = setup_test_app().await;

    let (status, body) = send_json(
        &app,
        Method::POST,
        "/api/v1/auth/login",
        None,
        None,
        Some(json!({ "username": "nonexistent", "password": "any-password-here" })),
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED, "response: {}", body);
}

#[tokio::test]
async fn test_login_disabled_user_returns_401() {
    let (app, store, _enc, _jwt, _state) = setup_test_app().await;
    // Create a disabled user
    let _user = create_user_in_db(
        &*store,
        "disabled",
        TEST_PASSWORD,
        UserRole::Admin,
        false,
        false,
    )
    .await;

    let (status, body) = send_json(
        &app,
        Method::POST,
        "/api/v1/auth/login",
        None,
        None,
        Some(json!({ "username": "disabled", "password": TEST_PASSWORD })),
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED, "response: {}", body);
}

#[tokio::test]
async fn test_me_with_valid_session_returns_user_info() {
    let (app, store, _enc, _jwt, _state) = setup_test_app().await;
    let user = create_user_in_db(
        &*store,
        "alice",
        TEST_PASSWORD,
        UserRole::Admin,
        false,
        true,
    )
    .await;

    let cookie = login_user(&app, "alice", TEST_PASSWORD).await;

    let (status, body) = send_json(
        &app,
        Method::GET,
        "/api/v1/auth/me",
        None,
        Some(&cookie),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::OK, "response: {}", body);
    let data = &body["data"];
    assert_eq!(data["username"], "alice");
    assert_eq!(data["id"], user.id.0.to_string());
    assert_eq!(data["role"], "admin");
}

#[tokio::test]
async fn test_me_without_session_returns_401() {
    let (app, _store, _enc, _jwt, _state) = setup_test_app().await;

    let (status, _body) = send_json(&app, Method::GET, "/api/v1/auth/me", None, None, None).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_logout_invalidates_session() {
    let (app, store, _enc, _jwt, _state) = setup_test_app().await;
    let _user = create_user_in_db(
        &*store,
        "alice",
        TEST_PASSWORD,
        UserRole::Admin,
        false,
        true,
    )
    .await;

    let cookie = login_user(&app, "alice", TEST_PASSWORD).await;

    // Verify we can access /auth/me with the cookie
    let (status, _body) = send_json(
        &app,
        Method::GET,
        "/api/v1/auth/me",
        None,
        Some(&cookie),
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "session should be valid before logout"
    );

    // Logout
    let (status, body) = send_json(
        &app,
        Method::POST,
        "/api/v1/auth/logout",
        None,
        Some(&cookie),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "logout response: {}", body);

    // Verify session is invalidated — /auth/me should now return 401
    let (status, _body) = send_json(
        &app,
        Method::GET,
        "/api/v1/auth/me",
        None,
        Some(&cookie),
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "session should be invalidated after logout"
    );
}

// ===========================================================================
// Tests: User CRUD (create, list, delete, update)
// ===========================================================================

#[tokio::test]
async fn test_create_user_as_admin() {
    let (app, store, _enc, _jwt, _state) = setup_test_app().await;
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
        "/api/v1/users",
        None,
        Some(&cookie),
        Some(json!({
            "username": "newuser",
            "password": "another-strong-pwd!",
            "display_name": "New User",
            "role": "viewer"
        })),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "create user response: {}", body);
    let data = &body["data"];
    assert_eq!(data["username"], "newuser");
    assert_eq!(data["role"], "viewer");
    assert_eq!(data["display_name"], "New User");
    assert!(data["id"].is_string());
}

#[tokio::test]
async fn test_create_user_password_too_short_returns_400() {
    let (app, store, _enc, _jwt, _state) = setup_test_app().await;
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
        "/api/v1/users",
        None,
        Some(&cookie),
        Some(json!({
            "username": "shortpwd",
            "password": "short",
        })),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "response: {}", body);
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap_or("")
            .contains("12 characters"),
        "error should mention minimum password length: {}",
        body
    );
}

#[tokio::test]
async fn test_create_user_as_non_admin_returns_403() {
    let (app, store, _enc, _jwt, _state) = setup_test_app().await;
    // Create a viewer user
    let _viewer = create_user_in_db(
        &*store,
        "viewer",
        TEST_PASSWORD,
        UserRole::Viewer,
        false,
        true,
    )
    .await;

    let cookie = login_user(&app, "viewer", TEST_PASSWORD).await;

    let (status, body) = send_json(
        &app,
        Method::POST,
        "/api/v1/users",
        None,
        Some(&cookie),
        Some(json!({
            "username": "newuser",
            "password": "strong-password-123",
        })),
    )
    .await;

    assert_eq!(status, StatusCode::FORBIDDEN, "response: {}", body);
}

#[tokio::test]
async fn test_list_users_as_admin() {
    let (app, store, _enc, _jwt, _state) = setup_test_app().await;
    let _admin = create_user_in_db(
        &*store,
        "admin",
        TEST_PASSWORD,
        UserRole::Admin,
        false,
        true,
    )
    .await;
    let _user2 = create_user_in_db(
        &*store,
        "user2",
        TEST_PASSWORD,
        UserRole::Viewer,
        false,
        true,
    )
    .await;

    let cookie = login_user(&app, "admin", TEST_PASSWORD).await;

    let (status, body) = send_json(
        &app,
        Method::GET,
        "/api/v1/users",
        None,
        Some(&cookie),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::OK, "response: {}", body);
    let data = &body["data"];
    assert!(data.is_array(), "data must be an array");
    assert!(
        data.as_array().unwrap().len() >= 2,
        "must contain at least 2 users"
    );
}

#[tokio::test]
async fn test_delete_user_as_admin() {
    let (app, store, _enc, _jwt, _state) = setup_test_app().await;
    let _admin = create_user_in_db(
        &*store,
        "admin",
        TEST_PASSWORD,
        UserRole::Admin,
        false,
        true,
    )
    .await;
    let target = create_user_in_db(
        &*store,
        "target",
        TEST_PASSWORD,
        UserRole::Viewer,
        false,
        true,
    )
    .await;

    let cookie = login_user(&app, "admin", TEST_PASSWORD).await;

    let uri = format!("/api/v1/users/{}", target.id.0);
    let (status, body) = send_json(&app, Method::DELETE, &uri, None, Some(&cookie), None).await;

    assert_eq!(status, StatusCode::OK, "delete response: {}", body);
    assert_eq!(body["data"]["deleted"], true);

    // Verify user is gone
    let result = store.get_user(&target.id).await.expect("get_user");
    assert!(result.is_none(), "deleted user should not exist in store");
}

#[tokio::test]
async fn test_delete_root_user_returns_403() {
    let (app, store, _enc, _jwt, _state) = setup_test_app().await;
    let admin = create_user_in_db(
        &*store,
        "admin",
        TEST_PASSWORD,
        UserRole::Admin,
        false,
        true,
    )
    .await;
    let root = create_user_in_db(&*store, "root", TEST_PASSWORD, UserRole::Admin, true, true).await;

    let cookie = login_user(&app, "admin", TEST_PASSWORD).await;

    let uri = format!("/api/v1/users/{}", root.id.0);
    let (status, body) = send_json(&app, Method::DELETE, &uri, None, Some(&cookie), None).await;

    assert_eq!(status, StatusCode::FORBIDDEN, "response: {}", body);

    // Verify root user still exists
    let result = store.get_user(&root.id).await.expect("get_user");
    assert!(result.is_some(), "root user must not be deleted");

    // Suppress unused variable warning
    let _ = admin;
}

#[tokio::test]
async fn test_update_root_role_returns_403() {
    let (app, store, _enc, _jwt, _state) = setup_test_app().await;
    let _admin = create_user_in_db(
        &*store,
        "admin",
        TEST_PASSWORD,
        UserRole::Admin,
        false,
        true,
    )
    .await;
    let root = create_user_in_db(&*store, "root", TEST_PASSWORD, UserRole::Admin, true, true).await;

    let cookie = login_user(&app, "admin", TEST_PASSWORD).await;

    let uri = format!("/api/v1/users/{}", root.id.0);
    let (status, body) = send_json(
        &app,
        Method::PUT,
        &uri,
        None,
        Some(&cookie),
        Some(json!({ "role": "viewer" })),
    )
    .await;

    assert_eq!(status, StatusCode::FORBIDDEN, "response: {}", body);

    // Verify root user role is unchanged
    let result = store.get_user(&root.id).await.expect("get_user").unwrap();
    assert_eq!(result.role, UserRole::Admin, "root role must remain admin");
}

#[tokio::test]
async fn test_disable_root_user_returns_403() {
    let (app, store, _enc, _jwt, _state) = setup_test_app().await;
    let _admin = create_user_in_db(
        &*store,
        "admin",
        TEST_PASSWORD,
        UserRole::Admin,
        false,
        true,
    )
    .await;
    let root = create_user_in_db(&*store, "root", TEST_PASSWORD, UserRole::Admin, true, true).await;

    let cookie = login_user(&app, "admin", TEST_PASSWORD).await;

    let uri = format!("/api/v1/users/{}", root.id.0);
    let (status, body) = send_json(
        &app,
        Method::PUT,
        &uri,
        None,
        Some(&cookie),
        Some(json!({ "enabled": false })),
    )
    .await;

    assert_eq!(status, StatusCode::FORBIDDEN, "response: {}", body);

    // Verify root user is still enabled
    let result = store.get_user(&root.id).await.expect("get_user").unwrap();
    assert!(result.enabled, "root user must remain enabled");
}

// ===========================================================================
// Tests: Credential Ownership
// ===========================================================================

#[tokio::test]
async fn test_user_creates_credential_has_created_by_user() {
    let (app, store, _enc, _jwt, _state) = setup_test_app().await;
    let admin = create_user_in_db(
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
        "/api/v1/credentials",
        None,
        Some(&cookie),
        Some(json!({
            "name": "user-created-cred",
            "service": "github",
            "secret_value": "ghp_test1234567890",
            "scopes": ["repo"]
        })),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "response: {}", body);
    let data = &body["data"];
    assert_eq!(data["name"], "user-created-cred");

    // Verify created_by_user is set to the admin's ID
    assert_eq!(
        data["created_by_user"].as_str().unwrap_or(""),
        admin.id.0.to_string(),
        "credential should be owned by the user"
    );

    // Verify created_by (agent) is null
    assert!(
        data["created_by"].is_null(),
        "created_by (agent) should be null for user-created credentials"
    );
}

#[tokio::test]
async fn test_agent_creates_credential_has_created_by_agent() {
    let (_app, store, _enc, _jwt, state) = setup_test_app().await;
    let (agent, api_key) =
        create_agent_in_db(&*store, "test-agent", vec!["admin"], true, None).await;

    let (device_id, dev_key) = create_device_and_bind_agent(&state, &agent).await;
    let jwt = get_jwt_via_device(&state, &dev_key, &device_id, &api_key).await;
    let app2 = agent_cordon_server::build_router(state.clone());
    let (status, body) = send_json_dual_auth(
        &app2,
        Method::POST,
        "/api/v1/credentials",
        &dev_key,
        &device_id,
        &jwt,
        Some(json!({
            "name": "agent-created-cred",
            "service": "slack",
            "secret_value": "xoxb-test1234567890",
            "scopes": ["chat:write"]
        })),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "response: {}", body);
    let data = &body["data"];
    assert_eq!(data["name"], "agent-created-cred");

    // Verify created_by (agent) is set
    assert_eq!(
        data["created_by"].as_str().unwrap_or(""),
        agent.id.0.to_string(),
        "credential should be owned by the agent"
    );

    // Verify created_by_user is null
    assert!(
        data["created_by_user"].is_null(),
        "created_by_user should be null for agent-created credentials"
    );
}

// ===========================================================================
// Tests: Agent Management
// ===========================================================================

#[tokio::test]
async fn test_agent_list_requires_user_auth() {
    let (app, store, _enc, _jwt, _state) = setup_test_app().await;

    // Create an agent (not a user) and try to list agents with bearer auth
    let (_agent, api_key) =
        create_agent_in_db(&*store, "test-agent", vec!["admin"], true, None).await;

    // Agents should NOT be able to list agents — the route requires AuthenticatedUser
    let (status, _body) = send_json(
        &app,
        Method::GET,
        "/api/v1/workspaces",
        Some(&api_key),
        None,
        None,
    )
    .await;

    // AuthenticatedUser extractor looks for session cookie only, so a bearer-only
    // request should fail with 401 (no session cookie found).
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "agent bearer token should not work for user-only endpoints"
    );
}

#[tokio::test]
async fn test_agent_create_not_exposed() {
    let (app, store, _enc, _jwt, _state) = setup_test_app().await;
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

    // POST /workspaces should not exist as a creation endpoint here
    let (status, _body) = send_json(
        &app,
        Method::POST,
        "/api/v1/workspaces",
        None,
        Some(&cookie),
        Some(json!({
            "name": "new-agent",
            "roles": ["viewer"]
        })),
    )
    .await;

    // Should return 405 Method Not Allowed (route exists for GET, not POST)
    assert_eq!(
        status,
        StatusCode::METHOD_NOT_ALLOWED,
        "POST /agents should not be allowed"
    );
}

// ===========================================================================
// Tests: Additional edge cases
// ===========================================================================

#[tokio::test]
async fn test_list_users_as_viewer_returns_403() {
    let (app, store, _enc, _jwt, _state) = setup_test_app().await;
    let _viewer = create_user_in_db(
        &*store,
        "viewer",
        TEST_PASSWORD,
        UserRole::Viewer,
        false,
        true,
    )
    .await;

    let cookie = login_user(&app, "viewer", TEST_PASSWORD).await;

    let (status, body) = send_json(
        &app,
        Method::GET,
        "/api/v1/users",
        None,
        Some(&cookie),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::FORBIDDEN, "response: {}", body);
}

#[tokio::test]
async fn test_list_users_as_operator_returns_403() {
    let (app, store, _enc, _jwt, _state) = setup_test_app().await;
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

    let (status, body) = send_json(
        &app,
        Method::GET,
        "/api/v1/users",
        None,
        Some(&cookie),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::FORBIDDEN, "response: {}", body);
}

#[tokio::test]
async fn test_agent_list_as_admin_user_succeeds() {
    let (app, store, _enc, _jwt, _state) = setup_test_app().await;
    let admin = create_user_in_db(
        &*store,
        "admin",
        TEST_PASSWORD,
        UserRole::Admin,
        false,
        true,
    )
    .await;
    let (_agent, _key) = create_agent_in_db(
        &*store,
        "listed-agent",
        vec!["viewer"],
        true,
        Some(admin.id.clone()),
    )
    .await;

    let cookie = login_user(&app, "admin", TEST_PASSWORD).await;

    let (status, body) = send_json(
        &app,
        Method::GET,
        "/api/v1/workspaces",
        None,
        Some(&cookie),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::OK, "response: {}", body);
    let data = &body["data"];
    assert!(data.is_array(), "data must be an array");
    assert!(
        !data.as_array().unwrap().is_empty(),
        "must contain at least 1 agent"
    );
}

#[tokio::test]
async fn test_me_with_invalid_cookie_returns_401() {
    let (app, _store, _enc, _jwt, _state) = setup_test_app().await;

    let (status, _body) = send_json(
        &app,
        Method::GET,
        "/api/v1/auth/me",
        None,
        Some("agtcrdn_session=invalid-token-value"),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_create_user_duplicate_username_returns_409() {
    let (app, store, _enc, _jwt, _state) = setup_test_app().await;
    let _admin = create_user_in_db(
        &*store,
        "admin",
        TEST_PASSWORD,
        UserRole::Admin,
        false,
        true,
    )
    .await;
    let _existing = create_user_in_db(
        &*store,
        "existing",
        TEST_PASSWORD,
        UserRole::Viewer,
        false,
        true,
    )
    .await;

    let cookie = login_user(&app, "admin", TEST_PASSWORD).await;

    let (status, body) = send_json(
        &app,
        Method::POST,
        "/api/v1/users",
        None,
        Some(&cookie),
        Some(json!({
            "username": "existing",
            "password": "another-strong-pwd!",
        })),
    )
    .await;

    assert_eq!(status, StatusCode::CONFLICT, "response: {}", body);
}

// ===========================================================================
// Tests: Audit Log — User Login Events
// ===========================================================================

#[tokio::test]
async fn test_successful_login_emits_user_login_success_audit_event() {
    let (app, store, _enc, _jwt, _state) = setup_test_app().await;
    let user = create_user_in_db(
        &*store,
        "audituser",
        TEST_PASSWORD,
        UserRole::Admin,
        false,
        true,
    )
    .await;

    // Perform login
    let (status, _body) = send_json(
        &app,
        Method::POST,
        "/api/v1/auth/login",
        None,
        None,
        Some(json!({ "username": "audituser", "password": TEST_PASSWORD })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Query audit events and find the UserLoginSuccess event
    let events = store
        .list_audit_events(50, 0)
        .await
        .expect("list audit events");
    let login_event = events
        .iter()
        .find(|e| {
            let type_json = serde_json::to_string(&e.event_type).unwrap();
            type_json.contains("user_login_success")
        })
        .expect("must have a user_login_success audit event");

    // Verify event fields
    assert_eq!(login_event.action, "login_success");
    assert_eq!(login_event.resource_type, "session");
    assert_eq!(
        login_event.user_id.as_deref(),
        Some(user.id.0.to_string().as_str())
    );
    assert_eq!(login_event.user_name.as_deref(), Some("audituser"));
    assert!(
        !login_event.correlation_id.is_empty(),
        "correlation_id must be present"
    );

    // Verify metadata contains username and user_id
    assert_eq!(login_event.metadata["username"], "audituser");
    assert_eq!(login_event.metadata["user_id"], user.id.0.to_string());

    // Verify no secrets in metadata
    let meta_str = serde_json::to_string(&login_event.metadata).unwrap();
    assert!(
        !meta_str.contains(TEST_PASSWORD),
        "password must NEVER appear in audit metadata"
    );
    assert!(
        !meta_str.contains("password"),
        "no password-related keys in audit metadata"
    );
}

#[tokio::test]
async fn test_failed_login_wrong_password_emits_user_login_failed_audit_event() {
    let (app, store, _enc, _jwt, _state) = setup_test_app().await;
    let _user = create_user_in_db(
        &*store,
        "auditfail",
        TEST_PASSWORD,
        UserRole::Admin,
        false,
        true,
    )
    .await;

    // Attempt login with wrong password
    let (status, _body) = send_json(
        &app,
        Method::POST,
        "/api/v1/auth/login",
        None,
        None,
        Some(json!({ "username": "auditfail", "password": "totally-wrong-password" })),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Query audit events and find the UserLoginFailed event
    let events = store
        .list_audit_events(50, 0)
        .await
        .expect("list audit events");
    let fail_event = events
        .iter()
        .find(|e| {
            let type_json = serde_json::to_string(&e.event_type).unwrap();
            type_json.contains("user_login_failed")
        })
        .expect("must have a user_login_failed audit event");

    // Verify event fields
    assert_eq!(fail_event.action, "login_failed");
    assert_eq!(fail_event.resource_type, "session");
    assert_eq!(fail_event.user_name.as_deref(), Some("auditfail"));
    assert!(
        !fail_event.correlation_id.is_empty(),
        "correlation_id must be present"
    );

    // Verify metadata contains username and reason
    assert_eq!(fail_event.metadata["username"], "auditfail");
    assert_eq!(fail_event.metadata["reason"], "invalid_password");

    // Verify no secrets in metadata
    let meta_str = serde_json::to_string(&fail_event.metadata).unwrap();
    assert!(
        !meta_str.contains("totally-wrong-password"),
        "password must NEVER appear in audit metadata"
    );
    assert!(
        !meta_str.contains(TEST_PASSWORD),
        "correct password must NEVER appear in audit metadata"
    );
}

#[tokio::test]
async fn test_failed_login_user_not_found_emits_audit_event() {
    let (app, store, _enc, _jwt, _state) = setup_test_app().await;

    // Attempt login with non-existent user
    let (status, _body) = send_json(
        &app,
        Method::POST,
        "/api/v1/auth/login",
        None,
        None,
        Some(json!({ "username": "ghost", "password": "some-password-123" })),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Query audit events
    let events = store
        .list_audit_events(50, 0)
        .await
        .expect("list audit events");
    let fail_event = events
        .iter()
        .find(|e| {
            let type_json = serde_json::to_string(&e.event_type).unwrap();
            type_json.contains("user_login_failed")
        })
        .expect("must have a user_login_failed audit event");

    assert_eq!(fail_event.metadata["username"], "ghost");
    assert_eq!(fail_event.metadata["reason"], "user_not_found");

    // Verify no secrets
    let meta_str = serde_json::to_string(&fail_event.metadata).unwrap();
    assert!(
        !meta_str.contains("some-password-123"),
        "password must NEVER appear in audit metadata"
    );
}

#[tokio::test]
async fn test_failed_login_disabled_user_emits_audit_event() {
    let (app, store, _enc, _jwt, _state) = setup_test_app().await;
    let _user = create_user_in_db(
        &*store,
        "disabledaudit",
        TEST_PASSWORD,
        UserRole::Admin,
        false,
        false,
    )
    .await;

    // Attempt login with disabled user
    let (status, _body) = send_json(
        &app,
        Method::POST,
        "/api/v1/auth/login",
        None,
        None,
        Some(json!({ "username": "disabledaudit", "password": TEST_PASSWORD })),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Query audit events
    let events = store
        .list_audit_events(50, 0)
        .await
        .expect("list audit events");
    let fail_event = events
        .iter()
        .find(|e| {
            let type_json = serde_json::to_string(&e.event_type).unwrap();
            type_json.contains("user_login_failed")
        })
        .expect("must have a user_login_failed audit event");

    assert_eq!(fail_event.metadata["username"], "disabledaudit");
    assert_eq!(fail_event.metadata["reason"], "user_disabled");
}

#[tokio::test]
async fn test_audit_login_events_never_contain_secrets() {
    let (app, store, _enc, _jwt, _state) = setup_test_app().await;
    let _user = create_user_in_db(
        &*store,
        "secretcheck",
        TEST_PASSWORD,
        UserRole::Admin,
        false,
        true,
    )
    .await;

    // Successful login
    let (status, _body) = send_json(
        &app,
        Method::POST,
        "/api/v1/auth/login",
        None,
        None,
        Some(json!({ "username": "secretcheck", "password": TEST_PASSWORD })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Failed login
    let wrong_pwd = "wrong-secret-value-99!";
    let (status, _body) = send_json(
        &app,
        Method::POST,
        "/api/v1/auth/login",
        None,
        None,
        Some(json!({ "username": "secretcheck", "password": wrong_pwd })),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Check ALL audit events for secrets
    let events = store
        .list_audit_events(100, 0)
        .await
        .expect("list audit events");
    for event in &events {
        let full_json = serde_json::to_string(event).unwrap();
        assert!(
            !full_json.contains(TEST_PASSWORD),
            "audit event must never contain the correct password: {}",
            full_json
        );
        assert!(
            !full_json.contains(wrong_pwd),
            "audit event must never contain the wrong password: {}",
            full_json
        );
        // Check that no field named "password" or "password_hash" appears
        assert!(
            !full_json.contains("password_hash"),
            "audit event must never contain password_hash: {}",
            full_json
        );
    }
}

// ===========================================================================
// Tests: Login Rate Limiting (S-002)
// ===========================================================================

#[tokio::test]
async fn test_login_rate_limit_normal_login_still_works() {
    // With rate limiting enabled, a normal valid login should succeed
    let (app, store, _enc, _jwt, _state) = setup_test_app_with_rate_limit(5, 900).await;
    let _user = create_user_in_db(
        &*store,
        "alice",
        TEST_PASSWORD,
        UserRole::Admin,
        false,
        true,
    )
    .await;

    let (status, _body) = send_json(
        &app,
        Method::POST,
        "/api/v1/auth/login",
        None,
        None,
        Some(json!({ "username": "alice", "password": TEST_PASSWORD })),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "normal login should succeed");
}

#[tokio::test]
async fn test_login_rate_limit_blocks_after_max_failed_attempts() {
    // Set max_attempts=3 for faster testing
    let (app, store, _enc, _jwt, _state) = setup_test_app_with_rate_limit(3, 900).await;
    let _user = create_user_in_db(
        &*store,
        "bob",
        TEST_PASSWORD,
        UserRole::Operator,
        false,
        true,
    )
    .await;

    // Make 3 failed login attempts
    for i in 1..=3 {
        let (status, _body) = send_json(
            &app,
            Method::POST,
            "/api/v1/auth/login",
            None,
            None,
            Some(json!({ "username": "bob", "password": "wrong-password" })),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "attempt {} should return 401",
            i
        );
    }

    // 4th attempt (even with correct password) should be rate-limited
    let (status, body) = send_json(
        &app,
        Method::POST,
        "/api/v1/auth/login",
        None,
        None,
        Some(json!({ "username": "bob", "password": TEST_PASSWORD })),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::TOO_MANY_REQUESTS,
        "should return 429 after max attempts"
    );
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap_or("")
            .contains("too many failed login attempts"),
        "error message should mention rate limiting: {:?}",
        body
    );
}

#[tokio::test]
async fn test_login_rate_limit_different_users_independent() {
    // Rate limiting is per-username: locking out bob should not affect alice
    let (app, store, _enc, _jwt, _state) = setup_test_app_with_rate_limit(2, 900).await;
    let _alice = create_user_in_db(
        &*store,
        "alice",
        TEST_PASSWORD,
        UserRole::Admin,
        false,
        true,
    )
    .await;
    let _bob = create_user_in_db(
        &*store,
        "bob",
        TEST_PASSWORD,
        UserRole::Operator,
        false,
        true,
    )
    .await;

    // Lock out bob with 2 failed attempts
    for _ in 0..2 {
        send_json(
            &app,
            Method::POST,
            "/api/v1/auth/login",
            None,
            None,
            Some(json!({ "username": "bob", "password": "nope" })),
        )
        .await;
    }

    // Bob is locked out
    let (status, _) = send_json(
        &app,
        Method::POST,
        "/api/v1/auth/login",
        None,
        None,
        Some(json!({ "username": "bob", "password": TEST_PASSWORD })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::TOO_MANY_REQUESTS,
        "bob should be locked out"
    );

    // Alice should still be able to log in
    let (status, _) = send_json(
        &app,
        Method::POST,
        "/api/v1/auth/login",
        None,
        None,
        Some(json!({ "username": "alice", "password": TEST_PASSWORD })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "alice should not be affected by bob's lockout"
    );
}

#[tokio::test]
async fn test_login_rate_limit_successful_login_resets_counter() {
    // With max_attempts=3, fail twice, then succeed. After that, 2 more fails
    // should not trigger lockout (counter was reset on success).
    let (app, store, _enc, _jwt, _state) = setup_test_app_with_rate_limit(3, 900).await;
    let _user = create_user_in_db(
        &*store,
        "carol",
        TEST_PASSWORD,
        UserRole::Admin,
        false,
        true,
    )
    .await;

    // 2 failed attempts
    for _ in 0..2 {
        let (status, _) = send_json(
            &app,
            Method::POST,
            "/api/v1/auth/login",
            None,
            None,
            Some(json!({ "username": "carol", "password": "wrong" })),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    // Successful login resets counter
    let (status, _) = send_json(
        &app,
        Method::POST,
        "/api/v1/auth/login",
        None,
        None,
        Some(json!({ "username": "carol", "password": TEST_PASSWORD })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "login with correct password should succeed"
    );

    // 2 more failed attempts should still not trigger lockout (counter was reset)
    for _ in 0..2 {
        let (status, _) = send_json(
            &app,
            Method::POST,
            "/api/v1/auth/login",
            None,
            None,
            Some(json!({ "username": "carol", "password": "wrong" })),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "should still be 401 not 429"
        );
    }

    // The 3rd fail now should trigger lockout (2 accumulated from the new window)
    // Actually we only had 2 failures so far, so the next one is #3 — which hits the limit.
    let (status, _) = send_json(
        &app,
        Method::POST,
        "/api/v1/auth/login",
        None,
        None,
        Some(json!({ "username": "carol", "password": "wrong" })),
    )
    .await;
    // After the 3rd failure (post-reset), the next attempt should be locked
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "3rd fail records but returns 401"
    );

    let (status, _) = send_json(
        &app,
        Method::POST,
        "/api/v1/auth/login",
        None,
        None,
        Some(json!({ "username": "carol", "password": TEST_PASSWORD })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::TOO_MANY_REQUESTS,
        "4th attempt should be locked out"
    );
}

#[tokio::test]
async fn test_login_rate_limit_expires_after_lockout_window() {
    // Use a 0-second lockout window so the lockout expires immediately.
    let (app, store, _enc, _jwt, _state) = setup_test_app_with_rate_limit(2, 0).await;
    let _user = create_user_in_db(
        &*store,
        "dave",
        TEST_PASSWORD,
        UserRole::Viewer,
        false,
        true,
    )
    .await;

    // Trigger lockout
    for _ in 0..2 {
        send_json(
            &app,
            Method::POST,
            "/api/v1/auth/login",
            None,
            None,
            Some(json!({ "username": "dave", "password": "wrong" })),
        )
        .await;
    }

    // With a 0-second window, old attempts are immediately pruned.
    // Login with correct password should now succeed.
    let (status, _) = send_json(
        &app,
        Method::POST,
        "/api/v1/auth/login",
        None,
        None,
        Some(json!({ "username": "dave", "password": TEST_PASSWORD })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "login should succeed after lockout window expires"
    );
}

#[tokio::test]
async fn test_login_rate_limit_emits_audit_event() {
    // Verify that a LoginRateLimited audit event is emitted
    let (app, store, _enc, _jwt, _state) = setup_test_app_with_rate_limit(2, 900).await;
    let _user =
        create_user_in_db(&*store, "eve", TEST_PASSWORD, UserRole::Admin, false, true).await;

    // Trigger lockout
    for _ in 0..2 {
        send_json(
            &app,
            Method::POST,
            "/api/v1/auth/login",
            None,
            None,
            Some(json!({ "username": "eve", "password": "wrong" })),
        )
        .await;
    }

    // This attempt should be rate-limited and produce an audit event
    let (status, _) = send_json(
        &app,
        Method::POST,
        "/api/v1/auth/login",
        None,
        None,
        Some(json!({ "username": "eve", "password": "anything" })),
    )
    .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);

    // Check audit events for LoginRateLimited
    let events = store
        .list_audit_events(100, 0)
        .await
        .expect("list audit events");
    let rate_limited_events: Vec<_> = events
        .iter()
        .filter(|e| {
            let json = serde_json::to_string(&e.event_type).unwrap();
            json.contains("login_rate_limited")
        })
        .collect();

    assert!(
        !rate_limited_events.is_empty(),
        "should have at least one LoginRateLimited audit event, found events: {:?}",
        events.iter().map(|e| &e.event_type).collect::<Vec<_>>()
    );

    // Verify the audit event has the expected fields
    let event = rate_limited_events[0];
    assert_eq!(event.user_name.as_deref(), Some("eve"));
    assert_eq!(event.action, "login_rate_limited");
}

#[tokio::test]
async fn test_login_rate_limit_wrong_password_returns_401_not_429_below_threshold() {
    // Below the threshold, wrong password should still be 401 Unauthorized, not 429
    let (app, store, _enc, _jwt, _state) = setup_test_app_with_rate_limit(5, 900).await;
    let _user = create_user_in_db(
        &*store,
        "frank",
        TEST_PASSWORD,
        UserRole::Admin,
        false,
        true,
    )
    .await;

    // 4 failed attempts (below the threshold of 5)
    for i in 1..=4 {
        let (status, _) = send_json(
            &app,
            Method::POST,
            "/api/v1/auth/login",
            None,
            None,
            Some(json!({ "username": "frank", "password": "wrong" })),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "attempt {} should return 401, not 429",
            i
        );
    }
}

#[tokio::test]
async fn test_login_rate_limit_nonexistent_user_also_rate_limited() {
    // Rate limiting should apply even for usernames that don't exist in the DB
    // to prevent user enumeration via timing differences.
    let (app, _store, _enc, _jwt, _state) = setup_test_app_with_rate_limit(2, 900).await;

    // 2 failed attempts for a nonexistent user
    for _ in 0..2 {
        let (status, _) = send_json(
            &app,
            Method::POST,
            "/api/v1/auth/login",
            None,
            None,
            Some(json!({ "username": "ghost", "password": "wrong" })),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    // 3rd attempt should be rate-limited
    let (status, _) = send_json(
        &app,
        Method::POST,
        "/api/v1/auth/login",
        None,
        None,
        Some(json!({ "username": "ghost", "password": "wrong" })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::TOO_MANY_REQUESTS,
        "nonexistent user should also be rate-limited"
    );
}

#[tokio::test]
async fn test_login_rate_limit_429_has_correct_error_structure() {
    // Verify the 429 response body has the expected shape:
    //   { "error": { "code": "too_many_requests", "message": "..." } }
    let (app, store, _enc, _jwt, _state) = setup_test_app_with_rate_limit(1, 60).await;
    let _user =
        create_user_in_db(&*store, "ivan", TEST_PASSWORD, UserRole::Admin, false, true).await;

    // 1 failed attempt triggers lockout (max_attempts=1)
    let (status, _body) = send_json(
        &app,
        Method::POST,
        "/api/v1/auth/login",
        None,
        None,
        Some(json!({ "username": "ivan", "password": "wrong-password" })),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Next attempt should be rate-limited — verify response structure
    let (status, body) = send_json(
        &app,
        Method::POST,
        "/api/v1/auth/login",
        None,
        None,
        Some(json!({ "username": "ivan", "password": "wrong-password" })),
    )
    .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);

    // Verify response structure
    assert!(
        body["error"].is_object(),
        "response should have error object"
    );
    assert_eq!(body["error"]["code"], "too_many_requests");
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap()
            .contains("too many"),
        "message should mention rate limiting"
    );
}
