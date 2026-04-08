//! Integration tests for S-003: CSRF Token Protection.
//!
//! Tests verify the double-submit cookie CSRF protection for cookie-authenticated
//! state-changing requests:
//! - Valid CSRF token succeeds
//! - Missing CSRF token returns 403
//! - Mismatched CSRF token returns 403
//! - GET requests work without CSRF token
//! - API key (Bearer) authenticated requests work without CSRF token
//! - Login endpoint is exempt from CSRF
//! - CSRF cookie is set on login and cleared on logout

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

type Agent = Workspace;

use crate::common::*;
use agent_cordon_server::test_helpers::TestAppBuilder;

// ---------------------------------------------------------------------------
// Test constants
// ---------------------------------------------------------------------------

const TEST_PASSWORD: &str = "strong-password-123!";

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

async fn setup_test_app() -> (
    Router,
    Arc<dyn Store + Send + Sync>,
    Arc<AesGcmEncryptor>,
    Arc<JwtIssuer>,
) {
    let ctx = TestAppBuilder::new().build().await;
    (ctx.app, ctx.store, ctx.encryptor, ctx.jwt_issuer)
}

async fn create_user_in_db(
    store: &(dyn Store + Send + Sync),
    username: &str,
    password: &str,
    role: UserRole,
) -> User {
    let password_hash = hash_password(password).expect("hash password");
    let now = chrono::Utc::now();
    let user = User {
        id: UserId(Uuid::new_v4()),
        username: username.to_string(),
        display_name: Some(format!("Test {}", username)),
        password_hash,
        role,
        is_root: false,
        enabled: true,
        created_at: now,
        updated_at: now,
    };
    store.create_user(&user).await.expect("create user");
    user
}

async fn create_agent_in_db(
    store: &(dyn Store + Send + Sync),
    name: &str,
    owner_id: Option<UserId>,
) -> (Agent, String) {
    let now = chrono::Utc::now();
    let agent = Agent {
        id: WorkspaceId(Uuid::new_v4()),
        name: name.to_string(),
        enabled: true,
        status: WorkspaceStatus::Active,
        pk_hash: None,
        encryption_public_key: None,
        tags: vec!["admin".to_string()],
        owner_id,
        parent_id: None,
        tool_name: None,
        created_at: now,
        updated_at: now,
    };
    store.create_workspace(&agent).await.expect("create agent");
    (agent, String::new())
}

/// Login and return (session_cookie_pair, csrf_token).
/// session_cookie_pair is e.g. `"agtcrdn_session=xxx"`.
/// csrf_token is the raw CSRF token value.
async fn login_user(app: &Router, username: &str, password: &str) -> (String, String) {
    let (status, body, headers) = send_request(
        app,
        Method::POST,
        "/api/v1/auth/login",
        None, // bearer
        None, // cookie
        None, // csrf header
        Some(json!({ "username": username, "password": password })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "login failed for '{}': {:?}",
        username,
        body
    );

    // Extract session cookie
    let session_cookie = headers
        .iter()
        .filter(|(name, _)| name == "set-cookie")
        .find(|(_, val)| val.starts_with("agtcrdn_session="))
        .expect("session Set-Cookie header must be present")
        .1
        .clone();
    let session_cookie = session_cookie.split(';').next().unwrap().trim().to_string();

    // Extract CSRF token from response body
    let csrf_token = body["data"]["csrf_token"]
        .as_str()
        .expect("login response must include csrf_token")
        .to_string();

    (session_cookie, csrf_token)
}

/// Send a request with fine-grained control over cookie, bearer, and CSRF header.
async fn send_request(
    app: &Router,
    method: Method,
    uri: &str,
    bearer: Option<&str>,
    cookie: Option<&str>,
    csrf_header: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value, Vec<(String, String)>) {
    let mut builder = Request::builder().method(method).uri(uri);

    if let Some(token) = bearer {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {}", token));
    }

    if let Some(cookie_val) = cookie {
        builder = builder.header(header::COOKIE, cookie_val);
    }

    if let Some(csrf) = csrf_header {
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

// ===========================================================================
// Tests: CSRF cookie lifecycle
// ===========================================================================

#[tokio::test]
async fn test_login_sets_csrf_cookie() {
    let (app, store, _enc, _jwt) = setup_test_app().await;
    let _user = create_user_in_db(&*store, "alice", TEST_PASSWORD, UserRole::Admin).await;

    let (status, body, headers) = send_request(
        &app,
        Method::POST,
        "/api/v1/auth/login",
        None,
        None,
        None,
        Some(json!({ "username": "alice", "password": TEST_PASSWORD })),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "response: {}", body);

    // Find the CSRF cookie
    let csrf_cookie = headers
        .iter()
        .filter(|(name, _)| name == "set-cookie")
        .find(|(_, val)| val.starts_with("agtcrdn_csrf="));
    assert!(csrf_cookie.is_some(), "login must set agtcrdn_csrf cookie");

    let csrf_cookie_val = csrf_cookie.unwrap().1.clone();

    // CSRF cookie must NOT be HttpOnly (so JS can read it)
    assert!(
        !csrf_cookie_val.contains("HttpOnly"),
        "CSRF cookie must NOT be HttpOnly, got: {}",
        csrf_cookie_val
    );

    // CSRF cookie must be SameSite=Lax (changed from Strict in v0.16 crypto hardening)
    assert!(
        csrf_cookie_val.contains("SameSite=Lax"),
        "CSRF cookie must be SameSite=Lax, got: {}",
        csrf_cookie_val
    );

    // CSRF cookie must be Secure
    assert!(
        csrf_cookie_val.contains("Secure"),
        "CSRF cookie must be Secure, got: {}",
        csrf_cookie_val
    );

    // CSRF token in response body must match cookie value
    let csrf_from_body = body["data"]["csrf_token"].as_str().unwrap();
    let csrf_from_cookie = csrf_cookie_val
        .split(';')
        .next()
        .unwrap()
        .trim()
        .strip_prefix("agtcrdn_csrf=")
        .unwrap();
    assert_eq!(
        csrf_from_body, csrf_from_cookie,
        "CSRF token in body must match cookie"
    );

    // CSRF token must be 32 alphanumeric characters
    assert_eq!(csrf_from_body.len(), 32, "CSRF token must be 32 chars");
    assert!(
        csrf_from_body.chars().all(|c| c.is_ascii_alphanumeric()),
        "CSRF token must be alphanumeric"
    );
}

#[tokio::test]
async fn test_logout_clears_csrf_cookie() {
    let (app, store, _enc, _jwt) = setup_test_app().await;
    let _user = create_user_in_db(&*store, "alice", TEST_PASSWORD, UserRole::Admin).await;

    let (session_cookie, csrf_token) = login_user(&app, "alice", TEST_PASSWORD).await;

    // Build combined cookie for logout request
    let combined_cookie = format!("{}; agtcrdn_csrf={}", session_cookie, csrf_token);

    let (status, _body, headers) = send_request(
        &app,
        Method::POST,
        "/api/v1/auth/logout",
        None,
        Some(&combined_cookie),
        Some(&csrf_token),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::OK);

    // Verify CSRF cookie is cleared (Max-Age=0)
    let csrf_clear = headers
        .iter()
        .filter(|(name, _)| name == "set-cookie")
        .find(|(_, val)| val.starts_with("agtcrdn_csrf="));
    assert!(csrf_clear.is_some(), "logout must clear CSRF cookie");
    let csrf_clear_val = csrf_clear.unwrap().1.clone();
    assert!(
        csrf_clear_val.contains("Max-Age=0"),
        "CSRF clear cookie must have Max-Age=0, got: {}",
        csrf_clear_val
    );
}

// ===========================================================================
// Tests: CSRF enforcement on state-changing cookie requests
// ===========================================================================

#[tokio::test]
async fn test_post_with_valid_csrf_token_succeeds() {
    let (app, store, _enc, _jwt) = setup_test_app().await;
    let _admin = create_user_in_db(&*store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let (session_cookie, csrf_token) = login_user(&app, "admin", TEST_PASSWORD).await;

    // Build combined cookie (session + CSRF) as the browser would send
    let combined_cookie = format!("{}; agtcrdn_csrf={}", session_cookie, csrf_token);

    // Create a user (POST) with valid CSRF token
    let (status, body, _headers) = send_request(
        &app,
        Method::POST,
        "/api/v1/users",
        None,
        Some(&combined_cookie),
        Some(&csrf_token), // CSRF header matches cookie
        Some(json!({
            "username": "newuser",
            "password": "another-strong-pwd!",
            "role": "viewer"
        })),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "valid CSRF should succeed: {}",
        body
    );
    assert_eq!(body["data"]["username"], "newuser");
}

#[tokio::test]
async fn test_post_without_csrf_token_returns_403() {
    let (app, store, _enc, _jwt) = setup_test_app().await;
    let _admin = create_user_in_db(&*store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let (session_cookie, csrf_token) = login_user(&app, "admin", TEST_PASSWORD).await;

    // Send session cookie + CSRF cookie but NO X-CSRF-Token header
    let combined_cookie = format!("{}; agtcrdn_csrf={}", session_cookie, csrf_token);

    let (status, body, _headers) = send_request(
        &app,
        Method::POST,
        "/api/v1/users",
        None,
        Some(&combined_cookie),
        None, // NO CSRF header
        Some(json!({
            "username": "should-fail",
            "password": "another-strong-pwd!",
            "role": "viewer"
        })),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "missing CSRF token should return 403: {}",
        body
    );
    assert_eq!(
        body["error"]["code"], "csrf_validation_failed",
        "error code should be csrf_validation_failed"
    );
}

#[tokio::test]
async fn test_post_with_wrong_csrf_token_returns_403() {
    let (app, store, _enc, _jwt) = setup_test_app().await;
    let _admin = create_user_in_db(&*store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let (session_cookie, csrf_token) = login_user(&app, "admin", TEST_PASSWORD).await;

    // Send correct CSRF cookie but WRONG X-CSRF-Token header
    let combined_cookie = format!("{}; agtcrdn_csrf={}", session_cookie, csrf_token);

    let (status, body, _headers) = send_request(
        &app,
        Method::POST,
        "/api/v1/users",
        None,
        Some(&combined_cookie),
        Some("wrong-csrf-token-value-12345678"), // Wrong CSRF header
        Some(json!({
            "username": "should-fail",
            "password": "another-strong-pwd!",
            "role": "viewer"
        })),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "wrong CSRF token should return 403: {}",
        body
    );
    assert_eq!(
        body["error"]["code"], "csrf_validation_failed",
        "error code should be csrf_validation_failed"
    );
}

#[tokio::test]
async fn test_post_with_csrf_header_but_no_csrf_cookie_returns_403() {
    let (app, store, _enc, _jwt) = setup_test_app().await;
    let _admin = create_user_in_db(&*store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let (session_cookie, csrf_token) = login_user(&app, "admin", TEST_PASSWORD).await;

    // Send ONLY session cookie (no CSRF cookie) but include CSRF header
    let (status, body, _headers) = send_request(
        &app,
        Method::POST,
        "/api/v1/users",
        None,
        Some(&session_cookie), // Only session cookie, no CSRF cookie
        Some(&csrf_token),     // CSRF header present
        Some(json!({
            "username": "should-fail",
            "password": "another-strong-pwd!",
            "role": "viewer"
        })),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "missing CSRF cookie should return 403: {}",
        body
    );
}

// ===========================================================================
// Tests: GET requests are exempt from CSRF
// ===========================================================================

#[tokio::test]
async fn test_get_request_works_without_csrf_token() {
    let (app, store, _enc, _jwt) = setup_test_app().await;
    let _admin = create_user_in_db(&*store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let (session_cookie, _csrf_token) = login_user(&app, "admin", TEST_PASSWORD).await;

    // GET /auth/me with session cookie but NO CSRF token
    let (status, body, _headers) = send_request(
        &app,
        Method::GET,
        "/api/v1/auth/me",
        None,
        Some(&session_cookie), // Only session cookie
        None,                  // No CSRF header
        None,
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "GET should work without CSRF: {}",
        body
    );
    assert_eq!(body["data"]["username"], "admin");
}

// ===========================================================================
// Tests: API key (Bearer) auth is exempt from CSRF
// ===========================================================================

#[tokio::test]
async fn test_bearer_auth_works_without_csrf_token() {
    let ctx = TestAppBuilder::new().build().await;
    let _admin = create_user_in_db(&*ctx.store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let (agent, api_key) = create_agent_in_db(&*ctx.store, "test-agent", Some(_admin.id)).await;

    // Create device + bind agent + get JWT via device-mediated token exchange
    let qda = quick_device_setup(&ctx.state, &agent, &api_key).await;

    // POST with dual auth (device JWT + agent JWT, no cookies, no CSRF) — should succeed
    let (status, body) = send_json_dual_auth(
        &ctx.app,
        Method::POST,
        "/api/v1/credentials",
        &qda.device_signing_key,
        &qda.device_id,
        &qda.agent_jwt,
        Some(json!({
            "name": "csrf-test-cred",
            "service": "test",
            "secret_value": "test-secret"
        })),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "Device+agent auth should work without CSRF: {}",
        body
    );
}

// ===========================================================================
// Tests: Login endpoint is exempt from CSRF
// ===========================================================================

#[tokio::test]
async fn test_login_endpoint_exempt_from_csrf() {
    let (app, store, _enc, _jwt) = setup_test_app().await;
    let _user = create_user_in_db(&*store, "alice", TEST_PASSWORD, UserRole::Admin).await;

    // POST to login without any CSRF token — should succeed
    let (status, body, _headers) = send_request(
        &app,
        Method::POST,
        "/api/v1/auth/login",
        None,
        None, // No cookies
        None, // No CSRF header
        Some(json!({ "username": "alice", "password": TEST_PASSWORD })),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "login should work without CSRF: {}",
        body
    );
}

// ===========================================================================
// Tests: PUT and DELETE also require CSRF
// ===========================================================================

#[tokio::test]
async fn test_put_without_csrf_returns_403() {
    let (app, store, _enc, _jwt) = setup_test_app().await;
    let _admin = create_user_in_db(&*store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let other = create_user_in_db(&*store, "other", TEST_PASSWORD, UserRole::Viewer).await;
    let (session_cookie, csrf_token) = login_user(&app, "admin", TEST_PASSWORD).await;

    // Send session cookie + CSRF cookie but NO X-CSRF-Token header
    let combined_cookie = format!("{}; agtcrdn_csrf={}", session_cookie, csrf_token);

    let uri = format!("/api/v1/users/{}", other.id.0);
    let (status, body, _headers) = send_request(
        &app,
        Method::PUT,
        &uri,
        None,
        Some(&combined_cookie),
        None, // NO CSRF header
        Some(json!({ "role": "operator" })),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "PUT without CSRF should return 403: {}",
        body
    );
}

#[tokio::test]
async fn test_delete_without_csrf_returns_403() {
    let (app, store, _enc, _jwt) = setup_test_app().await;
    let _admin = create_user_in_db(&*store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let other = create_user_in_db(&*store, "other", TEST_PASSWORD, UserRole::Viewer).await;
    let (session_cookie, csrf_token) = login_user(&app, "admin", TEST_PASSWORD).await;

    // Send session cookie + CSRF cookie but NO X-CSRF-Token header
    let combined_cookie = format!("{}; agtcrdn_csrf={}", session_cookie, csrf_token);

    let uri = format!("/api/v1/users/{}", other.id.0);
    let (status, body, _headers) = send_request(
        &app,
        Method::DELETE,
        &uri,
        None,
        Some(&combined_cookie),
        None, // NO CSRF header
        None,
    )
    .await;

    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "DELETE without CSRF should return 403: {}",
        body
    );
}

#[tokio::test]
async fn test_put_with_valid_csrf_succeeds() {
    let (app, store, _enc, _jwt) = setup_test_app().await;
    let _admin = create_user_in_db(&*store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let other = create_user_in_db(&*store, "other", TEST_PASSWORD, UserRole::Viewer).await;
    let (session_cookie, csrf_token) = login_user(&app, "admin", TEST_PASSWORD).await;

    let combined_cookie = format!("{}; agtcrdn_csrf={}", session_cookie, csrf_token);

    let uri = format!("/api/v1/users/{}", other.id.0);
    let (status, body, _headers) = send_request(
        &app,
        Method::PUT,
        &uri,
        None,
        Some(&combined_cookie),
        Some(&csrf_token),
        Some(json!({ "role": "operator" })),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "PUT with valid CSRF should succeed: {}",
        body
    );
}

// ===========================================================================
// Tests: Unauthenticated POST (no cookies) is not blocked by CSRF
// ===========================================================================

#[tokio::test]
async fn test_unauthenticated_post_not_blocked_by_csrf() {
    let (app, _store, _enc, _jwt) = setup_test_app().await;

    // POST to login with wrong credentials — should get 401, not 403
    // (CSRF middleware should let it through since no session cookie)
    let (status, body, _headers) = send_request(
        &app,
        Method::POST,
        "/api/v1/auth/login",
        None,
        None,
        None,
        Some(json!({ "username": "nonexistent", "password": "wrong" })),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "unauthenticated POST should get 401 not 403: {}",
        body
    );
}
