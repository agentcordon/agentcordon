//! Integration tests for v1.3 features: Device CRUD.
//!
//! Suite A (Server CRUD) and Suite B (OAuth 2.1) removed in v1.15.0
//! (OAuth Authorization Server removal).
//! Suite C: Device CRUD (admin session auth)

use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;
use uuid::Uuid;

use agent_cordon_core::crypto::password::hash_password;
use agent_cordon_core::domain::user::{User, UserId, UserRole};
use agent_cordon_core::storage::Store;

use agent_cordon_server::test_helpers::TestAppBuilder;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const TEST_PASSWORD: &str = "strong-test-password-123!";

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

/// Build the test app (default config).
async fn setup_test_app() -> (
    Router,
    Arc<dyn Store + Send + Sync>,
    agent_cordon_server::state::AppState,
) {
    let ctx = TestAppBuilder::new().build().await;
    (ctx.app, ctx.store, ctx.state)
}

/// Create a user directly in the store.
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
        show_advanced: true,
        created_at: now,
        updated_at: now,
    };
    store.create_user(&user).await.expect("create user");
    user
}

/// Login a user and return (combined_cookie, csrf_token).
async fn login_user(app: &Router, username: &str, password: &str) -> (String, String) {
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

    let combined = format!("{}; agtcrdn_csrf={}", session_cookie, csrf_token);
    (combined, csrf_token)
}

/// Extract CSRF token from a combined cookie string.
fn extract_csrf_from_cookie(cookie: &str) -> Option<String> {
    for pair in cookie.split(';') {
        let pair = pair.trim();
        if let Some(val) = pair.strip_prefix("agtcrdn_csrf=") {
            return Some(val.to_string());
        }
    }
    None
}

/// Send a JSON request with optional cookie and bearer, return (status, body, headers).
async fn send_json_with_headers(
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

        let is_state_changing = method == Method::POST
            || method == Method::PUT
            || method == Method::DELETE
            || method == Method::PATCH;
        if is_state_changing {
            if let Some(csrf) = csrf_token {
                builder = builder.header("x-csrf-token", csrf);
            } else if let Some(csrf) = extract_csrf_from_cookie(cookie_val) {
                builder = builder.header("x-csrf-token", csrf);
            }
        }
    } else if let Some(csrf) = csrf_token {
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

/// Send a JSON request (no headers returned).
async fn send_json(
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

// ===========================================================================
// Suite C: Device CRUD
// ===========================================================================

#[tokio::test]
#[ignore = "REMOVED: v2.0 has no device endpoints — devices unified into workspaces"]
async fn test_device_create_returns_bootstrap_token() {
    let (app, store, _state) = setup_test_app().await;
    let _admin = create_user_in_db(&*store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let (cookie, csrf) = login_user(&app, "admin", TEST_PASSWORD).await;

    let (status, body) = send_json(
        &app,
        Method::POST,
        "/api/v1/devices",
        None,
        Some(&cookie),
        Some(&csrf),
        Some(json!({
            "name": "test-device",
            "tags": ["dev"],
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "create device: {}", body);

    let data = &body["data"];
    assert!(data["id"].is_string(), "must have id");
    assert_eq!(data["name"], "test-device");
    assert_eq!(data["status"], "pending");
    assert!(
        data["bootstrap_token"].is_string(),
        "must return bootstrap_token"
    );
    assert!(
        !data["bootstrap_token"].as_str().unwrap().is_empty(),
        "bootstrap_token must not be empty"
    );
}

#[tokio::test]
#[ignore = "REMOVED: v2.0 has no device endpoints — devices unified into workspaces"]
async fn test_device_list() {
    let (app, store, _state) = setup_test_app().await;
    let _admin = create_user_in_db(&*store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let (cookie, csrf) = login_user(&app, "admin", TEST_PASSWORD).await;

    // Create a device
    send_json(
        &app,
        Method::POST,
        "/api/v1/devices",
        None,
        Some(&cookie),
        Some(&csrf),
        Some(json!({ "name": "list-device" })),
    )
    .await;

    // List devices
    let (status, body) = send_json(
        &app,
        Method::GET,
        "/api/v1/devices",
        None,
        Some(&cookie),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "list devices: {}", body);

    let devices = body["data"].as_array().expect("data must be array");
    assert!(!devices.is_empty(), "should have at least 1 device");
    let found = devices.iter().any(|s| s["name"] == "list-device");
    assert!(found, "created device should appear in list");
}

#[tokio::test]
#[ignore = "REMOVED: v2.0 has no device endpoints — devices unified into workspaces"]
async fn test_device_get_by_id() {
    let (app, store, _state) = setup_test_app().await;
    let _admin = create_user_in_db(&*store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let (cookie, csrf) = login_user(&app, "admin", TEST_PASSWORD).await;

    let (status, body) = send_json(
        &app,
        Method::POST,
        "/api/v1/devices",
        None,
        Some(&cookie),
        Some(&csrf),
        Some(json!({ "name": "get-device" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let device_id = body["data"]["id"].as_str().unwrap().to_string();

    let (status, body) = send_json(
        &app,
        Method::GET,
        &format!("/api/v1/devices/{}", device_id),
        None,
        Some(&cookie),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "get device: {}", body);

    let data = &body["data"];
    assert_eq!(data["id"], device_id);
    assert_eq!(data["name"], "get-device");
    assert_eq!(data["status"], "pending");
}

#[tokio::test]
#[ignore = "REMOVED: v2.0 has no device endpoints — devices unified into workspaces"]
async fn test_device_update() {
    let (app, store, _state) = setup_test_app().await;
    let _admin = create_user_in_db(&*store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let (cookie, csrf) = login_user(&app, "admin", TEST_PASSWORD).await;

    let (status, body) = send_json(
        &app,
        Method::POST,
        "/api/v1/devices",
        None,
        Some(&cookie),
        Some(&csrf),
        Some(json!({ "name": "update-device" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let device_id = body["data"]["id"].as_str().unwrap().to_string();

    let (status, body) = send_json(
        &app,
        Method::PUT,
        &format!("/api/v1/devices/{}", device_id),
        None,
        Some(&cookie),
        Some(&csrf),
        Some(json!({
            "name": "updated-device-name",
            "tags": ["prod", "critical"],
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "update device: {}", body);

    let data = &body["data"];
    assert_eq!(data["name"], "updated-device-name");
    assert_eq!(data["tags"], json!(["prod", "critical"]));
}

#[tokio::test]
#[ignore = "REMOVED: v2.0 has no device endpoints — devices unified into workspaces"]
async fn test_device_delete() {
    let (app, store, _state) = setup_test_app().await;
    let _admin = create_user_in_db(&*store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let (cookie, csrf) = login_user(&app, "admin", TEST_PASSWORD).await;

    let (status, body) = send_json(
        &app,
        Method::POST,
        "/api/v1/devices",
        None,
        Some(&cookie),
        Some(&csrf),
        Some(json!({ "name": "delete-device" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let device_id = body["data"]["id"].as_str().unwrap().to_string();

    let (status, body) = send_json(
        &app,
        Method::DELETE,
        &format!("/api/v1/devices/{}", device_id),
        None,
        Some(&cookie),
        Some(&csrf),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "delete device: {}", body);
    assert_eq!(body["data"]["deleted"], true);

    // Verify GET returns 404
    let (status, _body) = send_json(
        &app,
        Method::GET,
        &format!("/api/v1/devices/{}", device_id),
        None,
        Some(&cookie),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "deleted device should 404");
}

#[tokio::test]
#[ignore = "REMOVED: v2.0 has no device endpoints — devices unified into workspaces"]
async fn test_device_disable() {
    let (app, store, _state) = setup_test_app().await;
    let _admin = create_user_in_db(&*store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let (cookie, csrf) = login_user(&app, "admin", TEST_PASSWORD).await;

    let (status, body) = send_json(
        &app,
        Method::POST,
        "/api/v1/devices",
        None,
        Some(&cookie),
        Some(&csrf),
        Some(json!({ "name": "disable-device" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let device_id = body["data"]["id"].as_str().unwrap().to_string();

    // Disable the device
    let (status, body) = send_json(
        &app,
        Method::PUT,
        &format!("/api/v1/devices/{}", device_id),
        None,
        Some(&cookie),
        Some(&csrf),
        Some(json!({ "enabled": false })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "disable device: {}", body);
    assert_eq!(body["data"]["status"], "disabled");
}

#[tokio::test]
#[ignore = "REMOVED: v2.0 has no device endpoints — devices unified into workspaces"]
async fn test_device_create_empty_name_rejected() {
    let (app, store, _state) = setup_test_app().await;
    let _admin = create_user_in_db(&*store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let (cookie, csrf) = login_user(&app, "admin", TEST_PASSWORD).await;

    let (status, _body) = send_json(
        &app,
        Method::POST,
        "/api/v1/devices",
        None,
        Some(&cookie),
        Some(&csrf),
        Some(json!({ "name": "   " })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "empty name should be rejected"
    );
}

#[tokio::test]
#[ignore = "REMOVED: v2.0 has no device endpoints — devices unified into workspaces"]
async fn test_device_get_nonexistent_returns_404() {
    let (app, store, _state) = setup_test_app().await;
    let _admin = create_user_in_db(&*store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let (cookie, _csrf) = login_user(&app, "admin", TEST_PASSWORD).await;

    let fake_id = Uuid::new_v4();
    let (status, _body) = send_json(
        &app,
        Method::GET,
        &format!("/api/v1/devices/{}", fake_id),
        None,
        Some(&cookie),
        None,
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "nonexistent device should 404"
    );
}
