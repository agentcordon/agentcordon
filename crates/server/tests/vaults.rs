//! Integration tests for vault organization and vault sharing.
//!
//! Tests cover:
//! - Creating a vault, and creating credentials in it by id
//! - Default vault assignment when no vault is named
//! - Listing vault rows
//! - Listing credentials filtered by vault
//! - Sharing a vault with another user
//! - Listing vault shares
//! - Unsharing a vault
//! - Cannot share with nonexistent user (404)
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

use agent_cordon_core::crypto::password::hash_password;
use agent_cordon_core::domain::user::{User, UserId, UserRole};
use agent_cordon_core::domain::vault::DEFAULT_VAULT_ID;
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

async fn setup_test_app() -> (Router, Arc<dyn Store + Send + Sync>) {
    let ctx = TestAppBuilder::new().build().await;
    (ctx.app, ctx.store)
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
        created_at: now,
        updated_at: now,
    };
    store.create_user(&user).await.expect("create user");
    user
}

/// Login a user and return (combined_cookie, csrf_token).
/// The combined_cookie includes both session and CSRF cookies.
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

    // Combine session and CSRF cookies for double-submit pattern
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
    csrf_token: Option<&str>,
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
            // Use explicit csrf_token if provided, otherwise extract from cookie
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

// ---------------------------------------------------------------------------
// Vault Organization Tests
// ---------------------------------------------------------------------------

/// Create a vault owned by whoever the cookie belongs to. Returns its id.
async fn create_vault(app: &Router, cookie: &str, csrf: &str, name: &str) -> String {
    let (status, body) = send_json(
        app,
        Method::POST,
        "/api/v1/vaults",
        None,
        Some(cookie),
        Some(csrf),
        Some(json!({ "name": name })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "create vault {name}: {body:?}");
    body["data"]["id"].as_str().expect("vault id").to_string()
}

/// Put a credential in a vault, so the vault is not empty.
async fn seed_credential(app: &Router, cookie: &str, csrf: &str, name: &str, vault_id: &str) {
    let (status, body) = send_json(
        app,
        Method::POST,
        "/api/v1/credentials",
        None,
        Some(cookie),
        Some(csrf),
        Some(json!({
            "name": name,
            "service": "seed",
            "secret_value": "seed-secret",
            "vault_id": vault_id,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "seed credential {name}: {body:?}");
}

#[tokio::test]
async fn test_credential_with_default_vault() {
    let (app, store) = setup_test_app().await;
    let _admin = create_user_in_db(&*store, "vault-admin", TEST_PASSWORD, UserRole::Admin).await;
    let (cookie, csrf) = login_user(&app, "vault-admin", TEST_PASSWORD).await;

    // Create credential without specifying vault
    let (status, body) = send_json(
        &app,
        Method::POST,
        "/api/v1/credentials",
        None,
        Some(&cookie),
        Some(&csrf),
        Some(json!({
            "name": "no-vault-cred",
            "service": "test",
            "secret_value": "secret123"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "create credential: {:?}", body);
    assert_eq!(body["data"]["vault_id"], DEFAULT_VAULT_ID);
    assert_eq!(body["data"]["vault_name"], "default");
}

#[tokio::test]
async fn test_credential_with_explicit_vault() {
    let (app, store) = setup_test_app().await;
    let _admin = create_user_in_db(&*store, "vault-admin2", TEST_PASSWORD, UserRole::Admin).await;
    let (cookie, csrf) = login_user(&app, "vault-admin2", TEST_PASSWORD).await;
    let vault_id = create_vault(&app, &cookie, &csrf, "production").await;

    let (status, body) = send_json(
        &app,
        Method::POST,
        "/api/v1/credentials",
        None,
        Some(&cookie),
        Some(&csrf),
        Some(json!({
            "name": "prod-cred",
            "service": "github",
            "secret_value": "ghp_token123",
            "vault_id": vault_id
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "create credential: {:?}", body);
    assert_eq!(body["data"]["vault_id"], vault_id);
    assert_eq!(body["data"]["vault_name"], "production");
}

/// The vault list is rows, not names: two vaults called `alpha` are two
/// entries, and the system default is always there.
#[tokio::test]
async fn test_list_vaults_returns_rows_not_names() {
    let (app, store) = setup_test_app().await;
    let _admin = create_user_in_db(&*store, "vault-admin3", TEST_PASSWORD, UserRole::Admin).await;
    let (cookie, csrf) = login_user(&app, "vault-admin3", TEST_PASSWORD).await;

    // Distinct names: one owner may not hold two vaults of the same name.
    let alpha_one = create_vault(&app, &cookie, &csrf, "alpha").await;
    let alpha_two = create_vault(&app, &cookie, &csrf, "alpha-two").await;
    let beta = create_vault(&app, &cookie, &csrf, "beta").await;

    let (status, body) = send_json(
        &app,
        Method::GET,
        "/api/v1/vaults",
        None,
        Some(&cookie),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "list vaults: {:?}", body);

    let vaults = body["data"].as_array().expect("data should be array");
    let ids: Vec<&str> = vaults.iter().filter_map(|v| v["id"].as_str()).collect();
    for expected in [
        DEFAULT_VAULT_ID,
        alpha_one.as_str(),
        alpha_two.as_str(),
        beta.as_str(),
    ] {
        assert!(
            ids.contains(&expected),
            "{expected} should be listed: {ids:?}"
        );
    }
    assert_eq!(
        vaults.len(),
        4,
        "the default plus three created vaults: {ids:?}"
    );
    let default = vaults
        .iter()
        .find(|v| v["id"] == DEFAULT_VAULT_ID)
        .expect("the default vault");
    assert_eq!(default["is_default"], true, "{default}");
    assert!(default["owner_user_id"].is_null(), "{default}");
}

#[tokio::test]
async fn test_list_credentials_by_vault() {
    let (app, store) = setup_test_app().await;
    let _admin = create_user_in_db(&*store, "vault-admin4", TEST_PASSWORD, UserRole::Admin).await;
    let (cookie, csrf) = login_user(&app, "vault-admin4", TEST_PASSWORD).await;

    let production = create_vault(&app, &cookie, &csrf, "production").await;
    let staging = create_vault(&app, &cookie, &csrf, "staging").await;
    seed_credential(&app, &cookie, &csrf, "prod-token", &production).await;
    seed_credential(&app, &cookie, &csrf, "prod-github", &production).await;
    seed_credential(&app, &cookie, &csrf, "staging-token", &staging).await;

    let (status, body) = send_json(
        &app,
        Method::GET,
        &format!("/api/v1/vaults/{production}/credentials"),
        None,
        Some(&cookie),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "list vault creds: {:?}", body);

    let creds = body["data"].as_array().expect("data should be array");
    assert_eq!(creds.len(), 2, "production vault should have 2 credentials");
    let names: Vec<&str> = creds.iter().map(|c| c["name"].as_str().unwrap()).collect();
    assert!(names.contains(&"prod-token"));
    assert!(names.contains(&"prod-github"));

    let (status, body) = send_json(
        &app,
        Method::GET,
        &format!("/api/v1/vaults/{staging}/credentials"),
        None,
        Some(&cookie),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let creds = body["data"].as_array().unwrap();
    assert_eq!(creds.len(), 1);
    assert_eq!(creds[0]["name"].as_str().unwrap(), "staging-token");

    // A vault id nobody has is empty, not an error: the read answers with
    // what the caller may see.
    let (status, body) = send_json(
        &app,
        Method::GET,
        &format!("/api/v1/vaults/{}/credentials", Uuid::new_v4()),
        None,
        Some(&cookie),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let creds = body["data"].as_array().unwrap();
    assert_eq!(creds.len(), 0);
}

// ---------------------------------------------------------------------------
// Vault Sharing Tests
// ---------------------------------------------------------------------------

/// Sharing a vault is the business of whoever owns it: another admin, who
/// owns nothing there, is refused, and a vault that does not exist is a 404.
#[tokio::test]
async fn sharing_requires_owning_the_vault() {
    let (app, store) = setup_test_app().await;
    create_user_in_db(&*store, "vault-owner", TEST_PASSWORD, UserRole::Admin).await;
    create_user_in_db(&*store, "other-admin", TEST_PASSWORD, UserRole::Admin).await;
    let viewer = create_user_in_db(&*store, "share-target", TEST_PASSWORD, UserRole::Viewer).await;
    let (owner_cookie, owner_csrf) = login_user(&app, "vault-owner", TEST_PASSWORD).await;
    let (other_cookie, other_csrf) = login_user(&app, "other-admin", TEST_PASSWORD).await;

    let vault_id = create_vault(&app, &owner_cookie, &owner_csrf, "team-a").await;
    let share_body = json!({ "user_id": viewer.id.0.to_string(), "permission": "read" });

    let (status, _) = send_json(
        &app,
        Method::POST,
        &format!("/api/v1/vaults/{vault_id}/shares"),
        None,
        Some(&other_cookie),
        Some(&other_csrf),
        Some(share_body.clone()),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "non-owner admin cannot share"
    );

    let (status, _) = send_json(
        &app,
        Method::POST,
        &format!("/api/v1/vaults/{}/shares", Uuid::new_v4()),
        None,
        Some(&owner_cookie),
        Some(&owner_csrf),
        Some(share_body.clone()),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "no such vault");

    let (status, body) = send_json(
        &app,
        Method::POST,
        &format!("/api/v1/vaults/{vault_id}/shares"),
        None,
        Some(&owner_cookie),
        Some(&owner_csrf),
        Some(share_body),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "owner shares: {body:?}");
}

#[tokio::test]
async fn test_share_vault_with_user() {
    let (app, store) = setup_test_app().await;
    let _admin = create_user_in_db(&*store, "share-admin", TEST_PASSWORD, UserRole::Admin).await;
    let viewer = create_user_in_db(&*store, "share-viewer", TEST_PASSWORD, UserRole::Viewer).await;
    let (cookie, csrf) = login_user(&app, "share-admin", TEST_PASSWORD).await;
    let vault_id = create_vault(&app, &cookie, &csrf, "production").await;

    let (status, body) = send_json(
        &app,
        Method::POST,
        &format!("/api/v1/vaults/{vault_id}/shares"),
        None,
        Some(&cookie),
        Some(&csrf),
        Some(json!({
            "user_id": viewer.id.0.to_string(),
            "permission": "read"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "share vault: {:?}", body);
    assert_eq!(body["data"]["vault_id"], vault_id);
    assert_eq!(body["data"]["permission_level"], "read");
    assert_eq!(body["data"]["shared_with_user_id"], viewer.id.0.to_string());
}

#[tokio::test]
async fn test_list_vault_shares() {
    let (app, store) = setup_test_app().await;
    let _admin =
        create_user_in_db(&*store, "list-share-admin", TEST_PASSWORD, UserRole::Admin).await;
    let user1 = create_user_in_db(
        &*store,
        "list-share-user1",
        TEST_PASSWORD,
        UserRole::Operator,
    )
    .await;
    let user2 =
        create_user_in_db(&*store, "list-share-user2", TEST_PASSWORD, UserRole::Viewer).await;
    let (cookie, csrf) = login_user(&app, "list-share-admin", TEST_PASSWORD).await;
    let vault_id = create_vault(&app, &cookie, &csrf, "shared-vault").await;

    for user in [&user1, &user2] {
        let (status, body) = send_json(
            &app,
            Method::POST,
            &format!("/api/v1/vaults/{vault_id}/shares"),
            None,
            Some(&cookie),
            Some(&csrf),
            Some(json!({ "user_id": user.id.0.to_string(), "permission": "read" })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "share: {body:?}");
    }

    let (status, body) = send_json(
        &app,
        Method::GET,
        &format!("/api/v1/vaults/{vault_id}/shares"),
        None,
        Some(&cookie),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "list shares: {:?}", body);
    let shares = body["data"].as_array().expect("data should be array");
    assert_eq!(shares.len(), 2);
}

#[tokio::test]
async fn test_unshare_vault() {
    let (app, store) = setup_test_app().await;
    let _admin = create_user_in_db(&*store, "unshare-admin", TEST_PASSWORD, UserRole::Admin).await;
    let viewer =
        create_user_in_db(&*store, "unshare-viewer", TEST_PASSWORD, UserRole::Viewer).await;
    let (cookie, csrf) = login_user(&app, "unshare-admin", TEST_PASSWORD).await;
    let vault_id = create_vault(&app, &cookie, &csrf, "to-unshare").await;

    let (status, _) = send_json(
        &app,
        Method::POST,
        &format!("/api/v1/vaults/{vault_id}/shares"),
        None,
        Some(&cookie),
        Some(&csrf),
        Some(json!({
            "user_id": viewer.id.0.to_string(),
            "permission": "read"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let unshare_uri = format!("/api/v1/vaults/{vault_id}/shares/{}", viewer.id.0);
    let (status, body) = send_json(
        &app,
        Method::DELETE,
        &unshare_uri,
        None,
        Some(&cookie),
        Some(&csrf),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unshare: {:?}", body);
    assert_eq!(body["data"]["deleted"], true);

    let (status, body) = send_json(
        &app,
        Method::GET,
        &format!("/api/v1/vaults/{vault_id}/shares"),
        None,
        Some(&cookie),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["data"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn test_share_vault_with_nonexistent_user() {
    let (app, store) = setup_test_app().await;
    let _admin = create_user_in_db(
        &*store,
        "share-nouser-admin",
        TEST_PASSWORD,
        UserRole::Admin,
    )
    .await;
    let (cookie, csrf) = login_user(&app, "share-nouser-admin", TEST_PASSWORD).await;
    let vault_id = create_vault(&app, &cookie, &csrf, "some-vault").await;

    let fake_user_id = Uuid::new_v4().to_string();
    let (status, body) = send_json(
        &app,
        Method::POST,
        &format!("/api/v1/vaults/{vault_id}/shares"),
        None,
        Some(&cookie),
        Some(&csrf),
        Some(json!({
            "user_id": fake_user_id,
            "permission": "read"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "should 404: {:?}", body);
}

#[tokio::test]
async fn test_share_vault_default_permission() {
    let (app, store) = setup_test_app().await;
    let _admin = create_user_in_db(
        &*store,
        "default-perm-admin",
        TEST_PASSWORD,
        UserRole::Admin,
    )
    .await;
    let viewer = create_user_in_db(
        &*store,
        "default-perm-viewer",
        TEST_PASSWORD,
        UserRole::Viewer,
    )
    .await;
    let (cookie, csrf) = login_user(&app, "default-perm-admin", TEST_PASSWORD).await;
    let vault_id = create_vault(&app, &cookie, &csrf, "default-perm-vault").await;

    // Share without specifying permission — should default to "read"
    let (status, body) = send_json(
        &app,
        Method::POST,
        &format!("/api/v1/vaults/{vault_id}/shares"),
        None,
        Some(&cookie),
        Some(&csrf),
        Some(json!({
            "user_id": viewer.id.0.to_string()
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "share vault: {:?}", body);
    assert_eq!(body["data"]["permission_level"], "read");
}

/// A viewer holds no `create`, so there is no vault for them to own and
/// nothing for them to share.
#[tokio::test]
async fn test_viewer_cannot_create_or_share_a_vault() {
    let (app, store) = setup_test_app().await;
    let admin = create_user_in_db(
        &*store,
        "viewer-share-admin",
        TEST_PASSWORD,
        UserRole::Admin,
    )
    .await;
    let _viewer = create_user_in_db(
        &*store,
        "viewer-share-viewer",
        TEST_PASSWORD,
        UserRole::Viewer,
    )
    .await;
    let (admin_cookie, admin_csrf) = login_user(&app, "viewer-share-admin", TEST_PASSWORD).await;
    let (viewer_cookie, viewer_csrf) = login_user(&app, "viewer-share-viewer", TEST_PASSWORD).await;

    let (status, body) = send_json(
        &app,
        Method::POST,
        "/api/v1/vaults",
        None,
        Some(&viewer_cookie),
        Some(&viewer_csrf),
        Some(json!({ "name": "viewers-vault" })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "viewer create: {:?}", body);

    let vault_id = create_vault(&app, &admin_cookie, &admin_csrf, "admins-vault").await;
    let (status, body) = send_json(
        &app,
        Method::POST,
        &format!("/api/v1/vaults/{vault_id}/shares"),
        None,
        Some(&viewer_cookie),
        Some(&viewer_csrf),
        Some(json!({
            "user_id": admin.id.0.to_string(),
            "permission": "read"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "viewer share: {:?}", body);
}

#[tokio::test]
async fn test_agent_cannot_share_vault() {
    let ctx = TestAppBuilder::new().build().await;
    let _admin = create_user_in_db(
        &*ctx.store,
        "agent-share-admin",
        TEST_PASSWORD,
        UserRole::Admin,
    )
    .await;
    let viewer = create_user_in_db(
        &*ctx.store,
        "agent-share-viewer",
        TEST_PASSWORD,
        UserRole::Viewer,
    )
    .await;
    let (admin_cookie, admin_csrf) = login_user(&ctx.app, "agent-share-admin", TEST_PASSWORD).await;
    let vault_id = create_vault(&ctx.app, &admin_cookie, &admin_csrf, "agent-vault").await;

    // Create an admin agent and get a JWT via device
    let (agent, raw_key) =
        create_agent_in_db(&*ctx.store, "share-agent", vec!["admin"], true, None).await;

    // Setup device + get JWT for agent
    let qda = quick_device_setup(&ctx.state, &agent, &raw_key).await;

    // Agent tries to share vault via dual auth — should fail with 403
    let (status, body) = send_json_dual_auth(
        &ctx.app,
        Method::POST,
        &format!("/api/v1/vaults/{vault_id}/shares"),
        &qda.device_signing_key,
        &qda.device_id,
        &qda.agent_jwt,
        Some(json!({
            "user_id": viewer.id.0.to_string(),
            "permission": "read"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "agent share: {:?}", body);
}

#[tokio::test]
async fn test_share_vault_invalid_permission_returns_400() {
    let (app, store) = setup_test_app().await;
    let _admin = create_user_in_db(&*store, "bad-perm-admin", TEST_PASSWORD, UserRole::Admin).await;
    let viewer =
        create_user_in_db(&*store, "bad-perm-viewer", TEST_PASSWORD, UserRole::Viewer).await;
    let (cookie, csrf) = login_user(&app, "bad-perm-admin", TEST_PASSWORD).await;
    let vault_id = create_vault(&app, &cookie, &csrf, "some-vault").await;

    let (status, body) = send_json(
        &app,
        Method::POST,
        &format!("/api/v1/vaults/{vault_id}/shares"),
        None,
        Some(&cookie),
        Some(&csrf),
        Some(json!({
            "user_id": viewer.id.0.to_string(),
            "permission": "superadmin"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "invalid perm: {:?}", body);
}

#[tokio::test]
async fn test_unshare_nonexistent_returns_404() {
    let (app, store) = setup_test_app().await;
    let _admin =
        create_user_in_db(&*store, "unshare-404-admin", TEST_PASSWORD, UserRole::Admin).await;
    let (cookie, csrf) = login_user(&app, "unshare-404-admin", TEST_PASSWORD).await;
    let vault_id = create_vault(&app, &cookie, &csrf, "empty-shares").await;

    let fake_user_id = Uuid::new_v4();
    let uri = format!("/api/v1/vaults/{vault_id}/shares/{fake_user_id}");
    let (status, body) = send_json(
        &app,
        Method::DELETE,
        &uri,
        None,
        Some(&cookie),
        Some(&csrf),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "unshare 404: {:?}", body);
}
