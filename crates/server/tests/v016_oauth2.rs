//! Integration tests for v0.16 WS2: OAuth2 Client Credentials Connector
//! and WS3 backend support (credential list enrichment, audit rename).
//!
//! Covers: credential type validation, proxy with OAuth2 credentials,
//! audit events, and WS3 backend support changes.
//!
//! Tests that required slow operations (TTL sleep, timeout) are tested via unit tests.

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
use agent_cordon_core::domain::credential::{CredentialId, StoredCredential};
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
// Test helpers (matching v015_features pattern)
// ---------------------------------------------------------------------------

async fn setup_test_app() -> (
    Router,
    Arc<dyn Store + Send + Sync>,
    agent_cordon_server::state::AppState,
) {
    let ctx = TestAppBuilder::new().build().await;
    (ctx.app, ctx.store, ctx.state)
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

#[allow(dead_code)]
async fn store_test_credential(
    state: &agent_cordon_server::state::AppState,
    owner: &Workspace,
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

#[allow(dead_code)]
#[allow(clippy::too_many_arguments)]
async fn store_oauth2_credential(
    state: &agent_cordon_server::state::AppState,
    owner: &Workspace,
    name: &str,
    client_secret: &str,
    client_id: &str,
    token_endpoint: &str,
    scopes: Option<&str>,
    allowed_url_pattern: Option<&str>,
) -> CredentialId {
    let now = chrono::Utc::now();
    let cred_id = CredentialId(Uuid::new_v4());
    let (encrypted, nonce) = state
        .encryptor
        .encrypt(client_secret.as_bytes(), cred_id.0.to_string().as_bytes())
        .expect("encrypt");
    let mut metadata = serde_json::json!({
        "oauth2_client_id": client_id,
        "oauth2_token_endpoint": token_endpoint,
    });
    if let Some(sc) = scopes {
        metadata["oauth2_scopes"] = serde_json::json!(sc);
    }
    let cred = StoredCredential {
        id: cred_id.clone(),
        name: name.to_string(),
        service: "oauth2-test".to_string(),
        encrypted_value: encrypted,
        nonce,
        scopes: vec![],
        metadata,
        created_by: Some(owner.id.clone()),
        created_by_user: owner.owner_id.clone(),
        created_at: now,
        updated_at: now,
        allowed_url_pattern: allowed_url_pattern.map(|s| s.to_string()),
        expires_at: None,
        transform_script: None,
        transform_name: None,
        vault: "default".to_string(),
        credential_type: "oauth2_client_credentials".to_string(),
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
async fn get_jwt_da(
    state: &agent_cordon_server::state::AppState,
    agent: &Workspace,
    api_key: &str,
) -> (String, String, p256::ecdsa::SigningKey) {
    let (device_id, signing_key) = create_device_and_bind_agent(state, agent).await;
    let jwt = get_jwt_via_device(state, &signing_key, &device_id, api_key).await;
    (jwt, device_id, signing_key)
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

// ===========================================================================
// 1. CREDENTIAL TYPE VALIDATION — oauth2_client_credentials
// ===========================================================================
// The API should accept "oauth2_client_credentials" as a valid credential
// type with specific required fields.
// ===========================================================================

// HAPPY PATH: oauth2_client_credentials is accepted as a valid credential type
#[tokio::test]
async fn oauth2_credential_type_accepted() {
    let (app, store, _state) = setup_test_app().await;
    let admin = create_user_in_db(
        &*store,
        "admin",
        TEST_PASSWORD,
        UserRole::Admin,
        false,
        true,
    )
    .await;
    let (_agent, _api_key) = create_agent_in_db(
        &*store,
        "oauth2-agent",
        vec!["admin"],
        true,
        Some(admin.id.clone()),
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
            "name": "my-oauth2-service",
            "service": "example-api",
            "credential_type": "oauth2_client_credentials",
            "oauth2_client_id": "client-id-here",
            "secret_value": "client-secret-here",
            "oauth2_token_endpoint": "https://auth.example.com/oauth2/token",
            "oauth2_scopes": "read write",
            "allowed_url_pattern": "https://api.example.com/*"
        })),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "oauth2 credential creation: {:?}",
        body
    );
    let cred = &body["data"];
    assert_eq!(
        cred["credential_type"].as_str().unwrap(),
        "oauth2_client_credentials"
    );
    assert_eq!(
        cred["metadata"]["oauth2_client_id"].as_str().unwrap(),
        "client-id-here"
    );
    assert_eq!(
        cred["metadata"]["oauth2_token_endpoint"].as_str().unwrap(),
        "https://auth.example.com/oauth2/token"
    );
    assert_eq!(
        cred["metadata"]["oauth2_scopes"].as_str().unwrap(),
        "read write"
    );
}

// HAPPY PATH: oauth2_client_credentials with optional scopes omitted
#[tokio::test]
async fn oauth2_credential_type_accepted_without_scopes() {
    let (app, store, _state) = setup_test_app().await;
    let admin = create_user_in_db(
        &*store,
        "admin",
        TEST_PASSWORD,
        UserRole::Admin,
        false,
        true,
    )
    .await;
    let (_agent, _api_key) = create_agent_in_db(
        &*store,
        "oauth2-agent2",
        vec!["admin"],
        true,
        Some(admin.id.clone()),
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
            "name": "oauth2-no-scopes",
            "service": "example-api",
            "credential_type": "oauth2_client_credentials",
            "oauth2_client_id": "client-id-here",
            "secret_value": "client-secret-here",
            "oauth2_token_endpoint": "https://auth.example.com/oauth2/token",
            "allowed_url_pattern": "https://api.example.com/*"
        })),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "oauth2 without scopes: {:?}", body);
    let cred = &body["data"];
    assert_eq!(
        cred["credential_type"].as_str().unwrap(),
        "oauth2_client_credentials"
    );
    // oauth2_scopes should not be present in metadata when not provided
    assert!(cred["metadata"]["oauth2_scopes"].is_null());
}

// SAD PATH: Missing oauth2_client_id returns 400
#[tokio::test]
async fn oauth2_credential_missing_client_id_returns_400() {
    let (app, store, _state) = setup_test_app().await;
    let admin = create_user_in_db(
        &*store,
        "admin",
        TEST_PASSWORD,
        UserRole::Admin,
        false,
        true,
    )
    .await;
    let (_agent, _api_key) = create_agent_in_db(
        &*store,
        "oauth2-agent3",
        vec!["admin"],
        true,
        Some(admin.id.clone()),
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
            "name": "oauth2-missing-client-id",
            "service": "example-api",
            "credential_type": "oauth2_client_credentials",
            "secret_value": "client-secret-here",
            "oauth2_token_endpoint": "https://auth.example.com/oauth2/token"
        })),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "missing client_id: {:?}",
        body
    );
}

// SAD PATH: Missing secret_value (client secret) returns 400
#[tokio::test]
async fn oauth2_credential_missing_secret_returns_400() {
    let (app, store, _state) = setup_test_app().await;
    let admin = create_user_in_db(
        &*store,
        "admin",
        TEST_PASSWORD,
        UserRole::Admin,
        false,
        true,
    )
    .await;
    let (_agent, _api_key) = create_agent_in_db(
        &*store,
        "oauth2-agent4",
        vec!["admin"],
        true,
        Some(admin.id.clone()),
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
            "name": "oauth2-missing-secret",
            "service": "example-api",
            "credential_type": "oauth2_client_credentials",
            "oauth2_client_id": "client-id-here",
            "oauth2_token_endpoint": "https://auth.example.com/oauth2/token"
        })),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "missing secret_value: {:?}",
        body
    );
}

// SAD PATH: Missing oauth2_token_endpoint returns 400
#[tokio::test]
async fn oauth2_credential_missing_token_endpoint_returns_400() {
    let (app, store, _state) = setup_test_app().await;
    let admin = create_user_in_db(
        &*store,
        "admin",
        TEST_PASSWORD,
        UserRole::Admin,
        false,
        true,
    )
    .await;
    let (_agent, _api_key) = create_agent_in_db(
        &*store,
        "oauth2-agent5",
        vec!["admin"],
        true,
        Some(admin.id.clone()),
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
            "name": "oauth2-missing-endpoint",
            "service": "example-api",
            "credential_type": "oauth2_client_credentials",
            "oauth2_client_id": "client-id-here",
            "secret_value": "client-secret-here"
        })),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "missing token_endpoint: {:?}",
        body
    );
}

// SAD PATH: Invalid token_endpoint URL returns 400
#[tokio::test]
async fn oauth2_credential_invalid_token_endpoint_returns_400() {
    let (app, store, _state) = setup_test_app().await;
    let admin = create_user_in_db(
        &*store,
        "admin",
        TEST_PASSWORD,
        UserRole::Admin,
        false,
        true,
    )
    .await;
    let (_agent, _api_key) = create_agent_in_db(
        &*store,
        "oauth2-agent6",
        vec!["admin"],
        true,
        Some(admin.id.clone()),
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
            "name": "oauth2-bad-endpoint",
            "service": "example-api",
            "credential_type": "oauth2_client_credentials",
            "oauth2_client_id": "client-id-here",
            "secret_value": "client-secret-here",
            "oauth2_token_endpoint": "not-a-valid-url"
        })),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "invalid token_endpoint: {:?}",
        body
    );
}
// ===========================================================================
// 4. WS3 BACKEND SUPPORT
// ===========================================================================
// Backend changes supporting UX polish: owner_username in credential list,
// CredentialStored -> CredentialCreated rename.
// ===========================================================================

// HAPPY PATH: Credential list includes owner_username field
#[tokio::test]
async fn ws3_credential_list_includes_owner_username() {
    let (app, store, state) = setup_test_app().await;
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
        "owned-agent",
        vec!["admin"],
        true,
        Some(admin.id.clone()),
    )
    .await;
    let _cred = store_test_credential(&state, &agent, "owned-cred", b"secret").await;
    let cookie = login_user(&app, "admin", TEST_PASSWORD).await;

    let (status, body) = send_json(
        &app,
        Method::GET,
        "/api/v1/credentials",
        None,
        Some(&cookie),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::OK, "credential list: {:?}", body);
    let credentials = body["data"].as_array().expect("data should be array");
    assert!(
        !credentials.is_empty(),
        "should have at least one credential"
    );
    // The credential was created by an agent owned by the admin user;
    // owner_username should resolve through agent.owner_id to the user's display name.
    let cred = &credentials[0];
    assert_eq!(
        cred["owner_username"].as_str().unwrap(),
        "Test admin",
        "owner_username should resolve to the owning user's display name"
    );
}

// HAPPY PATH: Audit event type is CredentialCreated (not CredentialStored)
#[tokio::test]
async fn ws3_audit_event_credential_created_not_stored() {
    let (app, store, _state) = setup_test_app().await;
    let admin = create_user_in_db(
        &*store,
        "admin",
        TEST_PASSWORD,
        UserRole::Admin,
        false,
        true,
    )
    .await;
    let (_agent, _api_key) = create_agent_in_db(
        &*store,
        "audit-agent",
        vec!["admin"],
        true,
        Some(admin.id.clone()),
    )
    .await;
    let cookie = login_user(&app, "admin", TEST_PASSWORD).await;

    // Create a credential via API
    let (status, _body) = send_json(
        &app,
        Method::POST,
        "/api/v1/credentials",
        None,
        Some(&cookie),
        Some(json!({
            "name": "audit-test-cred",
            "service": "test-service",
            "credential_type": "generic",
            "secret_value": "test-secret"
        })),
    )
    .await;
    assert!(
        status == StatusCode::CREATED || status == StatusCode::OK,
        "create credential: {}",
        status
    );

    // Check audit log for the event type
    let (status, body) = send_json(
        &app,
        Method::GET,
        "/api/v1/audit",
        None,
        Some(&cookie),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "audit log: {:?}", body);

    let events = body["data"].as_array().expect("data should be array");
    let found_created = events
        .iter()
        .any(|e| e["event_type"].as_str() == Some("credential_created"));
    assert!(
        found_created,
        "should find 'credential_created' event in audit log: {:?}",
        events
    );
    let found_stored = events
        .iter()
        .any(|e| e["event_type"].as_str() == Some("credential_stored"));
    assert!(
        !found_stored,
        "should NOT find 'credential_stored' event in audit log"
    );
}

// SAD PATH: Old "credential_stored" event type no longer appears
#[tokio::test]
async fn ws3_audit_event_no_credential_stored() {
    let (app, store, _state) = setup_test_app().await;
    let admin = create_user_in_db(
        &*store,
        "admin",
        TEST_PASSWORD,
        UserRole::Admin,
        false,
        true,
    )
    .await;
    let (_agent, _api_key) = create_agent_in_db(
        &*store,
        "audit-agent2",
        vec!["admin"],
        true,
        Some(admin.id.clone()),
    )
    .await;
    let cookie = login_user(&app, "admin", TEST_PASSWORD).await;

    // Create a credential
    let (status, _body) = send_json(
        &app,
        Method::POST,
        "/api/v1/credentials",
        None,
        Some(&cookie),
        Some(json!({
            "name": "audit-test-cred2",
            "service": "test-service",
            "credential_type": "generic",
            "secret_value": "test-secret"
        })),
    )
    .await;
    assert!(
        status == StatusCode::CREATED || status == StatusCode::OK,
        "create credential: {}",
        status
    );

    // Verify no "credential_stored" in audit log
    let (status, body) = send_json(
        &app,
        Method::GET,
        "/api/v1/audit",
        None,
        Some(&cookie),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "audit log: {:?}", body);

    if let Some(events) = body["data"].as_array() {
        for event in events {
            let event_type = event["event_type"].as_str().unwrap_or("");
            assert_ne!(
                event_type, "credential_stored",
                "old 'credential_stored' event type should not appear"
            );
        }
    }
}

// ===========================================================================

/// OAuth2 credential created via API with missing token_endpoint should be rejected.
#[tokio::test]
async fn edge_case_oauth2_create_missing_token_endpoint_via_api() {
    let (app, store, _state) = setup_test_app().await;
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

    // Try to create an OAuth2 credential without token_endpoint
    let (status, body) = send_json(
        &app,
        Method::POST,
        "/api/v1/credentials",
        None,
        Some(&cookie),
        Some(json!({
            "name": "bad-oauth2-cred",
            "service": "test-service",
            "credential_type": "oauth2_client_credentials",
            "secret_value": "my-client-secret",
            "metadata": {
                "oauth2_client_id": "my-client-id"
                // Missing oauth2_token_endpoint
            }
        })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "missing token_endpoint should return 400: {:?}",
        body
    );
}
