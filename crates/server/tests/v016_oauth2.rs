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

// ===========================================================================
// 5. ENTRA ID HOTFIX — UNRESOLVED TEMPLATE PLACEHOLDER REJECTION
// ===========================================================================
// Regression guard: the Entra ID template contains a `{tenant_id}` placeholder
// in `oauth2_token_endpoint` that the FE is expected to substitute client-side.
// If a direct API caller (CLI, curl, script) submits the un-substituted URL,
// the broker would POST the literal URL at token fetch time and fail.
// The BE rejects unresolved `{...}` braces as a safety net; we lock that in.
// ===========================================================================

const ENTRA_TEMPLATE_URL: &str =
    "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token";
const ENTRA_RESOLVED_URL: &str =
    "https://login.microsoftonline.com/contoso.onmicrosoft.com/oauth2/v2.0/token";

// SAD PATH: unresolved {tenant_id} placeholder is rejected with "unresolved placeholder"
#[tokio::test]
async fn oauth2_unresolved_tenant_placeholder_rejected() {
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

    let (status, body) = send_json(
        &app,
        Method::POST,
        "/api/v1/credentials",
        None,
        Some(&cookie),
        Some(json!({
            "name": "entra-unresolved-placeholder",
            "service": "login.microsoftonline.com",
            "credential_type": "oauth2_client_credentials",
            "oauth2_client_id": "test-client-id",
            "secret_value": "test-client-secret",
            "oauth2_token_endpoint": ENTRA_TEMPLATE_URL,
            "oauth2_scopes": "https://graph.microsoft.com/.default"
        })),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "unresolved placeholder must be rejected: {:?}",
        body
    );
    // Error message must mention "unresolved placeholder" so callers know what to fix.
    let err_msg = body["error"]["message"]
        .as_str()
        .unwrap_or("")
        .to_lowercase();
    assert!(
        err_msg.contains("unresolved placeholder"),
        "error should mention 'unresolved placeholder', got: {:?}",
        body
    );
}

// SAD PATH: any stray `{` or `}` in the token endpoint URL is rejected.
#[tokio::test]
async fn oauth2_stray_brace_in_endpoint_rejected() {
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

    // Only a closing brace — still a malformed template.
    let (status, _body) = send_json(
        &app,
        Method::POST,
        "/api/v1/credentials",
        None,
        Some(&cookie),
        Some(json!({
            "name": "stray-close-brace",
            "service": "example",
            "credential_type": "oauth2_client_credentials",
            "oauth2_client_id": "cid",
            "secret_value": "secret",
            "oauth2_token_endpoint": "https://auth.example.com/oauth2/token}",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

// HAPPY PATH: a concrete (resolved) Entra URL is accepted and the metadata
// contains the exact resolved URL — no braces, no placeholders.
#[tokio::test]
async fn oauth2_resolved_entra_url_accepted() {
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

    let (status, body) = send_json(
        &app,
        Method::POST,
        "/api/v1/credentials",
        None,
        Some(&cookie),
        Some(json!({
            "name": "entra-resolved",
            "service": "login.microsoftonline.com",
            "credential_type": "oauth2_client_credentials",
            "oauth2_client_id": "test-client-id",
            "secret_value": "test-client-secret",
            "oauth2_token_endpoint": ENTRA_RESOLVED_URL,
            "oauth2_scopes": "https://graph.microsoft.com/.default"
        })),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "resolved entra URL must be accepted: {:?}",
        body
    );
    let stored_endpoint = body["data"]["metadata"]["oauth2_token_endpoint"]
        .as_str()
        .expect("oauth2_token_endpoint in metadata");
    assert_eq!(
        stored_endpoint, ENTRA_RESOLVED_URL,
        "metadata should contain the exact resolved URL"
    );
    assert!(
        !stored_endpoint.contains('{') && !stored_endpoint.contains('}'),
        "stored URL must not contain braces: {}",
        stored_endpoint
    );
}

// HAPPY PATH: the credential-templates API exposes `fields` for entra-id,
// and the list includes `tenant_id` so the FE knows to render that input.
#[tokio::test]
async fn credential_templates_entra_exposes_tenant_id_field() {
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

    let (status, body) = send_json(
        &app,
        Method::GET,
        "/api/v1/credential-templates",
        None,
        Some(&cookie),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::OK, "list templates: {:?}", body);

    let templates = body["data"].as_array().expect("data should be array");
    let entra = templates
        .iter()
        .find(|t| t["key"].as_str() == Some("entra-id"))
        .unwrap_or_else(|| panic!("entra-id template must be present: {:?}", templates));

    let fields = entra["fields"]
        .as_array()
        .unwrap_or_else(|| panic!("entra-id template must expose a `fields` array: {:?}", entra));
    let field_names: Vec<&str> = fields.iter().filter_map(|v| v.as_str()).collect();
    assert!(
        field_names.contains(&"tenant_id"),
        "entra-id template `fields` must include 'tenant_id' so FE renders the input; got: {:?}",
        field_names
    );
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

// ===========================================================================
// v0.16 OAuth2 Device Authorization Grant — security guards
// ===========================================================================
// The tests below lock in six security fixes landed on the device-authorization
// flow:
//   1. policy gate (MANAGE_WORKSPACES) on approve/deny
//   2. pk_hash binding check on approve (approver-squat defense)
//   3. rate limiter: 10 4xx attempts / 60s then 429 with Retry-After
//   4. scope intersect against the workspace OAuth client on token exchange
//   5. no silent bootstrap fallback when workspace/client state is broken
//   6. CAS prevents double-approve under concurrent requests
// ===========================================================================

const DEVICE_BROKER_CLIENT_ID: &str = "agentcordon-broker";
const DEVICE_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:device_code";

/// POST a form-encoded body and return `(status, json_or_null, headers)`.
///
/// Local to the device-flow security tests below; does not overlap with the
/// JSON-based `send_json` helper above.
async fn post_device_form(
    app: &Router,
    uri: &str,
    body: &str,
    extra_headers: &[(&str, &str)],
) -> (StatusCode, Value, Vec<(String, String)>) {
    let mut builder = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    for (k, v) in extra_headers {
        builder = builder.header(*k, *v);
    }
    let req = builder.body(Body::from(body.to_string())).unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let headers: Vec<(String, String)> = resp
        .headers()
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, json, headers)
}

/// Issue a device_code bound to a workspace_name + pk_hash. Returns the raw
/// device_code (plaintext for later token exchange) and the normalized
/// user_code (used by approve/deny endpoints).
async fn issue_workspace_device_code(
    app: &Router,
    workspace_name: &str,
    pk_hash: &str,
    scopes: &str,
) -> (String, String) {
    let body = format!(
        "client_id={}&scope={}&workspace_name={}&public_key_hash={}",
        DEVICE_BROKER_CLIENT_ID,
        scopes.replace(' ', "+"),
        workspace_name,
        pk_hash,
    );
    let (status, json, _) = post_device_form(app, "/api/v1/oauth/device/code", &body, &[]).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "device_code issuance failed: {:?}",
        json
    );
    let device_code = json["device_code"]
        .as_str()
        .expect("device_code present")
        .to_string();
    let user_code = json["user_code"]
        .as_str()
        .expect("user_code present")
        .to_string();
    (device_code, user_code)
}

// ---------------------------------------------------------------------------
// 1. Policy gate — MANAGE_WORKSPACES required on /oauth/device/approve
// ---------------------------------------------------------------------------
//
// A Viewer with a valid session and CSRF token, presenting the correct
// user_code + matching pk_hash, MUST still be rejected. This is the critical
// fix: without the Cedar gate any authenticated user could approve a device
// code issued against someone else's workspace name.

#[tokio::test]
async fn device_approve_requires_manage_workspaces_policy() {
    let (app, store, _state) = setup_test_app().await;
    let _admin = create_user_in_db(
        &*store,
        "admin-policy",
        TEST_PASSWORD,
        UserRole::Admin,
        true,
        true,
    )
    .await;
    let _viewer = create_user_in_db(
        &*store,
        "viewer-policy",
        TEST_PASSWORD,
        UserRole::Viewer,
        false,
        true,
    )
    .await;

    // Issue a workspace-bound device code. The endpoint is public form-POST;
    // no caller auth is needed.
    let pk_hash = "a".repeat(64);
    let (_device_code, user_code) = issue_workspace_device_code(
        &app,
        "policy-gate-ws",
        &pk_hash,
        "credentials:discover",
    )
    .await;

    // The Viewer logs in and tries to approve. They present valid
    // user_code + matching pk_hash, so everything downstream of the policy
    // gate would succeed — only Cedar stands between them and provisioning.
    let viewer_cookie = login_user(&app, "viewer-policy", TEST_PASSWORD).await;
    let (status, body) = send_json(
        &app,
        Method::POST,
        "/api/v1/oauth/device/approve",
        None,
        Some(&viewer_cookie),
        Some(json!({
            "user_code": user_code,
            "public_key_hash": pk_hash,
        })),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "Viewer must be denied by policy gate, got body: {:?}",
        body
    );
    let msg = body["error"]["message"]
        .as_str()
        .unwrap_or("")
        .to_lowercase();
    assert!(
        msg.contains("policy") || msg.contains("access denied"),
        "expected policy-denial message, got: {:?}",
        body
    );
}

// ---------------------------------------------------------------------------
// 2. pk_hash binding — approver must re-present the hash bound at issue time
// ---------------------------------------------------------------------------
//
// Defends against an approver squatting on someone else's device flow by
// swapping in their own workspace key at approval time.

#[tokio::test]
async fn device_approve_rejects_pk_hash_mismatch() {
    let (app, store, _state) = setup_test_app().await;
    let _admin = create_user_in_db(
        &*store,
        "admin-pk",
        TEST_PASSWORD,
        UserRole::Admin,
        true,
        true,
    )
    .await;

    let hash_a = "a".repeat(64);
    let hash_b = "b".repeat(64);
    let (_device_code, user_code) =
        issue_workspace_device_code(&app, "pk-bind-ws", &hash_a, "credentials:discover").await;

    let admin_cookie = login_user(&app, "admin-pk", TEST_PASSWORD).await;
    let (status, body) = send_json(
        &app,
        Method::POST,
        "/api/v1/oauth/device/approve",
        None,
        Some(&admin_cookie),
        Some(json!({
            "user_code": user_code,
            "public_key_hash": hash_b,
        })),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "mismatch must be rejected, got body: {:?}",
        body
    );
    let msg = body["error"]["message"]
        .as_str()
        .unwrap_or("")
        .to_lowercase();
    assert!(
        msg.contains("public_key_hash") && msg.contains("does not match"),
        "expected pk_hash mismatch message, got: {:?}",
        body
    );
}

// ---------------------------------------------------------------------------
// 3. Rate limit — 10 failing attempts / 60s then 429 + Retry-After
// ---------------------------------------------------------------------------
//
// Pin the rate-limit key via X-Forwarded-For so the test is independent of
// ConnectInfo availability in the oneshot router. We feed invalid user codes
// that pass policy (admin is authorized) but fail the row lookup → 400. The
// 11th attempt MUST short-circuit to 429 with a Retry-After header.

#[tokio::test]
async fn device_approve_rate_limited_after_threshold() {
    let (app, store, _state) = setup_test_app().await;
    let _admin = create_user_in_db(
        &*store,
        "admin-rate",
        TEST_PASSWORD,
        UserRole::Admin,
        true,
        true,
    )
    .await;
    let admin_cookie = login_user(&app, "admin-rate", TEST_PASSWORD).await;
    let xff = "192.0.2.99";

    // Build a single request template and fire it 10 times. Each attempt uses
    // a made-up user_code that will miss the row lookup → 400 → counted.
    let bad_body = json!({
        "user_code": "aaaa-bbbb-cccc-dddd",
        "public_key_hash": "c".repeat(64),
    });
    for i in 0..10 {
        let csrf = extract_csrf_from_cookie(&admin_cookie).expect("csrf");
        let req = Request::builder()
            .method(Method::POST)
            .uri("/api/v1/oauth/device/approve")
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::COOKIE, &admin_cookie)
            .header("x-csrf-token", &csrf)
            .header("x-forwarded-for", xff)
            .body(Body::from(serde_json::to_vec(&bad_body).unwrap()))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert!(
            resp.status().is_client_error(),
            "attempt {i} must be a 4xx to count against the bucket, got {}",
            resp.status()
        );
        assert_ne!(
            resp.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "bucket should not trip inside the first 10 attempts (attempt {i})"
        );
    }

    // 11th attempt: rate limiter short-circuits with 429 + Retry-After.
    let csrf = extract_csrf_from_cookie(&admin_cookie).expect("csrf");
    let req = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/oauth/device/approve")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::COOKIE, &admin_cookie)
        .header("x-csrf-token", csrf)
        .header("x-forwarded-for", xff)
        .body(Body::from(serde_json::to_vec(&bad_body).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "11th attempt must be rate-limited"
    );
    let retry_after = resp
        .headers()
        .get("retry-after")
        .and_then(|v| v.to_str().ok())
        .expect("retry-after header must be present");
    assert!(
        retry_after.parse::<u64>().is_ok(),
        "retry-after must be a numeric seconds value, got {retry_after:?}"
    );
}

// ---------------------------------------------------------------------------
// 4. Scope intersect — device_code scopes must be within workspace client
// ---------------------------------------------------------------------------
//
// Setup creates a narrow OAuth client (allowed_scopes = [discover]) bound to
// a specific pk_hash, then issues and approves a device code that asks for
// BOTH discover + vend. The approve handler sees a pre-existing client for
// this pk_hash and reuses it (rather than creating a wide one), so at token
// exchange time the device_code.scopes ([discover, vend]) exceed the client's
// allowed_scopes ([discover]) — the intersect check must fire.

#[tokio::test]
async fn device_token_exchange_intersects_scopes() {
    use agent_cordon_core::domain::user::UserId;
    use agent_cordon_core::oauth2::types::{OAuthClient, OAuthScope};

    let (app, store, state) = setup_test_app().await;
    let admin = create_user_in_db(
        &*store,
        "admin-scope",
        TEST_PASSWORD,
        UserRole::Admin,
        true,
        true,
    )
    .await;

    let pk_hash = "d".repeat(64);
    let workspace_name = "scope-intersect-ws";

    // Pre-create the narrow OAuth client. The approve endpoint checks
    // `get_oauth_client_by_public_key_hash` and skips creation when a client
    // already exists for this pk_hash.
    let narrow_client = OAuthClient {
        id: Uuid::new_v4(),
        client_id: format!("ac_cli_{}", Uuid::new_v4().simple()),
        client_secret_hash: None,
        workspace_name: workspace_name.to_string(),
        public_key_hash: pk_hash.clone(),
        redirect_uris: vec![],
        allowed_scopes: vec![OAuthScope::CredentialsDiscover],
        created_by_user: UserId(admin.id.0),
        created_at: chrono::Utc::now(),
        revoked_at: None,
    };
    store
        .create_oauth_client(&narrow_client)
        .await
        .expect("pre-create narrow oauth client");

    // Issue a device_code with BOTH scopes. The bootstrap broker client has
    // all four scopes so this passes issue-time validation.
    let (device_code_plain, user_code) = issue_workspace_device_code(
        &app,
        workspace_name,
        &pk_hash,
        "credentials:discover credentials:vend",
    )
    .await;

    // Admin approves. The approve handler finds our narrow client, reuses it.
    let admin_cookie = login_user(&app, "admin-scope", TEST_PASSWORD).await;
    let (status, body) = send_json(
        &app,
        Method::POST,
        "/api/v1/oauth/device/approve",
        None,
        Some(&admin_cookie),
        Some(json!({
            "user_code": user_code,
            "public_key_hash": pk_hash,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "approve must succeed: {:?}", body);

    // Sanity: the client wasn't widened.
    let after = state
        .store
        .get_oauth_client_by_public_key_hash(&pk_hash)
        .await
        .expect("lookup after approve")
        .expect("client still present");
    assert_eq!(
        after.allowed_scopes,
        vec![OAuthScope::CredentialsDiscover],
        "approve must not widen an existing client's allowed_scopes"
    );

    // Exchange — scopes on the row exceed the client's envelope, so the
    // intersect check must fire.
    let form = format!(
        "grant_type={DEVICE_GRANT_TYPE}&client_id={DEVICE_BROKER_CLIENT_ID}&device_code={device_code_plain}",
    );
    let (status, json, _) = post_device_form(&app, "/api/v1/oauth/token", &form, &[]).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "intersect mismatch must be 400: {:?}",
        json
    );
    assert_eq!(
        json["error"].as_str(),
        Some("invalid_scope"),
        "expected invalid_scope, got: {:?}",
        json
    );
    let desc = json["error_description"]
        .as_str()
        .unwrap_or("")
        .to_lowercase();
    assert!(
        desc.contains("exceeds") && desc.contains("allowed_scopes"),
        "expected scope-exceeds message, got: {:?}",
        json
    );
    assert!(
        json["access_token"].is_null(),
        "no token must be issued on scope mismatch, got: {:?}",
        json
    );
}

// ---------------------------------------------------------------------------
// 5. No silent bootstrap fallback when workspace OAuth client is revoked
// ---------------------------------------------------------------------------
//
// After approval, if the workspace's OAuth client is revoked before the token
// exchange, the exchange MUST fail with invalid_grant — NOT silently issue a
// token against the bootstrap broker client.

#[tokio::test]
async fn device_token_exchange_no_silent_bootstrap_fallback() {
    let (app, store, state) = setup_test_app().await;
    let _admin = create_user_in_db(
        &*store,
        "admin-fallback",
        TEST_PASSWORD,
        UserRole::Admin,
        true,
        true,
    )
    .await;

    let pk_hash = "e".repeat(64);
    let (device_code_plain, user_code) = issue_workspace_device_code(
        &app,
        "fallback-ws",
        &pk_hash,
        "credentials:discover",
    )
    .await;

    let admin_cookie = login_user(&app, "admin-fallback", TEST_PASSWORD).await;
    let (status, body) = send_json(
        &app,
        Method::POST,
        "/api/v1/oauth/device/approve",
        None,
        Some(&admin_cookie),
        Some(json!({
            "user_code": user_code,
            "public_key_hash": pk_hash,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "approve must succeed: {:?}", body);

    // Revoke the workspace-bound OAuth client.
    let client = state
        .store
        .get_oauth_client_by_public_key_hash(&pk_hash)
        .await
        .expect("lookup")
        .expect("client exists after approve");
    assert_ne!(
        client.client_id, DEVICE_BROKER_CLIENT_ID,
        "approve must bind to a workspace-specific client, not the bootstrap broker"
    );
    let revoked = state
        .store
        .revoke_oauth_client(&client.client_id)
        .await
        .expect("revoke oauth client");
    assert!(revoked, "revoke must flip revoked_at");

    // Exchange — workspace client is now revoked; exchange MUST fail with
    // invalid_grant. It MUST NOT silently fall back to the bootstrap client.
    let form = format!(
        "grant_type={DEVICE_GRANT_TYPE}&client_id={DEVICE_BROKER_CLIENT_ID}&device_code={device_code_plain}",
    );
    let (status, json, _) = post_device_form(&app, "/api/v1/oauth/token", &form, &[]).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "revoked workspace client must fail exchange: {:?}",
        json
    );
    assert_eq!(
        json["error"].as_str(),
        Some("invalid_grant"),
        "expected invalid_grant, got: {:?}",
        json
    );
    let desc = json["error_description"]
        .as_str()
        .unwrap_or("")
        .to_lowercase();
    assert!(
        desc.contains("workspace")
            && (desc.contains("missing") || desc.contains("revoked") || desc.contains("incomplete")),
        "expected workspace-integrity failure message, got: {:?}",
        json
    );
    assert!(
        json["access_token"].is_null(),
        "no token may be issued when workspace client is revoked — bootstrap fallback is forbidden: {:?}",
        json
    );
}

// ---------------------------------------------------------------------------
// 6. CAS prevents double-approve under concurrent requests
// ---------------------------------------------------------------------------
//
// Two concurrent approve calls with the same user_code + pk_hash must resolve
// to exactly one 2xx and one 4xx — never two 2xx.

#[tokio::test]
async fn device_approve_cas_prevents_double_approve() {
    let (app, store, _state) = setup_test_app().await;
    let _admin = create_user_in_db(
        &*store,
        "admin-cas",
        TEST_PASSWORD,
        UserRole::Admin,
        true,
        true,
    )
    .await;

    let pk_hash = "f".repeat(64);
    let (_device_code, user_code) =
        issue_workspace_device_code(&app, "cas-ws", &pk_hash, "credentials:discover").await;
    let admin_cookie = login_user(&app, "admin-cas", TEST_PASSWORD).await;

    // Build two identical request bodies and fire them concurrently. Each
    // task clones the router; the backing state (store + CAS) is shared.
    let body_json = json!({
        "user_code": user_code,
        "public_key_hash": pk_hash,
    });
    let app_a = app.clone();
    let app_b = app.clone();
    let cookie_a = admin_cookie.clone();
    let cookie_b = admin_cookie.clone();
    let body_a = body_json.clone();
    let body_b = body_json.clone();

    let h1 = tokio::spawn(async move {
        send_json(
            &app_a,
            Method::POST,
            "/api/v1/oauth/device/approve",
            None,
            Some(&cookie_a),
            Some(body_a),
        )
        .await
    });
    let h2 = tokio::spawn(async move {
        send_json(
            &app_b,
            Method::POST,
            "/api/v1/oauth/device/approve",
            None,
            Some(&cookie_b),
            Some(body_b),
        )
        .await
    });
    let (r1, r2) = (h1.await.unwrap(), h2.await.unwrap());

    let (ok_count, loser_body) = {
        let mut oks = 0;
        let mut loser: Option<Value> = None;
        for (status, body) in [&r1, &r2] {
            if status.is_success() {
                oks += 1;
            } else {
                loser = Some(body.clone());
            }
        }
        (oks, loser)
    };

    assert_eq!(
        ok_count, 1,
        "exactly one approve must win CAS, got r1={:?} r2={:?}",
        r1, r2
    );
    let loser = loser_body.expect("one loser must exist");
    let msg = loser["error"]["message"]
        .as_str()
        .unwrap_or("")
        .to_lowercase();
    assert!(
        msg.contains("already") || msg.contains("consumed") || msg.contains("not pending"),
        "CAS-loser must indicate already-consumed / not-pending, got: {:?}",
        loser
    );
}
