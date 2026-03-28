//! Integration tests for v0.15 features:
//!
//! 1. Cedar Schema Endpoint — `GET /api/v1/policies/schema` (admin-only)
//! 2. Disabled Principal Forbid Policy — Cedar denies disabled agents/users
//! 3. Time-Based Policy — additive compatibility test (existing policies unaffected)

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
use agent_cordon_core::domain::credential::{CredentialId, StoredCredential};
use agent_cordon_core::domain::policy::PolicyDecisionResult;
use agent_cordon_core::domain::user::{User, UserId, UserRole};
use agent_cordon_core::domain::workspace::{Workspace, WorkspaceId, WorkspaceStatus};
use agent_cordon_core::policy::cedar::CedarPolicyEngine;
use agent_cordon_core::policy::{PolicyContext, PolicyEngine, PolicyPrincipal, PolicyResource};
use agent_cordon_core::storage::Store;

use crate::common::*;
use agent_cordon_server::test_helpers::TestAppBuilder;

// ---------------------------------------------------------------------------
// Test constants
// ---------------------------------------------------------------------------

const TEST_PASSWORD: &str = "strong-password-123!";

// ---------------------------------------------------------------------------
// Test helpers (reused from v014_features pattern)
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
// 2. CEDAR SCHEMA ENDPOINT
// ===========================================================================
// STATUS: ENABLED — GET /api/v1/policies/schema endpoint implemented
// ===========================================================================

// HAPPY PATH: Admin user can retrieve the Cedar schema
#[tokio::test]
async fn schema_endpoint_admin_gets_schema_text() {
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
        Method::GET,
        "/api/v1/policies/schema",
        None,
        Some(&cookie),
        None,
    )
    .await;

    // The endpoint should exist and return the schema
    assert_eq!(status, StatusCode::OK, "schema endpoint: {:?}", body);
    // Schema should contain recognizable Cedar entity type names
    let schema_text = body["data"].as_str().unwrap_or("");
    assert!(
        schema_text.contains("Agent") || schema_text.contains("Credential"),
        "schema should contain known entity types, got: {}",
        &schema_text[..schema_text.len().min(200)]
    );
}

// HAPPY PATH: Root user can retrieve the Cedar schema
#[tokio::test]
async fn schema_endpoint_root_gets_schema_text() {
    let (app, store, _enc, _state) = setup_test_app().await;
    let _root =
        create_user_in_db(&*store, "root", TEST_PASSWORD, UserRole::Admin, true, true).await;
    let cookie = login_user(&app, "root", TEST_PASSWORD).await;

    let (status, body) = send_json(
        &app,
        Method::GET,
        "/api/v1/policies/schema",
        None,
        Some(&cookie),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "root schema access: {:?}", body);
}

// SAD PATH: Operator user gets 403 from schema endpoint
#[tokio::test]
async fn schema_endpoint_operator_gets_403() {
    let (app, store, _enc, _state) = setup_test_app().await;
    let _op = create_user_in_db(
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
        Method::GET,
        "/api/v1/policies/schema",
        None,
        Some(&cookie),
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "operator should be denied schema access"
    );
}

// SAD PATH: Viewer user gets 403 from schema endpoint
#[tokio::test]
async fn schema_endpoint_viewer_gets_403() {
    let (app, store, _enc, _state) = setup_test_app().await;
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

    let (status, _body) = send_json(
        &app,
        Method::GET,
        "/api/v1/policies/schema",
        None,
        Some(&cookie),
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "viewer should be denied schema access"
    );
}

// SAD PATH: Unauthenticated request gets 401 from schema endpoint
#[tokio::test]
async fn schema_endpoint_unauthenticated_gets_401() {
    let (app, _store, _enc, _state) = setup_test_app().await;

    let (status, _body) = send_json(
        &app,
        Method::GET,
        "/api/v1/policies/schema",
        None,
        None,
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "unauthenticated should get 401"
    );
}

// SAD PATH: Agent JWT gets 403 from schema endpoint (user-only endpoint)
#[tokio::test]
async fn schema_endpoint_agent_jwt_gets_403() {
    let (app, store, _enc, state) = setup_test_app().await;
    let _root =
        create_user_in_db(&*store, "root", TEST_PASSWORD, UserRole::Admin, true, true).await;
    let (agent, api_key) =
        create_agent_in_db(&*store, "agent-schema", vec!["admin"], true, None).await;
    let (jwt, dev_id, dev_key) = get_jwt_da(&state, &agent, &api_key).await;

    let (status, _body) = send_json_dual_auth(
        &app,
        Method::GET,
        "/api/v1/policies/schema",
        &dev_key,
        &dev_id,
        &jwt,
        None,
    )
    .await;
    // Agents should not be able to access schema management
    assert!(
        status == StatusCode::FORBIDDEN || status == StatusCode::UNAUTHORIZED,
        "agent should be denied schema access, got: {}",
        status
    );
}

// ===========================================================================
// 3. DISABLED PRINCIPAL FORBID POLICY
// ===========================================================================
// These tests verify Cedar forbid rules (Section 3 of default.cedar) that
// deny all actions for disabled agents and users, providing defense-in-depth
// beyond the auth extractor checks.
//
// STATUS: ENABLED — Cedar forbid rules exist in default.cedar and the
// policy engine builds entities with enabled attributes. Tests exercise
// both HTTP-level and direct policy engine evaluation.
// ===========================================================================

// HAPPY PATH: Enabled agent can access credentials (baseline)
#[tokio::test]
async fn disabled_forbid_enabled_agent_can_access() {
    // Verify that an enabled agent with proper permissions can access
    // a credential — baseline that forbid rules don't break normal access.
    let (app, store, _enc, state) = setup_test_app().await;
    let _root =
        create_user_in_db(&*store, "root", TEST_PASSWORD, UserRole::Admin, true, true).await;
    let (agent, api_key) =
        create_agent_in_db(&*store, "enabled-agent", vec!["admin"], true, None).await;
    let _cred = store_test_credential(&state, &agent, "test-cred", b"secret123").await;
    let (jwt, dev_id, dev_key) = get_jwt_da(&state, &agent, &api_key).await;

    let (status, _body) = send_json_dual_auth(
        &app,
        Method::GET,
        "/api/v1/credentials",
        &dev_key,
        &dev_id,
        &jwt,
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "enabled agent should access credentials"
    );
}

// HAPPY PATH: Enabled user can list credentials (baseline)
#[tokio::test]
async fn disabled_forbid_enabled_user_can_list() {
    // Verify that an enabled admin user can list credentials — baseline.
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
        "enabled user should list credentials"
    );
}

// SAD PATH: Disabled agent is denied by Cedar forbid policy
#[tokio::test]
async fn disabled_forbid_disabled_agent_denied_by_cedar() {
    // An agent with enabled=false should be denied ALL actions by the
    // Cedar forbid rule, even if they have admin tags.
    let (app, store, _enc, state) = setup_test_app().await;
    let _root =
        create_user_in_db(&*store, "root", TEST_PASSWORD, UserRole::Admin, true, true).await;
    // Create enabled agent, get JWT, then disable it
    let (agent, api_key) =
        create_agent_in_db(&*store, "will-disable", vec!["admin"], true, None).await;
    let (jwt, dev_id, dev_key) = get_jwt_da(&state, &agent, &api_key).await;

    // Disable the agent via admin API
    let cookie = login_user(&app, "root", TEST_PASSWORD).await;
    let (status, _) = send_json(
        &app,
        Method::PUT,
        &format!("/api/v1/workspaces/{}", agent.id.0),
        None,
        Some(&cookie),
        Some(json!({ "enabled": false })),
    )
    .await;
    assert!(
        status == StatusCode::OK || status == StatusCode::NO_CONTENT,
        "disable agent: {}",
        status
    );

    // Now try to use the JWT — should be denied
    let (status, _body) = send_json_dual_auth(
        &app,
        Method::GET,
        "/api/v1/credentials",
        &dev_key,
        &dev_id,
        &jwt,
        None,
    )
    .await;
    assert!(
        status == StatusCode::FORBIDDEN || status == StatusCode::UNAUTHORIZED,
        "disabled agent should be denied, got: {}",
        status
    );
}

// SAD PATH: Disabled agent is denied credential access specifically
#[tokio::test]
async fn disabled_forbid_disabled_agent_denied_credential_access() {
    // A disabled agent cannot access (decrypt) credentials even if they
    // are the owner with full permissions. The Cedar forbid overrides permits.
    let (app, store, _enc, state) = setup_test_app().await;
    let _root =
        create_user_in_db(&*store, "root", TEST_PASSWORD, UserRole::Admin, true, true).await;

    // Create agent with credential + permissions, get JWT
    let (agent, api_key) =
        create_agent_in_db(&*store, "owner-agent", vec!["admin"], true, None).await;
    let _cred = store_test_credential(&state, &agent, "owned-cred", b"my-secret").await;
    let (jwt, dev_id, dev_key) = get_jwt_da(&state, &agent, &api_key).await;

    // Verify access works while enabled
    let (status, _) = send_json_dual_auth(
        &app,
        Method::GET,
        "/api/v1/credentials",
        &dev_key,
        &dev_id,
        &jwt,
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "enabled owner should access credentials"
    );

    // Disable the agent
    let cookie = login_user(&app, "root", TEST_PASSWORD).await;
    let (status, _) = send_json(
        &app,
        Method::PUT,
        &format!("/api/v1/workspaces/{}", agent.id.0),
        None,
        Some(&cookie),
        Some(json!({ "enabled": false })),
    )
    .await;
    assert!(
        status == StatusCode::OK || status == StatusCode::NO_CONTENT,
        "disable agent: {}",
        status
    );

    // Attempt credential access — should be denied
    let (status, _body) = send_json_dual_auth(
        &app,
        Method::GET,
        "/api/v1/credentials",
        &dev_key,
        &dev_id,
        &jwt,
        None,
    )
    .await;
    assert!(
        status == StatusCode::FORBIDDEN || status == StatusCode::UNAUTHORIZED,
        "disabled agent owner should be denied credential access, got: {}",
        status
    );
}

// SAD PATH: Disabled user is denied by Cedar forbid policy (direct engine test)
#[tokio::test]
async fn disabled_forbid_disabled_user_denied_by_cedar() {
    // A user with enabled=false should be denied by Cedar forbid.
    // We test the policy engine directly since login is blocked for disabled users.
    let default_cedar = include_str!("../../../policies/default.cedar");
    let engine = CedarPolicyEngine::new(vec![("default".to_string(), default_cedar.to_string())])
        .expect("init policy engine");

    let disabled_admin = User {
        id: UserId(Uuid::new_v4()),
        username: "disabled-admin".to_string(),
        display_name: Some("Disabled Admin".to_string()),
        password_hash: "not-used".to_string(),
        role: UserRole::Admin,
        is_root: false,
        enabled: false,
        show_advanced: true,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };

    let decision = engine
        .evaluate(
            &PolicyPrincipal::User(&disabled_admin),
            "list",
            &PolicyResource::System,
            &PolicyContext {
                target_url: None,
                requested_scopes: vec![],
                ..Default::default()
            },
        )
        .expect("evaluate should not error");

    assert_eq!(
        decision.decision,
        PolicyDecisionResult::Forbid,
        "disabled user should be denied by Cedar forbid: reasons={:?}",
        decision.reasons
    );
}

// SAD PATH: Disabled admin user denied even with admin role (direct engine test)
#[tokio::test]
async fn disabled_forbid_disabled_admin_user_denied() {
    // Cedar's forbid(!principal.enabled) overrides the admin permit rule.
    // A disabled admin must be denied, proving forbid > permit in Cedar.
    let default_cedar = include_str!("../../../policies/default.cedar");
    let engine = CedarPolicyEngine::new(vec![("default".to_string(), default_cedar.to_string())])
        .expect("init policy engine");

    let disabled_admin = User {
        id: UserId(Uuid::new_v4()),
        username: "disabled-admin-2".to_string(),
        display_name: Some("Disabled Admin 2".to_string()),
        password_hash: "not-used".to_string(),
        role: UserRole::Admin,
        is_root: false,
        enabled: false,
        show_advanced: true,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };

    // Test multiple actions to prove ALL are denied.
    // Note: manage_policies requires PolicyAdmin resource, not System.
    let system_actions = &["list", "create", "delete", "manage_users", "view_audit"];
    for action in system_actions {
        let decision = engine
            .evaluate(
                &PolicyPrincipal::User(&disabled_admin),
                action,
                &PolicyResource::System,
                &PolicyContext {
                    target_url: None,
                    requested_scopes: vec![],
                    ..Default::default()
                },
            )
            .expect("evaluate should not error");

        assert_eq!(
            decision.decision,
            PolicyDecisionResult::Forbid,
            "disabled admin should be denied action '{}': reasons={:?}",
            action,
            decision.reasons
        );
    }

    // Also test manage_policies with the correct resource type
    let decision = engine
        .evaluate(
            &PolicyPrincipal::User(&disabled_admin),
            "manage_policies",
            &PolicyResource::PolicyAdmin,
            &PolicyContext {
                target_url: None,
                requested_scopes: vec![],
                ..Default::default()
            },
        )
        .expect("evaluate should not error");

    assert_eq!(
        decision.decision,
        PolicyDecisionResult::Forbid,
        "disabled admin should be denied manage_policies: reasons={:?}",
        decision.reasons
    );
}

// HAPPY PATH: Re-enabling an agent restores access
#[tokio::test]
async fn disabled_forbid_reenable_agent_restores_access() {
    // After disabling and re-enabling an agent, access should be restored.
    let (app, store, _enc, state) = setup_test_app().await;
    let _root =
        create_user_in_db(&*store, "root", TEST_PASSWORD, UserRole::Admin, true, true).await;
    let (agent, api_key) =
        create_agent_in_db(&*store, "toggle-agent", vec!["admin"], true, None).await;
    let (jwt, dev_id, dev_key) = get_jwt_da(&state, &agent, &api_key).await;
    let cookie = login_user(&app, "root", TEST_PASSWORD).await;

    // Verify initial access works
    let (status, _) = send_json_dual_auth(
        &app,
        Method::GET,
        "/api/v1/credentials",
        &dev_key,
        &dev_id,
        &jwt,
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "initially enabled agent should have access"
    );

    // Disable
    let (status, _) = send_json(
        &app,
        Method::PUT,
        &format!("/api/v1/workspaces/{}", agent.id.0),
        None,
        Some(&cookie),
        Some(json!({ "enabled": false })),
    )
    .await;
    assert!(status == StatusCode::OK || status == StatusCode::NO_CONTENT);

    // Verify denied
    let (status, _) = send_json_dual_auth(
        &app,
        Method::GET,
        "/api/v1/credentials",
        &dev_key,
        &dev_id,
        &jwt,
        None,
    )
    .await;
    assert!(
        status == StatusCode::FORBIDDEN || status == StatusCode::UNAUTHORIZED,
        "disabled agent should be denied, got: {}",
        status
    );

    // Re-enable
    let (status, _) = send_json(
        &app,
        Method::PUT,
        &format!("/api/v1/workspaces/{}", agent.id.0),
        None,
        Some(&cookie),
        Some(json!({ "enabled": true })),
    )
    .await;
    assert!(status == StatusCode::OK || status == StatusCode::NO_CONTENT);

    // Verify access restored
    let (status, _) = send_json_dual_auth(
        &app,
        Method::GET,
        "/api/v1/credentials",
        &dev_key,
        &dev_id,
        &jwt,
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "re-enabled agent should have access restored"
    );
}

// HAPPY PATH: Re-enabling a user restores access (direct engine test)
#[tokio::test]
async fn disabled_forbid_reenable_user_restores_access() {
    // After disabling and re-enabling a user, Cedar policy should allow again.
    let default_cedar = include_str!("../../../policies/default.cedar");
    let engine = CedarPolicyEngine::new(vec![("default".to_string(), default_cedar.to_string())])
        .expect("init policy engine");

    let user_id = UserId(Uuid::new_v4());

    // First, test with disabled user
    let disabled_user = User {
        id: user_id.clone(),
        username: "toggle-user".to_string(),
        display_name: Some("Toggle User".to_string()),
        password_hash: "not-used".to_string(),
        role: UserRole::Admin,
        is_root: false,
        enabled: false,
        show_advanced: true,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };

    let decision = engine
        .evaluate(
            &PolicyPrincipal::User(&disabled_user),
            "list",
            &PolicyResource::System,
            &PolicyContext {
                target_url: None,
                requested_scopes: vec![],
                ..Default::default()
            },
        )
        .expect("evaluate");

    assert_eq!(
        decision.decision,
        PolicyDecisionResult::Forbid,
        "disabled user denied"
    );

    // Now test with re-enabled user
    let enabled_user = User {
        id: user_id,
        username: "toggle-user".to_string(),
        display_name: Some("Toggle User".to_string()),
        password_hash: "not-used".to_string(),
        role: UserRole::Admin,
        is_root: false,
        enabled: true,
        show_advanced: true,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };

    let decision = engine
        .evaluate(
            &PolicyPrincipal::User(&enabled_user),
            "list",
            &PolicyResource::System,
            &PolicyContext {
                target_url: None,
                requested_scopes: vec![],
                ..Default::default()
            },
        )
        .expect("evaluate");

    assert_eq!(
        decision.decision,
        PolicyDecisionResult::Permit,
        "re-enabled admin user should be allowed"
    );
}

// ===========================================================================
// 3b. DISABLED PRINCIPAL — EDGE CASE TESTS (added in Phase 3)
// ===========================================================================

// EDGE CASE: Disabled agent with admin tag denied (forbid beats permit)
#[tokio::test]
async fn disabled_forbid_disabled_admin_agent_denied_by_cedar() {
    // Even an agent with "admin" tag is denied when disabled.
    // This proves Cedar forbid overrides the broad admin permit.
    let default_cedar = include_str!("../../../policies/default.cedar");
    let engine = CedarPolicyEngine::new(vec![("default".to_string(), default_cedar.to_string())])
        .expect("init policy engine");

    let disabled_admin_agent = Workspace {
        id: WorkspaceId(Uuid::new_v4()),
        name: "disabled-admin-agent".to_string(),
        enabled: false,
        status: WorkspaceStatus::Active,
        pk_hash: None,
        encryption_public_key: None,
        tags: vec!["admin".to_string()],
        owner_id: None,
        parent_id: None,
        tool_name: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };

    let decision = engine
        .evaluate(
            &PolicyPrincipal::Workspace(&disabled_admin_agent),
            "list",
            &PolicyResource::System,
            &PolicyContext {
                target_url: None,
                requested_scopes: vec![],
                ..Default::default()
            },
        )
        .expect("evaluate");

    assert_eq!(
        decision.decision,
        PolicyDecisionResult::Forbid,
        "disabled admin agent should be denied by Cedar forbid"
    );
}

// EDGE CASE: Disabled viewer user also denied (not just admins)
#[tokio::test]
async fn disabled_forbid_disabled_viewer_user_denied() {
    let default_cedar = include_str!("../../../policies/default.cedar");
    let engine = CedarPolicyEngine::new(vec![("default".to_string(), default_cedar.to_string())])
        .expect("init policy engine");

    let disabled_viewer = User {
        id: UserId(Uuid::new_v4()),
        username: "disabled-viewer".to_string(),
        display_name: None,
        password_hash: "not-used".to_string(),
        role: UserRole::Viewer,
        is_root: false,
        enabled: false,
        show_advanced: true,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };

    let decision = engine
        .evaluate(
            &PolicyPrincipal::User(&disabled_viewer),
            "list",
            &PolicyResource::System,
            &PolicyContext {
                target_url: None,
                requested_scopes: vec![],
                ..Default::default()
            },
        )
        .expect("evaluate");

    assert_eq!(
        decision.decision,
        PolicyDecisionResult::Forbid,
        "disabled viewer should be denied"
    );
}

// EDGE CASE: Enabled agent without admin tag denied for manage_policies (defense-in-depth 3c)
#[tokio::test]
async fn disabled_forbid_non_admin_agent_denied_manage_policies() {
    // Section 3c of default.cedar: agents without "admin" tag cannot manage_policies.
    let default_cedar = include_str!("../../../policies/default.cedar");
    let engine = CedarPolicyEngine::new(vec![("default".to_string(), default_cedar.to_string())])
        .expect("init policy engine");

    let non_admin_agent = Workspace {
        id: WorkspaceId(Uuid::new_v4()),
        name: "non-admin-agent".to_string(),
        enabled: true,
        status: WorkspaceStatus::Active,
        pk_hash: None,
        encryption_public_key: None,
        tags: vec!["ci".to_string(), "deploy".to_string()],
        owner_id: None,
        parent_id: None,
        tool_name: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };

    let decision = engine
        .evaluate(
            &PolicyPrincipal::Workspace(&non_admin_agent),
            "manage_policies",
            &PolicyResource::PolicyAdmin,
            &PolicyContext {
                target_url: None,
                requested_scopes: vec![],
                ..Default::default()
            },
        )
        .expect("evaluate");

    assert_eq!(
        decision.decision,
        PolicyDecisionResult::Forbid,
        "non-admin agent should be forbidden from managing policies"
    );
}

// ===========================================================================
// 4. TIME-BASED POLICY CONDITIONS
// ===========================================================================

// SAD PATH: Timestamp field does not break existing policies — ENABLED
#[tokio::test]
async fn time_policy_timestamp_additive_does_not_break_existing() {
    // Adding timestamp to the context must not break any existing
    // policy evaluations. This test verifies existing policies work.
    let (app, store, _enc, _state) = setup_test_app().await;
    let _root =
        create_user_in_db(&*store, "root", TEST_PASSWORD, UserRole::Admin, true, true).await;
    let _admin = create_user_in_db(
        &*store,
        "admin",
        TEST_PASSWORD,
        UserRole::Admin,
        false,
        true,
    )
    .await;

    // Admin user should still be able to list credentials
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
        "timestamp addition should not break existing policy evaluation"
    );
}
