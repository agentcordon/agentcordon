//! Integration tests for S-006 + S-007: Cedar policy-based route authorization.
//!
//! These tests verify that routes previously using hardcoded role checks
//! now correctly delegate to the Cedar policy engine for authorization.
//!
//! Key behaviors tested:
//! - Admin users can access audit, user-management, policy, and agent routes
//! - Operator users can access audit routes (Cedar grants view_audit to operators)
//! - Viewer users can access audit routes (Cedar grants view_audit to viewers)
//! - Non-admin users are denied user management (Cedar denies manage_users)
//! - Non-admin users are denied policy management (Cedar denies manage_policies)
//! - Root users bypass Cedar entirely (root_bypass)
//! - Operator users can manage agents (Cedar grants these)
//! - Viewer users are denied agent management

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
    role: UserRole,
    is_root: bool,
) -> User {
    let password_hash = hash_password(TEST_PASSWORD).expect("hash password");
    let now = chrono::Utc::now();
    let user = User {
        id: UserId(Uuid::new_v4()),
        username: username.to_string(),
        display_name: Some(format!("Test {}", username)),
        password_hash,
        role,
        is_root,
        enabled: true,
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
    owner_id: Option<UserId>,
) -> (Workspace, String) {
    let now = chrono::Utc::now();
    let workspace = Workspace {
        id: WorkspaceId(Uuid::new_v4()),
        name: name.to_string(),
        enabled: true,
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

async fn login_user(app: &Router, username: &str) -> String {
    let (status, _body, headers) = send_json_with_headers(
        app,
        Method::POST,
        "/api/v1/auth/login",
        None,
        None,
        Some(json!({ "username": username, "password": TEST_PASSWORD })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "login failed for '{}': {:?}",
        username,
        _body
    );

    // Extract all Set-Cookie headers and combine cookie name=value pairs
    let mut cookie_parts = Vec::new();
    for (name, value) in &headers {
        if name == "set-cookie" {
            if let Some(nv) = value.split(';').next() {
                cookie_parts.push(nv.trim().to_string());
            }
        }
    }
    cookie_parts.join("; ")
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
    let (status, json, _) = send_json_with_headers(app, method, uri, bearer, cookie, body).await;
    (status, json)
}

// ===========================================================================
// S-006: Audit route uses Cedar view_audit policy
// ===========================================================================

#[tokio::test]
async fn test_audit_admin_user_can_view_audit() {
    let (app, store, _state) = setup_test_app().await;
    let _admin = create_user_in_db(&*store, "admin", UserRole::Admin, false).await;
    let cookie = login_user(&app, "admin").await;

    let (status, body) = send_json(
        &app,
        Method::GET,
        "/api/v1/audit",
        None,
        Some(&cookie),
        None,
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "admin should access audit: {}",
        body
    );
    assert!(body["data"].is_array(), "audit data should be an array");
}

#[tokio::test]
async fn test_audit_operator_can_view_audit_via_cedar() {
    let (app, store, _state) = setup_test_app().await;
    let _operator = create_user_in_db(&*store, "operator", UserRole::Operator, false).await;
    let cookie = login_user(&app, "operator").await;

    let (status, body) = send_json(
        &app,
        Method::GET,
        "/api/v1/audit",
        None,
        Some(&cookie),
        None,
    )
    .await;

    // Cedar policy grants view_audit to operators (rule 2f)
    assert_eq!(
        status,
        StatusCode::OK,
        "operator should access audit via Cedar: {}",
        body
    );
    assert!(body["data"].is_array(), "audit data should be an array");
}

#[tokio::test]
async fn test_audit_viewer_can_view_audit_via_cedar() {
    let (app, store, _state) = setup_test_app().await;
    let _viewer = create_user_in_db(&*store, "viewer", UserRole::Viewer, false).await;
    let cookie = login_user(&app, "viewer").await;

    let (status, body) = send_json(
        &app,
        Method::GET,
        "/api/v1/audit",
        None,
        Some(&cookie),
        None,
    )
    .await;

    // Cedar policy grants view_audit to viewers (rule 2h)
    assert_eq!(
        status,
        StatusCode::OK,
        "viewer should access audit via Cedar: {}",
        body
    );
    assert!(body["data"].is_array(), "audit data should be an array");
}

#[tokio::test]
async fn test_audit_root_user_can_view_audit() {
    let (app, store, _state) = setup_test_app().await;
    let _root = create_user_in_db(&*store, "root", UserRole::Admin, true).await;
    let cookie = login_user(&app, "root").await;

    let (status, body) = send_json(
        &app,
        Method::GET,
        "/api/v1/audit",
        None,
        Some(&cookie),
        None,
    )
    .await;

    // Root users bypass Cedar entirely
    assert_eq!(status, StatusCode::OK, "root should access audit: {}", body);
}

#[tokio::test]
async fn test_audit_admin_agent_can_view_audit() {
    let (_app, store, state) = setup_test_app().await;
    let (agent, api_key) = create_agent_in_db(&*store, "admin-agent", vec!["admin"], None).await;

    let (device_id, dev_key) = create_device_and_bind_agent(&state, &agent).await;
    let jwt = get_jwt_via_device(&state, &dev_key, &device_id, &api_key).await;
    let app2 = agent_cordon_server::build_router(state.clone());
    let (status, body) = send_json_dual_auth(
        &app2,
        Method::GET,
        "/api/v1/audit",
        &dev_key,
        &device_id,
        &jwt,
        None,
    )
    .await;

    // Admin agents have full access via Cedar (rule 1a)
    assert_eq!(
        status,
        StatusCode::OK,
        "admin agent should access audit: {}",
        body
    );
}

#[tokio::test]
async fn test_audit_non_admin_agent_denied() {
    let (_app, store, state) = setup_test_app().await;
    let (agent, api_key) = create_agent_in_db(&*store, "viewer-agent", vec!["viewer"], None).await;

    let (device_id, dev_key) = create_device_and_bind_agent(&state, &agent).await;
    let jwt = get_jwt_via_device(&state, &dev_key, &device_id, &api_key).await;
    let app2 = agent_cordon_server::build_router(state.clone());
    let (status, _body) = send_json_dual_auth(
        &app2,
        Method::GET,
        "/api/v1/audit",
        &dev_key,
        &device_id,
        &jwt,
        None,
    )
    .await;

    // Non-admin agents have no view_audit policy
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "non-admin agent should be denied audit access"
    );
}

// ===========================================================================
// S-007: User management routes use Cedar manage_users policy
// ===========================================================================

#[tokio::test]
async fn test_users_list_admin_allowed() {
    let (app, store, _state) = setup_test_app().await;
    let _admin = create_user_in_db(&*store, "admin", UserRole::Admin, false).await;
    let cookie = login_user(&app, "admin").await;

    let (status, body) = send_json(
        &app,
        Method::GET,
        "/api/v1/users",
        None,
        Some(&cookie),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::OK, "admin should list users: {}", body);
}

#[tokio::test]
async fn test_users_list_operator_denied() {
    let (app, store, _state) = setup_test_app().await;
    let _operator = create_user_in_db(&*store, "operator", UserRole::Operator, false).await;
    let cookie = login_user(&app, "operator").await;

    let (status, _body) = send_json(
        &app,
        Method::GET,
        "/api/v1/users",
        None,
        Some(&cookie),
        None,
    )
    .await;

    // Cedar denies manage_users for operators (no policy grants it)
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "operator should be denied user management"
    );
}

#[tokio::test]
async fn test_users_list_viewer_denied() {
    let (app, store, _state) = setup_test_app().await;
    let _viewer = create_user_in_db(&*store, "viewer", UserRole::Viewer, false).await;
    let cookie = login_user(&app, "viewer").await;

    let (status, _body) = send_json(
        &app,
        Method::GET,
        "/api/v1/users",
        None,
        Some(&cookie),
        None,
    )
    .await;

    // Cedar denies manage_users for viewers
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "viewer should be denied user management"
    );
}

#[tokio::test]
async fn test_users_create_admin_allowed() {
    let (app, store, _state) = setup_test_app().await;
    let _admin = create_user_in_db(&*store, "admin", UserRole::Admin, false).await;
    let cookie = login_user(&app, "admin").await;

    let (status, body) = send_json(
        &app,
        Method::POST,
        "/api/v1/users",
        None,
        Some(&cookie),
        Some(json!({
            "username": "newuser",
            "password": "strong-password-123!",
            "role": "viewer"
        })),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "admin should create users: {}",
        body
    );
}

#[tokio::test]
async fn test_users_create_operator_denied() {
    let (app, store, _state) = setup_test_app().await;
    let _operator = create_user_in_db(&*store, "operator", UserRole::Operator, false).await;
    let cookie = login_user(&app, "operator").await;

    let (status, _body) = send_json(
        &app,
        Method::POST,
        "/api/v1/users",
        None,
        Some(&cookie),
        Some(json!({
            "username": "newuser",
            "password": "strong-password-123!",
        })),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "operator should be denied user creation"
    );
}

#[tokio::test]
async fn test_users_root_can_manage_users() {
    let (app, store, _state) = setup_test_app().await;
    let _root = create_user_in_db(&*store, "root", UserRole::Admin, true).await;
    let cookie = login_user(&app, "root").await;

    let (status, body) = send_json(
        &app,
        Method::GET,
        "/api/v1/users",
        None,
        Some(&cookie),
        None,
    )
    .await;

    // Root bypasses Cedar
    assert_eq!(status, StatusCode::OK, "root should manage users: {}", body);
}

#[tokio::test]
async fn test_users_get_self_allowed_for_all_roles() {
    let (app, store, _state) = setup_test_app().await;
    let viewer = create_user_in_db(&*store, "viewer", UserRole::Viewer, false).await;
    let cookie = login_user(&app, "viewer").await;

    let uri = format!("/api/v1/users/{}", viewer.id.0);
    let (status, body) = send_json(&app, Method::GET, &uri, None, Some(&cookie), None).await;

    // Self-view is always allowed regardless of Cedar policy
    assert_eq!(
        status,
        StatusCode::OK,
        "viewer should view own profile: {}",
        body
    );
    assert_eq!(body["data"]["username"], "viewer");
}

#[tokio::test]
async fn test_users_get_other_denied_for_viewer() {
    let (app, store, _state) = setup_test_app().await;
    let _viewer = create_user_in_db(&*store, "viewer", UserRole::Viewer, false).await;
    let other = create_user_in_db(&*store, "other", UserRole::Viewer, false).await;
    let cookie = login_user(&app, "viewer").await;

    let uri = format!("/api/v1/users/{}", other.id.0);
    let (status, _body) = send_json(&app, Method::GET, &uri, None, Some(&cookie), None).await;

    // Viewing another user's profile requires manage_users
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "viewer should not view other's profile"
    );
}

// ===========================================================================
// S-007: Policy management routes use Cedar manage_policies
// ===========================================================================

#[tokio::test]
async fn test_policies_list_admin_allowed() {
    let (app, store, _state) = setup_test_app().await;
    let _admin = create_user_in_db(&*store, "admin", UserRole::Admin, false).await;
    let cookie = login_user(&app, "admin").await;

    let (status, body) = send_json(
        &app,
        Method::GET,
        "/api/v1/policies",
        None,
        Some(&cookie),
        None,
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "admin should list policies: {}",
        body
    );
}

#[tokio::test]
async fn test_policies_list_operator_denied() {
    let (app, store, _state) = setup_test_app().await;
    let _operator = create_user_in_db(&*store, "operator", UserRole::Operator, false).await;
    let cookie = login_user(&app, "operator").await;

    let (status, _body) = send_json(
        &app,
        Method::GET,
        "/api/v1/policies",
        None,
        Some(&cookie),
        None,
    )
    .await;

    // Cedar denies manage_policies for operators
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "operator should be denied policy management"
    );
}

#[tokio::test]
async fn test_policies_list_viewer_denied() {
    let (app, store, _state) = setup_test_app().await;
    let _viewer = create_user_in_db(&*store, "viewer", UserRole::Viewer, false).await;
    let cookie = login_user(&app, "viewer").await;

    let (status, _body) = send_json(
        &app,
        Method::GET,
        "/api/v1/policies",
        None,
        Some(&cookie),
        None,
    )
    .await;

    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "viewer should be denied policy management"
    );
}

#[tokio::test]
async fn test_policies_root_can_manage() {
    let (app, store, _state) = setup_test_app().await;
    let _root = create_user_in_db(&*store, "root", UserRole::Admin, true).await;
    let cookie = login_user(&app, "root").await;

    let (status, body) = send_json(
        &app,
        Method::GET,
        "/api/v1/policies",
        None,
        Some(&cookie),
        None,
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "root should manage policies: {}",
        body
    );
}

// ===========================================================================
// S-007: Agent management routes use Cedar manage_agents
// ===========================================================================

#[tokio::test]
async fn test_agents_list_admin_allowed() {
    let (app, store, _state) = setup_test_app().await;
    let _admin = create_user_in_db(&*store, "admin", UserRole::Admin, false).await;
    let cookie = login_user(&app, "admin").await;

    let (status, body) = send_json(
        &app,
        Method::GET,
        "/api/v1/workspaces",
        None,
        Some(&cookie),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::OK, "admin should list agents: {}", body);
}

#[tokio::test]
async fn test_agents_list_operator_allowed_via_cedar() {
    let (app, store, _state) = setup_test_app().await;
    let _operator = create_user_in_db(&*store, "operator", UserRole::Operator, false).await;
    let cookie = login_user(&app, "operator").await;

    let (status, body) = send_json(
        &app,
        Method::GET,
        "/api/v1/workspaces",
        None,
        Some(&cookie),
        None,
    )
    .await;

    // Cedar grants manage_agents to operators (rule 2d)
    assert_eq!(
        status,
        StatusCode::OK,
        "operator should list agents via Cedar: {}",
        body
    );
}

#[tokio::test]
async fn test_agents_list_viewer_denied() {
    let (app, store, _state) = setup_test_app().await;
    let _viewer = create_user_in_db(&*store, "viewer", UserRole::Viewer, false).await;
    let cookie = login_user(&app, "viewer").await;

    let (status, _body) = send_json(
        &app,
        Method::GET,
        "/api/v1/workspaces",
        None,
        Some(&cookie),
        None,
    )
    .await;

    // Cedar denies manage_agents for viewers
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "viewer should be denied agent management"
    );
}

#[tokio::test]
async fn test_agents_update_operator_allowed() {
    let (app, store, _state) = setup_test_app().await;
    let operator = create_user_in_db(&*store, "operator", UserRole::Operator, false).await;
    let (agent, _key) = create_agent_in_db(
        &*store,
        "my-agent",
        vec!["viewer"],
        Some(operator.id.clone()),
    )
    .await;
    let cookie = login_user(&app, "operator").await;

    let uri = format!("/api/v1/workspaces/{}", agent.id.0);
    let (status, body) = send_json(
        &app,
        Method::PUT,
        &uri,
        None,
        Some(&cookie),
        Some(json!({ "name": "renamed-agent" })),
    )
    .await;

    // Cedar grants manage_agents to operators
    assert_eq!(
        status,
        StatusCode::OK,
        "operator should update agents via Cedar: {}",
        body
    );
    assert_eq!(body["data"]["name"], "renamed-agent");
}

#[tokio::test]
async fn test_agents_delete_viewer_denied() {
    let (app, store, _state) = setup_test_app().await;
    let _viewer = create_user_in_db(&*store, "viewer", UserRole::Viewer, false).await;
    let (agent, _key) = create_agent_in_db(&*store, "target-agent", vec!["viewer"], None).await;
    let cookie = login_user(&app, "viewer").await;

    let uri = format!("/api/v1/workspaces/{}", agent.id.0);
    let (status, _body) = send_json(&app, Method::DELETE, &uri, None, Some(&cookie), None).await;

    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "viewer should be denied agent deletion"
    );
}

// ===========================================================================
// S-005: Cedar policy schema validation on upload
// ===========================================================================

#[tokio::test]
async fn test_create_policy_valid_syntax_and_schema_accepted() {
    let (app, store, _state) = setup_test_app().await;
    let _admin = create_user_in_db(&*store, "admin", UserRole::Admin, false).await;
    let cookie = login_user(&app, "admin").await;

    // A valid policy that conforms to the schema
    let valid_cedar = r#"permit(
        principal is AgentCordon::Workspace,
        action == AgentCordon::Action::"access",
        resource is AgentCordon::Credential
    ) when {
        principal.tags.contains("custom-role")
    };"#;

    let (status, body) = send_json(
        &app,
        Method::POST,
        "/api/v1/policies",
        None,
        Some(&cookie),
        Some(json!({
            "name": "valid-test-policy",
            "description": "A valid test policy",
            "cedar_policy": valid_cedar
        })),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "valid policy should be accepted: {}",
        body
    );
    assert_eq!(body["data"]["name"], "valid-test-policy");
}

#[tokio::test]
async fn test_create_policy_syntax_error_rejected_400() {
    let (app, store, _state) = setup_test_app().await;
    let _admin = create_user_in_db(&*store, "admin", UserRole::Admin, false).await;
    let cookie = login_user(&app, "admin").await;

    // Syntactically invalid Cedar
    let bad_syntax = "permit( this is not valid cedar ;";

    let (status, body) = send_json(
        &app,
        Method::POST,
        "/api/v1/policies",
        None,
        Some(&cookie),
        Some(json!({
            "name": "bad-syntax-policy",
            "cedar_policy": bad_syntax
        })),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "syntactically invalid policy should be rejected: {}",
        body
    );
    let code = body["error"]["code"].as_str().unwrap_or("");
    assert!(
        code == "VALIDATION_FAILED" || code == "bad_request",
        "error code should indicate validation failure, got: {}",
        code
    );
}

#[tokio::test]
async fn test_create_policy_schema_violation_unknown_action_returns_400() {
    let (app, store, _state) = setup_test_app().await;
    let _admin = create_user_in_db(&*store, "admin", UserRole::Admin, false).await;
    let cookie = login_user(&app, "admin").await;

    // Syntactically valid but references an action not in the schema
    let bad_action = r#"permit(
        principal is AgentCordon::Workspace,
        action == AgentCordon::Action::"nonexistent_action",
        resource is AgentCordon::Credential
    );"#;

    let (status, body) = send_json(
        &app,
        Method::POST,
        "/api/v1/policies",
        None,
        Some(&cookie),
        Some(json!({
            "name": "bad-action-policy",
            "cedar_policy": bad_action
        })),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "schema-violating policy should be rejected: {}",
        body
    );
    let msg = body["error"]["message"].as_str().unwrap_or("");
    assert!(
        msg.contains("validation"),
        "error message should mention validation, got: {}",
        msg
    );
}

#[tokio::test]
async fn test_create_policy_schema_violation_unknown_entity_type_returns_400() {
    let (app, store, _state) = setup_test_app().await;
    let _admin = create_user_in_db(&*store, "admin", UserRole::Admin, false).await;
    let cookie = login_user(&app, "admin").await;

    // Syntactically valid but references an entity type not in the schema
    let bad_entity = r#"permit(
        principal is AgentCordon::FakeEntity,
        action == AgentCordon::Action::"access",
        resource is AgentCordon::Credential
    );"#;

    let (status, body) = send_json(
        &app,
        Method::POST,
        "/api/v1/policies",
        None,
        Some(&cookie),
        Some(json!({
            "name": "bad-entity-policy",
            "cedar_policy": bad_entity
        })),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "policy with unknown entity type should be rejected: {}",
        body
    );
    let msg = body["error"]["message"].as_str().unwrap_or("");
    assert!(
        msg.contains("validation"),
        "error message should mention validation, got: {}",
        msg
    );
}

#[tokio::test]
async fn test_update_policy_cedar_text_with_schema_violation_returns_400() {
    let (app, store, _state) = setup_test_app().await;
    let _admin = create_user_in_db(&*store, "admin", UserRole::Admin, false).await;
    let cookie = login_user(&app, "admin").await;

    // Create a valid policy directly in the DB so the policy engine is not
    // reloaded (which would remove admin permissions from the default set).
    let now = chrono::Utc::now();
    let policy_id = Uuid::new_v4();
    let policy = agent_cordon_core::domain::policy::StoredPolicy {
        id: agent_cordon_core::domain::policy::PolicyId(policy_id),
        name: "test-policy".to_string(),
        description: None,
        cedar_policy: r#"permit(
            principal is AgentCordon::Workspace,
            action == AgentCordon::Action::"access",
            resource is AgentCordon::Credential
        ) when { principal.tags.contains("test") };"#
            .to_string(),
        enabled: true,
        is_system: false,
        created_at: now,
        updated_at: now,
    };
    store.store_policy(&policy).await.expect("store policy");

    // Now try to update with a schema-violating policy
    let bad_cedar = r#"permit(
        principal is AgentCordon::Workspace,
        action == AgentCordon::Action::"totally_fake_action",
        resource is AgentCordon::Credential
    );"#;

    let update_uri = format!("/api/v1/policies/{}", policy_id);
    let (status, body) = send_json(
        &app,
        Method::PUT,
        &update_uri,
        None,
        Some(&cookie),
        Some(json!({
            "cedar_policy": bad_cedar
        })),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "updating with schema-violating policy should fail: {}",
        body
    );
    let msg = body["error"]["message"].as_str().unwrap_or("");
    assert!(
        msg.contains("validation"),
        "error message should mention validation, got: {}",
        msg
    );
}

#[tokio::test]
async fn test_update_policy_cedar_text_with_valid_schema_accepted() {
    let (app, store, _state) = setup_test_app().await;
    let _admin = create_user_in_db(&*store, "admin", UserRole::Admin, false).await;
    let cookie = login_user(&app, "admin").await;

    // Create a valid policy directly in the DB
    let now = chrono::Utc::now();
    let policy_id = Uuid::new_v4();
    let policy = agent_cordon_core::domain::policy::StoredPolicy {
        id: agent_cordon_core::domain::policy::PolicyId(policy_id),
        name: "test-update-policy".to_string(),
        description: None,
        cedar_policy: r#"permit(
            principal is AgentCordon::Workspace,
            action == AgentCordon::Action::"access",
            resource is AgentCordon::Credential
        ) when { principal.tags.contains("test") };"#
            .to_string(),
        enabled: true,
        is_system: false,
        created_at: now,
        updated_at: now,
    };
    store.store_policy(&policy).await.expect("store policy");

    // Update with a different but still valid policy
    let new_valid_cedar = r#"permit(
        principal is AgentCordon::User,
        action == AgentCordon::Action::"view_audit",
        resource is AgentCordon::System
    ) when {
        principal.role == "operator"
    };"#;

    let update_uri = format!("/api/v1/policies/{}", policy_id);
    let (status, body) = send_json(
        &app,
        Method::PUT,
        &update_uri,
        None,
        Some(&cookie),
        Some(json!({
            "cedar_policy": new_valid_cedar
        })),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "updating with valid policy should succeed: {}",
        body
    );
}
