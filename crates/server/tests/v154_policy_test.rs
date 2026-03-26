//! Integration tests for Feature 7: POST /api/v1/policies/test endpoint.
//!
//! Tests the server-side Cedar policy evaluation endpoint that accepts
//! principal/action/resource/context and returns permit/deny with diagnostics.

use crate::common::*;

use axum::http::{Method, StatusCode};
use serde_json::json;

use agent_cordon_core::domain::user::UserRole;
use agent_cordon_server::test_helpers::TestAppBuilder;

// ===========================================================================
// 7A. Endpoint Basics
// ===========================================================================

#[tokio::test]
async fn test_policy_test_endpoint_exists() {
    let ctx = TestAppBuilder::new().build().await;
    let _admin = create_test_user(&*ctx.store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let (cookie, csrf) = login_user(&ctx.app, "admin", TEST_PASSWORD).await;
    let full_cookie = combined_cookie(&cookie, &csrf);

    let (status, body) = send_json(
        &ctx.app,
        Method::POST,
        "/api/v1/policies/test",
        None,
        Some(&full_cookie),
        Some(&csrf),
        Some(json!({
            "principal": { "type": "Agent", "id": "test-agent", "attributes": { "tags": ["admin"], "enabled": true } },
            "action": "access",
            "resource": { "type": "System" },
        })),
    )
    .await;
    // Non-404 — endpoint exists
    assert_ne!(
        status,
        StatusCode::NOT_FOUND,
        "policy test endpoint must exist: {}",
        body
    );
}

#[tokio::test]
async fn test_policy_test_requires_authentication() {
    let ctx = TestAppBuilder::new().build().await;

    let (status, _body) = send_json(
        &ctx.app,
        Method::POST,
        "/api/v1/policies/test",
        None,
        None,
        None,
        Some(json!({
            "principal": { "type": "Agent", "id": "test", "attributes": { "tags": [], "enabled": true } },
            "action": "access",
            "resource": { "type": "System" },
        })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "unauthenticated should be 401"
    );
}

#[tokio::test]
async fn test_policy_test_requires_manage_policies_permission() {
    let ctx = TestAppBuilder::new().build().await;
    let _operator =
        create_test_user(&*ctx.store, "operator", TEST_PASSWORD, UserRole::Operator).await;
    let (cookie, csrf) = login_user(&ctx.app, "operator", TEST_PASSWORD).await;
    let full_cookie = combined_cookie(&cookie, &csrf);

    let (status, _body) = send_json(
        &ctx.app,
        Method::POST,
        "/api/v1/policies/test",
        None,
        Some(&full_cookie),
        Some(&csrf),
        Some(json!({
            "principal": { "type": "Agent", "id": "test", "attributes": { "tags": [], "enabled": true } },
            "action": "access",
            "resource": { "type": "System" },
        })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "operator should be denied manage_policies"
    );
}

#[tokio::test]
async fn test_policy_test_viewer_denied() {
    let ctx = TestAppBuilder::new().build().await;
    let _viewer = create_test_user(&*ctx.store, "viewer", TEST_PASSWORD, UserRole::Viewer).await;
    let (cookie, csrf) = login_user(&ctx.app, "viewer", TEST_PASSWORD).await;
    let full_cookie = combined_cookie(&cookie, &csrf);

    let (status, _body) = send_json(
        &ctx.app,
        Method::POST,
        "/api/v1/policies/test",
        None,
        Some(&full_cookie),
        Some(&csrf),
        Some(json!({
            "principal": { "type": "Agent", "id": "test", "attributes": { "tags": [], "enabled": true } },
            "action": "access",
            "resource": { "type": "System" },
        })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "viewer should be denied");
}

#[tokio::test]
async fn test_policy_test_root_user_can_access() {
    let ctx = TestAppBuilder::new().build().await;
    let _root = create_user_in_db(
        &*ctx.store,
        "root",
        TEST_PASSWORD,
        UserRole::Admin,
        true,
        true,
    )
    .await;
    let (cookie, csrf) = login_user(&ctx.app, "root", TEST_PASSWORD).await;
    let full_cookie = combined_cookie(&cookie, &csrf);

    let (status, body) = send_json(
        &ctx.app,
        Method::POST,
        "/api/v1/policies/test",
        None,
        Some(&full_cookie),
        Some(&csrf),
        Some(json!({
            "principal": { "type": "Agent", "id": "test", "attributes": { "name": "test", "tags": ["admin"], "enabled": true } },
            "action": "list",
            "resource": { "type": "Credential", "id": "test-cred", "attributes": { "name": "c", "service": "s", "scopes": [], "owner": "u1", "tags": [] } },
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "root user should access: {}", body);
    assert!(body["data"]["decision"].is_string(), "must return decision");
}

// ===========================================================================
// 7B. Evaluation Results
// ===========================================================================

#[tokio::test]
async fn test_policy_test_returns_permit_for_admin_agent() {
    let ctx = TestAppBuilder::new().build().await;
    let _admin = create_test_user(&*ctx.store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let (cookie, csrf) = login_user(&ctx.app, "admin", TEST_PASSWORD).await;
    let full_cookie = combined_cookie(&cookie, &csrf);

    let (status, body) = send_json(
        &ctx.app,
        Method::POST,
        "/api/v1/policies/test",
        None,
        Some(&full_cookie),
        Some(&csrf),
        Some(json!({
            "principal": { "type": "Agent", "id": "admin-agent", "attributes": { "tags": ["admin"], "enabled": true } },
            "action": "access",
            "resource": { "type": "Credential", "id": "test-cred", "attributes": { "name": "test", "service": "svc", "scopes": [], "owner": "user1", "readers": [], "writers": [], "deleters": [], "delegated_users": [], "tags": [] } },
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "response: {}", body);
    assert_eq!(
        body["data"]["decision"], "permit",
        "admin agent should be permitted"
    );
}

#[tokio::test]
async fn test_policy_test_returns_deny_for_unauthorized_agent() {
    let ctx = TestAppBuilder::new().build().await;
    let _admin = create_test_user(&*ctx.store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let (cookie, csrf) = login_user(&ctx.app, "admin", TEST_PASSWORD).await;
    let full_cookie = combined_cookie(&cookie, &csrf);

    let (status, body) = send_json(
        &ctx.app,
        Method::POST,
        "/api/v1/policies/test",
        None,
        Some(&full_cookie),
        Some(&csrf),
        Some(json!({
            "principal": { "type": "Agent", "id": "no-perm-agent", "attributes": { "tags": [], "enabled": true } },
            "action": "access",
            "resource": { "type": "Credential", "id": "test-cred", "attributes": { "name": "test", "service": "svc", "scopes": [], "owner": "other-user", "readers": [], "writers": [], "deleters": [], "delegated_users": [], "tags": [] } },
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "response: {}", body);
    // Without blanket policy 5c, an agent without explicit grants is denied access.
    assert_eq!(
        body["data"]["decision"], "deny",
        "agent without grants should be denied credential access"
    );
}

#[tokio::test]
async fn test_policy_test_returns_deny_for_disabled_agent() {
    let ctx = TestAppBuilder::new().build().await;
    let _admin = create_test_user(&*ctx.store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let (cookie, csrf) = login_user(&ctx.app, "admin", TEST_PASSWORD).await;
    let full_cookie = combined_cookie(&cookie, &csrf);

    let (status, body) = send_json(
        &ctx.app,
        Method::POST,
        "/api/v1/policies/test",
        None,
        Some(&full_cookie),
        Some(&csrf),
        Some(json!({
            "principal": { "type": "Agent", "id": "disabled-agent", "attributes": { "tags": ["admin"], "enabled": false } },
            "action": "access",
            "resource": { "type": "Credential", "id": "test-cred", "attributes": { "name": "test", "service": "svc", "scopes": [], "owner": "user1", "readers": [], "writers": [], "deleters": [], "delegated_users": [], "tags": [] } },
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "response: {}", body);
    assert_eq!(
        body["data"]["decision"], "forbid",
        "disabled agent should be forbidden by forbid rule"
    );
}

#[tokio::test]
async fn test_policy_test_returns_diagnostics() {
    let ctx = TestAppBuilder::new().build().await;
    let _admin = create_test_user(&*ctx.store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let (cookie, csrf) = login_user(&ctx.app, "admin", TEST_PASSWORD).await;
    let full_cookie = combined_cookie(&cookie, &csrf);

    let (status, body) = send_json(
        &ctx.app,
        Method::POST,
        "/api/v1/policies/test",
        None,
        Some(&full_cookie),
        Some(&csrf),
        Some(json!({
            "principal": { "type": "Agent", "id": "admin-agent", "attributes": { "tags": ["admin"], "enabled": true } },
            "action": "access",
            "resource": { "type": "Credential", "id": "test-cred", "attributes": { "name": "test", "service": "svc", "scopes": [], "owner": "user1", "readers": [], "writers": [], "deleters": [], "delegated_users": [], "tags": [] } },
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "response: {}", body);
    let diagnostics = &body["data"]["diagnostics"];
    assert!(
        diagnostics.is_array(),
        "diagnostics must be an array: {}",
        body
    );
}

#[tokio::test]
async fn test_policy_test_owner_match_permits() {
    let ctx = TestAppBuilder::new().build().await;
    let _admin = create_test_user(&*ctx.store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let (cookie, csrf) = login_user(&ctx.app, "admin", TEST_PASSWORD).await;
    let full_cookie = combined_cookie(&cookie, &csrf);

    // Use same owner ID for both principal and resource
    let owner_id = "shared-owner-user";
    let (status, body) = send_json(
        &ctx.app,
        Method::POST,
        "/api/v1/policies/test",
        None,
        Some(&full_cookie),
        Some(&csrf),
        Some(json!({
            "principal": { "type": "Agent", "id": "agent-1", "attributes": { "tags": [], "enabled": true, "owner": owner_id } },
            "action": "vend_credential",
            "resource": { "type": "Credential", "id": "cred-1", "attributes": { "name": "test", "service": "svc", "scopes": [], "owner": owner_id, "readers": [], "writers": [], "deleters": [], "delegated_users": [], "tags": [] } },
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "response: {}", body);
    assert_eq!(
        body["data"]["decision"], "permit",
        "owner match should permit vend_credential"
    );
}

#[tokio::test]
async fn test_policy_test_owner_mismatch_denies() {
    let ctx = TestAppBuilder::new().build().await;
    let _admin = create_test_user(&*ctx.store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let (cookie, csrf) = login_user(&ctx.app, "admin", TEST_PASSWORD).await;
    let full_cookie = combined_cookie(&cookie, &csrf);

    let (status, body) = send_json(
        &ctx.app,
        Method::POST,
        "/api/v1/policies/test",
        None,
        Some(&full_cookie),
        Some(&csrf),
        Some(json!({
            "principal": { "type": "Agent", "id": "agent-1", "attributes": { "tags": [], "enabled": true, "owner": "user-A" } },
            "action": "vend_credential",
            "resource": { "type": "Credential", "id": "cred-1", "attributes": { "name": "test", "service": "svc", "scopes": [], "owner": "user-B", "readers": [], "writers": [], "deleters": [], "delegated_users": [], "tags": [] } },
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "response: {}", body);
    // v1.15.0: vend_credential requires explicit grants or ownership match.
    assert_eq!(
        body["data"]["decision"], "deny",
        "vend with ownership mismatch and no grants should deny"
    );
}

// ===========================================================================
// 7C. Input Validation
// ===========================================================================

#[tokio::test]
async fn test_policy_test_missing_principal_returns_400() {
    let ctx = TestAppBuilder::new().build().await;
    let _admin = create_test_user(&*ctx.store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let (cookie, csrf) = login_user(&ctx.app, "admin", TEST_PASSWORD).await;
    let full_cookie = combined_cookie(&cookie, &csrf);

    let (status, _body) = send_json(
        &ctx.app,
        Method::POST,
        "/api/v1/policies/test",
        None,
        Some(&full_cookie),
        Some(&csrf),
        Some(json!({
            "action": "access",
            "resource": { "type": "System" },
        })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "missing principal should be 400"
    );
}

#[tokio::test]
async fn test_policy_test_missing_action_returns_400() {
    let ctx = TestAppBuilder::new().build().await;
    let _admin = create_test_user(&*ctx.store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let (cookie, csrf) = login_user(&ctx.app, "admin", TEST_PASSWORD).await;
    let full_cookie = combined_cookie(&cookie, &csrf);

    let (status, _body) = send_json(
        &ctx.app,
        Method::POST,
        "/api/v1/policies/test",
        None,
        Some(&full_cookie),
        Some(&csrf),
        Some(json!({
            "principal": { "type": "Agent", "id": "test", "attributes": { "tags": [], "enabled": true } },
            "resource": { "type": "System" },
        })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "missing action should be 400"
    );
}

#[tokio::test]
async fn test_policy_test_unknown_action_returns_meaningful_response() {
    let ctx = TestAppBuilder::new().build().await;
    let _admin = create_test_user(&*ctx.store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let (cookie, csrf) = login_user(&ctx.app, "admin", TEST_PASSWORD).await;
    let full_cookie = combined_cookie(&cookie, &csrf);

    let (status, body) = send_json(
        &ctx.app,
        Method::POST,
        "/api/v1/policies/test",
        None,
        Some(&full_cookie),
        Some(&csrf),
        Some(json!({
            "principal": { "type": "Agent", "id": "test", "attributes": { "tags": [], "enabled": true } },
            "action": "nonexistent_action",
            "resource": { "type": "System" },
        })),
    )
    .await;
    // Either a 400 error or a deny result — both are acceptable
    assert!(
        status == StatusCode::BAD_REQUEST
            || (status == StatusCode::OK && body["data"]["decision"] == "deny"),
        "unknown action should return 400 or deny: status={}, body={}",
        status,
        body
    );
}

#[tokio::test]
async fn test_policy_test_unknown_entity_type_returns_400() {
    let ctx = TestAppBuilder::new().build().await;
    let _admin = create_test_user(&*ctx.store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let (cookie, csrf) = login_user(&ctx.app, "admin", TEST_PASSWORD).await;
    let full_cookie = combined_cookie(&cookie, &csrf);

    let (status, _body) = send_json(
        &ctx.app,
        Method::POST,
        "/api/v1/policies/test",
        None,
        Some(&full_cookie),
        Some(&csrf),
        Some(json!({
            "principal": { "type": "FakeType", "id": "test", "attributes": {} },
            "action": "access",
            "resource": { "type": "System" },
        })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "unknown entity type should be 400"
    );
}

#[tokio::test]
async fn test_policy_test_empty_body_returns_400() {
    let ctx = TestAppBuilder::new().build().await;
    let _admin = create_test_user(&*ctx.store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let (cookie, csrf) = login_user(&ctx.app, "admin", TEST_PASSWORD).await;
    let full_cookie = combined_cookie(&cookie, &csrf);

    let (status, _body) = send_json(
        &ctx.app,
        Method::POST,
        "/api/v1/policies/test",
        None,
        Some(&full_cookie),
        Some(&csrf),
        Some(json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "empty body should be 400");
}

// ===========================================================================
// 7D. Context Forwarding
// ===========================================================================

#[tokio::test]
async fn test_policy_test_context_target_url_forwarded() {
    let ctx = TestAppBuilder::new().build().await;
    let _admin = create_test_user(&*ctx.store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let (cookie, csrf) = login_user(&ctx.app, "admin", TEST_PASSWORD).await;
    let full_cookie = combined_cookie(&cookie, &csrf);

    let (status, body) = send_json(
        &ctx.app,
        Method::POST,
        "/api/v1/policies/test",
        None,
        Some(&full_cookie),
        Some(&csrf),
        Some(json!({
            "principal": { "type": "Agent", "id": "admin-agent", "attributes": { "tags": ["admin"], "enabled": true } },
            "action": "vend_credential",
            "resource": { "type": "Credential", "id": "cred-1", "attributes": { "name": "test", "service": "svc", "scopes": [], "owner": "user1", "readers": [], "writers": [], "deleters": [], "delegated_users": [], "tags": [] } },
            "context": { "target_url": "https://api.example.com" },
        })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "context forwarding should work: {}",
        body
    );
    assert_eq!(
        body["data"]["decision"], "permit",
        "admin agent with context should be permitted"
    );
}

#[tokio::test]
async fn test_policy_test_context_tag_value_forwarded() {
    let ctx = TestAppBuilder::new().build().await;
    let _admin = create_test_user(&*ctx.store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let (cookie, csrf) = login_user(&ctx.app, "admin", TEST_PASSWORD).await;
    let full_cookie = combined_cookie(&cookie, &csrf);

    let (status, body) = send_json(
        &ctx.app,
        Method::POST,
        "/api/v1/policies/test",
        None,
        Some(&full_cookie),
        Some(&csrf),
        Some(json!({
            "principal": { "type": "User", "id": "admin-user", "attributes": { "name": "admin", "role": "admin", "enabled": true, "is_root": false } },
            "action": "manage_tags",
            "resource": { "type": "AgentResource", "id": "agent-1", "attributes": { "name": "test-agent", "enabled": true } },
            "context": { "tag_value": "admin" },
        })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "tag_value context should work: {}",
        body
    );
    // Admin user should be permitted manage_tags
    assert_eq!(
        body["data"]["decision"], "permit",
        "admin user manage_tags should be permitted"
    );
}
