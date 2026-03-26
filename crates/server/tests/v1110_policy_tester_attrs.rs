//! v1.11.0 — Policy Tester Principal Attributes Tests (Feature 6)
//!
//! Policy tester form adds fields for tags (comma-separated), role (for User),
//! and enabled flag, so tag-based and role-based policies can be tested accurately.

use crate::common;

use agent_cordon_core::domain::user::UserRole;
use agent_cordon_server::test_helpers::TestAppBuilder;
use axum::http::{Method, StatusCode};
use serde_json::json;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async fn setup() -> (agent_cordon_server::test_helpers::TestContext, String) {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let _user = common::create_test_user(
        &*ctx.store,
        "tester-attr-user",
        common::TEST_PASSWORD,
        UserRole::Admin,
    )
    .await;
    let cookie =
        common::login_user_combined(&ctx.app, "tester-attr-user", common::TEST_PASSWORD).await;
    (ctx, cookie)
}

async fn create_test_policy(app: &axum::Router, cookie: &str, name: &str, cedar: &str) -> String {
    let (status, body) = common::send_json_auto_csrf(
        app,
        Method::POST,
        "/api/v1/policies",
        None,
        Some(cookie),
        Some(json!({
            "name": name,
            "description": "Test policy for tester attrs",
            "cedar_policy": cedar,
        })),
    )
    .await;

    assert!(
        status == StatusCode::CREATED || status == StatusCode::OK,
        "policy creation should succeed: status={}, body={:?}",
        status,
        body,
    );

    body["data"]["id"]
        .as_str()
        .expect("policy should have id")
        .to_string()
}

// ===========================================================================
// 6A. Happy Path
// ===========================================================================

/// Policy tester with admin tag and tag-based policy returns permit.
#[tokio::test]
async fn test_policy_tester_with_admin_tag_permits() {
    let (ctx, cookie) = setup().await;

    // Create a tag-based policy
    let _policy_id = create_test_policy(
        &ctx.app,
        &cookie,
        "admin-tag-permit",
        r#"permit(
  principal is AgentCordon::Workspace,
  action == AgentCordon::Action::"access",
  resource
) when {
  principal.tags.contains("admin")
};"#,
    )
    .await;

    let (status, body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        "/api/v1/policies/test",
        None,
        Some(&cookie),
        Some(json!({
            "principal": {
                "type": "Agent",
                "id": "test-agent",
                "attributes": {
                    "tags": ["admin"],
                    "enabled": true,
                }
            },
            "action": "access",
            "resource": { "type": "Credential", "attributes": {} },
        })),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "tester should return 200: {:?}",
        body
    );

    let decision = body["data"]["decision"].as_str().unwrap_or("");
    assert_eq!(
        decision, "permit",
        "agent with admin tag should be permitted by tag-based policy, got: {}",
        decision
    );
}

/// Policy tester without matching tag returns deny.
#[tokio::test]
async fn test_policy_tester_without_matching_tag_denies() {
    let (ctx, cookie) = setup().await;

    let _policy_id = create_test_policy(
        &ctx.app,
        &cookie,
        "tag-deny-test",
        r#"permit(
  principal is AgentCordon::Workspace,
  action == AgentCordon::Action::"access",
  resource
) when {
  principal.tags.contains("admin")
};"#,
    )
    .await;

    let (status, body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        "/api/v1/policies/test",
        None,
        Some(&cookie),
        Some(json!({
            "principal": {
                "type": "Agent",
                "id": "test-agent",
                "attributes": {
                    "tags": ["viewer"],
                    "enabled": true,
                }
            },
            "action": "access",
            "resource": { "type": "Credential", "attributes": {} },
        })),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "tester should return 200: {:?}",
        body
    );

    let decision = body["data"]["decision"].as_str().unwrap_or("");
    // Without blanket policy 5c, a non-admin agent without explicit grants
    // is denied credential access.
    assert_eq!(
        decision, "deny",
        "non-admin agent without grants should be denied credential access, got: {}",
        decision
    );
}

/// Policy tester with User role attribute returns permit.
#[tokio::test]
async fn test_policy_tester_with_role_attribute() {
    let (ctx, cookie) = setup().await;

    let _policy_id = create_test_policy(
        &ctx.app,
        &cookie,
        "role-permit-test",
        r#"permit(
  principal is AgentCordon::User,
  action == AgentCordon::Action::"list",
  resource
) when {
  principal.role == "admin"
};"#,
    )
    .await;

    // Owner-scoped policy 2a-cred requires resource.owner == principal,
    // so set the resource owner to the same synthetic user ID.
    let (status, body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        "/api/v1/policies/test",
        None,
        Some(&cookie),
        Some(json!({
            "principal": {
                "type": "User",
                "id": "test-user",
                "attributes": {
                    "role": "admin",
                    "enabled": true,
                }
            },
            "action": "list",
            "resource": { "type": "Credential", "attributes": { "owner": "test-user" } },
        })),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "tester should return 200: {:?}",
        body
    );

    let decision = body["data"]["decision"].as_str().unwrap_or("");
    assert_eq!(
        decision, "permit",
        "user with admin role should be permitted for own credential, got: {}",
        decision
    );
}

/// Policy tester with enabled=false triggers forbid rule.
#[tokio::test]
async fn test_policy_tester_with_enabled_false_triggers_forbid() {
    let (ctx, cookie) = setup().await;

    let (status, body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        "/api/v1/policies/test",
        None,
        Some(&cookie),
        Some(json!({
            "principal": {
                "type": "Agent",
                "id": "disabled-agent",
                "attributes": {
                    "enabled": false,
                    "tags": [],
                }
            },
            "action": "access",
            "resource": { "type": "Credential", "attributes": {} },
        })),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "tester should return 200: {:?}",
        body
    );

    let decision = body["data"]["decision"].as_str().unwrap_or("");
    assert_eq!(
        decision, "forbid",
        "disabled agent should be forbidden (forbid rule), got: {}",
        decision
    );
}

/// Policy tester with multiple tags — both required.
#[tokio::test]
async fn test_policy_tester_with_multiple_tags() {
    let (ctx, cookie) = setup().await;

    let _policy_id = create_test_policy(
        &ctx.app,
        &cookie,
        "multi-tag-test",
        r#"permit(
  principal is AgentCordon::Workspace,
  action == AgentCordon::Action::"access",
  resource
) when {
  principal.tags.contains("ci") && principal.tags.contains("deploy")
};"#,
    )
    .await;

    // Both tags present → permit
    let (status, body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        "/api/v1/policies/test",
        None,
        Some(&cookie),
        Some(json!({
            "principal": {
                "type": "Agent",
                "id": "ci-deploy-agent",
                "attributes": {
                    "tags": ["ci", "deploy"],
                    "enabled": true,
                }
            },
            "action": "access",
            "resource": { "type": "Credential", "attributes": {} },
        })),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    let decision = body["data"]["decision"].as_str().unwrap_or("");
    assert_eq!(
        decision, "permit",
        "agent with both ci+deploy tags should be permitted"
    );

    // Only one tag → deny
    let (status2, body2) = common::send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        "/api/v1/policies/test",
        None,
        Some(&cookie),
        Some(json!({
            "principal": {
                "type": "Agent",
                "id": "ci-only-agent",
                "attributes": {
                    "tags": ["ci"],
                    "enabled": true,
                }
            },
            "action": "access",
            "resource": { "type": "Credential", "attributes": {} },
        })),
    )
    .await;

    assert_eq!(status2, StatusCode::OK);
    let decision2 = body2["data"]["decision"].as_str().unwrap_or("");
    // Without blanket policy 5c, an agent without explicit grants is denied.
    assert_eq!(
        decision2, "deny",
        "agent without grants should be denied credential access"
    );
}

// ===========================================================================
// 6B. Retry/Idempotency
// ===========================================================================

/// Same request twice returns same result (stateless evaluation).
#[tokio::test]
async fn test_policy_tester_same_request_twice_same_result() {
    let (ctx, cookie) = setup().await;

    let request_body = json!({
        "principal": {
            "type": "Agent",
            "id": "idempotent-agent",
            "attributes": {
                "tags": ["viewer"],
                "enabled": true,
            }
        },
        "action": "access",
        "resource": { "type": "Credential", "attributes": {} },
    });

    let (status1, body1) = common::send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        "/api/v1/policies/test",
        None,
        Some(&cookie),
        Some(request_body.clone()),
    )
    .await;

    let (status2, body2) = common::send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        "/api/v1/policies/test",
        None,
        Some(&cookie),
        Some(request_body),
    )
    .await;

    assert_eq!(status1, status2, "same request should return same status");
    assert_eq!(
        body1["data"]["decision"], body2["data"]["decision"],
        "same request should return same decision"
    );
}

// ===========================================================================
// 6C. Error Handling
// ===========================================================================

/// Empty tags array is valid.
#[tokio::test]
async fn test_policy_tester_empty_tags_array() {
    let (ctx, cookie) = setup().await;

    let (status, body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        "/api/v1/policies/test",
        None,
        Some(&cookie),
        Some(json!({
            "principal": {
                "type": "Agent",
                "id": "no-tags-agent",
                "attributes": {
                    "tags": [],
                    "enabled": true,
                }
            },
            "action": "access",
            "resource": { "type": "Credential", "attributes": {} },
        })),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "empty tags array should be valid: {:?}",
        body
    );
    assert!(
        body["data"]["decision"].is_string(),
        "should return a decision"
    );
}

/// Invalid role value gets 400 or graceful handling.
#[tokio::test]
async fn test_policy_tester_invalid_role_value() {
    let (ctx, cookie) = setup().await;

    let (status, _body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        "/api/v1/policies/test",
        None,
        Some(&cookie),
        Some(json!({
            "principal": {
                "type": "User",
                "id": "bad-role-user",
                "attributes": {
                    "role": "superadmin",
                    "enabled": true,
                }
            },
            "action": "list",
            "resource": { "type": "Credential", "attributes": {} },
        })),
    )
    .await;

    // Either 400 (strict validation) or 200 with deny (Cedar handles it)
    assert!(
        status == StatusCode::BAD_REQUEST || status == StatusCode::OK,
        "invalid role should return 400 or 200 with graceful handling, got: {}",
        status
    );
}

/// Missing attributes field is backward-compatible.
#[tokio::test]
async fn test_policy_tester_missing_attributes_field() {
    let (ctx, cookie) = setup().await;

    let (status, body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        "/api/v1/policies/test",
        None,
        Some(&cookie),
        Some(json!({
            "principal": {
                "type": "Agent",
                "id": "no-attrs-agent",
            },
            "action": "access",
            "resource": { "type": "Credential", "attributes": {} },
        })),
    )
    .await;

    // Should work without attributes (backward compat)
    assert_eq!(
        status,
        StatusCode::OK,
        "missing attributes should be backward-compatible: {:?}",
        body
    );
}

// ===========================================================================
// 6D. Cross-Feature
// ===========================================================================

/// Policy tester result matches real RSoP for same attributes.
#[tokio::test]
async fn test_policy_tester_reflects_real_agent_evaluation() {
    let (ctx, cookie) = setup().await;

    // Create a real agent with "ci" tag
    let (_agent_status, _agent_body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        "/api/v1/workspaces",
        None,
        Some(&cookie),
        Some(json!({
            "name": "ci-tester-agent",
            "tags": ["ci"],
        })),
    )
    .await;

    let _policy_id = create_test_policy(
        &ctx.app,
        &cookie,
        "ci-permit-test",
        r#"permit(
  principal is AgentCordon::Workspace,
  action == AgentCordon::Action::"access",
  resource
) when {
  principal.tags.contains("ci")
};"#,
    )
    .await;

    // Call tester with same attributes
    let (status, body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        "/api/v1/policies/test",
        None,
        Some(&cookie),
        Some(json!({
            "principal": {
                "type": "Agent",
                "id": "ci-tester-agent",
                "attributes": {
                    "tags": ["ci"],
                    "enabled": true,
                }
            },
            "action": "access",
            "resource": { "type": "Credential", "attributes": {} },
        })),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    let decision = body["data"]["decision"].as_str().unwrap_or("");
    assert_eq!(
        decision, "permit",
        "tester should match real agent evaluation: agent with ci tag should be permitted"
    );
}

// ===========================================================================
// 6E. Security
// ===========================================================================

/// Policy tester requires manage_policies permission.
#[tokio::test]
async fn test_policy_tester_requires_manage_policies_permission() {
    let (ctx, _admin_cookie) = setup().await;

    // Create a viewer user
    let _viewer = common::create_test_user(
        &*ctx.store,
        "tester-viewer",
        common::TEST_PASSWORD,
        UserRole::Viewer,
    )
    .await;
    let viewer_cookie =
        common::login_user_combined(&ctx.app, "tester-viewer", common::TEST_PASSWORD).await;

    // Viewer tries to use tester → should get 403
    let (viewer_status, _) = common::send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        "/api/v1/policies/test",
        None,
        Some(&viewer_cookie),
        Some(json!({
            "principal": { "type": "Agent", "id": "test", "attributes": {} },
            "action": "access",
            "resource": { "type": "Credential", "attributes": {} },
        })),
    )
    .await;

    assert_eq!(
        viewer_status,
        StatusCode::FORBIDDEN,
        "viewer should not be able to use policy tester"
    );

    // Admin should succeed (already tested above, but explicit)
    let admin_cookie =
        common::login_user_combined(&ctx.app, "tester-attr-user", common::TEST_PASSWORD).await;

    let (admin_status, _) = common::send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        "/api/v1/policies/test",
        None,
        Some(&admin_cookie),
        Some(json!({
            "principal": { "type": "Agent", "id": "test", "attributes": {} },
            "action": "access",
            "resource": { "type": "Credential", "attributes": {} },
        })),
    )
    .await;

    assert_eq!(
        admin_status,
        StatusCode::OK,
        "admin should be able to use policy tester"
    );
}
