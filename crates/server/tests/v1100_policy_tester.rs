//! v1.10.0 — Policy Tester Integration Tests (Feature 7).
//!
//! Verifies the policy tester API endpoint (POST /api/v1/policies/test)
//! and the tester UI elements on the policy detail page.

use crate::common;

use agent_cordon_core::domain::user::UserRole;
use agent_cordon_server::test_helpers::TestAppBuilder;
use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::json;
use tower::ServiceExt;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async fn setup() -> (agent_cordon_server::test_helpers::TestContext, String) {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let _user = common::create_test_user(
        &*ctx.store,
        "policy-tester-user",
        common::TEST_PASSWORD,
        UserRole::Admin,
    )
    .await;
    let cookie =
        common::login_user_combined(&ctx.app, "policy-tester-user", common::TEST_PASSWORD).await;
    (ctx, cookie)
}

async fn get_html(app: &axum::Router, uri: &str, cookie: &str) -> (StatusCode, String) {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(uri)
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let status = resp.status();
    let body = String::from_utf8(
        resp.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();

    (status, body)
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
            "description": "Test policy for tester",
            "cedar_policy": cedar,
        })),
    )
    .await;

    assert!(
        status == StatusCode::CREATED || status == StatusCode::OK,
        "policy creation should succeed: {:?}",
        body,
    );

    body["data"]["id"]
        .as_str()
        .expect("policy should have id")
        .to_string()
}

const SIMPLE_PERMIT: &str = r#"permit(
  principal,
  action == AgentCordon::Action::"access",
  resource
);"#;

// Deny-all Cedar policy available for future tests.
#[allow(dead_code)]
const DENY_ALL: &str = r#"forbid(
  principal,
  action,
  resource
);"#;

// ===========================================================================
// 7A. Policy Tester API Tests
// ===========================================================================

/// POST /api/v1/policies/test with valid request returns permit/deny.
#[tokio::test]
async fn test_policy_tester_api_returns_decision() {
    let (ctx, cookie) = setup().await;

    let (status, body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        "/api/v1/policies/test",
        None,
        Some(&cookie),
        Some(json!({
            "principal": { "type": "Agent", "id": "test-agent", "attributes": {} },
            "action": "access",
            "resource": { "type": "Credential", "attributes": {} },
        })),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "test endpoint should return 200: {:?}",
        body
    );

    let decision = body["data"]["decision"].as_str().expect("decision field");
    assert!(
        decision == "permit" || decision == "deny",
        "decision should be 'permit' or 'deny', got: {}",
        decision
    );
}

/// Test that diagnostics are included in the response.
#[tokio::test]
async fn test_policy_tester_returns_diagnostics() {
    let (ctx, cookie) = setup().await;

    let (status, body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        "/api/v1/policies/test",
        None,
        Some(&cookie),
        Some(json!({
            "principal": { "type": "Agent", "id": "diag-test-agent", "attributes": {} },
            "action": "access",
            "resource": { "type": "Credential", "attributes": {} },
        })),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert!(
        body["data"]["diagnostics"].is_array(),
        "response should include diagnostics array"
    );
}

/// Test with different principal types (Agent, User, Device).
#[tokio::test]
async fn test_policy_tester_principal_types() {
    let (ctx, cookie) = setup().await;

    // Each principal type must be tested with an action it's valid for per the Cedar schema.
    // "access" only allows Agent. "list" allows Agent and User. "vend_credential" allows Agent and Device.
    let cases: Vec<(&str, &str, &str)> = vec![
        ("Agent", "access", "Credential"),
        ("User", "list", "Credential"),
        ("Device", "vend_credential", "Credential"),
    ];
    for (principal_type, action, resource_type) in &cases {
        let (status, body) = common::send_json_auto_csrf(
            &ctx.app,
            Method::POST,
            "/api/v1/policies/test",
            None,
            Some(&cookie),
            Some(json!({
                "principal": { "type": principal_type, "id": "test-id", "attributes": {} },
                "action": action,
                "resource": { "type": resource_type, "attributes": {} },
            })),
        )
        .await;

        assert_eq!(
            status,
            StatusCode::OK,
            "test with principal type {} / action {} should return 200: {:?}",
            principal_type,
            action,
            body
        );
    }
}

/// Test with different resource types.
#[tokio::test]
async fn test_policy_tester_resource_types() {
    let (ctx, cookie) = setup().await;

    // Each resource type must be tested with a valid action per the Cedar schema.
    // Agent principal is used for all; action must match the resource type.
    // v2.0: AgentResource -> WorkspaceResource, manage_agents -> manage_workspaces
    let cases: Vec<(&str, &str)> = vec![
        ("Credential", "access"),              // access: Workspace -> Credential
        ("McpServer", "mcp_tool_call"),        // mcp_tool_call: Workspace -> McpServer
        ("System", "list"),                    // list: Workspace -> System
        ("PolicyResource", "manage_policies"), // manage_policies: Workspace -> PolicyResource
        ("WorkspaceResource", "manage_workspaces"), // manage_workspaces: Workspace -> WorkspaceResource
    ];
    for (resource_type, action) in &cases {
        let (status, body) = common::send_json_auto_csrf(
            &ctx.app,
            Method::POST,
            "/api/v1/policies/test",
            None,
            Some(&cookie),
            Some(json!({
                "principal": { "type": "Agent", "id": "test-agent", "attributes": {} },
                "action": action,
                "resource": { "type": resource_type, "attributes": {} },
            })),
        )
        .await;

        assert_eq!(
            status,
            StatusCode::OK,
            "test with resource type {} / action {} should return 200: {:?}",
            resource_type,
            action,
            body
        );
    }
}

/// Test with unknown principal type returns 400.
#[tokio::test]
async fn test_policy_tester_invalid_principal_type() {
    let (ctx, cookie) = setup().await;

    let (status, _body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        "/api/v1/policies/test",
        None,
        Some(&cookie),
        Some(json!({
            "principal": { "type": "UnknownType", "id": "test", "attributes": {} },
            "action": "access",
            "resource": { "type": "Credential", "attributes": {} },
        })),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "unknown principal type should return 400"
    );
}

/// Missing required fields returns 400.
#[tokio::test]
async fn test_policy_tester_missing_fields() {
    let (ctx, cookie) = setup().await;

    // Missing principal
    let (status, _body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        "/api/v1/policies/test",
        None,
        Some(&cookie),
        Some(json!({
            "action": "access",
            "resource": { "type": "Credential", "attributes": {} },
        })),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "missing principal should return 400"
    );
}

// ===========================================================================
// 7B. Policy Tester UI Elements
// ===========================================================================

/// The policy detail page should have the policy tester section.
#[tokio::test]
async fn test_policy_detail_has_tester_ui() {
    let (ctx, cookie) = setup().await;
    let policy_id = create_test_policy(&ctx.app, &cookie, "tester-ui-test", SIMPLE_PERMIT).await;

    let (status, body) = get_html(&ctx.app, &format!("/security/{}", policy_id), &cookie).await;

    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("Policy Tester"),
        "policy detail page should contain the 'Policy Tester' section"
    );
    assert!(
        body.contains("test-principal-type"),
        "policy detail should have principal type selector"
    );
    assert!(
        body.contains("test-action"),
        "policy detail should have action input"
    );
    assert!(
        body.contains("test-resource-type"),
        "policy detail should have resource type selector"
    );
    assert!(
        body.contains("Test Policy"),
        "policy detail should have 'Test Policy' button"
    );
}

/// The tester dropdown should include Agent/Workspace and User options.
#[tokio::test]
async fn test_policy_tester_principal_options() {
    let (ctx, cookie) = setup().await;
    let policy_id =
        create_test_policy(&ctx.app, &cookie, "tester-options-test", SIMPLE_PERMIT).await;

    let (status, body) = get_html(&ctx.app, &format!("/security/{}", policy_id), &cookie).await;

    assert_eq!(status, StatusCode::OK);
    // Check for principal type options (v2.0: Device removed, Workspace/Agent unified)
    let has_agent_or_workspace =
        body.contains(r#"value="Agent"#) || body.contains(r#"value="Workspace"#);
    assert!(
        has_agent_or_workspace,
        "should have Agent or Workspace option"
    );
    assert!(body.contains(r#"value="User"#), "should have User option");
    // Check for resource type options
    assert!(
        body.contains(r#"value="Credential"#),
        "should have Credential option"
    );
    assert!(
        body.contains(r#"value="McpServer"#),
        "should have McpServer option"
    );
}
