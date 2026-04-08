//! v1.10.0 — RSoP API Tests (Feature 3)
//!
//! Tests the Resultant Set of Policy (RSoP) endpoint: `POST /api/v1/policies/rsop`.
//! RSoP evaluates all agents/devices against a given resource and returns a
//! permission matrix showing which principals can perform which actions.
//!
//! Covers: happy path, resource types, error handling, security, conditional
//! policies, performance, and cross-feature integration.

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
        "rsop-user",
        common::TEST_PASSWORD,
        UserRole::Admin,
    )
    .await;
    let cookie = common::login_user_combined(&ctx.app, "rsop-user", common::TEST_PASSWORD).await;

    // Create a credential owned by the test user for RSoP tests to find.
    let (status, _body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        "/api/v1/credentials",
        None,
        Some(&cookie),
        Some(json!({
            "name": "rsop-test-cred",
            "service": "test-service",
            "credential_type": "generic",
            "secret_value": "rsop-test-secret"
        })),
    )
    .await;
    assert!(
        status == StatusCode::CREATED || status == StatusCode::OK,
        "rsop setup: create credential should succeed"
    );

    (ctx, cookie)
}

async fn setup_with_seed() -> (agent_cordon_server::test_helpers::TestContext, String) {
    let ctx = TestAppBuilder::new().with_admin().build().await;

    // Use root user so Cedar owner-scoping doesn't hide credentials.
    let _user = common::create_user_in_db(
        &*ctx.store,
        "rsop-seed-user",
        common::TEST_PASSWORD,
        UserRole::Admin,
        true,
        true,
    )
    .await;
    let cookie =
        common::login_user_combined(&ctx.app, "rsop-seed-user", common::TEST_PASSWORD).await;

    // Create a test credential through the API
    let (status, _body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        "/api/v1/credentials",
        None,
        Some(&cookie),
        Some(json!({
            "name": "rsop-seed-cred",
            "service": "test-service",
            "credential_type": "generic",
            "secret_value": "rsop-seed-secret"
        })),
    )
    .await;
    assert!(
        status == StatusCode::CREATED || status == StatusCode::OK,
        "rsop setup: create credential should succeed"
    );

    (ctx, cookie)
}

/// Get the first credential ID from the API (requires seeded data).
async fn get_first_credential_id(
    ctx: &agent_cordon_server::test_helpers::TestContext,
    cookie: &str,
) -> String {
    let (status, body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::GET,
        "/api/v1/credentials",
        None,
        Some(cookie),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "list credentials: {:?}", body);

    let creds = body["data"].as_array().expect("data array");
    assert!(
        !creds.is_empty(),
        "need at least one credential for RSoP tests"
    );
    creds[0]["id"].as_str().expect("credential id").to_string()
}

// ===========================================================================
// 3A. Happy Path — Credential resource type
// ===========================================================================

#[tokio::test]
async fn test_rsop_credential_returns_matrix() {
    let (ctx, cookie) = setup_with_seed().await;
    let cred_id = get_first_credential_id(&ctx, &cookie).await;

    let (status, body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        "/api/v1/policies/rsop",
        None,
        Some(&cookie),
        Some(serde_json::json!({
            "resource_type": "Credential",
            "resource_id": cred_id,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "RSoP should succeed: {:?}", body);

    let data = &body["data"];
    assert!(
        data["resource"].is_object(),
        "response should have resource field"
    );
    assert!(
        data["matrix"].is_array(),
        "response should have matrix array"
    );
    assert!(
        data["evaluated_at"].is_string(),
        "response should have evaluated_at"
    );
    assert!(
        data["principal_count"].is_number(),
        "response should have principal_count"
    );
}

#[tokio::test]
async fn test_rsop_credential_resource_metadata() {
    let (ctx, cookie) = setup_with_seed().await;
    let cred_id = get_first_credential_id(&ctx, &cookie).await;

    let (status, body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        "/api/v1/policies/rsop",
        None,
        Some(&cookie),
        Some(serde_json::json!({
            "resource_type": "Credential",
            "resource_id": cred_id,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let resource = &body["data"]["resource"];
    assert_eq!(resource["type"].as_str(), Some("Credential"));
    assert_eq!(resource["id"].as_str(), Some(cred_id.as_str()));
    assert!(resource["name"].is_string(), "resource should have name");
}

#[tokio::test]
async fn test_rsop_credential_matrix_has_action_results() {
    let (ctx, cookie) = setup_with_seed().await;
    let cred_id = get_first_credential_id(&ctx, &cookie).await;

    let (status, body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        "/api/v1/policies/rsop",
        None,
        Some(&cookie),
        Some(serde_json::json!({
            "resource_type": "Credential",
            "resource_id": cred_id,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let matrix = body["data"]["matrix"].as_array().expect("matrix array");
    assert!(!matrix.is_empty(), "matrix should have at least one entry");

    let entry = &matrix[0];
    assert!(
        entry["principal_type"].is_string(),
        "entry should have principal_type"
    );
    assert!(
        entry["principal_id"].is_string(),
        "entry should have principal_id"
    );
    assert!(
        entry["principal_name"].is_string(),
        "entry should have principal_name"
    );
    assert!(
        entry["results"].is_object(),
        "entry should have results object"
    );

    // Check that results contain action decisions
    let results = entry["results"].as_object().expect("results object");
    for (_action, result) in results {
        assert!(
            result["decision"].is_string(),
            "result should have decision"
        );
        assert!(
            result["decision"].as_str() == Some("permit")
                || result["decision"].as_str() == Some("deny")
                || result["decision"].as_str() == Some("forbid"),
            "decision should be 'permit', 'deny', or 'forbid'"
        );
    }
}

#[tokio::test]
async fn test_rsop_credential_includes_vend_credential_action() {
    let (ctx, cookie) = setup_with_seed().await;
    let cred_id = get_first_credential_id(&ctx, &cookie).await;

    let (status, body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        "/api/v1/policies/rsop",
        None,
        Some(&cookie),
        Some(serde_json::json!({
            "resource_type": "Credential",
            "resource_id": cred_id,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let matrix = body["data"]["matrix"].as_array().expect("matrix");
    assert!(!matrix.is_empty());

    let entry = &matrix[0];
    let results = entry["results"].as_object().expect("results");
    assert!(
        results.contains_key("vend_credential"),
        "credential RSoP should include vend_credential action. Actions present: {:?}",
        results.keys().collect::<Vec<_>>()
    );
}

// ===========================================================================
// 3B. Happy Path — McpServer resource type
// ===========================================================================

#[tokio::test]
async fn test_rsop_mcpserver_returns_matrix() {
    let (ctx, cookie) = setup_with_seed().await;

    // Create an MCP server in the store
    let (device_id, _) = common::create_standalone_device(&ctx.state).await;
    let d_uuid = agent_cordon_core::domain::workspace::WorkspaceId(
        uuid::Uuid::parse_str(&device_id).unwrap(),
    );
    let now = chrono::Utc::now();
    let mcp = agent_cordon_core::domain::mcp::McpServer {
        id: agent_cordon_core::domain::mcp::McpServerId(uuid::Uuid::new_v4()),
        workspace_id: d_uuid,
        name: "rsop-test-mcp".to_string(),
        upstream_url: "http://localhost:9999".to_string(),
        transport: agent_cordon_core::domain::mcp::McpTransport::Http,
        allowed_tools: None,
        enabled: true,
        created_by: None,
        created_at: now,
        updated_at: now,
        tags: vec![],
        required_credentials: None,
        auth_method: agent_cordon_core::domain::mcp::McpAuthMethod::default(),
        template_key: None,
        discovered_tools: None,
        created_by_user: None,
    };
    ctx.store
        .create_mcp_server(&mcp)
        .await
        .expect("create mcp server");
    let server_id = mcp.id.0.to_string();

    let (status, body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        "/api/v1/policies/rsop",
        None,
        Some(&cookie),
        Some(serde_json::json!({
            "resource_type": "McpServer",
            "resource_id": server_id,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "RSoP for McpServer: {:?}", body);

    let resource = &body["data"]["resource"];
    assert_eq!(resource["type"].as_str(), Some("McpServer"));
    assert!(body["data"]["matrix"].is_array());
}

#[tokio::test]
async fn test_rsop_mcpserver_includes_mcp_actions() {
    let (ctx, cookie) = setup_with_seed().await;

    let (device_id, _) = common::create_standalone_device(&ctx.state).await;
    let d_uuid = agent_cordon_core::domain::workspace::WorkspaceId(
        uuid::Uuid::parse_str(&device_id).unwrap(),
    );
    let now = chrono::Utc::now();
    let mcp = agent_cordon_core::domain::mcp::McpServer {
        id: agent_cordon_core::domain::mcp::McpServerId(uuid::Uuid::new_v4()),
        workspace_id: d_uuid,
        name: "rsop-mcp-actions".to_string(),
        upstream_url: "http://localhost:9999".to_string(),
        transport: agent_cordon_core::domain::mcp::McpTransport::Http,
        allowed_tools: None,
        enabled: true,
        created_by: None,
        created_at: now,
        updated_at: now,
        tags: vec![],
        required_credentials: None,
        auth_method: agent_cordon_core::domain::mcp::McpAuthMethod::default(),
        template_key: None,
        discovered_tools: None,
        created_by_user: None,
    };
    ctx.store
        .create_mcp_server(&mcp)
        .await
        .expect("create mcp server");
    let server_id = mcp.id.0.to_string();

    let (status, body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        "/api/v1/policies/rsop",
        None,
        Some(&cookie),
        Some(serde_json::json!({
            "resource_type": "McpServer",
            "resource_id": server_id,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let matrix = body["data"]["matrix"].as_array().expect("matrix");
    if !matrix.is_empty() {
        let results = matrix[0]["results"].as_object().expect("results");
        assert!(
            results.contains_key("mcp_tool_call"),
            "McpServer RSoP should include mcp_tool_call"
        );
        assert!(
            results.contains_key("mcp_list_tools"),
            "McpServer RSoP should include mcp_list_tools"
        );
    }
}

// ===========================================================================
// 3C. Limit parameter
// ===========================================================================

#[tokio::test]
async fn test_rsop_limit_parameter() {
    let (ctx, cookie) = setup_with_seed().await;
    let cred_id = get_first_credential_id(&ctx, &cookie).await;

    let (status, body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        "/api/v1/policies/rsop",
        None,
        Some(&cookie),
        Some(serde_json::json!({
            "resource_type": "Credential",
            "resource_id": cred_id,
            "limit": 1,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let matrix = body["data"]["matrix"].as_array().expect("matrix");
    assert!(
        matrix.len() <= 1,
        "with limit=1, matrix should have at most 1 entry, got {}",
        matrix.len()
    );
}

#[tokio::test]
async fn test_rsop_default_limit_is_100() {
    let (ctx, cookie) = setup_with_seed().await;
    let cred_id = get_first_credential_id(&ctx, &cookie).await;

    // Without explicit limit, should use default of 100
    let (status, body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        "/api/v1/policies/rsop",
        None,
        Some(&cookie),
        Some(serde_json::json!({
            "resource_type": "Credential",
            "resource_id": cred_id,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let matrix = body["data"]["matrix"].as_array().expect("matrix");
    assert!(
        matrix.len() <= 100,
        "default limit should cap at 100, got {}",
        matrix.len()
    );
}

// ===========================================================================
// 3D. Error Handling — invalid resource_type
// ===========================================================================

#[tokio::test]
async fn test_rsop_invalid_resource_type() {
    let (ctx, cookie) = setup_with_seed().await;

    let (status, body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        "/api/v1/policies/rsop",
        None,
        Some(&cookie),
        Some(serde_json::json!({
            "resource_type": "InvalidType",
            "resource_id": "00000000-0000-0000-0000-000000000000",
        })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "invalid resource_type should return 400: {:?}",
        body
    );
}

// ===========================================================================
// 3E. Error Handling — resource not found
// ===========================================================================

#[tokio::test]
async fn test_rsop_credential_not_found() {
    let (ctx, cookie) = setup().await;

    let (status, body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        "/api/v1/policies/rsop",
        None,
        Some(&cookie),
        Some(serde_json::json!({
            "resource_type": "Credential",
            "resource_id": "00000000-0000-0000-0000-000000000000",
        })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "non-existent credential should return 404: {:?}",
        body
    );
}

#[tokio::test]
async fn test_rsop_mcpserver_not_found() {
    let (ctx, cookie) = setup().await;

    let (status, body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        "/api/v1/policies/rsop",
        None,
        Some(&cookie),
        Some(serde_json::json!({
            "resource_type": "McpServer",
            "resource_id": "00000000-0000-0000-0000-000000000000",
        })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "non-existent MCP server should return 404: {:?}",
        body
    );
}

// ===========================================================================
// 3F. Error Handling — missing required fields
// ===========================================================================

#[tokio::test]
async fn test_rsop_missing_resource_type() {
    let (ctx, cookie) = setup().await;

    let (status, _body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        "/api/v1/policies/rsop",
        None,
        Some(&cookie),
        Some(serde_json::json!({
            "resource_id": "00000000-0000-0000-0000-000000000000",
        })),
    )
    .await;
    assert!(
        status == StatusCode::BAD_REQUEST || status == StatusCode::UNPROCESSABLE_ENTITY,
        "missing resource_type should return 400/422, got {}",
        status
    );
}

#[tokio::test]
async fn test_rsop_missing_resource_id() {
    let (ctx, cookie) = setup().await;

    let (status, _body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        "/api/v1/policies/rsop",
        None,
        Some(&cookie),
        Some(serde_json::json!({
            "resource_type": "Credential",
        })),
    )
    .await;
    assert!(
        status == StatusCode::BAD_REQUEST || status == StatusCode::UNPROCESSABLE_ENTITY,
        "missing resource_id should return 400/422, got {}",
        status
    );
}

#[tokio::test]
async fn test_rsop_empty_body() {
    let (ctx, cookie) = setup().await;

    let (status, _body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        "/api/v1/policies/rsop",
        None,
        Some(&cookie),
        Some(serde_json::json!({})),
    )
    .await;
    assert!(
        status == StatusCode::BAD_REQUEST || status == StatusCode::UNPROCESSABLE_ENTITY,
        "empty body should return 400/422, got {}",
        status
    );
}

// ===========================================================================
// 3G. Security — requires authentication
// ===========================================================================

#[tokio::test]
async fn test_rsop_requires_auth() {
    let (ctx, cookie) = setup_with_seed().await;
    // Use the root user cookie from setup to get a valid credential ID
    let cred_id = get_first_credential_id(&ctx, &cookie).await;

    let (status, _body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        "/api/v1/policies/rsop",
        None,
        None, // no cookie
        Some(serde_json::json!({
            "resource_type": "Credential",
            "resource_id": cred_id,
        })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "RSoP should require authentication"
    );
}

// ===========================================================================
// 3H. Security — requires manage_policies permission
// ===========================================================================

#[tokio::test]
async fn test_rsop_requires_manage_policies_permission() {
    let (ctx, _admin_cookie) = setup_with_seed().await;

    // Create a viewer user (viewers cannot manage policies)
    let _viewer = common::create_test_user(
        &*ctx.store,
        "rsop-viewer",
        common::TEST_PASSWORD,
        UserRole::Viewer,
    )
    .await;
    let viewer_cookie =
        common::login_user_combined(&ctx.app, "rsop-viewer", common::TEST_PASSWORD).await;

    let (status, _body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        "/api/v1/policies/rsop",
        None,
        Some(&viewer_cookie),
        Some(serde_json::json!({
            "resource_type": "Credential",
            "resource_id": "00000000-0000-0000-0000-000000000000",
        })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "viewer should not have manage_policies permission"
    );
}

// ===========================================================================
// 3I. Security — operator cannot access RSoP
// ===========================================================================

#[tokio::test]
async fn test_rsop_operator_denied() {
    let (ctx, _admin_cookie) = setup_with_seed().await;

    let _operator = common::create_test_user(
        &*ctx.store,
        "rsop-operator",
        common::TEST_PASSWORD,
        UserRole::Operator,
    )
    .await;
    let operator_cookie =
        common::login_user_combined(&ctx.app, "rsop-operator", common::TEST_PASSWORD).await;

    let (status, _body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        "/api/v1/policies/rsop",
        None,
        Some(&operator_cookie),
        Some(serde_json::json!({
            "resource_type": "Credential",
            "resource_id": "00000000-0000-0000-0000-000000000000",
        })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "operator should not have manage_policies permission"
    );
}

// ===========================================================================
// 3J. Matrix entries include principal metadata
// ===========================================================================

#[tokio::test]
async fn test_rsop_matrix_includes_principal_tags() {
    let (ctx, cookie) = setup_with_seed().await;
    let cred_id = get_first_credential_id(&ctx, &cookie).await;

    let (status, body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        "/api/v1/policies/rsop",
        None,
        Some(&cookie),
        Some(serde_json::json!({
            "resource_type": "Credential",
            "resource_id": cred_id,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let matrix = body["data"]["matrix"].as_array().expect("matrix");
    for entry in matrix {
        assert!(
            entry["principal_tags"].is_array(),
            "each entry should have principal_tags array"
        );
    }
}

// ===========================================================================
// 3K. Matrix includes both agents and devices
// ===========================================================================

#[tokio::test]
async fn test_rsop_includes_workspaces() {
    // v2.0: Devices removed; all principals are Workspaces (or Agents, depending on labeling)
    let (ctx, cookie) = setup_with_seed().await;
    let cred_id = get_first_credential_id(&ctx, &cookie).await;

    let (status, body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        "/api/v1/policies/rsop",
        None,
        Some(&cookie),
        Some(serde_json::json!({
            "resource_type": "Credential",
            "resource_id": cred_id,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let matrix = body["data"]["matrix"].as_array().expect("matrix");
    let has_principal = matrix.iter().any(|e| {
        let pt = e["principal_type"].as_str().unwrap_or("");
        pt == "Agent" || pt == "Workspace"
    });

    assert!(
        has_principal,
        "RSoP matrix should include at least one Agent/Workspace principal"
    );
}

// ===========================================================================
// 3L. Action results include reasons
// ===========================================================================

#[tokio::test]
async fn test_rsop_action_results_have_reasons() {
    let (ctx, cookie) = setup_with_seed().await;
    let cred_id = get_first_credential_id(&ctx, &cookie).await;

    let (status, body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        "/api/v1/policies/rsop",
        None,
        Some(&cookie),
        Some(serde_json::json!({
            "resource_type": "Credential",
            "resource_id": cred_id,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let matrix = body["data"]["matrix"].as_array().expect("matrix");
    if !matrix.is_empty() {
        let results = matrix[0]["results"].as_object().expect("results");
        for (_action, result) in results {
            assert!(
                result["reasons"].is_array(),
                "action results should include reasons array"
            );
        }
    }
}

// ===========================================================================
// 3M. Conditional policies detection
// ===========================================================================

#[tokio::test]
async fn test_rsop_conditional_policies_field_present() {
    let (ctx, cookie) = setup_with_seed().await;
    let cred_id = get_first_credential_id(&ctx, &cookie).await;

    let (status, body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        "/api/v1/policies/rsop",
        None,
        Some(&cookie),
        Some(serde_json::json!({
            "resource_type": "Credential",
            "resource_id": cred_id,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    assert!(
        body["data"]["conditional_policies"].is_array(),
        "response should include conditional_policies array"
    );
}

#[tokio::test]
async fn test_rsop_detects_time_based_conditional_policy() {
    let (ctx, cookie) = setup_with_seed().await;
    let cred_id = get_first_credential_id(&ctx, &cookie).await;

    // Create a time-based policy
    let (status, _) = common::send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        "/api/v1/policies",
        None,
        Some(&cookie),
        Some(serde_json::json!({
            "name": "time-based-test",
            "description": "Test policy with time condition",
            "cedar_policy": r#"forbid(
                principal is AgentCordon::Workspace,
                action == AgentCordon::Action::"access",
                resource is AgentCordon::Credential
            ) when {
                context.timestamp == "2099-01-01T00:00:00Z"
            };"#,
        })),
    )
    .await;
    assert!(status == StatusCode::OK || status == StatusCode::CREATED);

    // Now call RSoP and check conditional policies
    let (status, body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        "/api/v1/policies/rsop",
        None,
        Some(&cookie),
        Some(serde_json::json!({
            "resource_type": "Credential",
            "resource_id": cred_id,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let conditional = body["data"]["conditional_policies"]
        .as_array()
        .expect("conditional");
    let has_time_based = conditional
        .iter()
        .any(|c| c["condition_type"].as_str() == Some("time-based"));
    assert!(
        has_time_based,
        "should detect time-based conditional policy. Got: {:?}",
        conditional
    );
}

// ===========================================================================
// 3N. RSoP uses POST (not GET)
// ===========================================================================

#[tokio::test]
async fn test_rsop_get_method_not_allowed() {
    let (ctx, cookie) = setup().await;

    let (status, _body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::GET,
        "/api/v1/policies/rsop",
        None,
        Some(&cookie),
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::METHOD_NOT_ALLOWED,
        "RSoP should only accept POST"
    );
}

// ===========================================================================
// 3O. Invalid UUID in resource_id
// ===========================================================================

#[tokio::test]
async fn test_rsop_invalid_uuid() {
    let (ctx, cookie) = setup().await;

    let (status, _body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        "/api/v1/policies/rsop",
        None,
        Some(&cookie),
        Some(serde_json::json!({
            "resource_type": "Credential",
            "resource_id": "not-a-valid-uuid",
        })),
    )
    .await;
    assert!(
        status == StatusCode::BAD_REQUEST || status == StatusCode::UNPROCESSABLE_ENTITY,
        "invalid UUID should return 400/422, got {}",
        status
    );
}

// ===========================================================================
// 3P. principal_count matches matrix length
// ===========================================================================

#[tokio::test]
async fn test_rsop_principal_count_matches_matrix() {
    let (ctx, cookie) = setup_with_seed().await;
    let cred_id = get_first_credential_id(&ctx, &cookie).await;

    let (status, body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        "/api/v1/policies/rsop",
        None,
        Some(&cookie),
        Some(serde_json::json!({
            "resource_type": "Credential",
            "resource_id": cred_id,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let matrix = body["data"]["matrix"].as_array().expect("matrix");
    let principal_count = body["data"]["principal_count"]
        .as_u64()
        .expect("principal_count");
    assert_eq!(
        principal_count,
        matrix.len() as u64,
        "principal_count should match matrix length"
    );
}

// ===========================================================================
// 3Q. evaluated_at is valid RFC3339 timestamp
// ===========================================================================

#[tokio::test]
async fn test_rsop_evaluated_at_is_rfc3339() {
    let (ctx, cookie) = setup_with_seed().await;
    let cred_id = get_first_credential_id(&ctx, &cookie).await;

    let (status, body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        "/api/v1/policies/rsop",
        None,
        Some(&cookie),
        Some(serde_json::json!({
            "resource_type": "Credential",
            "resource_id": cred_id,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let evaluated_at = body["data"]["evaluated_at"]
        .as_str()
        .expect("evaluated_at string");
    let parsed = chrono::DateTime::parse_from_rfc3339(evaluated_at);
    assert!(
        parsed.is_ok(),
        "evaluated_at should be valid RFC3339: {}",
        evaluated_at
    );
}

// ===========================================================================
// 3R. Device entries only have device-applicable actions
// ===========================================================================

#[tokio::test]
async fn test_rsop_device_entries_have_correct_actions() {
    let (ctx, cookie) = setup_with_seed().await;
    let cred_id = get_first_credential_id(&ctx, &cookie).await;

    let (status, body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        "/api/v1/policies/rsop",
        None,
        Some(&cookie),
        Some(serde_json::json!({
            "resource_type": "Credential",
            "resource_id": cred_id,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let matrix = body["data"]["matrix"].as_array().expect("matrix");
    let device_entries: Vec<_> = matrix
        .iter()
        .filter(|e| e["principal_type"].as_str() == Some("Device"))
        .collect();

    for entry in &device_entries {
        let results = entry["results"].as_object().expect("results");
        // For Credential resource, devices should only have vend_credential
        assert!(
            results.contains_key("vend_credential"),
            "device entry should have vend_credential action"
        );
    }
}

// ===========================================================================
// 3S. Multiple agents with different permissions
// ===========================================================================

#[tokio::test]
async fn test_rsop_multiple_agents_different_decisions() {
    let (ctx, cookie) = setup_with_seed().await;
    let cred_id = get_first_credential_id(&ctx, &cookie).await;

    // Create additional agents with different tags
    common::create_agent_in_db(&*ctx.store, "rsop-admin-agent", vec!["admin"], true, None).await;
    common::create_agent_in_db(&*ctx.store, "rsop-basic-agent", vec![], true, None).await;

    let (status, body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        "/api/v1/policies/rsop",
        None,
        Some(&cookie),
        Some(serde_json::json!({
            "resource_type": "Credential",
            "resource_id": cred_id,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let matrix = body["data"]["matrix"].as_array().expect("matrix");
    // v2.0: principal_type may be "Agent" or "Workspace"
    let agent_entries: Vec<_> = matrix
        .iter()
        .filter(|e| {
            let pt = e["principal_type"].as_str().unwrap_or("");
            pt == "Agent" || pt == "Workspace"
        })
        .collect();

    // Admin agent should have different decisions than basic agent
    assert!(
        agent_entries.len() >= 2,
        "should have at least 2 agent/workspace entries, got {}",
        agent_entries.len()
    );

    // Find the admin agent entry
    let admin_entry = agent_entries.iter().find(|e| {
        e["principal_tags"]
            .as_array()
            .map(|tags| tags.iter().any(|t| t.as_str() == Some("admin")))
            .unwrap_or(false)
    });
    assert!(
        admin_entry.is_some(),
        "should have an admin-tagged agent in the matrix"
    );
}

// ===========================================================================
// 3T. Performance — RSoP with many agents responds in reasonable time
// ===========================================================================

#[tokio::test]
async fn test_rsop_performance_many_agents() {
    let (ctx, cookie) = setup_with_seed().await;
    let cred_id = get_first_credential_id(&ctx, &cookie).await;

    // Create 50 agents to test performance
    for i in 0..50 {
        common::create_agent_in_db(
            &*ctx.store,
            &format!("perf-agent-{}", i),
            vec!["perf"],
            true,
            None,
        )
        .await;
    }

    let start = std::time::Instant::now();

    let (status, body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        "/api/v1/policies/rsop",
        None,
        Some(&cookie),
        Some(serde_json::json!({
            "resource_type": "Credential",
            "resource_id": cred_id,
        })),
    )
    .await;

    let elapsed = start.elapsed();
    assert_eq!(status, StatusCode::OK, "RSoP should succeed: {:?}", body);

    // Should complete within 5 seconds even with 50+ agents
    assert!(
        elapsed.as_secs() < 5,
        "RSoP with 50+ agents should complete within 5s, took {:?}",
        elapsed
    );

    let matrix = body["data"]["matrix"].as_array().expect("matrix");
    assert!(
        matrix.len() >= 50,
        "matrix should include at least 50 entries, got {}",
        matrix.len()
    );
}

// ===========================================================================
// 3U. Performance — RSoP with limit bounds response size
// ===========================================================================

#[tokio::test]
async fn test_rsop_performance_limit_bounds_response() {
    let (ctx, cookie) = setup_with_seed().await;
    let cred_id = get_first_credential_id(&ctx, &cookie).await;

    // Create 20 agents
    for i in 0..20 {
        common::create_agent_in_db(
            &*ctx.store,
            &format!("limit-agent-{}", i),
            vec![],
            true,
            None,
        )
        .await;
    }

    let (status, body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        "/api/v1/policies/rsop",
        None,
        Some(&cookie),
        Some(serde_json::json!({
            "resource_type": "Credential",
            "resource_id": cred_id,
            "limit": 5,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let matrix = body["data"]["matrix"].as_array().expect("matrix");
    assert!(
        matrix.len() <= 5,
        "with limit=5, matrix should have at most 5 entries, got {}",
        matrix.len()
    );
}

// ===========================================================================
// 3V. Conditional policy detection — tool-specific
// ===========================================================================

#[tokio::test]
async fn test_rsop_detects_tool_specific_conditional_policy() {
    let (ctx, cookie) = setup_with_seed().await;

    // Create an MCP server in the store
    let (device_id, _) = common::create_standalone_device(&ctx.state).await;
    let d_uuid = agent_cordon_core::domain::workspace::WorkspaceId(
        uuid::Uuid::parse_str(&device_id).unwrap(),
    );
    let now = chrono::Utc::now();
    let mcp = agent_cordon_core::domain::mcp::McpServer {
        id: agent_cordon_core::domain::mcp::McpServerId(uuid::Uuid::new_v4()),
        workspace_id: d_uuid,
        name: "conditional-mcp".to_string(),
        upstream_url: "http://localhost:9999".to_string(),
        transport: agent_cordon_core::domain::mcp::McpTransport::Http,
        allowed_tools: None,
        enabled: true,
        created_by: None,
        created_at: now,
        updated_at: now,
        tags: vec![],
        required_credentials: None,
        auth_method: agent_cordon_core::domain::mcp::McpAuthMethod::default(),
        template_key: None,
        discovered_tools: None,
        created_by_user: None,
    };
    ctx.store
        .create_mcp_server(&mcp)
        .await
        .expect("create mcp server");
    let server_id = mcp.id.0.to_string();

    // Create a tool-specific conditional policy
    let (status, _) = common::send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        "/api/v1/policies",
        None,
        Some(&cookie),
        Some(serde_json::json!({
            "name": "tool-specific-test",
            "description": "Policy dependent on tool name",
            "cedar_policy": r#"forbid(
                principal is AgentCordon::Workspace,
                action == AgentCordon::Action::"mcp_tool_call",
                resource is AgentCordon::McpServer
            ) when {
                context.tool_name == "dangerous_tool"
            };"#,
        })),
    )
    .await;
    assert!(status == StatusCode::OK || status == StatusCode::CREATED);

    let (status, body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        "/api/v1/policies/rsop",
        None,
        Some(&cookie),
        Some(serde_json::json!({
            "resource_type": "McpServer",
            "resource_id": server_id,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let conditional = body["data"]["conditional_policies"]
        .as_array()
        .expect("conditional");
    let has_tool_specific = conditional
        .iter()
        .any(|c| c["condition_type"].as_str() == Some("tool-specific"));
    assert!(
        has_tool_specific,
        "should detect tool-specific conditional policy. Got: {:?}",
        conditional
    );
}
