//! v2.01 — MCP tool-call authorization endpoint tests.
//!
//! Tests the `POST /api/v1/workspaces/mcp-authorize` endpoint which evaluates
//! Cedar policy for MCP tool calls and returns permit/forbid decisions.

use axum::http::{Method, StatusCode};
use uuid::Uuid;

use agent_cordon_core::domain::mcp::{McpServer, McpServerId};
use agent_cordon_core::domain::workspace::WorkspaceId;
use agent_cordon_core::storage::Store;

use crate::common::*;
use agent_cordon_server::test_helpers::TestAppBuilder;
use serde_json::json;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async fn create_mcp_server_for_workspace(
    store: &(dyn Store + Send + Sync),
    workspace_id: &WorkspaceId,
    name: &str,
    enabled: bool,
) -> McpServerId {
    let now = chrono::Utc::now();
    let server = McpServer {
        id: McpServerId(Uuid::new_v4()),
        workspace_id: workspace_id.clone(),
        name: name.to_string(),
        upstream_url: format!("http://localhost:9999/{}", name),
        transport: "stdio".to_string(),
        allowed_tools: Some(vec!["list_issues".to_string(), "create_pr".to_string()]),
        enabled,
        created_by: None,
        created_at: now,
        updated_at: now,
        tags: vec![],
        required_credentials: None,
    };
    store
        .create_mcp_server(&server)
        .await
        .expect("create MCP server");
    server.id
}

// ===========================================================================
// 1. Permit — default policy allows mcp_tool_call on enabled servers
// ===========================================================================

#[tokio::test]
async fn test_mcp_authorize_permit_with_policy() {
    // Default policy includes permit for mcp_tool_call on enabled McpServer
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let ws = ctx.admin_agent.as_ref().unwrap();

    let _server_id =
        create_mcp_server_for_workspace(&*ctx.store, &ws.id, "github", true).await;

    let jwt = ctx_admin_jwt(&ctx).await;

    let (status, body) = send_json(
        &ctx.app,
        Method::POST,
        "/api/v1/workspaces/mcp-authorize",
        Some(&jwt),
        None,
        None,
        Some(json!({
            "server_name": "github",
            "tool_name": "list_issues"
        })),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "mcp-authorize: {}", body);
    let data = &body["data"];
    assert_eq!(
        data["decision"].as_str().unwrap(),
        "permit",
        "should permit with default policy: {}",
        body
    );
    assert!(
        data["correlation_id"].as_str().is_some(),
        "should include correlation_id"
    );

    // Reasons should reference at least one policy
    let reasons = data["reasons"].as_array().unwrap();
    assert!(
        !reasons.is_empty(),
        "permit decision should include policy reasons"
    );
}

// ===========================================================================
// 2. Forbid — no mcp_tool_call policy → deny-by-default
// ===========================================================================

#[tokio::test]
async fn test_mcp_authorize_forbid_no_policy() {
    // Use a minimal custom policy that does NOT include mcp_tool_call permission
    let ctx = TestAppBuilder::new()
        .with_policy(
            r#"
permit(
  principal is AgentCordon::Workspace,
  action == AgentCordon::Action::"list",
  resource is AgentCordon::System
);
"#,
        )
        .with_admin()
        .build()
        .await;

    let ws = ctx.admin_agent.as_ref().unwrap();
    let _server_id =
        create_mcp_server_for_workspace(&*ctx.store, &ws.id, "github", true).await;

    let jwt = ctx_admin_jwt(&ctx).await;

    let (status, body) = send_json(
        &ctx.app,
        Method::POST,
        "/api/v1/workspaces/mcp-authorize",
        Some(&jwt),
        None,
        None,
        Some(json!({
            "server_name": "github",
            "tool_name": "list_issues"
        })),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "mcp-authorize: {}", body);
    let data = &body["data"];
    assert_eq!(
        data["decision"].as_str().unwrap(),
        "forbid",
        "should forbid when no mcp_tool_call policy exists: {}",
        body
    );
}

// ===========================================================================
// 3. Unknown server → forbid with "unknown_server" reason
// ===========================================================================

#[tokio::test]
async fn test_mcp_authorize_unknown_server() {
    let ctx = TestAppBuilder::new().with_admin().build().await;

    let jwt = ctx_admin_jwt(&ctx).await;

    let (status, body) = send_json(
        &ctx.app,
        Method::POST,
        "/api/v1/workspaces/mcp-authorize",
        Some(&jwt),
        None,
        None,
        Some(json!({
            "server_name": "nonexistent-server",
            "tool_name": "some_tool"
        })),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "mcp-authorize: {}", body);
    let data = &body["data"];
    assert_eq!(
        data["decision"].as_str().unwrap(),
        "forbid",
        "should forbid for unknown server"
    );

    let reasons = data["reasons"].as_array().unwrap();
    let has_unknown_server = reasons
        .iter()
        .any(|r| r["reason"].as_str() == Some("unknown_server"));
    assert!(
        has_unknown_server,
        "reasons should include 'unknown_server': {:?}",
        reasons
    );
}

// ===========================================================================
// 4. Unauthenticated → 401
// ===========================================================================

#[tokio::test]
async fn test_mcp_authorize_unauthenticated() {
    let ctx = TestAppBuilder::new().with_admin().build().await;

    let (status, _body) = send_json(
        &ctx.app,
        Method::POST,
        "/api/v1/workspaces/mcp-authorize",
        None, // no bearer token
        None,
        None,
        Some(json!({
            "server_name": "github",
            "tool_name": "list_issues"
        })),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "unauthenticated mcp-authorize should be 401"
    );
}

// ===========================================================================
// 5. Cross-workspace isolation — WS-B cannot authorize on WS-A's servers
// ===========================================================================

#[tokio::test]
async fn test_mcp_authorize_cross_workspace_isolation() {
    let ctx = TestAppBuilder::new()
        .with_admin()
        .with_agent("ws-b", &[])
        .build()
        .await;

    let ws_a = ctx.admin_agent.as_ref().unwrap();

    // Create MCP server belonging to WS-A only
    let _server_id =
        create_mcp_server_for_workspace(&*ctx.store, &ws_a.id, "ws-a-only-server", true).await;

    // WS-B tries to authorize a tool call on WS-A's server
    let jwt_b = ctx_agent_jwt(&ctx, "ws-b").await;

    let (status, body) = send_json(
        &ctx.app,
        Method::POST,
        "/api/v1/workspaces/mcp-authorize",
        Some(&jwt_b),
        None,
        None,
        Some(json!({
            "server_name": "ws-a-only-server",
            "tool_name": "list_issues"
        })),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "cross-ws mcp-authorize: {}", body);
    let data = &body["data"];
    assert_eq!(
        data["decision"].as_str().unwrap(),
        "forbid",
        "WS-B should be forbidden from WS-A's server: {}",
        body
    );

    // Should report unknown_server since the lookup is workspace-scoped
    let reasons = data["reasons"].as_array().unwrap();
    let has_unknown = reasons
        .iter()
        .any(|r| r["reason"].as_str() == Some("unknown_server"));
    assert!(
        has_unknown,
        "cross-workspace should report unknown_server (server not found for WS-B): {:?}",
        reasons
    );
}

// ===========================================================================
// 6. Disabled server → forbid even when permit policy exists
// ===========================================================================

#[tokio::test]
async fn test_mcp_authorize_disabled_server_denied() {
    // Default policy has both permit (resource.enabled) and forbid (!resource.enabled)
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let ws = ctx.admin_agent.as_ref().unwrap();

    // Create a DISABLED MCP server
    let _server_id =
        create_mcp_server_for_workspace(&*ctx.store, &ws.id, "disabled-server", false).await;

    let jwt = ctx_admin_jwt(&ctx).await;

    let (status, body) = send_json(
        &ctx.app,
        Method::POST,
        "/api/v1/workspaces/mcp-authorize",
        Some(&jwt),
        None,
        None,
        Some(json!({
            "server_name": "disabled-server",
            "tool_name": "list_issues"
        })),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "disabled-server mcp-authorize: {}", body);
    let data = &body["data"];
    assert_eq!(
        data["decision"].as_str().unwrap(),
        "forbid",
        "disabled server should be forbidden even with permit policy: {}",
        body
    );
}
