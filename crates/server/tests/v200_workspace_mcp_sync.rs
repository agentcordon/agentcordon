//! v2.0 — Workspace MCP server sync endpoint tests.
//!
//! Tests the `GET /api/v1/workspaces/mcp-servers` endpoint which allows
//! authenticated workspaces to discover their MCP servers.

use axum::http::{Method, StatusCode};
use uuid::Uuid;

use agent_cordon_core::domain::mcp::{McpServer, McpServerId};
use agent_cordon_core::domain::workspace::WorkspaceId;
use agent_cordon_core::storage::Store;

use crate::common::*;
use agent_cordon_server::test_helpers::TestAppBuilder;

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
        allowed_tools: Some(vec!["tool_a".to_string(), "tool_b".to_string()]),
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
// 1. Workspace fetches its own MCP servers
// ===========================================================================

#[tokio::test]
async fn test_workspace_mcp_sync_returns_own_servers() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let ws = ctx.admin_agent.as_ref().unwrap();

    // Create two MCP servers for this workspace (1 enabled, 1 disabled)
    let _s1 = create_mcp_server_for_workspace(&*ctx.store, &ws.id, "github-mcp", true).await;
    let _s2 = create_mcp_server_for_workspace(&*ctx.store, &ws.id, "slack-mcp", true).await;
    let _s3 = create_mcp_server_for_workspace(&*ctx.store, &ws.id, "disabled-mcp", false).await;

    let jwt = ctx_admin_jwt(&ctx).await;

    let (status, body) = send_json(
        &ctx.app,
        Method::GET,
        "/api/v1/workspaces/mcp-servers",
        Some(&jwt),
        None,
        None,
        None,
    )
    .await;

    assert_eq!(status, StatusCode::OK, "mcp sync: {}", body);
    let servers = body["data"]["servers"].as_array().unwrap();

    // Only enabled servers should be returned
    assert_eq!(
        servers.len(),
        2,
        "should return 2 enabled servers (not the disabled one): {:?}",
        servers
    );

    let names: Vec<&str> = servers
        .iter()
        .map(|s| s["name"].as_str().unwrap())
        .collect();
    assert!(names.contains(&"github-mcp"), "should include github-mcp");
    assert!(names.contains(&"slack-mcp"), "should include slack-mcp");
    assert!(
        !names.contains(&"disabled-mcp"),
        "should NOT include disabled-mcp"
    );

    // Verify structure of each entry
    for server in servers {
        assert!(server["id"].is_string(), "server should have id");
        assert!(server["name"].is_string(), "server should have name");
        assert!(
            server["transport"].is_string(),
            "server should have transport"
        );
    }
}

// ===========================================================================
// 2. Unauthenticated request -> 401
// ===========================================================================

#[tokio::test]
async fn test_workspace_mcp_sync_unauthenticated_rejected() {
    let ctx = TestAppBuilder::new().with_admin().build().await;

    let (status, _body) = send_json(
        &ctx.app,
        Method::GET,
        "/api/v1/workspaces/mcp-servers",
        None, // no bearer
        None,
        None,
        None,
    )
    .await;

    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "unauthenticated MCP sync should be 401"
    );
}

// ===========================================================================
// 3. WS-A only sees own MCP servers, not WS-B's
// ===========================================================================

#[tokio::test]
async fn test_workspace_mcp_sync_does_not_leak_other_workspaces() {
    let ctx = TestAppBuilder::new()
        .with_admin()
        .with_agent("ws-b", &[])
        .build()
        .await;

    let ws_a = ctx.admin_agent.as_ref().unwrap();
    let ws_b = ctx.agents.get("ws-b").unwrap();

    // Create MCP servers for each workspace
    let _a1 = create_mcp_server_for_workspace(&*ctx.store, &ws_a.id, "ws-a-server", true).await;
    let _b1 = create_mcp_server_for_workspace(&*ctx.store, &ws_b.id, "ws-b-server", true).await;

    // WS-A fetches its MCP servers
    let jwt_a = ctx_admin_jwt(&ctx).await;
    let (status, body) = send_json(
        &ctx.app,
        Method::GET,
        "/api/v1/workspaces/mcp-servers",
        Some(&jwt_a),
        None,
        None,
        None,
    )
    .await;

    assert_eq!(status, StatusCode::OK, "ws-a sync: {}", body);
    let servers = body["data"]["servers"].as_array().unwrap();
    let names: Vec<&str> = servers
        .iter()
        .map(|s| s["name"].as_str().unwrap())
        .collect();

    assert!(
        names.contains(&"ws-a-server"),
        "WS-A should see its own server"
    );
    assert!(
        names.contains(&"ws-b-server"),
        "WS-A should see WS-B's server (MCP servers are a global catalog)"
    );

    // WS-B fetches its MCP servers
    let jwt_b = ctx_agent_jwt(&ctx, "ws-b").await;
    let (status, body) = send_json(
        &ctx.app,
        Method::GET,
        "/api/v1/workspaces/mcp-servers",
        Some(&jwt_b),
        None,
        None,
        None,
    )
    .await;

    assert_eq!(status, StatusCode::OK, "ws-b sync: {}", body);
    let servers = body["data"]["servers"].as_array().unwrap();
    let names: Vec<&str> = servers
        .iter()
        .map(|s| s["name"].as_str().unwrap())
        .collect();

    assert!(
        names.contains(&"ws-b-server"),
        "WS-B should see its own server"
    );
    assert!(
        names.contains(&"ws-a-server"),
        "WS-B should see WS-A's server (MCP servers are a global catalog)"
    );
}
