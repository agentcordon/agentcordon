//! S20 — per-tool MCP gating: what an operator can narrow, what a refusal
//! records, and what the two reference lists must name.
//!
//! Server HTTP seam (`TestAppBuilder` + `tower::ServiceExt::oneshot`) for the
//! behaviour, and the template sources for the two prose action references.
//! The UAT scenario that found these is
//! `uat/playwright/tests/22-s20-mcp-gating.spec.ts`.

use axum::http::{Method, StatusCode};
use serde_json::json;
use uuid::Uuid;

use agent_cordon_core::domain::audit::{AuditEvent, AuditEventType};
use agent_cordon_core::domain::mcp::{
    McpAuthMethod, McpServer, McpServerId, McpTool, McpTransport,
};
use agent_cordon_core::domain::user::UserRole;
use agent_cordon_core::domain::workspace::WorkspaceId;
use agent_cordon_core::storage::{AuditFilter, Store};

use crate::common::*;
use agent_cordon_server::test_helpers::{TestAppBuilder, TestContext};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn tool(name: &str) -> McpTool {
    McpTool {
        name: name.to_string(),
        description: Some(format!("the {name} tool")),
        input_schema: Some(json!({ "type": "object" })),
    }
}

/// An MCP server bound to `workspace_id` through the junction, with the four
/// tools the UAT scenario's mock server publishes.
async fn create_bound_mcp_server(
    store: &(dyn Store + Send + Sync),
    workspace_id: &WorkspaceId,
    name: &str,
) -> McpServerId {
    let now = chrono::Utc::now();
    let tools = vec![tool("echo"), tool("whoami"), tool("team_notice")];
    let server = McpServer {
        id: McpServerId(Uuid::new_v4()),
        workspace_id: Some(workspace_id.clone()),
        name: name.to_string(),
        upstream_url: format!("http://localhost:9999/{}", name),
        transport: McpTransport::Http,
        allowed_tools: Some(tools.iter().map(|t| t.name.clone()).collect()),
        enabled: true,
        created_by: None,
        created_at: now,
        updated_at: now,
        tags: vec![],
        required_credentials: None,
        auth_method: McpAuthMethod::default(),
        template_key: None,
        discovered_tools: Some(tools),
        created_by_user: None,
    };
    store
        .create_mcp_server(&server)
        .await
        .expect("create MCP server");
    store
        .add_mcp_server_workspace(&server.id, workspace_id, None)
        .await
        .expect("bind MCP server to workspace");
    server.id
}

/// Admin user + combined session cookie/csrf on a context that also has an
/// admin workspace.
async fn admin_session(ctx: &TestContext, username: &str) -> (String, String) {
    create_user_in_db(
        &*ctx.store,
        username,
        TEST_PASSWORD,
        UserRole::Admin,
        false,
        true,
    )
    .await;
    let (session, csrf) = login_user(&ctx.app, username, TEST_PASSWORD).await;
    (combined_cookie(&session, &csrf), csrf)
}

fn audit_type_str(t: &AuditEventType) -> String {
    serde_json::to_value(t)
        .ok()
        .and_then(|v| v.as_str().map(String::from))
        .unwrap_or_default()
}

async fn audit_events_of(ctx: &TestContext, event_type: &str) -> Vec<AuditEvent> {
    let filter = AuditFilter {
        limit: 1000,
        ..Default::default()
    };
    ctx.store
        .list_audit_events_filtered(&filter)
        .await
        .expect("list audit")
        .into_iter()
        .filter(|e| audit_type_str(&e.event_type) == event_type)
        .collect()
}

/// `POST /api/v1/workspaces/mcp-authorize` as the admin workspace.
async fn authorize(
    ctx: &TestContext,
    jwt: &str,
    server_name: &str,
    tool_name: &str,
) -> (StatusCode, serde_json::Value) {
    send_json(
        &ctx.app,
        Method::POST,
        "/api/v1/workspaces/mcp-authorize",
        Some(jwt),
        None,
        None,
        Some(json!({ "server_name": server_name, "tool_name": tool_name })),
    )
    .await
}

/// A policy set that permits everything except `whoami` on any MCP server —
/// the shape the Access tab's per-tool Deny writes.
const PER_TOOL_DENY: &str = r#"
permit(
  principal is AgentCordon::Workspace,
  action,
  resource
) when { principal.enabled };

permit(
  principal is AgentCordon::User,
  action,
  resource
);

forbid(
  principal is AgentCordon::Workspace,
  action == AgentCordon::Action::"mcp_tool_call",
  resource is AgentCordon::McpServer
) when { context.tool_name == "whoami" };
"#;

// ===========================================================================
// G-S20-5 — a tool call refused by policy writes an mcp_tool_call_denied row
// ===========================================================================

#[tokio::test]
async fn a_policy_refusal_writes_an_mcp_tool_call_denied_audit_row() {
    let ctx = TestAppBuilder::new()
        .with_policy(PER_TOOL_DENY)
        .with_admin()
        .build()
        .await;
    let ws = ctx.admin_agent.as_ref().unwrap();
    let ws_name = ws.name.clone();
    let ws_id = ws.id.clone();
    create_bound_mcp_server(&*ctx.store, &ws_id, "uat-none").await;
    let jwt = ctx_admin_jwt(&ctx).await;

    let (status, body) = authorize(&ctx, &jwt, "uat-none", "whoami").await;
    assert_eq!(status, StatusCode::OK, "mcp-authorize: {}", body);
    assert_eq!(
        body["data"]["decision"], "forbid",
        "the per-tool deny must refuse: {}",
        body
    );
    let correlation_id = body["data"]["correlation_id"].as_str().unwrap().to_string();

    let denied = audit_events_of(&ctx, "mcp_tool_call_denied").await;
    let row = denied
        .iter()
        .find(|e| e.correlation_id == correlation_id)
        .unwrap_or_else(|| {
            panic!(
                "a policy refusal must write mcp_tool_call_denied; rows: {:?}",
                denied
                    .iter()
                    .map(|e| e.metadata.clone())
                    .collect::<Vec<_>>()
            )
        });

    assert_eq!(
        row.metadata.get("server_name").and_then(|v| v.as_str()),
        Some("uat-none"),
        "the row names the server"
    );
    assert_eq!(
        row.metadata.get("tool_name").and_then(|v| v.as_str()),
        Some("whoami"),
        "the row names the tool"
    );
    assert_eq!(
        row.workspace_name.as_deref(),
        Some(ws_name.as_str()),
        "the row names the workspace that was refused"
    );
    assert_eq!(
        format!("{:?}", row.decision).to_lowercase(),
        "forbid",
        "the row is a forbid"
    );
    let reason = row
        .metadata
        .get("reason")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    assert!(
        !reason.is_empty() && reason != "unknown_server",
        "the row says why the call was refused, not 'unknown_server': {:?}",
        row.metadata
    );
}

#[tokio::test]
async fn a_permitted_tool_call_writes_no_denied_row() {
    let ctx = TestAppBuilder::new()
        .with_policy(PER_TOOL_DENY)
        .with_admin()
        .build()
        .await;
    let ws_id = ctx.admin_agent.as_ref().unwrap().id.clone();
    create_bound_mcp_server(&*ctx.store, &ws_id, "uat-none").await;
    let jwt = ctx_admin_jwt(&ctx).await;

    let (status, body) = authorize(&ctx, &jwt, "uat-none", "echo").await;
    assert_eq!(status, StatusCode::OK, "mcp-authorize: {}", body);
    assert_eq!(body["data"]["decision"], "permit", "{}", body);

    assert!(
        audit_events_of(&ctx, "mcp_tool_call_denied")
            .await
            .is_empty(),
        "a permitted call writes no denial"
    );
    assert_eq!(
        audit_events_of(&ctx, "mcp_tool_called").await.len(),
        1,
        "a permitted call writes the domain event"
    );
}

#[tokio::test]
async fn a_disabled_server_says_so_in_the_denied_row() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let ws_id = ctx.admin_agent.as_ref().unwrap().id.clone();
    let id = create_bound_mcp_server(&*ctx.store, &ws_id, "uat-none").await;
    let (cookie, csrf) = admin_session(&ctx, "s20-disable-admin").await;
    let (status, body) = send_json(
        &ctx.app,
        Method::PUT,
        &format!("/api/v1/mcp-servers/{}", id.0),
        None,
        Some(&cookie),
        Some(&csrf),
        Some(json!({ "enabled": false })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "PUT enabled=false: {}", body);

    let jwt = ctx_admin_jwt(&ctx).await;
    let (status, body) = authorize(&ctx, &jwt, "uat-none", "echo").await;
    assert_eq!(status, StatusCode::OK, "{}", body);
    assert_eq!(body["data"]["decision"], "forbid", "{}", body);

    let denied = audit_events_of(&ctx, "mcp_tool_call_denied").await;
    let row = denied.first().expect("a denial row");
    assert_eq!(
        row.metadata.get("reason").and_then(|v| v.as_str()),
        Some("server_disabled"),
        "a disabled server is not an unknown one: {:?}",
        row.metadata
    );
}

#[tokio::test]
async fn an_unknown_server_still_says_unknown_server() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let jwt = ctx_admin_jwt(&ctx).await;
    let (status, body) = authorize(&ctx, &jwt, "no-such-server", "echo").await;
    assert_eq!(status, StatusCode::OK, "{}", body);
    assert_eq!(body["data"]["decision"], "forbid", "{}", body);

    let denied = audit_events_of(&ctx, "mcp_tool_call_denied").await;
    let row = denied.first().expect("a denial row");
    assert_eq!(
        row.metadata.get("reason").and_then(|v| v.as_str()),
        Some("unknown_server"),
        "{:?}",
        row.metadata
    );
}
