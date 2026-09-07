//! D10 — an MCP server must be disableable through `PUT /api/v1/mcp-servers/{id}`.
//!
//! `docs/granting-mcp-server-access.md` documents disabling twice: as security
//! property 4 (the default policy forbids `mcp_tool_call`/`mcp_list_tools` on a
//! disabled server) and as the immediate-revocation escape hatch for a shared
//! MCP. Both depend on the API accepting `enabled` on the update body.
//!
//! These tests drive the real router (server HTTP seam) end to end: disable via
//! the admin API, then observe the two consequences a broker sees — the server
//! drops out of workspace sync, and a tool call against it is refused.

use axum::http::{Method, StatusCode};
use serde_json::json;
use uuid::Uuid;

use agent_cordon_core::domain::audit::AuditEvent;
use agent_cordon_core::domain::mcp::{McpAuthMethod, McpServer, McpServerId, McpTransport};
use agent_cordon_core::domain::user::UserRole;
use agent_cordon_core::domain::workspace::WorkspaceId;
use agent_cordon_core::storage::{AuditFilter, Store};

use crate::common::*;
use agent_cordon_server::test_helpers::{TestAppBuilder, TestContext};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Create an MCP server bound (via the junction) to `workspace_id`.
async fn create_bound_mcp_server(
    store: &(dyn Store + Send + Sync),
    workspace_id: &WorkspaceId,
    name: &str,
) -> McpServerId {
    let now = chrono::Utc::now();
    let server = McpServer {
        id: McpServerId(Uuid::new_v4()),
        workspace_id: Some(workspace_id.clone()),
        name: name.to_string(),
        upstream_url: format!("http://localhost:9999/{}", name),
        transport: McpTransport::Http,
        allowed_tools: Some(vec!["list_issues".to_string(), "create_pr".to_string()]),
        enabled: true,
        created_by: None,
        created_at: now,
        updated_at: now,
        tags: vec![],
        required_credentials: None,
        auth_method: McpAuthMethod::default(),
        template_key: None,
        discovered_tools: None,
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

/// `PUT /api/v1/mcp-servers/{id}` as a logged-in admin user.
async fn put_update(
    ctx: &TestContext,
    cookie: &str,
    csrf: &str,
    id: &McpServerId,
    body: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    send_json(
        &ctx.app,
        Method::PUT,
        &format!("/api/v1/mcp-servers/{}", id.0),
        None,
        Some(cookie),
        Some(csrf),
        Some(body),
    )
    .await
}

/// Admin user + session cookie/csrf on a context that also has an admin workspace.
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

fn audit_type_str(t: &agent_cordon_core::domain::audit::AuditEventType) -> String {
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

// ===========================================================================
// 1. PUT {"enabled": false} disables, and {"enabled": true} restores
// ===========================================================================

#[tokio::test]
async fn test_mcp_server_can_be_disabled_and_reenabled_via_api() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let ws = ctx.admin_agent.as_ref().unwrap().id.clone();
    let (cookie, csrf) = admin_session(&ctx, "d10-admin-toggle").await;

    let id = create_bound_mcp_server(&*ctx.store, &ws, "toggle-mcp").await;

    // Disable.
    let (status, body) = put_update(&ctx, &cookie, &csrf, &id, json!({ "enabled": false })).await;
    assert_eq!(status, StatusCode::OK, "PUT enabled=false: {}", body);
    assert_eq!(
        body["data"]["enabled"], false,
        "update response must report the server disabled: {}",
        body
    );

    // The detail endpoint agrees.
    let (status, body) = send_json(
        &ctx.app,
        Method::GET,
        &format!("/api/v1/mcp-servers/{}", id.0),
        None,
        Some(&cookie),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "GET detail: {}", body);
    assert_eq!(
        body["data"]["enabled"], false,
        "detail must show enabled=false: {}",
        body
    );

    // Re-enable.
    let (status, body) = put_update(&ctx, &cookie, &csrf, &id, json!({ "enabled": true })).await;
    assert_eq!(status, StatusCode::OK, "PUT enabled=true: {}", body);
    assert_eq!(
        body["data"]["enabled"], true,
        "update response must report the server enabled again: {}",
        body
    );

    // A name-only update must not silently flip `enabled` back.
    let (status, body) = put_update(&ctx, &cookie, &csrf, &id, json!({ "enabled": false })).await;
    assert_eq!(status, StatusCode::OK, "PUT enabled=false: {}", body);
    let (status, body) =
        put_update(&ctx, &cookie, &csrf, &id, json!({ "name": "toggle-mcp-2" })).await;
    assert_eq!(status, StatusCode::OK, "PUT name-only: {}", body);
    assert_eq!(
        body["data"]["enabled"], false,
        "a name-only update must leave enabled untouched: {}",
        body
    );
}

// ===========================================================================
// 2. Disabling drops the server out of the broker's workspace sync
// ===========================================================================

#[tokio::test]
async fn test_disabled_mcp_server_is_omitted_from_workspace_sync() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let ws = ctx.admin_agent.as_ref().unwrap().id.clone();
    let (cookie, csrf) = admin_session(&ctx, "d10-admin-sync").await;

    let id = create_bound_mcp_server(&*ctx.store, &ws, "sync-mcp").await;
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
    assert_eq!(status, StatusCode::OK, "sync before disable: {}", body);
    let names: Vec<String> = body["data"]["servers"]
        .as_array()
        .expect("servers array")
        .iter()
        .filter_map(|s| s["name"].as_str().map(String::from))
        .collect();
    assert!(
        names.iter().any(|n| n == "sync-mcp"),
        "server must sync while enabled: {:?}",
        names
    );

    let (status, body) = put_update(&ctx, &cookie, &csrf, &id, json!({ "enabled": false })).await;
    assert_eq!(status, StatusCode::OK, "PUT enabled=false: {}", body);

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
    assert_eq!(status, StatusCode::OK, "sync after disable: {}", body);
    let names: Vec<String> = body["data"]["servers"]
        .as_array()
        .expect("servers array")
        .iter()
        .filter_map(|s| s["name"].as_str().map(String::from))
        .collect();
    assert!(
        !names.iter().any(|n| n == "sync-mcp"),
        "a disabled server must not sync to the broker: {:?}",
        names
    );
}

// ===========================================================================
// 3. Disabling refuses tool calls at the authorize endpoint
// ===========================================================================

#[tokio::test]
async fn test_disabled_mcp_server_tool_call_is_forbidden() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let ws = ctx.admin_agent.as_ref().unwrap().id.clone();
    let (cookie, csrf) = admin_session(&ctx, "d10-admin-authz").await;

    let id = create_bound_mcp_server(&*ctx.store, &ws, "authz-mcp").await;
    let jwt = ctx_admin_jwt(&ctx).await;

    let authorize = json!({ "server_name": "authz-mcp", "tool_name": "list_issues" });

    let (status, body) = send_json(
        &ctx.app,
        Method::POST,
        "/api/v1/workspaces/mcp-authorize",
        Some(&jwt),
        None,
        None,
        Some(authorize.clone()),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "authorize before disable: {}", body);
    assert_eq!(
        body["data"]["decision"], "permit",
        "an enabled server must permit: {}",
        body
    );

    let (status, body) = put_update(&ctx, &cookie, &csrf, &id, json!({ "enabled": false })).await;
    assert_eq!(status, StatusCode::OK, "PUT enabled=false: {}", body);

    let (status, body) = send_json(
        &ctx.app,
        Method::POST,
        "/api/v1/workspaces/mcp-authorize",
        Some(&jwt),
        None,
        None,
        Some(authorize),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "authorize after disable: {}", body);
    assert_eq!(
        body["data"]["decision"], "forbid",
        "a disabled server must refuse tool calls: {}",
        body
    );

    let denied = audit_events_of(&ctx, "mcp_tool_call_denied").await;
    assert!(
        denied
            .iter()
            .any(|e| e.metadata.get("server_name").and_then(|v| v.as_str()) == Some("authz-mcp")),
        "the refusal must be audited"
    );
}

// ===========================================================================
// 4. The enabled change is audited on McpServerUpdated
// ===========================================================================

#[tokio::test]
async fn test_disabling_is_recorded_in_the_update_audit_event() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let ws = ctx.admin_agent.as_ref().unwrap().id.clone();
    let (cookie, csrf) = admin_session(&ctx, "d10-admin-audit").await;

    let id = create_bound_mcp_server(&*ctx.store, &ws, "audit-mcp").await;

    let (status, body) = put_update(&ctx, &cookie, &csrf, &id, json!({ "enabled": false })).await;
    assert_eq!(status, StatusCode::OK, "PUT enabled=false: {}", body);

    let updates = audit_events_of(&ctx, "mcp_server_updated").await;
    assert!(
        updates.iter().any(|e| {
            e.metadata.get("server_name").and_then(|v| v.as_str()) == Some("audit-mcp")
                && e.metadata.get("enabled").and_then(|v| v.as_bool()) == Some(false)
        }),
        "McpServerUpdated must record the enabled change, got: {:?}",
        updates
            .iter()
            .map(|e| e.metadata.clone())
            .collect::<Vec<_>>()
    );
}
