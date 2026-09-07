//! Integration tests — issue #37: consolidate MCP↔workspace relationship onto
//! the `mcp_server_workspaces` junction table as the single source of truth.
//!
//! Symptom that motivated this: the workspace detail page's "MCP Servers" tab
//! (which calls `GET /api/v1/mcp-servers?workspace_id=<id>`) was returning no
//! results because the endpoint read from the legacy denormalized
//! `mcp_servers.workspace_id` column instead of the junction.

use axum::http::{Method, StatusCode};
use serde_json::Value;
use uuid::Uuid;

use agent_cordon_core::domain::mcp::{McpAuthMethod, McpServer, McpServerId, McpTransport};
use agent_cordon_core::domain::user::{User, UserRole};
use agent_cordon_core::domain::workspace::{Workspace, WorkspaceId, WorkspaceStatus};
use agent_cordon_server::test_helpers::{TestAppBuilder, TestContext};

use crate::common;

async fn make_admin(ctx: &TestContext, username: &str) -> User {
    common::create_test_user(
        &*ctx.store,
        username,
        common::TEST_PASSWORD,
        UserRole::Admin,
    )
    .await
}

async fn make_workspace(ctx: &TestContext, name: &str, owner: &User) -> Workspace {
    let now = chrono::Utc::now();
    let ws = Workspace {
        id: WorkspaceId(Uuid::new_v4()),
        name: name.to_string(),
        status: WorkspaceStatus::Active,
        pk_hash: None,
        encryption_public_key: None,
        tags: vec![],
        owner_id: Some(owner.id.clone()),
        parent_id: None,
        tool_name: None,
        created_at: now,
        updated_at: now,
    };
    ctx.store.create_workspace(&ws).await.expect("create ws");
    ws
}

/// Create an MCP server whose legacy `workspace_id` column points at
/// `anchor_ws`, and bind it via the junction *only* to `bound_ws`. This
/// simulates the post-migration state of an MCP that was originally
/// provisioned for one workspace and later re-bound elsewhere.
async fn make_mcp_bound_to(
    ctx: &TestContext,
    name: &str,
    anchor_ws: &Workspace,
    bound_ws: &Workspace,
    owner: &User,
) -> McpServer {
    let now = chrono::Utc::now();
    let mcp = McpServer {
        id: McpServerId(Uuid::new_v4()),
        workspace_id: Some(anchor_ws.id.clone()),
        name: name.to_string(),
        upstream_url: format!("https://example.test/{}", name),
        transport: McpTransport::Http,
        allowed_tools: None,
        enabled: true,
        created_by: None,
        created_at: now,
        updated_at: now,
        tags: vec![],
        required_credentials: None,
        auth_method: McpAuthMethod::None,
        template_key: None,
        discovered_tools: None,
        created_by_user: Some(owner.id.clone()),
    };
    ctx.store.create_mcp_server(&mcp).await.expect("create mcp");
    ctx.store
        .add_mcp_server_workspace(&mcp.id, &bound_ws.id, Some(&owner.id))
        .await
        .expect("bind to target workspace via junction");
    mcp
}

#[tokio::test]
async fn create_mcp_server_does_not_write_legacy_workspace_id_column() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let admin = make_admin(&ctx, "store-admin").await;
    let ws = make_workspace(&ctx, "store-ws", &admin).await;

    // The struct may carry a workspace_id (legacy callers), but the store
    // layer is expected to drop it on the write path (#37 phase-out).
    let now = chrono::Utc::now();
    let mcp = McpServer {
        id: McpServerId(Uuid::new_v4()),
        workspace_id: Some(ws.id.clone()),
        name: "phase-out-mcp".to_string(),
        upstream_url: "https://example.test/x".to_string(),
        transport: McpTransport::Http,
        allowed_tools: None,
        enabled: true,
        created_by: None,
        created_at: now,
        updated_at: now,
        tags: vec![],
        required_credentials: None,
        auth_method: McpAuthMethod::None,
        template_key: None,
        discovered_tools: None,
        created_by_user: Some(admin.id.clone()),
    };
    ctx.store.create_mcp_server(&mcp).await.expect("create mcp");

    let retrieved = ctx
        .store
        .get_mcp_server(&mcp.id)
        .await
        .expect("get_mcp_server")
        .expect("mcp row exists");

    assert!(
        retrieved.workspace_id.is_none(),
        "store.create_mcp_server must drop the legacy workspace_id on write — \
         post-#37 junction is the single source of truth. Got: {:?}",
        retrieved.workspace_id
    );
}

#[tokio::test]
async fn list_mcp_servers_filtered_by_workspace_reads_junction_not_legacy_column() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let admin = make_admin(&ctx, "consol-admin").await;
    let (session, csrf) = common::login_user(&ctx.app, "consol-admin", common::TEST_PASSWORD).await;
    let cookie = common::combined_cookie(&session, &csrf);

    let ws_target = make_workspace(&ctx, "target-ws", &admin).await;
    let ws_anchor = make_workspace(&ctx, "anchor-ws", &admin).await;

    // MCP whose legacy column points at anchor-ws, junction binds to target-ws.
    let mcp = make_mcp_bound_to(&ctx, "consol-mcp", &ws_anchor, &ws_target, &admin).await;

    let uri = format!("/api/v1/mcp-servers?workspace_id={}", ws_target.id.0);
    let (status, body) =
        common::send_json(&ctx.app, Method::GET, &uri, None, Some(&cookie), None, None).await;

    assert_eq!(status, StatusCode::OK, "list endpoint failed: {}", body);

    let items: &Vec<Value> = body["data"]
        .as_array()
        .expect("response data should be an array");
    let ids: Vec<String> = items
        .iter()
        .filter_map(|v| v["id"].as_str().map(|s| s.to_string()))
        .collect();

    assert!(
        ids.iter().any(|id| id == &mcp.id.0.to_string()),
        "workspace MCP listing should include junction-bound MCPs even when \
         the legacy workspace_id points elsewhere. Got ids: {:?}",
        ids
    );
}

/// Parity test (#41): for a workspace bound to N MCPs via the junction, the
/// two independent consumer paths must see the same set —
///   * admin filter   `GET /api/v1/mcp-servers?workspace_id=W`
///   * broker sync    `GET /api/v1/workspaces/mcp-servers` (workspace JWT)
/// This pins the "single source of truth" invariant from #37.
#[tokio::test]
async fn admin_filter_and_broker_sync_agree_on_junction_bound_mcps() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let admin = make_admin(&ctx, "parity-admin").await;
    let (session, csrf) = common::login_user(&ctx.app, "parity-admin", common::TEST_PASSWORD).await;
    let cookie = common::combined_cookie(&session, &csrf);

    let ws = make_workspace(&ctx, "parity-ws", &admin).await;
    let other = make_workspace(&ctx, "parity-other", &admin).await;

    // Bind two MCPs to ws via the junction. A *third* MCP is junction-bound
    // only to `other` — none of the three paths should return it for `ws`.
    let mcp_a = make_mcp_bound_to(&ctx, "parity-a", &ws, &ws, &admin).await;
    let mcp_b = make_mcp_bound_to(&ctx, "parity-b", &ws, &ws, &admin).await;
    let _mcp_other = make_mcp_bound_to(&ctx, "parity-other-only", &other, &other, &admin).await;

    let expected: std::collections::HashSet<String> = [mcp_a.name.clone(), mcp_b.name.clone()]
        .into_iter()
        .collect();

    // Path 1: admin filter
    let (status, body) = common::send_json(
        &ctx.app,
        Method::GET,
        &format!("/api/v1/mcp-servers?workspace_id={}", ws.id.0),
        None,
        Some(&cookie),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "admin filter: {}", body);
    let admin_names: std::collections::HashSet<String> = body["data"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v["name"].as_str().map(|s| s.to_string()))
        .collect();
    assert_eq!(
        admin_names, expected,
        "admin filter set diverges from junction bindings"
    );

    // Path 2: broker sync (workspace JWT)
    let jwt = common::issue_agent_jwt(&ctx.state, &ws).await;
    let (status, body) = common::send_json(
        &ctx.app,
        Method::GET,
        "/api/v1/workspaces/mcp-servers",
        Some(&jwt),
        None,
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "broker sync: {}", body);
    let broker_names: std::collections::HashSet<String> = body["data"]["servers"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v["name"].as_str().map(|s| s.to_string()))
        .collect();
    assert_eq!(
        broker_names, expected,
        "broker sync set diverges from junction bindings"
    );
}
