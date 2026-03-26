//! v1.7.0 — Cross-Feature Integration Tests
//!
//! Tests that span multiple features:
//! - install.sh + enrollment (E2E — device-side, ignored)
//! - MCP policy generation idempotency

use axum::http::{Method, StatusCode};
use serde_json::json;
use uuid::Uuid;

use agent_cordon_core::domain::mcp::{McpServer, McpServerId};
use agent_cordon_core::domain::user::UserRole;
use agent_cordon_core::storage::Store;

use agent_cordon_server::test_helpers::TestAppBuilder;

use crate::common::*;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async fn create_mcp_server_in_store(
    store: &(dyn Store + Send + Sync),
    name: &str,
    upstream_url: &str,
) -> McpServer {
    // Create a test device for this MCP server
    let device = agent_cordon_core::domain::workspace::Workspace {
        id: agent_cordon_core::domain::workspace::WorkspaceId(Uuid::new_v4()),
        name: format!("test-workspace-{}", name),
        enabled: true,
        status: agent_cordon_core::domain::workspace::WorkspaceStatus::Active,
        pk_hash: None,
        encryption_public_key: None,
        tags: vec![],
        owner_id: None,
        parent_id: None,
        tool_name: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };
    store
        .create_workspace(&device)
        .await
        .expect("create test device");
    let now = chrono::Utc::now();
    let server = McpServer {
        id: McpServerId(Uuid::new_v4()),
        workspace_id: device.id,
        name: name.to_string(),
        upstream_url: upstream_url.to_string(),
        transport: "http".to_string(),
        allowed_tools: None,
        enabled: true,
        created_by: None,
        created_at: now,
        updated_at: now,
        tags: vec![],
        required_credentials: None,
    };
    store
        .create_mcp_server(&server)
        .await
        .expect("create mcp server");
    server
}

async fn setup_admin(app: &axum::Router, store: &(dyn Store + Send + Sync)) -> (String, String) {
    create_user_in_db(
        store,
        "cross-admin",
        TEST_PASSWORD,
        UserRole::Admin,
        false,
        true,
    )
    .await;
    let cookie = login_user_combined(app, "cross-admin", TEST_PASSWORD).await;
    let csrf = extract_csrf_from_cookie(&cookie).unwrap();
    (cookie, csrf)
}

// ===========================================================================
// Cross-Feature: install.sh + enrollment (device-side — ignored)
// ===========================================================================

// ===========================================================================
// Cross-Feature: MCP policy generation idempotency
// ===========================================================================

#[tokio::test]
async fn test_regenerate_policies_idempotent() {
    let ctx = TestAppBuilder::new()
        .with_config(|c| c.proxy_allow_loopback = true)
        .build()
        .await;
    let (cookie, csrf) = setup_admin(&ctx.app, &*ctx.store).await;

    let mcp = create_mcp_server_in_store(&*ctx.store, "idem-slack", "http://localhost:9999").await;

    let gen_url = format!("/api/v1/mcp-servers/{}/generate-policies", mcp.id.0);
    let gen_body = json!({
        "tools": ["send_message"],
        "agent_tags": ["ops"]
    });

    // Generate policies once
    let (status1, body1) = send_json(
        &ctx.app,
        Method::POST,
        &gen_url,
        None,
        Some(&cookie),
        Some(&csrf),
        Some(gen_body.clone()),
    )
    .await;
    assert_eq!(status1, StatusCode::OK);
    let created1 = body1["data"]["policies_created"]
        .as_array()
        .expect("first gen");
    assert_eq!(created1.len(), 1, "should create 1 policy");

    // Generate again — should skip duplicates
    let (status2, body2) = send_json(
        &ctx.app,
        Method::POST,
        &gen_url,
        None,
        Some(&cookie),
        Some(&csrf),
        Some(gen_body),
    )
    .await;
    assert_eq!(status2, StatusCode::OK);
    let created2 = body2["data"]["policies_created"]
        .as_array()
        .expect("second gen");
    assert_eq!(
        created2.len(),
        0,
        "duplicate policies should be skipped: {}",
        body2
    );
}
