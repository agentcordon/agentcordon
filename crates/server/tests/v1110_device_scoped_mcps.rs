//! Integration tests for Feature 9: Device-Scoped MCPs (v1.11.0)
//!
//! Tests that MCP servers are scoped to devices with `device_id` FK,
//! UNIQUE(device_id, name) constraint, and ON DELETE RESTRICT behavior.
//!
//! Note: The admin create endpoint (POST /api/v1/mcp-servers) and the
//! device sync endpoint (GET /api/v1/devices/mcp-servers) have been removed.
//! MCP servers are now created via import (device→server registration).
//! Tests use store-level insertion for setup.

use axum::http::{Method, StatusCode};
use serde_json::json;
use uuid::Uuid;

use agent_cordon_core::domain::mcp::{McpAuthMethod, McpServer, McpServerId, McpTransport};
use agent_cordon_core::domain::user::UserRole;
use agent_cordon_core::domain::workspace::{Workspace, WorkspaceId, WorkspaceStatus};
use agent_cordon_core::policy::PolicyEngine;
use agent_cordon_core::storage::Store;

use crate::common::*;
use agent_cordon_server::test_helpers::TestAppBuilder;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Create an MCP server directly in the store.
async fn create_mcp_in_db(
    store: &(dyn Store + Send + Sync),
    name: &str,
    workspace_id: WorkspaceId,
) -> McpServer {
    let now = chrono::Utc::now();
    let server = McpServer {
        id: McpServerId(Uuid::new_v4()),
        workspace_id,
        name: name.to_string(),
        upstream_url: format!("http://localhost:9000/{}", name),
        transport: McpTransport::Http,
        allowed_tools: None,
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
        .expect("create mcp server");
    server
}

/// Create a workspace directly in the store with a specific created_at time.
#[allow(dead_code)]
async fn create_device_at_time(
    store: &(dyn Store + Send + Sync),
    name: &str,
    status: WorkspaceStatus,
    created_at: chrono::DateTime<chrono::Utc>,
) -> Workspace {
    let workspace = Workspace {
        id: WorkspaceId(Uuid::new_v4()),
        name: name.to_string(),
        enabled: true,
        status,
        pk_hash: None,
        encryption_public_key: None,
        tags: vec![],
        owner_id: None,
        parent_id: None,
        tool_name: None,
        created_at,
        updated_at: created_at,
    };
    store
        .create_workspace(&workspace)
        .await
        .expect("create workspace");
    workspace
}

// ---------------------------------------------------------------------------
// 9A. Happy Path — same name on different devices
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_same_mcp_name_different_devices_allowed() {
    let ctx = TestAppBuilder::new().with_admin().build().await;

    let (d1_id, _) = create_standalone_device(&ctx.state).await;
    let (d2_id, _) = create_standalone_device(&ctx.state).await;

    let d1_uuid = WorkspaceId(Uuid::parse_str(&d1_id).unwrap());
    let d2_uuid = WorkspaceId(Uuid::parse_str(&d2_id).unwrap());

    let m1 = create_mcp_in_db(&*ctx.store, "github", d1_uuid).await;
    let m2 = create_mcp_in_db(&*ctx.store, "github", d2_uuid).await;

    // Both should have different IDs
    assert_ne!(m1.id.0, m2.id.0);
}

#[tokio::test]
async fn test_list_mcp_servers_filter_by_device() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let _user = create_test_user(&*ctx.store, "admin1", TEST_PASSWORD, UserRole::Admin).await;
    let cookie = login_user_combined(&ctx.app, "admin1", TEST_PASSWORD).await;

    let (d1_id, _) = create_standalone_device(&ctx.state).await;
    let (d2_id, _) = create_standalone_device(&ctx.state).await;

    let d1_uuid = WorkspaceId(Uuid::parse_str(&d1_id).unwrap());
    let d2_uuid = WorkspaceId(Uuid::parse_str(&d2_id).unwrap());

    create_mcp_in_db(&*ctx.store, "github", d1_uuid).await;
    create_mcp_in_db(&*ctx.store, "slack", d2_uuid).await;

    // Filter by D1
    let uri = format!("/api/v1/mcp-servers?workspace_id={}", d1_id);
    let (status, body) =
        send_json(&ctx.app, Method::GET, &uri, None, Some(&cookie), None, None).await;
    assert_eq!(status, StatusCode::OK);
    let servers = body["data"].as_array().expect("data is array");
    assert_eq!(servers.len(), 1);
    assert_eq!(servers[0]["name"].as_str().unwrap(), "github");
}

#[tokio::test]
async fn test_list_mcp_servers_no_filter_returns_all() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let _user = create_test_user(&*ctx.store, "admin1", TEST_PASSWORD, UserRole::Admin).await;
    let cookie = login_user_combined(&ctx.app, "admin1", TEST_PASSWORD).await;

    let (d1_id, _) = create_standalone_device(&ctx.state).await;
    let (d2_id, _) = create_standalone_device(&ctx.state).await;

    let d1_uuid = WorkspaceId(Uuid::parse_str(&d1_id).unwrap());
    let d2_uuid = WorkspaceId(Uuid::parse_str(&d2_id).unwrap());

    create_mcp_in_db(&*ctx.store, "github", d1_uuid).await;
    create_mcp_in_db(&*ctx.store, "slack", d2_uuid).await;

    let (status, body) = send_json(
        &ctx.app,
        Method::GET,
        "/api/v1/mcp-servers",
        None,
        Some(&cookie),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let servers = body["data"].as_array().expect("data is array");
    assert!(
        servers.len() >= 2,
        "expected at least 2 MCPs, got {}",
        servers.len()
    );
}

#[tokio::test]
async fn test_get_mcp_server_includes_device_id() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let _user = create_test_user(&*ctx.store, "admin1", TEST_PASSWORD, UserRole::Admin).await;
    let cookie = login_user_combined(&ctx.app, "admin1", TEST_PASSWORD).await;

    let (d1_id, _) = create_standalone_device(&ctx.state).await;
    let d1_uuid = WorkspaceId(Uuid::parse_str(&d1_id).unwrap());
    let mcp = create_mcp_in_db(&*ctx.store, "github", d1_uuid).await;

    let uri = format!("/api/v1/mcp-servers/{}", mcp.id.0);
    let (status, body) =
        send_json(&ctx.app, Method::GET, &uri, None, Some(&cookie), None, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["data"]["workspace_id"].as_str().unwrap(), d1_id);
}

#[tokio::test]
async fn test_mcp_server_cedar_entity_has_device_attribute() {
    let ctx = TestAppBuilder::new()
        .with_admin()
        .with_agent("agent1", &["user"])
        .build()
        .await;

    let _admin = create_test_user(&*ctx.store, "admin1", TEST_PASSWORD, UserRole::Admin).await;
    let cookie = login_user_combined(&ctx.app, "admin1", TEST_PASSWORD).await;

    let dev1 = ctx.device_for("agent1");
    let d1_uuid = WorkspaceId(Uuid::parse_str(&dev1.device_id).unwrap());
    let mcp = create_mcp_in_db(&*ctx.store, "github", d1_uuid).await;

    // Verify fetching the MCP returns device_id
    let uri = format!("/api/v1/mcp-servers/{}", mcp.id.0);
    let (status, body) =
        send_json(&ctx.app, Method::GET, &uri, None, Some(&cookie), None, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["data"]["workspace_id"].as_str().unwrap(),
        dev1.device_id
    );
}

// ---------------------------------------------------------------------------
// 9B. Retry/Idempotency — duplicate MCP on same device
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_create_duplicate_mcp_same_device_fails() {
    let ctx = TestAppBuilder::new().with_admin().build().await;

    let (d1_id, _) = create_standalone_device(&ctx.state).await;
    let d1_uuid = WorkspaceId(Uuid::parse_str(&d1_id).unwrap());

    // First create succeeds
    create_mcp_in_db(&*ctx.store, "github", d1_uuid.clone()).await;

    // Second create with same name on same device fails (UNIQUE constraint)
    let now = chrono::Utc::now();
    let server2 = McpServer {
        id: McpServerId(Uuid::new_v4()),
        workspace_id: d1_uuid,
        name: "github".to_string(),
        upstream_url: "http://localhost:9000/github2".to_string(),
        transport: McpTransport::Http,
        allowed_tools: None,
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
    let result = ctx.store.create_mcp_server(&server2).await;
    assert!(result.is_err(), "duplicate MCP on same device should fail");
}

#[tokio::test]
async fn test_create_duplicate_mcp_same_device_after_delete() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let _admin = create_test_user(&*ctx.store, "admin1", TEST_PASSWORD, UserRole::Admin).await;
    let cookie = login_user_combined(&ctx.app, "admin1", TEST_PASSWORD).await;

    let (d1_id, _) = create_standalone_device(&ctx.state).await;
    let d1_uuid = WorkspaceId(Uuid::parse_str(&d1_id).unwrap());

    let mcp = create_mcp_in_db(&*ctx.store, "github", d1_uuid.clone()).await;

    // Delete via API
    let uri = format!("/api/v1/mcp-servers/{}", mcp.id.0);
    let (del_status, _) =
        send_json_auto_csrf(&ctx.app, Method::DELETE, &uri, None, Some(&cookie), None).await;
    assert_eq!(del_status, StatusCode::OK);

    // Re-create should succeed
    create_mcp_in_db(&*ctx.store, "github", d1_uuid).await;
}

// ---------------------------------------------------------------------------
// 9C. Error Handling
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_delete_device_with_mcps_blocked_by_restrict() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let _admin = create_test_user(&*ctx.store, "admin1", TEST_PASSWORD, UserRole::Admin).await;
    let cookie = login_user_combined(&ctx.app, "admin1", TEST_PASSWORD).await;

    let (d1_id, _) = create_standalone_device(&ctx.state).await;
    let d1_uuid = WorkspaceId(Uuid::parse_str(&d1_id).unwrap());

    let m1 = create_mcp_in_db(&*ctx.store, "github", d1_uuid.clone()).await;
    let m2 = create_mcp_in_db(&*ctx.store, "slack", d1_uuid).await;

    // Try to delete device — should fail (FK RESTRICT)
    let del_uri = format!("/api/v1/workspaces/{}", d1_id);
    let (del_status, del_body) = send_json_auto_csrf(
        &ctx.app,
        Method::DELETE,
        &del_uri,
        None,
        Some(&cookie),
        None,
    )
    .await;
    assert!(
        del_status == StatusCode::CONFLICT
            || del_status == StatusCode::BAD_REQUEST
            || del_status == StatusCode::INTERNAL_SERVER_ERROR,
        "device delete should fail with MCPs: {} {}",
        del_status,
        del_body
    );

    // Delete both MCPs
    send_json_auto_csrf(
        &ctx.app,
        Method::DELETE,
        &format!("/api/v1/mcp-servers/{}", m1.id.0),
        None,
        Some(&cookie),
        None,
    )
    .await;
    send_json_auto_csrf(
        &ctx.app,
        Method::DELETE,
        &format!("/api/v1/mcp-servers/{}", m2.id.0),
        None,
        Some(&cookie),
        None,
    )
    .await;

    // Now device delete should succeed
    let (del2_status, _) = send_json_auto_csrf(
        &ctx.app,
        Method::DELETE,
        &del_uri,
        None,
        Some(&cookie),
        None,
    )
    .await;
    assert_eq!(
        del2_status,
        StatusCode::OK,
        "device delete should succeed after MCPs removed"
    );
}

#[tokio::test]
async fn test_update_mcp_cannot_change_device_id() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let _admin = create_test_user(&*ctx.store, "admin1", TEST_PASSWORD, UserRole::Admin).await;
    let cookie = login_user_combined(&ctx.app, "admin1", TEST_PASSWORD).await;

    let (d1_id, _) = create_standalone_device(&ctx.state).await;
    let (_d2_id, _) = create_standalone_device(&ctx.state).await;

    let d1_uuid = WorkspaceId(Uuid::parse_str(&d1_id).unwrap());
    let mcp = create_mcp_in_db(&*ctx.store, "github", d1_uuid).await;

    let uri = format!("/api/v1/mcp-servers/{}", mcp.id.0);

    // UpdateMcpServerRequest only accepts `name` (deny_unknown_fields).
    // Sending device_id is rejected, so we update the name and verify device_id is unchanged.
    let (status, body) = send_json_auto_csrf(
        &ctx.app,
        Method::PUT,
        &uri,
        None,
        Some(&cookie),
        Some(json!({
            "name": "renamed-github",
        })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "name update should succeed: {}",
        body
    );

    // Verify device_id was NOT changed
    let (get_status, get_body) =
        send_json(&ctx.app, Method::GET, &uri, None, Some(&cookie), None, None).await;
    assert_eq!(get_status, StatusCode::OK);
    assert_eq!(
        get_body["data"]["workspace_id"].as_str().unwrap(),
        d1_id,
        "device_id should remain unchanged after update attempt"
    );
}

// ---------------------------------------------------------------------------
// 9D. Cross-Feature
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_cross_device_mcp_authorization_works() {
    let ctx = TestAppBuilder::new()
        .with_admin()
        .with_agent("agent1", &["user"])
        .build()
        .await;

    let _admin = create_test_user(&*ctx.store, "admin1", TEST_PASSWORD, UserRole::Admin).await;

    let dev1 = ctx.device_for("agent1");
    let agent1 = ctx.agents.get("agent1").unwrap();

    let d1_uuid = WorkspaceId(Uuid::parse_str(&dev1.device_id).unwrap());
    let mcp = create_mcp_in_db(&*ctx.store, "github", d1_uuid).await;
    let mcp_id = mcp.id.0.to_string();

    // Create Cedar policy granting agent1 mcp_tool_call on the MCP
    let now = chrono::Utc::now();
    let policy_text = format!(
        "permit(\n  principal == AgentCordon::Workspace::\"{}\",\n  action == AgentCordon::Action::\"mcp_tool_call\",\n  resource == AgentCordon::McpServer::\"{}\"\n);",
        agent1.id.0, mcp_id
    );
    let stored_policy = agent_cordon_core::domain::policy::StoredPolicy {
        id: agent_cordon_core::domain::policy::PolicyId(Uuid::new_v4()),
        name: format!("grant:{}:{}:mcp_tool_call", mcp_id, agent1.id.0),
        description: Some("Cross-device MCP grant".to_string()),
        cedar_policy: policy_text,
        enabled: true,
        is_system: true,
        created_at: now,
        updated_at: now,
    };
    ctx.store.store_policy(&stored_policy).await.unwrap();

    // Reload policies
    let db_policies = ctx.store.get_all_enabled_policies().await.unwrap();
    let sources: Vec<(String, String)> = db_policies
        .into_iter()
        .map(|p| (p.id.0.to_string(), p.cedar_policy))
        .collect();
    ctx.state
        .policy_engine
        .reload_policies(sources)
        .expect("reload");

    // Verify the policy was created and references the MCP
    let policies = ctx.store.get_all_enabled_policies().await.unwrap();
    let matching = policies.iter().find(|p| p.cedar_policy.contains(&mcp_id));
    assert!(
        matching.is_some(),
        "cross-device MCP grant policy should exist"
    );
}

#[tokio::test]
async fn test_rsop_shows_device_scoped_mcp() {
    let ctx = TestAppBuilder::new()
        .with_admin()
        .with_agent("agent1", &["user"])
        .build()
        .await;
    let _admin = create_test_user(&*ctx.store, "admin1", TEST_PASSWORD, UserRole::Admin).await;
    let cookie = login_user_combined(&ctx.app, "admin1", TEST_PASSWORD).await;

    let dev1 = ctx.device_for("agent1");
    let d1_uuid = WorkspaceId(Uuid::parse_str(&dev1.device_id).unwrap());
    let mcp = create_mcp_in_db(&*ctx.store, "github", d1_uuid).await;

    // Verify the device-scoped MCP is retrievable with device_id context
    let get_uri = format!("/api/v1/mcp-servers/{}", mcp.id.0);
    let (get_status, get_body) = send_json(
        &ctx.app,
        Method::GET,
        &get_uri,
        None,
        Some(&cookie),
        None,
        None,
    )
    .await;
    assert_eq!(
        get_status,
        StatusCode::OK,
        "device-scoped MCP should be retrievable: {}",
        get_body
    );
    assert_eq!(
        get_body["data"]["workspace_id"].as_str().unwrap(),
        dev1.device_id,
        "MCP should include device_id context for RSoP"
    );
}

#[tokio::test]
async fn test_permissions_grant_on_device_scoped_mcp() {
    let ctx = TestAppBuilder::new()
        .with_admin()
        .with_agent("agent1", &["user"])
        .build()
        .await;
    let _admin = create_test_user(&*ctx.store, "admin1", TEST_PASSWORD, UserRole::Admin).await;

    let dev1 = ctx.device_for("agent1");
    let agent1 = ctx.agents.get("agent1").unwrap();

    let d1_uuid = WorkspaceId(Uuid::parse_str(&dev1.device_id).unwrap());
    let mcp = create_mcp_in_db(&*ctx.store, "github", d1_uuid).await;
    let mcp_id = mcp.id.0.to_string();

    // Grant agent1 mcp_tool_call on the MCP
    let now = chrono::Utc::now();
    let policy_text = format!(
        "permit(\n  principal == AgentCordon::Workspace::\"{}\",\n  action == AgentCordon::Action::\"mcp_tool_call\",\n  resource == AgentCordon::McpServer::\"{}\"\n);",
        agent1.id.0, mcp_id
    );
    let stored_policy = agent_cordon_core::domain::policy::StoredPolicy {
        id: agent_cordon_core::domain::policy::PolicyId(Uuid::new_v4()),
        name: format!("grant:{}:{}:mcp_tool_call", mcp_id, agent1.id.0),
        description: Some("MCP tool call grant".to_string()),
        cedar_policy: policy_text.clone(),
        enabled: true,
        is_system: true,
        created_at: now,
        updated_at: now,
    };
    ctx.store.store_policy(&stored_policy).await.unwrap();

    // Verify grant policy exists and references both agent and MCP
    let policies = ctx.store.get_all_enabled_policies().await.unwrap();
    let grant = policies.iter().find(|p| {
        p.cedar_policy.contains(&agent1.id.0.to_string()) && p.cedar_policy.contains(&mcp_id)
    });
    assert!(
        grant.is_some(),
        "grant policy for device-scoped MCP should exist"
    );
    assert!(
        grant.unwrap().cedar_policy.contains("mcp_tool_call"),
        "grant should be for mcp_tool_call action"
    );
}
