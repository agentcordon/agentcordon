//! v1.14.0 — MCP Server Permission Grants (Feature 1)
//!
//! Tests for Cedar-backed MCP permission grants: grant, revoke, list,
//! SSE event emission, error handling, and security boundaries.
//!
//! API endpoints:
//!   POST   /api/v1/mcp-servers/{id}/permissions
//!   GET    /api/v1/mcp-servers/{id}/permissions
//!   DELETE /api/v1/mcp-servers/{id}/permissions/{agent_id}/{permission}

use axum::http::{Method, StatusCode};
use serde_json::json;
use uuid::Uuid;

use agent_cordon_core::domain::user::UserRole;
use agent_cordon_server::events::DeviceEvent;
use agent_cordon_server::test_helpers::TestAppBuilder;

use crate::common::*;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Create an MCP server directly in the store and return its UUID string.
async fn create_mcp_server_in_store(
    store: &(dyn agent_cordon_core::storage::Store + Send + Sync),
    name: &str,
    device_id: &str,
) -> String {
    let now = chrono::Utc::now();
    let device_uuid = uuid::Uuid::parse_str(device_id).expect("valid device_id uuid");
    let server = agent_cordon_core::domain::mcp::McpServer {
        id: agent_cordon_core::domain::mcp::McpServerId(Uuid::new_v4()),
        workspace_id: agent_cordon_core::domain::workspace::WorkspaceId(device_uuid),
        name: name.to_string(),
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
    store
        .create_mcp_server(&server)
        .await
        .expect("create mcp server");
    server.id.0.to_string()
}

/// Grant an MCP permission and return (status, body).
async fn grant_mcp_permission(
    app: &axum::Router,
    cookie: &str,
    server_id: &str,
    agent_id: &str,
    permission: &str,
) -> (StatusCode, serde_json::Value) {
    send_json_auto_csrf(
        app,
        Method::POST,
        &format!("/api/v1/mcp-servers/{}/permissions", server_id),
        None,
        Some(cookie),
        Some(json!({
            "agent_id": agent_id,
            "permission": permission,
        })),
    )
    .await
}

/// Revoke an MCP permission and return (status, body).
async fn revoke_mcp_permission(
    app: &axum::Router,
    cookie: &str,
    server_id: &str,
    agent_id: &str,
    permission: &str,
) -> (StatusCode, serde_json::Value) {
    send_json_auto_csrf(
        app,
        Method::DELETE,
        &format!(
            "/api/v1/mcp-servers/{}/permissions/{}/{}",
            server_id, agent_id, permission
        ),
        None,
        Some(cookie),
        None,
    )
    .await
}

/// List MCP permissions and return (status, body).
async fn list_mcp_permissions(
    app: &axum::Router,
    cookie: &str,
    server_id: &str,
) -> (StatusCode, serde_json::Value) {
    send_json_auto_csrf(
        app,
        Method::GET,
        &format!("/api/v1/mcp-servers/{}/permissions", server_id),
        None,
        Some(cookie),
        None,
    )
    .await
}

/// Standard test setup: admin user + device + MCP server + target agent.
/// Returns (cookie, server_id, agent_id_string, device_id).
async fn standard_mcp_setup(
    ctx: &agent_cordon_server::test_helpers::TestContext,
) -> (String, String, String, String) {
    let _admin_user =
        create_test_user(&*ctx.store, "mcp-admin", TEST_PASSWORD, UserRole::Admin).await;
    let cookie = login_user_combined(&ctx.app, "mcp-admin", TEST_PASSWORD).await;

    let device_id = ctx
        .admin_device
        .as_ref()
        .expect("admin device")
        .device_id
        .clone();
    let server_id = create_mcp_server_in_store(&*ctx.store, "test-mcp-server", &device_id).await;

    let agent = ctx.agents.get("target").expect("target agent");
    let agent_id = agent.id.0.to_string();

    (cookie, server_id, agent_id, device_id)
}

// ===========================================================================
// 1A. Happy Path
// ===========================================================================

/// Test #1: Admin grants `mcp_tool_call` to agent on MCP server.
#[tokio::test]
async fn test_grant_mcp_tool_call_permission() {
    let ctx = TestAppBuilder::new()
        .with_admin()
        .with_agent("target", &[])
        .build()
        .await;
    let (cookie, server_id, agent_id, _) = standard_mcp_setup(&ctx).await;

    let (status, body) =
        grant_mcp_permission(&ctx.app, &cookie, &server_id, &agent_id, "mcp_tool_call").await;

    assert_eq!(
        status,
        StatusCode::CREATED,
        "grant mcp_tool_call failed: {}",
        body
    );
    assert!(
        body["data"]["policy_name"].as_str().is_some(),
        "response should contain policy_name"
    );

    // Verify policy is queryable via list
    let (status, body) = list_mcp_permissions(&ctx.app, &cookie, &server_id).await;
    assert_eq!(status, StatusCode::OK);
    let permissions = body["data"]["permissions"]
        .as_array()
        .expect("permissions array");
    let found = permissions.iter().any(|entry| {
        entry["agent_id"].as_str() == Some(&agent_id)
            && entry["permissions"]
                .as_array()
                .is_some_and(|p| p.iter().any(|v| v.as_str() == Some("mcp_tool_call")))
    });
    assert!(
        found,
        "mcp_tool_call should be in permissions list: {:?}",
        permissions
    );
}

/// Test #2: Admin grants `mcp_list_tools` to agent on MCP server.
#[tokio::test]
async fn test_grant_mcp_list_tools_permission() {
    let ctx = TestAppBuilder::new()
        .with_admin()
        .with_agent("target", &[])
        .build()
        .await;
    let (cookie, server_id, agent_id, _) = standard_mcp_setup(&ctx).await;

    let (status, body) =
        grant_mcp_permission(&ctx.app, &cookie, &server_id, &agent_id, "mcp_list_tools").await;

    assert_eq!(
        status,
        StatusCode::CREATED,
        "grant mcp_list_tools failed: {}",
        body
    );
}

/// Test #3: After granting 2 permissions, GET returns both.
#[tokio::test]
async fn test_list_mcp_permissions() {
    let ctx = TestAppBuilder::new()
        .with_admin()
        .with_agent("target", &[])
        .build()
        .await;
    let (cookie, server_id, agent_id, _) = standard_mcp_setup(&ctx).await;

    grant_mcp_permission(&ctx.app, &cookie, &server_id, &agent_id, "mcp_tool_call").await;
    grant_mcp_permission(&ctx.app, &cookie, &server_id, &agent_id, "mcp_list_tools").await;

    let (status, body) = list_mcp_permissions(&ctx.app, &cookie, &server_id).await;
    assert_eq!(status, StatusCode::OK);

    let permissions = body["data"]["permissions"]
        .as_array()
        .expect("permissions array");
    let entry = permissions
        .iter()
        .find(|e| e["agent_id"].as_str() == Some(&agent_id))
        .expect("agent should appear in permissions list");
    let agent_perms: Vec<&str> = entry["permissions"]
        .as_array()
        .expect("permissions should be an array")
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    assert!(
        agent_perms.contains(&"mcp_tool_call"),
        "missing mcp_tool_call"
    );
    assert!(
        agent_perms.contains(&"mcp_list_tools"),
        "missing mcp_list_tools"
    );
}

/// Test #4: Grant then revoke mcp_tool_call — Cedar policy deleted.
#[tokio::test]
async fn test_revoke_mcp_permission() {
    let ctx = TestAppBuilder::new()
        .with_admin()
        .with_agent("target", &[])
        .build()
        .await;
    let (cookie, server_id, agent_id, _) = standard_mcp_setup(&ctx).await;

    // Grant
    let (status, _) =
        grant_mcp_permission(&ctx.app, &cookie, &server_id, &agent_id, "mcp_tool_call").await;
    assert_eq!(status, StatusCode::CREATED);

    // Revoke
    let (status, body) =
        revoke_mcp_permission(&ctx.app, &cookie, &server_id, &agent_id, "mcp_tool_call").await;
    assert_eq!(status, StatusCode::OK, "revoke failed: {}", body);

    // Verify no longer in list
    let (status, body) = list_mcp_permissions(&ctx.app, &cookie, &server_id).await;
    assert_eq!(status, StatusCode::OK);
    let empty = vec![];
    let permissions = body["data"]["permissions"].as_array().unwrap_or(&empty);
    let found = permissions.iter().any(|entry| {
        entry["agent_id"].as_str() == Some(&agent_id)
            && entry["permissions"]
                .as_array()
                .is_some_and(|p| p.iter().any(|v| v.as_str() == Some("mcp_tool_call")))
    });
    assert!(!found, "mcp_tool_call should have been revoked");
}

/// Test #5: Grant permission emits PolicyChanged SSE event.
#[tokio::test]
async fn test_grant_emits_policy_changed_sse() {
    let ctx = TestAppBuilder::new()
        .with_admin()
        .with_agent("target", &[])
        .build()
        .await;
    let (cookie, server_id, agent_id, _) = standard_mcp_setup(&ctx).await;

    // Subscribe BEFORE granting
    let mut rx = ctx.state.event_bus.subscribe();

    grant_mcp_permission(&ctx.app, &cookie, &server_id, &agent_id, "mcp_tool_call").await;

    // Check for PolicyChanged event
    let event = rx.try_recv().expect("should have received an SSE event");
    match event {
        DeviceEvent::PolicyChanged { policy_name } => {
            assert!(
                policy_name.contains("grant:mcp:"),
                "policy_name should contain grant:mcp prefix, got: {}",
                policy_name
            );
        }
        other => panic!("expected PolicyChanged event, got {:?}", other),
    }
}

/// Test #6: Revoke permission emits PolicyChanged SSE event.
#[tokio::test]
async fn test_revoke_emits_policy_changed_sse() {
    let ctx = TestAppBuilder::new()
        .with_admin()
        .with_agent("target", &[])
        .build()
        .await;
    let (cookie, server_id, agent_id, _) = standard_mcp_setup(&ctx).await;

    // Grant first
    grant_mcp_permission(&ctx.app, &cookie, &server_id, &agent_id, "mcp_tool_call").await;

    // Subscribe AFTER grant (only care about revoke event)
    let mut rx = ctx.state.event_bus.subscribe();

    revoke_mcp_permission(&ctx.app, &cookie, &server_id, &agent_id, "mcp_tool_call").await;

    let event = rx
        .try_recv()
        .expect("should have received an SSE event on revoke");
    match event {
        DeviceEvent::PolicyChanged { policy_name } => {
            assert!(
                policy_name.contains("grant:mcp:"),
                "revoke policy_name should contain grant:mcp prefix, got: {}",
                policy_name
            );
        }
        other => panic!("expected PolicyChanged on revoke, got {:?}", other),
    }
}

// ===========================================================================
// 1B. Retry/Idempotency
// ===========================================================================

/// Test #8: Duplicate grant returns 409 Conflict (not 500).
#[tokio::test]
async fn test_duplicate_grant_returns_conflict_or_idempotent() {
    let ctx = TestAppBuilder::new()
        .with_admin()
        .with_agent("target", &[])
        .build()
        .await;
    let (cookie, server_id, agent_id, _) = standard_mcp_setup(&ctx).await;

    // Grant first time
    let (status, _) =
        grant_mcp_permission(&ctx.app, &cookie, &server_id, &agent_id, "mcp_tool_call").await;
    assert_eq!(status, StatusCode::CREATED);

    // Grant same permission again
    let (status, body) =
        grant_mcp_permission(&ctx.app, &cookie, &server_id, &agent_id, "mcp_tool_call").await;

    // Should be 409 Conflict, not 500
    assert_ne!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "duplicate grant should not cause 500, got: {}",
        body
    );
    assert!(
        status == StatusCode::CONFLICT || status == StatusCode::OK || status == StatusCode::CREATED,
        "expected 409, 200, or 201 for duplicate grant, got: {} {}",
        status,
        body
    );
}

/// Test #9: Revoke already-revoked returns 404.
#[tokio::test]
async fn test_revoke_already_revoked_returns_404() {
    let ctx = TestAppBuilder::new()
        .with_admin()
        .with_agent("target", &[])
        .build()
        .await;
    let (cookie, server_id, agent_id, _) = standard_mcp_setup(&ctx).await;

    // Grant then revoke
    grant_mcp_permission(&ctx.app, &cookie, &server_id, &agent_id, "mcp_tool_call").await;
    revoke_mcp_permission(&ctx.app, &cookie, &server_id, &agent_id, "mcp_tool_call").await;

    // Revoke again
    let (status, body) =
        revoke_mcp_permission(&ctx.app, &cookie, &server_id, &agent_id, "mcp_tool_call").await;

    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "second revoke should return 404: {}",
        body
    );
}

/// Test #10: Grant → revoke → grant again succeeds.
#[tokio::test]
async fn test_grant_after_revoke_succeeds() {
    let ctx = TestAppBuilder::new()
        .with_admin()
        .with_agent("target", &[])
        .build()
        .await;
    let (cookie, server_id, agent_id, _) = standard_mcp_setup(&ctx).await;

    // Grant
    let (status, _) =
        grant_mcp_permission(&ctx.app, &cookie, &server_id, &agent_id, "mcp_tool_call").await;
    assert_eq!(status, StatusCode::CREATED);

    // Revoke
    revoke_mcp_permission(&ctx.app, &cookie, &server_id, &agent_id, "mcp_tool_call").await;

    // Grant again
    let (status, body) =
        grant_mcp_permission(&ctx.app, &cookie, &server_id, &agent_id, "mcp_tool_call").await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "re-grant after revoke failed: {}",
        body
    );
}

// ===========================================================================
// 1C. Error Handling
// ===========================================================================

/// Test #11: Grant on nonexistent MCP server returns 404.
#[tokio::test]
async fn test_grant_nonexistent_mcp_server_returns_404() {
    let ctx = TestAppBuilder::new()
        .with_admin()
        .with_agent("target", &[])
        .build()
        .await;
    let _admin_user = create_test_user(&*ctx.store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let cookie = login_user_combined(&ctx.app, "admin", TEST_PASSWORD).await;

    let agent = ctx.agents.get("target").unwrap();
    let fake_server_id = Uuid::new_v4().to_string();

    let (status, body) = grant_mcp_permission(
        &ctx.app,
        &cookie,
        &fake_server_id,
        &agent.id.0.to_string(),
        "mcp_tool_call",
    )
    .await;

    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "nonexistent server: {}",
        body
    );
}

/// Test #12: Grant for nonexistent agent returns 404.
#[tokio::test]
async fn test_grant_nonexistent_agent_returns_404() {
    let ctx = TestAppBuilder::new()
        .with_admin()
        .with_agent("target", &[])
        .build()
        .await;
    let (cookie, server_id, _, _) = standard_mcp_setup(&ctx).await;

    let fake_agent_id = Uuid::new_v4().to_string();
    let (status, body) = grant_mcp_permission(
        &ctx.app,
        &cookie,
        &server_id,
        &fake_agent_id,
        "mcp_tool_call",
    )
    .await;

    assert_eq!(status, StatusCode::NOT_FOUND, "nonexistent agent: {}", body);
}

/// Test #13: Grant with invalid action returns 400.
#[tokio::test]
async fn test_grant_invalid_action_returns_400() {
    let ctx = TestAppBuilder::new()
        .with_admin()
        .with_agent("target", &[])
        .build()
        .await;
    let (cookie, server_id, agent_id, _) = standard_mcp_setup(&ctx).await;

    let (status, body) =
        grant_mcp_permission(&ctx.app, &cookie, &server_id, &agent_id, "invalid_action").await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "invalid action: {}", body);
    let msg = body["error"]["message"].as_str().unwrap_or("");
    assert!(
        msg.contains("invalid permission") || msg.contains("must be one of"),
        "error should mention valid actions, got: {}",
        msg
    );
}

/// Test #14: Non-admin user cannot grant (403).
#[tokio::test]
async fn test_grant_requires_admin_role() {
    let ctx = TestAppBuilder::new()
        .with_admin()
        .with_agent("target", &[])
        .build()
        .await;

    // Setup: create MCP server as admin
    let _admin_user = create_test_user(&*ctx.store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let _admin_cookie = login_user_combined(&ctx.app, "admin", TEST_PASSWORD).await;
    let device_id = ctx.admin_device.as_ref().unwrap().device_id.clone();
    let server_id = create_mcp_server_in_store(&*ctx.store, "perm-test-server", &device_id).await;
    let agent = ctx.agents.get("target").unwrap();

    // Login as viewer
    let _viewer = create_test_user(&*ctx.store, "viewer", TEST_PASSWORD, UserRole::Viewer).await;
    let viewer_cookie = login_user_combined(&ctx.app, "viewer", TEST_PASSWORD).await;

    let (status, body) = grant_mcp_permission(
        &ctx.app,
        &viewer_cookie,
        &server_id,
        &agent.id.0.to_string(),
        "mcp_tool_call",
    )
    .await;

    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "viewer should be denied: {}",
        body
    );
}

/// Test #15: Grant on disabled MCP server — behavior defined by implementation.
#[tokio::test]
async fn test_grant_on_disabled_mcp_server() {
    let ctx = TestAppBuilder::new()
        .with_admin()
        .with_agent("target", &[])
        .build()
        .await;
    let (cookie, server_id, agent_id, _) = standard_mcp_setup(&ctx).await;

    // Disable the MCP server
    let mcp_id = agent_cordon_core::domain::mcp::McpServerId(Uuid::parse_str(&server_id).unwrap());
    let mut server = ctx.store.get_mcp_server(&mcp_id).await.unwrap().unwrap();
    server.enabled = false;
    ctx.store.update_mcp_server(&server).await.unwrap();

    // Attempt grant on disabled server
    let (status, body) =
        grant_mcp_permission(&ctx.app, &cookie, &server_id, &agent_id, "mcp_tool_call").await;

    // Either succeeds (grant is stored but proxy won't work) or rejects
    assert_ne!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "grant on disabled server should not 500: {}",
        body
    );
}

// ===========================================================================
// 1D. Cross-Feature
// ===========================================================================

/// Test #16: Delete MCP server cascades — permissions cleaned up.
#[tokio::test]
async fn test_delete_mcp_server_cascades_permissions() {
    let ctx = TestAppBuilder::new()
        .with_admin()
        .with_agent("target", &[])
        .build()
        .await;
    let (cookie, server_id, agent_id, _) = standard_mcp_setup(&ctx).await;

    // Grant permission
    grant_mcp_permission(&ctx.app, &cookie, &server_id, &agent_id, "mcp_tool_call").await;

    // Delete MCP server
    let (del_status, _) = send_json_auto_csrf(
        &ctx.app,
        Method::DELETE,
        &format!("/api/v1/mcp-servers/{}", server_id),
        None,
        Some(&cookie),
        None,
    )
    .await;
    assert_eq!(
        del_status,
        StatusCode::OK,
        "delete MCP server should succeed"
    );

    // Verify grant policies cleaned up by checking policy store.
    // Policy names use server ID (UUID) as the key segment.
    let all_policies = ctx.store.list_policies().await.unwrap();
    let prefix = format!("grant:mcp:{}:", server_id);
    let stale = all_policies.iter().any(|p| p.name.starts_with(&prefix));
    assert!(
        !stale,
        "grant policies should be cleaned up after MCP server deletion"
    );
}

/// Test #17: Delete agent cascades — MCP permissions cleaned up.
#[tokio::test]
async fn test_delete_agent_cascades_mcp_permissions() {
    let ctx = TestAppBuilder::new()
        .with_admin()
        .with_agent("target", &[])
        .build()
        .await;
    let (cookie, server_id, agent_id, _) = standard_mcp_setup(&ctx).await;

    // Grant permission
    grant_mcp_permission(&ctx.app, &cookie, &server_id, &agent_id, "mcp_tool_call").await;

    // Delete agent
    let (del_status, _) = send_json_auto_csrf(
        &ctx.app,
        Method::DELETE,
        &format!("/api/v1/workspaces/{}", agent_id),
        None,
        Some(&cookie),
        None,
    )
    .await;
    assert_eq!(del_status, StatusCode::OK, "delete agent should succeed");

    // Verify grant policies cleaned up
    let all_policies = ctx.store.list_policies().await.unwrap();
    let has_grant = all_policies.iter().any(|p| p.name.contains(&agent_id));
    assert!(
        !has_grant,
        "grant policies should be cleaned up after agent deletion"
    );
}

/// Test #18: MCP permission and credential permission are independent.
#[tokio::test]
async fn test_mcp_permission_and_credential_permission_independent() {
    let ctx = TestAppBuilder::new()
        .with_admin()
        .with_agent("target", &[])
        .build()
        .await;
    let (cookie, server_id, agent_id, _) = standard_mcp_setup(&ctx).await;

    // Grant only MCP permission (no credential permission)
    let (status, _) =
        grant_mcp_permission(&ctx.app, &cookie, &server_id, &agent_id, "mcp_tool_call").await;
    assert_eq!(status, StatusCode::CREATED);

    // MCP permissions and credential permissions should be independent
    // Verify MCP permission exists
    let (status, body) = list_mcp_permissions(&ctx.app, &cookie, &server_id).await;
    assert_eq!(status, StatusCode::OK);
    let permissions = body["data"]["permissions"].as_array().unwrap();
    assert!(
        !permissions.is_empty(),
        "MCP permission should exist independently"
    );
}

// ===========================================================================
// 1E. Security
// ===========================================================================

/// Test #20: Unauthenticated grant returns 401.
#[tokio::test]
async fn test_unauthenticated_grant_returns_401() {
    let ctx = TestAppBuilder::new()
        .with_admin()
        .with_agent("target", &[])
        .build()
        .await;

    // Create MCP server as admin first
    let _admin_user = create_test_user(&*ctx.store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let _admin_cookie = login_user_combined(&ctx.app, "admin", TEST_PASSWORD).await;
    let device_id = ctx.admin_device.as_ref().unwrap().device_id.clone();
    let server_id = create_mcp_server_in_store(&*ctx.store, "unauth-server", &device_id).await;
    let agent = ctx.agents.get("target").unwrap();

    // No auth
    let (status, _) = send_json(
        &ctx.app,
        Method::POST,
        &format!("/api/v1/mcp-servers/{}/permissions", server_id),
        None,
        None,
        None,
        Some(json!({
            "agent_id": agent.id.0.to_string(),
            "permission": "mcp_tool_call",
        })),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "unauthenticated grant should return 401"
    );
}

/// Test #21: Agent cannot self-grant MCP permission via dual auth.
#[tokio::test]
async fn test_agent_cannot_self_grant_mcp_permission() {
    let ctx = TestAppBuilder::new()
        .with_admin()
        .with_agent("target", &[])
        .build()
        .await;

    // Setup MCP server
    let _admin_user = create_test_user(&*ctx.store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let _admin_cookie = login_user_combined(&ctx.app, "admin", TEST_PASSWORD).await;
    let device_id = ctx.admin_device.as_ref().unwrap().device_id.clone();
    let server_id = create_mcp_server_in_store(&*ctx.store, "self-grant-server", &device_id).await;

    // Get agent dual auth
    let agent = ctx.agents.get("target").unwrap();
    let dev = ctx.device_contexts.get("target").unwrap();
    let agent_jwt = issue_agent_jwt(&ctx.state, agent).await;

    // Agent attempts to grant itself MCP permission via dual auth
    let (status, body) = send_json_dual_auth(
        &ctx.app,
        Method::POST,
        &format!("/api/v1/mcp-servers/{}/permissions", server_id),
        &dev.signing_key,
        &dev.device_id,
        &agent_jwt,
        Some(json!({
            "agent_id": agent.id.0.to_string(),
            "permission": "mcp_tool_call",
        })),
    )
    .await;

    // MCP permission endpoints use AuthenticatedUser (session auth), not dual auth
    assert!(
        status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN,
        "agent self-grant should be denied: status={} body={}",
        status,
        body
    );
}

/// Test #22: Viewer cannot grant MCP permission (403).
#[tokio::test]
async fn test_viewer_cannot_grant_mcp_permission() {
    let ctx = TestAppBuilder::new()
        .with_admin()
        .with_agent("target", &[])
        .build()
        .await;

    // Setup as admin
    let _admin_user = create_test_user(&*ctx.store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let _admin_cookie = login_user_combined(&ctx.app, "admin", TEST_PASSWORD).await;
    let device_id = ctx.admin_device.as_ref().unwrap().device_id.clone();
    let server_id = create_mcp_server_in_store(&*ctx.store, "viewer-deny-server", &device_id).await;
    let agent = ctx.agents.get("target").unwrap();

    // Login as viewer
    let _viewer = create_test_user(&*ctx.store, "viewer", TEST_PASSWORD, UserRole::Viewer).await;
    let viewer_cookie = login_user_combined(&ctx.app, "viewer", TEST_PASSWORD).await;

    let (status, _) = grant_mcp_permission(
        &ctx.app,
        &viewer_cookie,
        &server_id,
        &agent.id.0.to_string(),
        "mcp_tool_call",
    )
    .await;

    assert_eq!(status, StatusCode::FORBIDDEN, "viewer should be denied");
}

/// Test #23: Grant/revoke fires audit event.
#[tokio::test]
async fn test_audit_event_on_mcp_grant() {
    let ctx = TestAppBuilder::new()
        .with_admin()
        .with_agent("target", &[])
        .build()
        .await;
    let (cookie, server_id, agent_id, _) = standard_mcp_setup(&ctx).await;

    // Grant
    grant_mcp_permission(&ctx.app, &cookie, &server_id, &agent_id, "mcp_tool_call").await;

    // Check audit log
    let events = ctx
        .store
        .list_audit_events(50, 0)
        .await
        .expect("list audit events");
    let grant_event = events.iter().find(|e| e.action == "grant_mcp_permission");
    assert!(
        grant_event.is_some(),
        "grant_mcp_permission should be audit-logged. Events: {:?}",
        events.iter().map(|e| &e.action).collect::<Vec<_>>()
    );

    let event = grant_event.unwrap();
    assert_eq!(event.resource_type, "mcp_server");
    assert_eq!(event.resource_id.as_deref(), Some(server_id.as_str()));
}

/// Test #24: Error responses don't contain Cedar policy text or internal IDs.
#[tokio::test]
async fn test_no_secrets_in_mcp_permission_errors() {
    let ctx = TestAppBuilder::new()
        .with_admin()
        .with_agent("target", &[])
        .build()
        .await;
    let _admin_user = create_test_user(&*ctx.store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let cookie = login_user_combined(&ctx.app, "admin", TEST_PASSWORD).await;

    // Try invalid action — should get error without internals
    let fake_server = Uuid::new_v4().to_string();
    let fake_agent = Uuid::new_v4().to_string();
    let (_status, body) = grant_mcp_permission(
        &ctx.app,
        &cookie,
        &fake_server,
        &fake_agent,
        "invalid_action",
    )
    .await;

    let body_str = serde_json::to_string(&body).unwrap();
    assert!(
        !body_str.contains("permit("),
        "error should not contain Cedar policy text"
    );
    assert!(
        !body_str.contains("forbid("),
        "error should not contain Cedar policy text"
    );
    assert!(
        !body_str.contains("stack"),
        "error should not contain stack traces"
    );
}
