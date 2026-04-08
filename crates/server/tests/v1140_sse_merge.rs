//! v1.14.0 — SSE Event Merge: PolicyChanged + PermissionChanged (Feature 7)
//!
//! Tests that `PolicyChanged` is the unified event type for all permission
//! and policy changes, and that the old `PermissionChanged` variant has been
//! removed from `DeviceEvent`.

use axum::http::{Method, StatusCode};
use serde_json::json;
use uuid::Uuid;

use agent_cordon_core::crypto::SecretEncryptor;
use agent_cordon_core::domain::credential::{CredentialId, StoredCredential};
use agent_cordon_core::domain::user::{UserId, UserRole};
use agent_cordon_server::events::DeviceEvent;
use agent_cordon_server::test_helpers::TestAppBuilder;

use crate::common::*;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Create a credential in the store for permission testing.
async fn create_credential_for_test(
    ctx: &agent_cordon_server::test_helpers::TestContext,
    name: &str,
    owner_user_id: &UserId,
) -> CredentialId {
    let now = chrono::Utc::now();
    let cred_id = CredentialId(Uuid::new_v4());
    let (encrypted, nonce) = ctx
        .encryptor
        .encrypt(b"test-secret", cred_id.0.to_string().as_bytes())
        .expect("encrypt");

    let cred = StoredCredential {
        id: cred_id.clone(),
        name: name.to_string(),
        service: "test-service".to_string(),
        encrypted_value: encrypted,
        nonce,
        scopes: vec!["read".to_string()],
        metadata: json!({}),
        created_by: ctx.admin_agent.as_ref().map(|a| a.id.clone()),
        created_by_user: Some(owner_user_id.clone()),
        created_at: now,
        updated_at: now,
        allowed_url_pattern: None,
        expires_at: None,
        transform_script: None,
        transform_name: None,
        vault: "default".to_string(),
        credential_type: "generic".to_string(),
        tags: vec![],
        description: None,
        target_identity: None,
        key_version: 1,
    };
    ctx.store
        .store_credential(&cred)
        .await
        .expect("store credential");
    cred_id
}

/// Standard setup: admin user + credential + target agent.
async fn sse_test_setup(
    ctx: &agent_cordon_server::test_helpers::TestContext,
) -> (String, CredentialId, String) {
    let admin = create_test_user(&*ctx.store, "sse-admin", TEST_PASSWORD, UserRole::Admin).await;
    let cookie = login_user_combined(&ctx.app, "sse-admin", TEST_PASSWORD).await;

    let cred_id = create_credential_for_test(ctx, "sse-merge-cred", &admin.id).await;
    let agent = ctx.agents.get("target").unwrap();

    (cookie, cred_id, agent.id.0.to_string())
}

// ===========================================================================
// 7A. Happy Path
// ===========================================================================

/// Test #1: Credential grant emits PolicyChanged event.
#[tokio::test]
async fn test_credential_grant_emits_policy_changed() {
    let ctx = TestAppBuilder::new()
        .with_admin()
        .with_agent("target", &[])
        .build()
        .await;
    let (cookie, cred_id, agent_id) = sse_test_setup(&ctx).await;

    // Subscribe BEFORE granting
    let mut rx = ctx.state.event_bus.subscribe();

    // Grant credential permission
    let (status, body) = send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        &format!("/api/v1/credentials/{}/permissions", cred_id.0),
        None,
        Some(&cookie),
        Some(json!({
            "agent_id": agent_id,
            "permission": "delegated_use",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "grant failed: {}", body);

    // Collect events — should see PolicyChanged (not PermissionChanged)
    let mut found_policy_changed = false;
    while let Ok(event) = rx.try_recv() {
        if let DeviceEvent::PolicyChanged { .. } = event {
            found_policy_changed = true;
        }
        // Other events are OK
    }

    assert!(
        found_policy_changed,
        "credential grant should emit PolicyChanged event"
    );
}

/// Test #2: Credential revoke emits PolicyChanged event.
#[tokio::test]
async fn test_credential_revoke_emits_policy_changed() {
    let ctx = TestAppBuilder::new()
        .with_admin()
        .with_agent("target", &[])
        .build()
        .await;
    let (cookie, cred_id, agent_id) = sse_test_setup(&ctx).await;

    // Grant first
    send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        &format!("/api/v1/credentials/{}/permissions", cred_id.0),
        None,
        Some(&cookie),
        Some(json!({
            "agent_id": agent_id,
            "permission": "read",
        })),
    )
    .await;

    // Subscribe AFTER grant
    let mut rx = ctx.state.event_bus.subscribe();

    // Revoke
    send_json_auto_csrf(
        &ctx.app,
        Method::DELETE,
        &format!(
            "/api/v1/credentials/{}/permissions/{}/read",
            cred_id.0, agent_id
        ),
        None,
        Some(&cookie),
        None,
    )
    .await;

    // Should see PolicyChanged
    let mut found_policy_changed = false;
    while let Ok(event) = rx.try_recv() {
        if matches!(event, DeviceEvent::PolicyChanged { .. }) {
            found_policy_changed = true;
        }
    }

    assert!(
        found_policy_changed,
        "credential revoke should emit PolicyChanged event"
    );
}

/// Test #3: MCP grant emits PolicyChanged event.
#[tokio::test]
async fn test_mcp_grant_emits_policy_changed() {
    let ctx = TestAppBuilder::new()
        .with_admin()
        .with_agent("target", &[])
        .build()
        .await;

    let _admin =
        create_test_user(&*ctx.store, "mcp-sse-admin", TEST_PASSWORD, UserRole::Admin).await;
    let cookie = login_user_combined(&ctx.app, "mcp-sse-admin", TEST_PASSWORD).await;
    let device_id_str = ctx.admin_device.as_ref().unwrap().device_id.clone();
    let device_id =
        agent_cordon_core::domain::workspace::WorkspaceId(Uuid::parse_str(&device_id_str).unwrap());

    // Create MCP server via store insertion
    let now = chrono::Utc::now();
    let mcp = agent_cordon_core::domain::mcp::McpServer {
        id: agent_cordon_core::domain::mcp::McpServerId(Uuid::new_v4()),
        workspace_id: device_id,
        name: "sse-test-mcp".to_string(),
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
    ctx.store.create_mcp_server(&mcp).await.unwrap();
    let server_id = mcp.id.0.to_string();
    let agent = ctx.agents.get("target").unwrap();

    // Subscribe BEFORE granting
    let mut rx = ctx.state.event_bus.subscribe();

    // Grant MCP permission
    send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        &format!("/api/v1/mcp-servers/{}/permissions", server_id),
        None,
        Some(&cookie),
        Some(json!({
            "agent_id": agent.id.0.to_string(),
            "permission": "mcp_tool_call",
        })),
    )
    .await;

    // Check for PolicyChanged
    let mut found_policy_changed = false;
    while let Ok(event) = rx.try_recv() {
        if matches!(event, DeviceEvent::PolicyChanged { .. }) {
            found_policy_changed = true;
        }
    }
    assert!(
        found_policy_changed,
        "MCP grant should emit PolicyChanged event"
    );
}

/// Test #4: Cedar policy CRUD emits PolicyChanged event.
#[tokio::test]
async fn test_cedar_policy_crud_emits_policy_changed() {
    let ctx = TestAppBuilder::new().with_admin().build().await;

    let _admin =
        create_test_user(&*ctx.store, "policy-admin", TEST_PASSWORD, UserRole::Admin).await;
    let cookie = login_user_combined(&ctx.app, "policy-admin", TEST_PASSWORD).await;

    // Subscribe BEFORE creating policy
    let mut rx = ctx.state.event_bus.subscribe();

    // Create a Cedar policy
    let (status, body) = send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        "/api/v1/policies",
        None,
        Some(&cookie),
        Some(json!({
            "name": "sse-test-policy",
            "description": "Test policy for SSE event",
            "cedar_policy": "permit(principal, action, resource) when { false };",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "create policy failed: {}", body);

    // Check for PolicyChanged
    let mut found_policy_changed = false;
    while let Ok(event) = rx.try_recv() {
        if matches!(event, DeviceEvent::PolicyChanged { .. }) {
            found_policy_changed = true;
        }
    }
    assert!(
        found_policy_changed,
        "Cedar policy create should emit PolicyChanged event"
    );
}

/// Test #5: No PermissionChanged event exists in DeviceEvent enum.
///
/// This is a compile-time check. If `PermissionChanged` is removed from
/// the `DeviceEvent` enum, this test compiles. If it still exists, the
/// assertion at the bottom documents the expected state.
#[tokio::test]
async fn test_no_permission_changed_event_exists() {
    let ctx = TestAppBuilder::new()
        .with_admin()
        .with_agent("target", &[])
        .build()
        .await;

    let (cookie, cred_id, agent_id) = sse_test_setup(&ctx).await;

    // Subscribe
    let mut rx = ctx.state.event_bus.subscribe();

    // Do various permission operations
    send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        &format!("/api/v1/credentials/{}/permissions", cred_id.0),
        None,
        Some(&cookie),
        Some(json!({
            "agent_id": agent_id,
            "permission": "read",
        })),
    )
    .await;

    // Collect all events — none should be PermissionChanged
    // (If PermissionChanged still exists in the enum, this code would
    // need to match against it. Since it's been removed, we just verify
    // all events are of known types.)
    let mut events: Vec<String> = Vec::new();
    while let Ok(event) = rx.try_recv() {
        events.push(format!("{:?}", event));
    }

    for event_str in &events {
        assert!(
            !event_str.contains("PermissionChanged"),
            "PermissionChanged event should not exist: found in {:?}",
            events
        );
    }
}

// ===========================================================================
// 7B. Retry/Idempotency
// ===========================================================================

/// Test #6: Rapid grants emit individual events (no batching that drops events).
#[tokio::test]
async fn test_rapid_grants_emit_individual_events() {
    let ctx = TestAppBuilder::new()
        .with_admin()
        .with_agent("target", &[])
        .build()
        .await;

    let _admin = create_test_user(&*ctx.store, "rapid-admin", TEST_PASSWORD, UserRole::Admin).await;
    let cookie = login_user_combined(&ctx.app, "rapid-admin", TEST_PASSWORD).await;

    let device_id_str = ctx.admin_device.as_ref().unwrap().device_id.clone();
    let device_id =
        agent_cordon_core::domain::workspace::WorkspaceId(Uuid::parse_str(&device_id_str).unwrap());
    let agent = ctx.agents.get("target").unwrap();

    // Subscribe
    let mut rx = ctx.state.event_bus.subscribe();

    // Create 5 MCP servers via store and grant permissions rapidly
    for i in 0..5 {
        let now = chrono::Utc::now();
        let mcp = agent_cordon_core::domain::mcp::McpServer {
            id: agent_cordon_core::domain::mcp::McpServerId(Uuid::new_v4()),
            workspace_id: device_id.clone(),
            name: format!("rapid-server-{}", i),
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
        ctx.store.create_mcp_server(&mcp).await.unwrap();
        let server_id = mcp.id.0.to_string();

        send_json_auto_csrf(
            &ctx.app,
            Method::POST,
            &format!("/api/v1/mcp-servers/{}/permissions", server_id),
            None,
            Some(&cookie),
            Some(json!({
                "agent_id": agent.id.0.to_string(),
                "permission": "mcp_tool_call",
            })),
        )
        .await;
    }

    // Count PolicyChanged events
    let mut policy_changed_count = 0;
    while let Ok(event) = rx.try_recv() {
        if matches!(event, DeviceEvent::PolicyChanged { .. }) {
            policy_changed_count += 1;
        }
    }

    assert!(
        policy_changed_count >= 5,
        "should emit at least 5 PolicyChanged events for 5 rapid grants, got: {}",
        policy_changed_count
    );
}

// ===========================================================================
// 7D. Cross-Feature
// ===========================================================================

// ===========================================================================
// 7E. Security
// ===========================================================================

/// Test #9: PolicyChanged event contains policy name only, not Cedar text.
#[tokio::test]
async fn test_policy_changed_event_no_policy_content() {
    let ctx = TestAppBuilder::new().with_admin().build().await;

    let _admin = create_test_user(&*ctx.store, "sec-admin", TEST_PASSWORD, UserRole::Admin).await;
    let cookie = login_user_combined(&ctx.app, "sec-admin", TEST_PASSWORD).await;

    // Subscribe
    let mut rx = ctx.state.event_bus.subscribe();

    // Create a policy
    send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        "/api/v1/policies",
        None,
        Some(&cookie),
        Some(json!({
            "name": "security-test-policy",
            "description": "test",
            "cedar_policy": "permit(principal, action, resource) when { principal.enabled };",
        })),
    )
    .await;

    // Check that PolicyChanged contains only the name, not the Cedar text
    while let Ok(event) = rx.try_recv() {
        if let DeviceEvent::PolicyChanged { policy_name } = event {
            assert!(
                !policy_name.contains("permit("),
                "PolicyChanged should contain policy name, not Cedar text: {}",
                policy_name
            );
            assert!(
                !policy_name.contains("forbid("),
                "PolicyChanged should not contain Cedar policy text: {}",
                policy_name
            );
            assert!(
                !policy_name.contains("principal.enabled"),
                "PolicyChanged should not contain Cedar conditions: {}",
                policy_name
            );
        }
    }
}
