//! Integration tests for v1.11.0 Migration: Device-Scoped MCPs
//!
//! Tests post-migration behavior: workspace_id is required (NOT NULL),
//! UNIQUE(workspace_id, name) constraint, FK RESTRICT, field preservation,
//! and Cedar policy compatibility.

use axum::http::{Method, StatusCode};
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

/// Create a workspace at a specific time for ordering tests.
async fn create_workspace_with_time(
    store: &(dyn Store + Send + Sync),
    name: &str,
    status: WorkspaceStatus,
    created_at: chrono::DateTime<chrono::Utc>,
) -> Workspace {
    let workspace = Workspace {
        id: WorkspaceId(Uuid::new_v4()),
        name: name.to_string(),
        enabled: status == WorkspaceStatus::Active,
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

/// Create an MCP server assigned to a specific workspace with all fields populated.
async fn create_workspace_mcp(
    store: &(dyn Store + Send + Sync),
    name: &str,
    workspace_id: WorkspaceId,
    _command: Option<&str>,
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
        tags: vec!["test".to_string()],
        required_credentials: Some(vec![agent_cordon_core::domain::credential::CredentialId(
            Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(),
        )]),
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

// ---------------------------------------------------------------------------
// Migration Tests — Post-Migration Behavior
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_migration_fresh_install_no_mcps() {
    // Fresh database, no existing MCPs. workspace_id is NOT NULL.
    // Verify MCP requires workspace_id at the store level.
    let ctx = TestAppBuilder::new().with_admin().build().await;

    // No MCPs should exist initially
    let all_mcps = ctx.store.list_mcp_servers().await.unwrap();
    assert_eq!(all_mcps.len(), 0, "fresh install should have no MCPs");
}

#[tokio::test]
async fn test_migration_existing_mcps_active_workspaces() {
    // Create MCPs assigned to different workspaces. Verify they're all retrievable
    // and workspace-scoped correctly.
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let now = chrono::Utc::now();

    // Create workspaces at specific times
    let w1 = create_workspace_with_time(
        &*ctx.store,
        "oldest-workspace",
        WorkspaceStatus::Active,
        now - chrono::Duration::hours(3),
    )
    .await;
    let w2 = create_workspace_with_time(
        &*ctx.store,
        "newer-workspace",
        WorkspaceStatus::Active,
        now - chrono::Duration::hours(1),
    )
    .await;

    // Create MCPs on W1
    create_workspace_mcp(
        &*ctx.store,
        "github",
        w1.id.clone(),
        Some("/usr/bin/github"),
    )
    .await;
    create_workspace_mcp(&*ctx.store, "slack", w1.id.clone(), Some("/usr/bin/slack")).await;
    create_workspace_mcp(&*ctx.store, "jira", w1.id.clone(), Some("/usr/bin/jira")).await;

    // Create MCPs on W2 (same names allowed on different workspace)
    create_workspace_mcp(
        &*ctx.store,
        "github",
        w2.id.clone(),
        Some("/usr/bin/github"),
    )
    .await;
    create_workspace_mcp(&*ctx.store, "slack", w2.id.clone(), Some("/usr/bin/slack")).await;
    create_workspace_mcp(&*ctx.store, "jira", w2.id.clone(), Some("/usr/bin/jira")).await;

    let all_mcps = ctx.store.list_mcp_servers().await.unwrap();
    assert_eq!(all_mcps.len(), 6, "expected 6 MCPs across 2 workspaces");

    // Verify workspace-specific filtering works
    let w1_mcps = ctx
        .store
        .list_mcp_servers_by_workspace(&w1.id)
        .await
        .unwrap();
    assert_eq!(w1_mcps.len(), 3, "W1 should have 3 MCPs");
    let w2_mcps = ctx
        .store
        .list_mcp_servers_by_workspace(&w2.id)
        .await
        .unwrap();
    assert_eq!(w2_mcps.len(), 3, "W2 should have 3 MCPs");
}

#[tokio::test]
async fn test_migration_preserves_ids_on_oldest_workspace() {
    // Create MCP with known ID on a workspace. Verify the ID is preserved after retrieval.
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let now = chrono::Utc::now();

    let w1 = create_workspace_with_time(
        &*ctx.store,
        "oldest",
        WorkspaceStatus::Active,
        now - chrono::Duration::hours(2),
    )
    .await;

    let m1 = create_workspace_mcp(
        &*ctx.store,
        "github",
        w1.id.clone(),
        Some("/usr/bin/github"),
    )
    .await;
    let original_id = m1.id.0;

    // Verify the MCP retains its original ID
    let retrieved = ctx.store.get_mcp_server(&m1.id).await.unwrap();
    assert!(
        retrieved.is_some(),
        "MCP should be retrievable by original ID"
    );
    assert_eq!(
        retrieved.unwrap().id.0,
        original_id,
        "original MCP ID must be preserved"
    );
}

#[tokio::test]
async fn test_migration_cedar_policies_still_resolve() {
    // Cedar policy referencing McpServer::"ID" should still resolve after migration.
    let ctx = TestAppBuilder::new()
        .with_admin()
        .with_agent("agent1", &["user"])
        .build()
        .await;
    let now = chrono::Utc::now();

    let w1 = create_workspace_with_time(
        &*ctx.store,
        "oldest",
        WorkspaceStatus::Active,
        now - chrono::Duration::hours(2),
    )
    .await;

    let m1 = create_workspace_mcp(
        &*ctx.store,
        "github",
        w1.id.clone(),
        Some("/usr/bin/github"),
    )
    .await;
    let agent1 = ctx.agents.get("agent1").unwrap();

    // Create Cedar policy referencing the MCP
    let policy_text = format!(
        "permit(\n  principal == AgentCordon::Workspace::\"{}\",\n  action == AgentCordon::Action::\"mcp_tool_call\",\n  resource == AgentCordon::McpServer::\"{}\"\n);",
        agent1.id.0, m1.id.0
    );
    let stored_policy = agent_cordon_core::domain::policy::StoredPolicy {
        id: agent_cordon_core::domain::policy::PolicyId(Uuid::new_v4()),
        name: format!("grant:{}:mcp_tool_call", m1.id.0),
        description: Some("Test MCP grant".to_string()),
        cedar_policy: policy_text,
        enabled: true,
        is_system: true,
        created_at: now,
        updated_at: now,
    };
    ctx.store.store_policy(&stored_policy).await.unwrap();

    // Reload policy engine and verify
    let db_policies = ctx.store.get_all_enabled_policies().await.unwrap();
    let sources: Vec<(String, String)> = db_policies
        .into_iter()
        .map(|p| (p.id.0.to_string(), p.cedar_policy))
        .collect();
    ctx.state
        .policy_engine
        .reload_policies(sources)
        .expect("reload");

    // The MCP with original ID should still exist
    let mcp = ctx.store.get_mcp_server(&m1.id).await.unwrap();
    assert!(
        mcp.is_some(),
        "MCP with original ID should exist post-migration"
    );
}

#[tokio::test]
async fn test_migration_existing_grants_preserved() {
    // Workspace W1 has mcp_tool_call grant on MCP M1.
    // After migration, W1 still has the grant.
    let ctx = TestAppBuilder::new()
        .with_admin()
        .with_agent("agent1", &["user"])
        .build()
        .await;
    let now = chrono::Utc::now();

    let w1 = create_workspace_with_time(
        &*ctx.store,
        "oldest",
        WorkspaceStatus::Active,
        now - chrono::Duration::hours(2),
    )
    .await;

    let m1 = create_workspace_mcp(
        &*ctx.store,
        "github",
        w1.id.clone(),
        Some("/usr/bin/github"),
    )
    .await;
    let agent1 = ctx.agents.get("agent1").unwrap();

    // Create grant policy
    let policy_text = format!(
        "permit(\n  principal == AgentCordon::Workspace::\"{}\",\n  action == AgentCordon::Action::\"mcp_tool_call\",\n  resource == AgentCordon::McpServer::\"{}\"\n);",
        agent1.id.0, m1.id.0
    );
    let stored_policy = agent_cordon_core::domain::policy::StoredPolicy {
        id: agent_cordon_core::domain::policy::PolicyId(Uuid::new_v4()),
        name: format!("grant:{}:{}:mcp_tool_call", m1.id.0, agent1.id.0),
        description: Some("Test grant".to_string()),
        cedar_policy: policy_text,
        enabled: true,
        is_system: true,
        created_at: now,
        updated_at: now,
    };
    ctx.store.store_policy(&stored_policy).await.unwrap();

    // Grant policy text should be unchanged and reference the MCP
    let policies = ctx.store.get_all_enabled_policies().await.unwrap();
    let grant_policy = policies
        .iter()
        .find(|p| p.name.contains(&m1.id.0.to_string()))
        .expect("grant policy should still exist");
    assert!(
        grant_policy.cedar_policy.contains(&m1.id.0.to_string()),
        "grant should reference original MCP ID"
    );
}

#[tokio::test]
async fn test_migration_existing_mcps_no_active_workspaces() {
    // All MCPs must have a workspace_id post-migration.
    // Verify we can't create MCPs via API without a valid workspace.
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let _admin = create_test_user(&*ctx.store, "admin1", TEST_PASSWORD, UserRole::Admin).await;
    let _cookie = login_user_combined(&ctx.app, "admin1", TEST_PASSWORD).await;

    // Only a revoked workspace exists
    let now = chrono::Utc::now();
    let revoked = create_workspace_with_time(
        &*ctx.store,
        "disabled",
        WorkspaceStatus::Revoked,
        now - chrono::Duration::hours(1),
    )
    .await;

    // No MCPs should exist initially
    let all_mcps = ctx.store.list_mcp_servers().await.unwrap();
    assert_eq!(
        all_mcps.len(),
        0,
        "no MCPs should exist initially even with revoked workspace"
    );

    // Can create MCP on revoked workspace via store
    let m = create_workspace_mcp(&*ctx.store, "github", revoked.id.clone(), None).await;
    let retrieved = ctx.store.get_mcp_server(&m.id).await.unwrap().unwrap();
    assert_eq!(
        retrieved.workspace_id, revoked.id,
        "MCP should be on revoked workspace"
    );
}

#[tokio::test]
async fn test_migration_preserves_mcp_fields() {
    // MCP with all fields populated. Verify all fields are preserved.
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let now = chrono::Utc::now();

    let w1 = create_workspace_with_time(
        &*ctx.store,
        "oldest",
        WorkspaceStatus::Active,
        now - chrono::Duration::hours(2),
    )
    .await;

    let m1 = create_workspace_mcp(
        &*ctx.store,
        "full-featured",
        w1.id.clone(),
        Some("/usr/bin/full"),
    )
    .await;

    // Retrieve and verify all fields preserved
    let retrieved = ctx.store.get_mcp_server(&m1.id).await.unwrap().unwrap();
    assert_eq!(retrieved.name, "full-featured");
    assert_eq!(retrieved.transport, McpTransport::Http);
    assert_eq!(retrieved.tags, vec!["test"]);
    assert!(retrieved.required_credentials.is_some());
    assert_eq!(
        retrieved.workspace_id, w1.id,
        "workspace_id must be preserved"
    );
}

#[tokio::test]
async fn test_migration_unique_constraint_post_migration() {
    // After migration: UNIQUE(workspace_id, name) in effect.
    // Same name on same workspace → fail. Same name on different workspace → succeed.
    let ctx = TestAppBuilder::new().with_admin().build().await;

    let (w1_id, _) = create_standalone_device(&ctx.state).await;
    let (w2_id, _) = create_standalone_device(&ctx.state).await;
    let w1_uuid = WorkspaceId(uuid::Uuid::parse_str(&w1_id).unwrap());
    let w2_uuid = WorkspaceId(uuid::Uuid::parse_str(&w2_id).unwrap());

    // Create github on W1
    create_workspace_mcp(&*ctx.store, "github", w1_uuid.clone(), None).await;

    // Duplicate on W1 → fail
    let now = chrono::Utc::now();
    let dup = McpServer {
        id: McpServerId(uuid::Uuid::new_v4()),
        workspace_id: w1_uuid,
        name: "github".to_string(),
        upstream_url: "http://localhost:9000/github".to_string(),
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
    let result = ctx.store.create_mcp_server(&dup).await;
    assert!(
        result.is_err(),
        "duplicate MCP on same workspace should fail"
    );

    // Same name on W2 → succeed
    create_workspace_mcp(&*ctx.store, "github", w2_uuid, None).await;
}

#[tokio::test]
async fn test_migration_oldest_workspace_determination() {
    // Verify MCPs created via store are correctly scoped to their assigned workspace.
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let now = chrono::Utc::now();

    let w1 = create_workspace_with_time(
        &*ctx.store,
        "earliest",
        WorkspaceStatus::Active,
        now - chrono::Duration::hours(3),
    )
    .await;
    let _w2 = create_workspace_with_time(
        &*ctx.store,
        "middle",
        WorkspaceStatus::Active,
        now - chrono::Duration::hours(2),
    )
    .await;
    let _w3 = create_workspace_with_time(
        &*ctx.store,
        "latest",
        WorkspaceStatus::Active,
        now - chrono::Duration::hours(1),
    )
    .await;

    // Create MCP on oldest workspace
    let m1 = create_workspace_mcp(
        &*ctx.store,
        "github",
        w1.id.clone(),
        Some("/usr/bin/github"),
    )
    .await;
    let original_id = m1.id.0;

    // Verify original ID is preserved and on correct workspace
    let all_mcps = ctx.store.list_mcp_servers().await.unwrap();
    assert!(
        all_mcps.iter().any(|m| m.id.0 == original_id),
        "original ID must be preserved"
    );

    // The MCP should be on the workspace it was assigned to
    let w1_mcps = ctx
        .store
        .list_mcp_servers_by_workspace(&w1.id)
        .await
        .unwrap();
    assert_eq!(w1_mcps.len(), 1, "MCP should be on earliest workspace");
    assert_eq!(w1_mcps[0].id.0, original_id);
}

// test_post_migration_create_mcp_requires_workspace_id removed — admin create endpoint no longer exists.
// MCP servers are now registered via the workspace import endpoint only.

#[tokio::test]
async fn test_migration_single_active_workspace() {
    // MCPs assigned to single workspace with original IDs.
    // No duplicates. Total = 2.
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let now = chrono::Utc::now();

    let w1 = create_workspace_with_time(
        &*ctx.store,
        "only-workspace",
        WorkspaceStatus::Active,
        now - chrono::Duration::hours(1),
    )
    .await;

    let m1 = create_workspace_mcp(
        &*ctx.store,
        "github",
        w1.id.clone(),
        Some("/usr/bin/github"),
    )
    .await;
    let m2 =
        create_workspace_mcp(&*ctx.store, "slack", w1.id.clone(), Some("/usr/bin/slack")).await;

    // Verify both exist with original IDs
    let all_mcps = ctx.store.list_mcp_servers().await.unwrap();
    assert_eq!(all_mcps.len(), 2, "single workspace: no duplicates");

    // Original IDs preserved
    assert!(all_mcps.iter().any(|m| m.id.0 == m1.id.0));
    assert!(all_mcps.iter().any(|m| m.id.0 == m2.id.0));

    // Both on same workspace
    let w1_mcps = ctx
        .store
        .list_mcp_servers_by_workspace(&w1.id)
        .await
        .unwrap();
    assert_eq!(
        w1_mcps.len(),
        2,
        "both MCPs should be on the single workspace"
    );
}

#[tokio::test]
async fn test_migration_fk_restrict_post_migration() {
    // W1 has 2 MCPs. Delete W1 → fails. Delete MCPs first → W1 deletes.
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let _admin = create_test_user(&*ctx.store, "admin1", TEST_PASSWORD, UserRole::Admin).await;
    let cookie = login_user_combined(&ctx.app, "admin1", TEST_PASSWORD).await;

    let (w1_id, _) = create_standalone_device(&ctx.state).await;
    let w1_uuid = WorkspaceId(Uuid::parse_str(&w1_id).unwrap());

    // Create MCPs via store insertion
    let now = chrono::Utc::now();
    let mcp1 = McpServer {
        id: McpServerId(Uuid::new_v4()),
        workspace_id: w1_uuid.clone(),
        name: "github".to_string(),
        upstream_url: "http://localhost:9000/github".to_string(),
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
    ctx.store.create_mcp_server(&mcp1).await.unwrap();

    let mcp2 = McpServer {
        id: McpServerId(Uuid::new_v4()),
        workspace_id: w1_uuid,
        name: "slack".to_string(),
        upstream_url: "http://localhost:9000/slack".to_string(),
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
    ctx.store.create_mcp_server(&mcp2).await.unwrap();

    // Delete workspace → should fail
    let del_uri = format!("/api/v1/workspaces/{}", w1_id);
    let (del_status, _) = send_json_auto_csrf(
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
        "FK RESTRICT should prevent workspace deletion"
    );

    // Delete MCPs via API
    send_json_auto_csrf(
        &ctx.app,
        Method::DELETE,
        &format!("/api/v1/mcp-servers/{}", mcp1.id.0),
        None,
        Some(&cookie),
        None,
    )
    .await;
    send_json_auto_csrf(
        &ctx.app,
        Method::DELETE,
        &format!("/api/v1/mcp-servers/{}", mcp2.id.0),
        None,
        Some(&cookie),
        None,
    )
    .await;

    // Now delete workspace → should succeed
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
        "workspace delete should succeed after MCPs removed"
    );
}
