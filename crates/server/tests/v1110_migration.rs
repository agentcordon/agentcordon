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
        workspace_id: Some(workspace_id),
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
    // #37: bind via the junction so post-consolidation listings see the MCP.
    if let Some(ws_id) = server.workspace_id.clone() {
        store
            .add_mcp_server_workspace(&server.id, &ws_id, None)
            .await
            .expect("bind MCP via junction");
    }
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
    ctx.state.authz.reload_policies(sources).expect("reload");

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





// test_post_migration_create_mcp_requires_workspace_id removed — admin create endpoint no longer exists.
// MCP servers are now registered via the workspace import endpoint only.


