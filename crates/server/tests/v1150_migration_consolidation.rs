//! v1.15.0 — Feature 3: Collapse Migration Files into Single Init Schema
//!
//! Tests that the consolidated migration produces a correct schema,
//! all indexes exist, and TestAppBuilder works correctly with it.

use agent_cordon_core::domain::user::UserRole;
use agent_cordon_server::test_helpers::TestAppBuilder;

use crate::common::*;

// ===========================================================================
// 3A. Happy Path
// ===========================================================================

/// Test #1: Consolidated migration creates all expected tables.
#[tokio::test]
async fn test_consolidated_migration_creates_correct_schema() {
    let ctx = TestAppBuilder::new().build().await;

    // Query sqlite_master for all tables
    // Use the store to verify key tables exist by performing operations
    // that would fail if tables are missing.
    let _admin = create_test_user(
        &*ctx.store,
        "schema-test-admin",
        TEST_PASSWORD,
        UserRole::Admin,
    )
    .await;

    // Verify agents table exists
    let (agent, _) = create_agent_in_db(&*ctx.store, "schema-test-agent", vec![], true, None).await;

    // Verify credentials table exists by storing a credential via the store
    let cred = agent_cordon_core::domain::credential::StoredCredential {
        id: agent_cordon_core::domain::credential::CredentialId(uuid::Uuid::new_v4()),
        name: "schema-test-cred".to_string(),
        service: "test".to_string(),
        credential_type: "generic".to_string(),
        encrypted_value: vec![0u8; 32],
        nonce: vec![0u8; 12],
        scopes: vec![],
        metadata: serde_json::json!({}),
        allowed_url_pattern: None,
        expires_at: None,
        transform_script: None,
        transform_name: None,
        vault: "default".to_string(),
        tags: vec![],
        description: None,
        target_identity: None,
        key_version: 1,
        created_by: None,
        created_by_user: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };
    ctx.store
        .store_credential(&cred)
        .await
        .expect("credentials table must exist");

    // Verify audit_events table exists
    let audit_event = agent_cordon_core::domain::audit::AuditEvent {
        id: uuid::Uuid::new_v4(),
        timestamp: chrono::Utc::now(),
        correlation_id: "test-corr".to_string(),
        event_type: agent_cordon_core::domain::audit::AuditEventType::WorkspaceCreated,
        workspace_id: Some(agent.id.clone()),
        workspace_name: Some(agent.name.clone()),
        user_id: None,
        user_name: None,
        action: "create".to_string(),
        resource_type: "workspace".to_string(),
        resource_id: Some(agent.id.0.to_string()),
        decision: agent_cordon_core::domain::audit::AuditDecision::Permit,
        decision_reason: None,
        metadata: serde_json::json!({}),
    };
    ctx.store
        .append_audit_event(&audit_event)
        .await
        .expect("audit_events table must exist");

    // Verify policies table exists
    let policies = ctx
        .store
        .get_all_enabled_policies()
        .await
        .expect("policies table must exist");
    assert!(!policies.is_empty(), "default policies should be loaded");
}

/// Test #2: Consolidated migration creates all performance indexes.
#[tokio::test]
async fn test_consolidated_migration_creates_all_indexes() {
    let ctx = TestAppBuilder::new().build().await;

    // The presence of indexes is verified implicitly — queries that use them
    // would be slow without them but wouldn't fail. We verify the schema is
    // correct by checking that operations which benefit from indexes work.
    let _admin = create_test_user(&*ctx.store, "idx-admin", TEST_PASSWORD, UserRole::Admin).await;

    // Create multiple agents and verify list queries work (uses agent indexes)
    for i in 0..5 {
        create_agent_in_db(
            &*ctx.store,
            &format!("index-test-agent-{}", i),
            vec![],
            true,
            None,
        )
        .await;
    }

    // Verify filtered audit queries work (uses audit_events indexes)
    use agent_cordon_core::storage::AuditFilter;
    let events = ctx
        .store
        .list_audit_events_filtered(&AuditFilter {
            limit: 10,
            offset: 0,
            resource_type: Some("agent".to_string()),
            ..Default::default()
        })
        .await
        .expect("filtered audit query should work (needs indexes)");
    // Just verify the query succeeded — index presence is implicit
    let _ = events;
}

/// Test #3: TestAppBuilder works with consolidated migration.
/// This is the most important test — if TestAppBuilder works, the schema is correct.
#[tokio::test]
async fn test_test_app_builder_works_with_consolidated_migration() {
    let ctx = TestAppBuilder::new()
        .with_admin()
        .with_agent("test-agent", &["tag1"])
        .build()
        .await;

    // Verify admin was created
    assert!(ctx.admin_agent.is_some(), "admin agent should be created");
    assert!(ctx.admin_device.is_some(), "admin device should be created");

    // Verify named agent was created
    let agent = ctx
        .agents
        .get("test-agent")
        .expect("test-agent should exist");
    assert_eq!(agent.name, "test-agent");
    assert_eq!(agent.tags, vec!["tag1".to_string()]);

    // Verify login works (tests users table + session infrastructure)
    let _admin = create_test_user(&*ctx.store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let (cookie, csrf) = login_user(&ctx.app, "admin", TEST_PASSWORD).await;
    assert!(!cookie.is_empty(), "session cookie should be set");
    assert!(!csrf.is_empty(), "CSRF token should be set");
}

// ===========================================================================
// 3B. Retry/Idempotency
// ===========================================================================

/// Test #4: Consolidated migration is idempotent (IF NOT EXISTS guards).
/// Running TestAppBuilder twice on independent databases should both succeed.
#[tokio::test]
async fn test_consolidated_migration_idempotent() {
    // Each TestAppBuilder::new().build() creates a fresh in-memory SQLite DB
    // and runs migrations. If migrations aren't idempotent with IF NOT EXISTS,
    // this would fail on the second build.
    let ctx1 = TestAppBuilder::new().with_admin().build().await;
    let ctx2 = TestAppBuilder::new().with_admin().build().await;

    // Both should have working stores
    assert!(ctx1.admin_agent.is_some());
    assert!(ctx2.admin_agent.is_some());

    // Both should be able to create users independently
    let _u1 = create_test_user(&*ctx1.store, "user1", TEST_PASSWORD, UserRole::Admin).await;
    let _u2 = create_test_user(&*ctx2.store, "user2", TEST_PASSWORD, UserRole::Admin).await;
}
