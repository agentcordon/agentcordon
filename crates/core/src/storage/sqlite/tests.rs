use super::*;
use crate::domain::audit::{AuditDecision, AuditEvent, AuditEventType};
use crate::domain::credential::{CredentialId, StoredCredential};
use crate::domain::policy::{PolicyId, StoredPolicy};
use crate::domain::workspace::{Workspace, WorkspaceId, WorkspaceStatus};
use crate::storage::traits::WorkspaceStore;
use chrono::Utc;
use uuid::Uuid;

async fn setup_store() -> SqliteStore {
    let store = SqliteStore::new_in_memory()
        .await
        .expect("create in-memory store");
    store.run_migrations().await.expect("run migrations");
    store
}

fn make_agent(name: &str) -> Workspace {
    let now = Utc::now();
    Workspace {
        id: WorkspaceId(Uuid::new_v4()),
        name: name.to_string(),
        tags: vec!["reader".to_string()],
        enabled: true,
        status: WorkspaceStatus::Active,
        pk_hash: None,
        encryption_public_key: None,
        owner_id: None,
        parent_id: None,
        tool_name: None,
        created_at: now,
        updated_at: now,
    }
}

#[tokio::test]
async fn test_create_and_get_agent() {
    let store = setup_store().await;
    let agent = make_agent("test-agent");

    store.create_workspace(&agent).await.expect("create agent");

    // Get by ID
    let fetched = store
        .get_workspace(&agent.id)
        .await
        .expect("get agent")
        .expect("agent should exist");
    assert_eq!(fetched.id, agent.id);
    assert_eq!(fetched.name, agent.name);
    assert_eq!(fetched.tags, agent.tags);
    assert_eq!(fetched.enabled, agent.enabled);

    // Get by name
    let fetched_by_name = store
        .get_workspace_by_name("test-agent")
        .await
        .expect("get agent by name")
        .expect("agent should exist");
    assert_eq!(fetched_by_name.id, agent.id);

    // Not found
    let missing: Option<Workspace> = store
        .get_workspace(&WorkspaceId(Uuid::new_v4()))
        .await
        .expect("get missing workspace");
    assert!(missing.is_none());
}

#[tokio::test]
async fn test_list_agents() {
    let store = setup_store().await;
    let a1 = make_agent("alpha-agent");
    let a2 = make_agent("beta-agent");

    store.create_workspace(&a1).await.expect("create a1");
    store.create_workspace(&a2).await.expect("create a2");

    let agents = store.list_workspaces().await.expect("list agents");
    assert_eq!(agents.len(), 2);
    // Ordered by name
    assert_eq!(agents[0].name, "alpha-agent");
    assert_eq!(agents[1].name, "beta-agent");
}

#[tokio::test]
async fn test_update_agent() {
    let store = setup_store().await;
    let mut agent = make_agent("updatable-agent");

    store.create_workspace(&agent).await.expect("create agent");

    agent.tags = vec!["admin".to_string(), "reader".to_string()];
    agent.updated_at = Utc::now();

    store
        .update_workspace(&agent)
        .await
        .expect("update workspace");

    let fetched = store
        .get_workspace(&agent.id)
        .await
        .expect("get workspace")
        .expect("workspace exists");
    assert_eq!(
        fetched.tags,
        vec!["admin".to_string(), "reader".to_string()]
    );
}

#[tokio::test]
async fn test_store_and_get_credential() {
    let store = setup_store().await;
    let agent = make_agent("cred-owner");
    store.create_workspace(&agent).await.expect("create agent");

    let now = Utc::now();
    let cred = StoredCredential {
        id: CredentialId(Uuid::new_v4()),
        name: "slack-token".to_string(),
        service: "slack".to_string(),
        encrypted_value: vec![1, 2, 3, 4, 5],
        nonce: vec![10, 20, 30],
        scopes: vec!["chat:write".to_string(), "channels:read".to_string()],
        metadata: serde_json::json!({"team": "engineering"}),
        created_by: Some(agent.id.clone()),
        created_by_user: None,
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

    store
        .store_credential(&cred)
        .await
        .expect("store credential");

    let fetched = store
        .get_credential(&cred.id)
        .await
        .expect("get credential")
        .expect("credential should exist");

    assert_eq!(fetched.id, cred.id);
    assert_eq!(fetched.name, "slack-token");
    assert_eq!(fetched.service, "slack");
    assert_eq!(fetched.encrypted_value, vec![1, 2, 3, 4, 5]);
    assert_eq!(fetched.nonce, vec![10, 20, 30]);
    assert_eq!(fetched.scopes, cred.scopes);
    assert_eq!(fetched.metadata, cred.metadata);
    assert_eq!(fetched.created_by, Some(agent.id));
    assert_eq!(fetched.expires_at, None);
}

#[tokio::test]
async fn test_store_credential_with_expiry() {
    let store = setup_store().await;
    let agent = make_agent("expiry-owner");
    store.create_workspace(&agent).await.expect("create agent");

    let now = Utc::now();
    let future = now + chrono::Duration::hours(24);
    let cred = StoredCredential {
        id: CredentialId(Uuid::new_v4()),
        name: "expiring-token".to_string(),
        service: "test".to_string(),
        encrypted_value: vec![1, 2, 3],
        nonce: vec![10, 20],
        scopes: vec!["read".to_string()],
        metadata: serde_json::json!({}),
        created_by: Some(agent.id.clone()),
        created_by_user: None,
        created_at: now,
        updated_at: now,
        allowed_url_pattern: None,
        expires_at: Some(future),
        transform_script: None,
        transform_name: None,
        vault: "default".to_string(),
        credential_type: "generic".to_string(),
        tags: vec![],
        description: None,
        target_identity: None,
        key_version: 1,
    };

    store
        .store_credential(&cred)
        .await
        .expect("store credential");

    let fetched = store
        .get_credential(&cred.id)
        .await
        .expect("get credential")
        .expect("credential should exist");

    assert!(fetched.expires_at.is_some());
    // Compare with second precision (RFC 3339 round-trip may lose sub-second precision)
    let diff = (fetched.expires_at.unwrap() - future).num_seconds().abs();
    assert!(diff <= 1, "expires_at should round-trip: diff={}s", diff);
    assert!(
        !fetched.is_expired(),
        "future credential should not be expired"
    );
}

#[tokio::test]
async fn test_expired_credential_is_expired() {
    let store = setup_store().await;
    let agent = make_agent("past-owner");
    store.create_workspace(&agent).await.expect("create agent");

    let now = Utc::now();
    let past = now - chrono::Duration::hours(1);
    let cred = StoredCredential {
        id: CredentialId(Uuid::new_v4()),
        name: "past-token".to_string(),
        service: "test".to_string(),
        encrypted_value: vec![1],
        nonce: vec![2],
        scopes: vec![],
        metadata: serde_json::json!({}),
        created_by: Some(agent.id.clone()),
        created_by_user: None,
        created_at: now,
        updated_at: now,
        allowed_url_pattern: None,
        expires_at: Some(past),
        transform_script: None,
        transform_name: None,
        vault: "default".to_string(),
        credential_type: "generic".to_string(),
        tags: vec![],
        description: None,
        target_identity: None,
        key_version: 1,
    };

    store
        .store_credential(&cred)
        .await
        .expect("store credential");

    let fetched = store
        .get_credential(&cred.id)
        .await
        .expect("get credential")
        .expect("credential should exist");

    assert!(fetched.is_expired(), "past credential should be expired");
}

#[tokio::test]
async fn test_list_credentials_shows_expired_flag() {
    let store = setup_store().await;
    let agent = make_agent("list-expiry-owner");
    store.create_workspace(&agent).await.expect("create agent");

    let now = Utc::now();
    let past = now - chrono::Duration::hours(1);
    let future = now + chrono::Duration::hours(24);

    let expired_cred = StoredCredential {
        id: CredentialId(Uuid::new_v4()),
        name: "aaa-expired".to_string(),
        service: "test".to_string(),
        encrypted_value: vec![1],
        nonce: vec![2],
        scopes: vec![],
        metadata: serde_json::json!({}),
        created_by: Some(agent.id.clone()),
        created_by_user: None,
        created_at: now,
        updated_at: now,
        allowed_url_pattern: None,
        expires_at: Some(past),
        transform_script: None,
        transform_name: None,
        vault: "default".to_string(),
        credential_type: "generic".to_string(),
        tags: vec![],
        description: None,
        target_identity: None,
        key_version: 1,
    };
    let active_cred = StoredCredential {
        id: CredentialId(Uuid::new_v4()),
        name: "bbb-active".to_string(),
        service: "test".to_string(),
        encrypted_value: vec![3],
        nonce: vec![4],
        scopes: vec![],
        metadata: serde_json::json!({}),
        created_by: Some(agent.id.clone()),
        created_by_user: None,
        created_at: now,
        updated_at: now,
        allowed_url_pattern: None,
        expires_at: Some(future),
        transform_script: None,
        transform_name: None,
        vault: "default".to_string(),
        credential_type: "generic".to_string(),
        tags: vec![],
        description: None,
        target_identity: None,
        key_version: 1,
    };
    let no_expiry_cred = StoredCredential {
        id: CredentialId(Uuid::new_v4()),
        name: "ccc-no-expiry".to_string(),
        service: "test".to_string(),
        encrypted_value: vec![5],
        nonce: vec![6],
        scopes: vec![],
        metadata: serde_json::json!({}),
        created_by: Some(agent.id.clone()),
        created_by_user: None,
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

    store
        .store_credential(&expired_cred)
        .await
        .expect("store expired");
    store
        .store_credential(&active_cred)
        .await
        .expect("store active");
    store
        .store_credential(&no_expiry_cred)
        .await
        .expect("store no-expiry");

    let summaries = store.list_credentials().await.expect("list credentials");
    assert_eq!(summaries.len(), 3);

    // Sorted by name
    let expired_summary = summaries.iter().find(|s| s.name == "aaa-expired").unwrap();
    assert!(
        expired_summary.expired,
        "expired credential should have expired=true"
    );
    assert!(expired_summary.expires_at.is_some());

    let active_summary = summaries.iter().find(|s| s.name == "bbb-active").unwrap();
    assert!(
        !active_summary.expired,
        "active credential should have expired=false"
    );
    assert!(active_summary.expires_at.is_some());

    let no_exp_summary = summaries
        .iter()
        .find(|s| s.name == "ccc-no-expiry")
        .unwrap();
    assert!(
        !no_exp_summary.expired,
        "no-expiry credential should have expired=false"
    );
    assert!(no_exp_summary.expires_at.is_none());
}

#[tokio::test]
async fn test_list_credentials_returns_summaries() {
    let store = setup_store().await;
    let agent = make_agent("summary-owner");
    store.create_workspace(&agent).await.expect("create agent");

    let now = Utc::now();
    let cred = StoredCredential {
        id: CredentialId(Uuid::new_v4()),
        name: "github-token".to_string(),
        service: "github".to_string(),
        encrypted_value: vec![99, 98, 97],
        nonce: vec![11, 22],
        scopes: vec!["repo".to_string()],
        metadata: serde_json::json!({}),
        created_by: Some(agent.id.clone()),
        created_by_user: None,
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

    store
        .store_credential(&cred)
        .await
        .expect("store credential");

    let summaries = store.list_credentials().await.expect("list credentials");
    assert_eq!(summaries.len(), 1);

    let summary = &summaries[0];
    assert_eq!(summary.id, cred.id);
    assert_eq!(summary.name, "github-token");
    assert_eq!(summary.service, "github");
    assert_eq!(summary.scopes, vec!["repo".to_string()]);
    assert_eq!(summary.created_by, Some(agent.id));
    // CredentialSummary does not contain encrypted_value or nonce — this is enforced by the type system
}

#[tokio::test]
async fn test_delete_credential() {
    let store = setup_store().await;
    let agent = make_agent("delete-owner");
    store.create_workspace(&agent).await.expect("create agent");

    let now = Utc::now();
    let cred = StoredCredential {
        id: CredentialId(Uuid::new_v4()),
        name: "disposable".to_string(),
        service: "test".to_string(),
        encrypted_value: vec![1],
        nonce: vec![2],
        scopes: vec![],
        metadata: serde_json::json!({}),
        created_by: Some(agent.id.clone()),
        created_by_user: None,
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

    store
        .store_credential(&cred)
        .await
        .expect("store credential");

    // Delete existing returns true
    let deleted = store
        .delete_credential(&cred.id)
        .await
        .expect("delete credential");
    assert!(deleted);

    // Delete again returns false
    let deleted_again = store
        .delete_credential(&cred.id)
        .await
        .expect("delete credential again");
    assert!(!deleted_again);

    // Verify it's gone
    let fetched = store
        .get_credential(&cred.id)
        .await
        .expect("get deleted credential");
    assert!(fetched.is_none());
}

#[tokio::test]
async fn test_store_and_get_policy() {
    let store = setup_store().await;
    let now = Utc::now();

    let policy = StoredPolicy {
        id: PolicyId(Uuid::new_v4()),
        name: "allow-read".to_string(),
        description: Some("Allow read access".to_string()),
        cedar_policy: "permit(principal, action == Action::\"read\", resource);".to_string(),
        enabled: true,
        is_system: false,
        created_at: now,
        updated_at: now,
    };

    store.store_policy(&policy).await.expect("store policy");

    let fetched = store
        .get_policy(&policy.id)
        .await
        .expect("get policy")
        .expect("policy should exist");

    assert_eq!(fetched.id, policy.id);
    assert_eq!(fetched.name, "allow-read");
    assert_eq!(fetched.description, Some("Allow read access".to_string()));
    assert_eq!(fetched.cedar_policy, policy.cedar_policy);
    assert!(fetched.enabled);
}

#[tokio::test]
async fn test_list_and_update_policy() {
    let store = setup_store().await;
    let now = Utc::now();

    let mut policy = StoredPolicy {
        id: PolicyId(Uuid::new_v4()),
        name: "mutable-policy".to_string(),
        description: None,
        cedar_policy: "forbid(principal, action, resource);".to_string(),
        enabled: true,
        is_system: false,
        created_at: now,
        updated_at: now,
    };

    store.store_policy(&policy).await.expect("store policy");

    // Update
    policy.description = Some("Now has description".to_string());
    policy.enabled = false;
    policy.updated_at = Utc::now();
    store.update_policy(&policy).await.expect("update policy");

    let fetched = store
        .get_policy(&policy.id)
        .await
        .expect("get policy")
        .expect("exists");
    assert_eq!(fetched.description, Some("Now has description".to_string()));
    assert!(!fetched.enabled);

    // List
    let policies = store.list_policies().await.expect("list policies");
    assert_eq!(policies.len(), 1);
}

#[tokio::test]
async fn test_delete_policy() {
    let store = setup_store().await;
    let now = Utc::now();

    let policy = StoredPolicy {
        id: PolicyId(Uuid::new_v4()),
        name: "deletable-policy".to_string(),
        description: None,
        cedar_policy: "forbid(principal, action, resource);".to_string(),
        enabled: true,
        is_system: false,
        created_at: now,
        updated_at: now,
    };

    store.store_policy(&policy).await.expect("store policy");

    let deleted = store
        .delete_policy(&policy.id)
        .await
        .expect("delete policy");
    assert!(deleted);

    let deleted_again = store.delete_policy(&policy.id).await.expect("delete again");
    assert!(!deleted_again);
}

#[tokio::test]
async fn test_get_all_enabled_policies() {
    let store = setup_store().await;
    let now = Utc::now();

    let p1 = StoredPolicy {
        id: PolicyId(Uuid::new_v4()),
        name: "enabled-policy".to_string(),
        description: None,
        cedar_policy: "permit(principal, action, resource);".to_string(),
        enabled: true,
        is_system: false,
        created_at: now,
        updated_at: now,
    };

    let p2 = StoredPolicy {
        id: PolicyId(Uuid::new_v4()),
        name: "disabled-policy".to_string(),
        description: None,
        cedar_policy: "forbid(principal, action, resource);".to_string(),
        enabled: false,
        is_system: false,
        created_at: now,
        updated_at: now,
    };

    store.store_policy(&p1).await.expect("store p1");
    store.store_policy(&p2).await.expect("store p2");

    let enabled = store.get_all_enabled_policies().await.expect("get enabled");
    assert_eq!(enabled.len(), 1);
    assert_eq!(enabled[0].name, "enabled-policy");
}

#[tokio::test]
async fn test_append_and_list_audit_events() {
    let store = setup_store().await;

    let event = AuditEvent {
        id: Uuid::new_v4(),
        timestamp: Utc::now(),
        correlation_id: Uuid::new_v4().to_string(),
        event_type: AuditEventType::WorkspaceCreated,
        workspace_id: Some(WorkspaceId(Uuid::new_v4())),
        workspace_name: Some("test-workspace".to_string()),
        user_id: None,
        user_name: None,
        action: "create".to_string(),
        resource_type: "workspace".to_string(),
        resource_id: Some(Uuid::new_v4().to_string()),
        decision: AuditDecision::Permit,
        decision_reason: Some("authorized".to_string()),
        metadata: serde_json::json!({"source": "test"}),
    };

    store
        .append_audit_event(&event)
        .await
        .expect("append event");

    let events = store.list_audit_events(10, 0).await.expect("list events");
    assert_eq!(events.len(), 1);

    let fetched = &events[0];
    assert_eq!(fetched.id, event.id);
    assert_eq!(fetched.correlation_id, event.correlation_id);
    assert_eq!(fetched.workspace_name, Some("test-workspace".to_string()));
    assert_eq!(fetched.action, "create");
    assert_eq!(fetched.resource_type, "workspace");
    assert_eq!(fetched.decision_reason, Some("authorized".to_string()));
}

#[tokio::test]
async fn test_audit_events_pagination() {
    let store = setup_store().await;

    // Insert 5 events with staggered timestamps
    for i in 0..5 {
        let event = AuditEvent {
            id: Uuid::new_v4(),
            timestamp: Utc::now() + chrono::TimeDelta::seconds(i),
            correlation_id: format!("corr-{}", i),
            event_type: AuditEventType::PolicyEvaluated,
            workspace_id: None,
            workspace_name: None,
            user_id: None,
            user_name: None,
            action: format!("action-{}", i),
            resource_type: "policy".to_string(),
            resource_id: None,
            decision: AuditDecision::NotApplicable,
            decision_reason: None,
            metadata: serde_json::json!({}),
        };
        store
            .append_audit_event(&event)
            .await
            .expect("append event");
    }

    // Limit
    let page1 = store.list_audit_events(2, 0).await.expect("page 1");
    assert_eq!(page1.len(), 2);

    // Offset
    let page2 = store.list_audit_events(2, 2).await.expect("page 2");
    assert_eq!(page2.len(), 2);

    // Beyond end
    let page3 = store.list_audit_events(10, 4).await.expect("page 3");
    assert_eq!(page3.len(), 1);
}

#[tokio::test]
async fn test_audit_event_with_no_optional_fields() {
    let store = setup_store().await;

    let event = AuditEvent {
        id: Uuid::new_v4(),
        timestamp: Utc::now(),
        correlation_id: "corr-123".to_string(),
        event_type: AuditEventType::AuthFailure,
        workspace_id: None,
        workspace_name: None,
        user_id: None,
        user_name: None,
        action: "authenticate".to_string(),
        resource_type: "session".to_string(),
        resource_id: None,
        decision: AuditDecision::Forbid,
        decision_reason: None,
        metadata: serde_json::json!({}),
    };

    store
        .append_audit_event(&event)
        .await
        .expect("append event");

    let events = store.list_audit_events(10, 0).await.expect("list events");
    assert_eq!(events.len(), 1);
    assert!(events[0].workspace_id.is_none());
    assert!(events[0].workspace_name.is_none());
    assert!(events[0].resource_id.is_none());
    assert!(events[0].decision_reason.is_none());
}

#[tokio::test]
async fn test_delete_agent() {
    let store = setup_store().await;
    let agent = make_agent("deletable-agent");
    store.create_workspace(&agent).await.expect("create agent");

    // Delete existing returns true
    let deleted = store
        .delete_workspace(&agent.id)
        .await
        .expect("delete agent");
    assert!(deleted);

    // Verify it's gone
    let fetched = store
        .get_workspace(&agent.id)
        .await
        .expect("get deleted agent");
    assert!(fetched.is_none());

    // Delete again returns false
    let deleted_again = store
        .delete_workspace(&agent.id)
        .await
        .expect("delete agent again");
    assert!(!deleted_again);
}

#[tokio::test]
async fn test_delete_agent_conflict_with_credentials() {
    let store = setup_store().await;
    let agent = make_agent("agent-with-creds");
    store.create_workspace(&agent).await.expect("create agent");

    let now = Utc::now();
    let cred = StoredCredential {
        id: CredentialId(Uuid::new_v4()),
        name: "some-cred".to_string(),
        service: "test".to_string(),
        encrypted_value: vec![1],
        nonce: vec![2],
        scopes: vec![],
        metadata: serde_json::json!({}),
        created_by: Some(agent.id.clone()),
        created_by_user: None,
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
    store
        .store_credential(&cred)
        .await
        .expect("store credential");

    // Should return Conflict
    let result = store.delete_workspace(&agent.id).await;
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(matches!(err, StoreError::Conflict { .. }));

    // Agent should still exist
    let fetched = store.get_workspace(&agent.id).await.expect("get agent");
    assert!(fetched.is_some());
}

// --- P4: WorkspaceStore additional tests ---

#[tokio::test]
async fn test_get_workspace_by_pk_hash() {
    let store = setup_store().await;
    let mut ws = make_agent("pk-hash-ws");
    ws.pk_hash = Some("abc123def456".to_string());
    store.create_workspace(&ws).await.expect("create workspace");

    // Found
    let fetched = store
        .get_workspace_by_pk_hash("abc123def456")
        .await
        .expect("get by pk_hash");
    assert!(fetched.is_some());
    assert_eq!(fetched.unwrap().name, "pk-hash-ws");

    // Not found
    let missing = store
        .get_workspace_by_pk_hash("nonexistent")
        .await
        .expect("get missing pk_hash");
    assert!(missing.is_none());
}

/// Helper: insert a user directly via SQL so FK constraints are satisfied.
async fn insert_test_user(store: &SqliteStore, user_id: &crate::domain::user::UserId) {
    let id_str = user_id.0.hyphenated().to_string();
    store.conn()
            .call(move |conn| {
                conn.execute(
                    "INSERT INTO users (id, username, password_hash, role, is_root, enabled, created_at, updated_at)
                     VALUES (?1, ?2, 'hash', 'admin', 0, 1, '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')",
                    rusqlite::params![id_str, format!("user-{}", &id_str[..8])],
                )
                .map_err(tokio_rusqlite::Error::Rusqlite)?;
                Ok(())
            })
            .await
            .expect("insert test user");
}

#[tokio::test]
async fn test_get_workspaces_by_owner() {
    let store = setup_store().await;
    let owner = crate::domain::user::UserId(Uuid::new_v4());
    let other_owner = crate::domain::user::UserId(Uuid::new_v4());

    // Create users so FK constraints are satisfied
    insert_test_user(&store, &owner).await;
    insert_test_user(&store, &other_owner).await;

    let mut ws1 = make_agent("owner-ws-1");
    ws1.owner_id = Some(owner.clone());
    let mut ws2 = make_agent("owner-ws-2");
    ws2.owner_id = Some(owner.clone());
    let mut ws3 = make_agent("other-ws");
    ws3.owner_id = Some(other_owner.clone());

    store.create_workspace(&ws1).await.expect("create ws1");
    store.create_workspace(&ws2).await.expect("create ws2");
    store.create_workspace(&ws3).await.expect("create ws3");

    let owned = store
        .get_workspaces_by_owner(&owner)
        .await
        .expect("get by owner");
    assert_eq!(owned.len(), 2);
    assert!(owned.iter().all(|w| w.owner_id.as_ref() == Some(&owner)));

    let other_owned = store
        .get_workspaces_by_owner(&other_owner)
        .await
        .expect("get by other owner");
    assert_eq!(other_owned.len(), 1);
    assert_eq!(other_owned[0].name, "other-ws");

    // No results for unknown owner (but don't need to create user for query-only)
    let nobody = crate::domain::user::UserId(Uuid::new_v4());
    let empty = store
        .get_workspaces_by_owner(&nobody)
        .await
        .expect("get by unknown owner");
    assert!(empty.is_empty());
}

#[tokio::test]
async fn test_store_and_check_workspace_jti() {
    let store = setup_store().await;
    let ws = make_agent("jti-ws");
    store.create_workspace(&ws).await.expect("create workspace");

    let jti = "unique-jti-12345";
    let expires_at = Utc::now() + chrono::Duration::hours(1);

    // Not yet stored
    let exists = store
        .check_workspace_jti(jti)
        .await
        .expect("check jti before store");
    assert!(!exists, "JTI should not exist before storing");

    // Store
    let stored = store
        .store_workspace_jti(jti, &ws.id, &expires_at)
        .await
        .expect("store jti");
    assert!(stored, "first store should succeed");

    // Now exists
    let exists_after = store
        .check_workspace_jti(jti)
        .await
        .expect("check jti after store");
    assert!(exists_after, "JTI should exist after storing");

    // Duplicate store returns false (INSERT OR IGNORE)
    let dup = store
        .store_workspace_jti(jti, &ws.id, &expires_at)
        .await
        .expect("duplicate jti");
    assert!(!dup, "duplicate JTI store should return false");
}

#[tokio::test]
async fn test_cleanup_expired_jtis() {
    let store = setup_store().await;
    let ws = make_agent("cleanup-ws");
    store.create_workspace(&ws).await.expect("create workspace");

    let now = Utc::now();

    // Store an expired JTI
    let expired_at = now - chrono::Duration::hours(1);
    store
        .store_workspace_jti("expired-jti", &ws.id, &expired_at)
        .await
        .expect("store expired jti");

    // Store a valid JTI
    let future = now + chrono::Duration::hours(1);
    store
        .store_workspace_jti("valid-jti", &ws.id, &future)
        .await
        .expect("store valid jti");

    // Cleanup
    let cleaned = store
        .cleanup_expired_workspace_jtis()
        .await
        .expect("cleanup");
    assert_eq!(cleaned, 1, "should clean up 1 expired JTI");

    // Expired one is gone
    let expired_exists = store
        .check_workspace_jti("expired-jti")
        .await
        .expect("check expired");
    assert!(!expired_exists, "expired JTI should be cleaned up");

    // Valid one still exists
    let valid_exists = store
        .check_workspace_jti("valid-jti")
        .await
        .expect("check valid");
    assert!(valid_exists, "valid JTI should still exist");
}

#[tokio::test]
async fn test_touch_workspace_authenticated() {
    let store = setup_store().await;
    let ws = make_agent("touch-ws");
    store.create_workspace(&ws).await.expect("create workspace");

    let auth_time = Utc::now();
    store
        .touch_workspace_authenticated(&ws.id, &auth_time)
        .await
        .expect("touch");

    // Verify updated_at changed (we can read the workspace; updated_at should be >= auth_time)
    let fetched = store.get_workspace(&ws.id).await.expect("get").unwrap();
    // The touch updates updated_at to the given time
    let diff = (fetched.updated_at - auth_time).num_seconds().abs();
    assert!(
        diff <= 1,
        "updated_at should reflect the touch time, diff={}s",
        diff
    );
}

#[tokio::test]
async fn test_workspace_registration_crud() {
    use crate::domain::workspace::WorkspaceRegistration;

    let store = setup_store().await;
    let now = Utc::now();
    let expires = now + chrono::Duration::hours(1);

    let reg = WorkspaceRegistration {
        pk_hash: "test-pk-hash-abc123".to_string(),
        code_challenge: "challenge-hash".to_string(),
        code_hash: "code-hash-value".to_string(),
        approval_code: Some("ALPHA-123456".to_string()),
        expires_at: expires,
        attempts: 0,
        max_attempts: 3,
        approved_by: Some("admin-user-id".to_string()),
        created_at: now,
    };

    // Create
    store
        .create_workspace_registration(&reg)
        .await
        .expect("create registration");

    // Read
    let fetched = store
        .get_workspace_registration("test-pk-hash-abc123")
        .await
        .expect("get")
        .unwrap();
    assert_eq!(fetched.pk_hash, "test-pk-hash-abc123");
    assert_eq!(fetched.code_challenge, "challenge-hash");
    assert_eq!(fetched.code_hash, "code-hash-value");
    assert_eq!(fetched.approval_code, Some("ALPHA-123456".to_string()));
    assert_eq!(fetched.attempts, 0);
    assert_eq!(fetched.max_attempts, 3);
    assert_eq!(fetched.approved_by, Some("admin-user-id".to_string()));

    // Null approval code
    store
        .null_registration_approval_code("test-pk-hash-abc123")
        .await
        .expect("null approval code");
    let after_null = store
        .get_workspace_registration("test-pk-hash-abc123")
        .await
        .expect("get after null")
        .unwrap();
    assert!(
        after_null.approval_code.is_none(),
        "approval code should be null after nulling"
    );

    // Increment attempts
    store
        .increment_registration_attempts("test-pk-hash-abc123")
        .await
        .expect("increment");
    let after_inc = store
        .get_workspace_registration("test-pk-hash-abc123")
        .await
        .expect("get after inc")
        .unwrap();
    assert_eq!(after_inc.attempts, 1, "attempts should be incremented");

    // Delete
    let deleted = store
        .delete_workspace_registration("test-pk-hash-abc123")
        .await
        .expect("delete");
    assert!(deleted);

    // Verify gone
    let gone = store
        .get_workspace_registration("test-pk-hash-abc123")
        .await
        .expect("get after delete");
    assert!(gone.is_none());

    // Delete non-existent returns false
    let deleted_again = store
        .delete_workspace_registration("test-pk-hash-abc123")
        .await
        .expect("delete again");
    assert!(!deleted_again);
}

/// Helper: create the provisioning_tokens table (migration not yet registered).
/// This is a known gap: the migration file exists at
/// migrations/20260321220100_provisioning_tokens.sql but is not in the
/// MIGRATIONS array in migrations.rs.
async fn create_provisioning_tokens_table(store: &SqliteStore) {
    store
        .conn()
        .call(move |conn| {
            conn.execute_batch(
                "CREATE TABLE IF NOT EXISTS provisioning_tokens (
                        token_hash TEXT PRIMARY KEY,
                        name TEXT NOT NULL,
                        expires_at TEXT NOT NULL,
                        used INTEGER NOT NULL DEFAULT 0,
                        created_at TEXT NOT NULL
                    );",
            )
            .map_err(tokio_rusqlite::Error::Rusqlite)?;
            Ok(())
        })
        .await
        .expect("create provisioning_tokens table");
}

#[tokio::test]
async fn test_provisioning_token_crud() {
    use crate::domain::workspace::ProvisioningToken;

    let store = setup_store().await;
    create_provisioning_tokens_table(&store).await;
    let now = Utc::now();
    let expires = now + chrono::Duration::hours(24);

    let token = ProvisioningToken {
        token_hash: "hash-of-raw-token-abc".to_string(),
        name: "ci-deploy-token".to_string(),
        expires_at: expires,
        used: false,
        created_at: now,
    };

    // Create
    store
        .create_provisioning_token(&token)
        .await
        .expect("create token");

    // Read
    let fetched = store
        .get_provisioning_token("hash-of-raw-token-abc")
        .await
        .expect("get")
        .unwrap();
    assert_eq!(fetched.name, "ci-deploy-token");
    assert!(!fetched.used);

    // Not found
    let missing = store
        .get_provisioning_token("nonexistent-hash")
        .await
        .expect("get missing");
    assert!(missing.is_none());

    // Mark used
    let marked = store
        .mark_provisioning_token_used("hash-of-raw-token-abc")
        .await
        .expect("mark used");
    assert!(marked, "marking unused token should succeed");

    // Verify used
    let after_use = store
        .get_provisioning_token("hash-of-raw-token-abc")
        .await
        .expect("get after use")
        .unwrap();
    assert!(after_use.used, "token should be marked as used");

    // Mark used again returns false
    let marked_again = store
        .mark_provisioning_token_used("hash-of-raw-token-abc")
        .await
        .expect("mark used again");
    assert!(
        !marked_again,
        "marking already-used token should return false"
    );
}

#[tokio::test]
async fn test_jti_duplicate_detection() {
    let store = setup_store().await;
    let ws = make_agent("jti-dup-ws");
    store.create_workspace(&ws).await.expect("create workspace");

    let expires = Utc::now() + chrono::Duration::hours(1);
    let jti = "replay-attempt-jti";

    // First store succeeds
    let first = store
        .store_workspace_jti(jti, &ws.id, &expires)
        .await
        .expect("first store");
    assert!(first);

    // Same JTI again = replay detected
    let replay = store
        .store_workspace_jti(jti, &ws.id, &expires)
        .await
        .expect("replay store");
    assert!(!replay, "replay JTI must be rejected");

    // Different JTI succeeds
    let different = store
        .store_workspace_jti("different-jti", &ws.id, &expires)
        .await
        .expect("different jti");
    assert!(different);
}

#[tokio::test]
async fn test_workspace_duplicate_id_conflict() {
    let store = setup_store().await;
    let ws1 = make_agent("first-ws");
    store.create_workspace(&ws1).await.expect("create first");

    // Second workspace with same ID (but different name) should fail with Conflict
    let mut ws2 = make_agent("second-ws");
    ws2.id = ws1.id.clone(); // same ID
    let result = store.create_workspace(&ws2).await;
    assert!(result.is_err(), "duplicate ID should fail");
    let err = result.unwrap_err();
    assert!(
        matches!(err, StoreError::Conflict { .. }),
        "error should be Conflict, got: {:?}",
        err
    );
}

#[tokio::test]
async fn test_get_workspace_by_pk_hash_not_found() {
    let store = setup_store().await;
    let result = store
        .get_workspace_by_pk_hash("totally-nonexistent")
        .await
        .expect("get by nonexistent pk_hash");
    assert!(result.is_none());
}

#[tokio::test]
async fn test_get_workspace_by_pk_hash_with_multiple_workspaces() {
    let store = setup_store().await;

    let mut ws1 = make_agent("ws-pk-1");
    ws1.pk_hash = Some("pk-hash-1".to_string());
    let mut ws2 = make_agent("ws-pk-2");
    ws2.pk_hash = Some("pk-hash-2".to_string());

    store.create_workspace(&ws1).await.expect("create ws1");
    store.create_workspace(&ws2).await.expect("create ws2");

    // Each returns the correct workspace
    let f1 = store
        .get_workspace_by_pk_hash("pk-hash-1")
        .await
        .expect("get pk1")
        .unwrap();
    assert_eq!(f1.name, "ws-pk-1");

    let f2 = store
        .get_workspace_by_pk_hash("pk-hash-2")
        .await
        .expect("get pk2")
        .unwrap();
    assert_eq!(f2.name, "ws-pk-2");
}

#[tokio::test]
async fn test_provisioning_token_duplicate_hash_conflict() {
    use crate::domain::workspace::ProvisioningToken;

    let store = setup_store().await;
    create_provisioning_tokens_table(&store).await;
    let now = Utc::now();
    let expires = now + chrono::Duration::hours(1);

    let token1 = ProvisioningToken {
        token_hash: "same-hash".to_string(),
        name: "token-1".to_string(),
        expires_at: expires,
        used: false,
        created_at: now,
    };
    let token2 = ProvisioningToken {
        token_hash: "same-hash".to_string(),
        name: "token-2".to_string(),
        expires_at: expires,
        used: false,
        created_at: now,
    };

    store
        .create_provisioning_token(&token1)
        .await
        .expect("create first token");
    let result = store.create_provisioning_token(&token2).await;
    assert!(result.is_err(), "duplicate token_hash should fail");
    assert!(
        matches!(result.unwrap_err(), StoreError::Conflict { .. }),
        "error should be Conflict for duplicate provisioning token"
    );
}

#[tokio::test]
async fn test_workspace_with_all_optional_fields() {
    let store = setup_store().await;
    let owner_id = crate::domain::user::UserId(Uuid::new_v4());
    let parent_id = WorkspaceId(Uuid::new_v4());
    let now = Utc::now();

    // Create user so FK constraint is satisfied
    insert_test_user(&store, &owner_id).await;

    // Create parent first (to have it exist in DB)
    let parent = Workspace {
        id: parent_id.clone(),
        name: "parent-workspace".to_string(),
        tags: vec![],
        enabled: true,
        status: WorkspaceStatus::Active,
        pk_hash: None,
        encryption_public_key: None,
        owner_id: None,
        parent_id: None,
        tool_name: None,
        created_at: now,
        updated_at: now,
    };
    store
        .create_workspace(&parent)
        .await
        .expect("create parent");

    let ws = Workspace {
        id: WorkspaceId(Uuid::new_v4()),
        name: "full-featured-ws".to_string(),
        tags: vec!["tag1".to_string(), "tag2".to_string()],
        enabled: true,
        status: WorkspaceStatus::Pending,
        pk_hash: Some("pk-hash-full".to_string()),
        encryption_public_key: Some("{\"kty\":\"EC\",\"crv\":\"P-256\"}".to_string()),
        owner_id: Some(owner_id.clone()),
        parent_id: Some(parent_id.clone()),
        tool_name: Some("claude-code".to_string()),
        created_at: now,
        updated_at: now,
    };

    store
        .create_workspace(&ws)
        .await
        .expect("create full workspace");

    let fetched = store.get_workspace(&ws.id).await.expect("get").unwrap();
    assert_eq!(fetched.name, "full-featured-ws");
    assert_eq!(fetched.pk_hash, Some("pk-hash-full".to_string()));
    assert_eq!(
        fetched.encryption_public_key,
        Some("{\"kty\":\"EC\",\"crv\":\"P-256\"}".to_string())
    );
    assert_eq!(fetched.owner_id, Some(owner_id));
    assert_eq!(fetched.parent_id, Some(parent_id));
    assert_eq!(fetched.tool_name, Some("claude-code".to_string()));
    assert_eq!(fetched.status, WorkspaceStatus::Pending);
    assert_eq!(fetched.tags, vec!["tag1".to_string(), "tag2".to_string()]);
}

#[tokio::test]
async fn test_cleanup_no_expired_jtis() {
    let store = setup_store().await;
    let ws = make_agent("no-expired-ws");
    store.create_workspace(&ws).await.expect("create workspace");

    let future = Utc::now() + chrono::Duration::hours(1);
    store
        .store_workspace_jti("future-jti", &ws.id, &future)
        .await
        .expect("store");

    let cleaned = store
        .cleanup_expired_workspace_jtis()
        .await
        .expect("cleanup");
    assert_eq!(cleaned, 0, "no expired JTIs should be cleaned");
}

#[tokio::test]
async fn test_workspace_registration_not_found() {
    let store = setup_store().await;
    let result = store
        .get_workspace_registration("nonexistent-pk-hash")
        .await
        .expect("get nonexistent");
    assert!(result.is_none());
}

#[tokio::test]
async fn test_workspace_registration_replace_on_conflict() {
    use crate::domain::workspace::WorkspaceRegistration;

    let store = setup_store().await;
    let now = Utc::now();
    let expires = now + chrono::Duration::hours(1);

    let reg1 = WorkspaceRegistration {
        pk_hash: "replace-pk-hash".to_string(),
        code_challenge: "challenge-1".to_string(),
        code_hash: "code-hash-1".to_string(),
        approval_code: Some("ALPHA-111111".to_string()),
        expires_at: expires,
        attempts: 0,
        max_attempts: 3,
        approved_by: None,
        created_at: now,
    };

    store
        .create_workspace_registration(&reg1)
        .await
        .expect("create first reg");

    // Create again with same pk_hash (INSERT OR REPLACE)
    let reg2 = WorkspaceRegistration {
        pk_hash: "replace-pk-hash".to_string(),
        code_challenge: "challenge-2".to_string(),
        code_hash: "code-hash-2".to_string(),
        approval_code: Some("BETA-222222".to_string()),
        expires_at: expires,
        attempts: 0,
        max_attempts: 5,
        approved_by: Some("admin".to_string()),
        created_at: now,
    };

    store
        .create_workspace_registration(&reg2)
        .await
        .expect("replace reg");

    // Should have the second registration's data
    let fetched = store
        .get_workspace_registration("replace-pk-hash")
        .await
        .expect("get")
        .unwrap();
    assert_eq!(fetched.code_challenge, "challenge-2");
    assert_eq!(fetched.approval_code, Some("BETA-222222".to_string()));
    assert_eq!(fetched.max_attempts, 5);
    assert_eq!(fetched.approved_by, Some("admin".to_string()));
}
