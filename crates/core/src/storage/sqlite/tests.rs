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
    assert_eq!(fetched.status, agent.status);

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
        vault_id: crate::domain::vault::DEFAULT_VAULT_ID.to_string(),
        vault_name: "default".to_string(),
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
        vault_id: crate::domain::vault::DEFAULT_VAULT_ID.to_string(),
        vault_name: "default".to_string(),
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
        vault_id: crate::domain::vault::DEFAULT_VAULT_ID.to_string(),
        vault_name: "default".to_string(),
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
        vault_id: crate::domain::vault::DEFAULT_VAULT_ID.to_string(),
        vault_name: "default".to_string(),
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
        vault_id: crate::domain::vault::DEFAULT_VAULT_ID.to_string(),
        vault_name: "default".to_string(),
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
        vault_id: crate::domain::vault::DEFAULT_VAULT_ID.to_string(),
        vault_name: "default".to_string(),
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
        vault_id: crate::domain::vault::DEFAULT_VAULT_ID.to_string(),
        vault_name: "default".to_string(),
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
        vault_id: crate::domain::vault::DEFAULT_VAULT_ID.to_string(),
        vault_name: "default".to_string(),
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
        vault_id: crate::domain::vault::DEFAULT_VAULT_ID.to_string(),
        vault_name: "default".to_string(),
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

// ---------------------------------------------------------------------------
// Store contracts: error mapping
//
// The driver's constraint failures surface as `Conflict` (naming the
// constraint) and a missing row as `NotFound`, from every method, so the
// HTTP layer can answer 409 and 404 without per-method special cases.
// ---------------------------------------------------------------------------

fn make_user(username: &str) -> crate::domain::user::User {
    let now = Utc::now();
    crate::domain::user::User {
        id: crate::domain::user::UserId(Uuid::new_v4()),
        username: username.to_string(),
        display_name: None,
        password_hash: "hash".to_string(),
        role: crate::domain::user::UserRole::Viewer,
        is_root: false,
        enabled: true,
        created_at: now,
        updated_at: now,
    }
}

fn make_credential(name: &str, created_at: chrono::DateTime<Utc>) -> StoredCredential {
    StoredCredential {
        id: CredentialId(Uuid::new_v4()),
        name: name.to_string(),
        service: "svc".to_string(),
        encrypted_value: vec![1, 2, 3],
        nonce: vec![4, 5, 6],
        scopes: vec![],
        metadata: serde_json::json!({}),
        created_by: None,
        created_by_user: None,
        created_at,
        updated_at: created_at,
        allowed_url_pattern: None,
        expires_at: None,
        transform_script: None,
        transform_name: None,
        vault_id: crate::domain::vault::DEFAULT_VAULT_ID.to_string(),
        vault_name: "default".to_string(),
        credential_type: "generic".to_string(),
        tags: vec![],
        description: None,
        target_identity: None,
        key_version: 1,
    }
}

fn conflict_message(err: StoreError) -> String {
    match err {
        StoreError::Conflict { message, .. } => message,
        other => panic!("expected Conflict, got {other:?}"),
    }
}

#[tokio::test]
async fn duplicate_username_is_a_conflict_naming_the_constraint() {
    let store = setup_store().await;
    store.create_user(&make_user("dup")).await.expect("first");
    let err = store
        .create_user(&make_user("dup"))
        .await
        .expect_err("second insert of the same username must fail");
    let message = conflict_message(err);
    assert!(message.contains("users.username"), "{message}");
}

#[tokio::test]
async fn updating_a_missing_user_is_not_found() {
    let store = setup_store().await;
    let err = store
        .update_user(&make_user("ghost"))
        .await
        .expect_err("no such user");
    assert!(matches!(err, StoreError::NotFound(_)), "{err:?}");
}

#[tokio::test]
async fn updating_a_missing_workspace_is_not_found() {
    let store = setup_store().await;
    let err = store
        .update_workspace(&make_agent("ghost"))
        .await
        .expect_err("no such workspace");
    assert!(matches!(err, StoreError::NotFound(_)), "{err:?}");
}

#[tokio::test]
async fn duplicate_credential_id_is_a_conflict() {
    let store = setup_store().await;
    let cred = make_credential("twice", Utc::now());
    store.store_credential(&cred).await.expect("first");
    let err = store
        .store_credential(&cred)
        .await
        .expect_err("same primary key");
    let message = conflict_message(err);
    assert!(message.contains("credentials.id"), "{message}");
}

#[tokio::test]
async fn dangling_foreign_key_is_a_conflict() {
    let store = setup_store().await;
    let mut cred = make_credential("orphan", Utc::now());
    cred.created_by_user = Some(crate::domain::user::UserId(Uuid::new_v4()));
    let err = store
        .store_credential(&cred)
        .await
        .expect_err("created_by_user points at no user");
    let message = conflict_message(err);
    assert!(message.contains("FOREIGN KEY"), "{message}");
}

#[tokio::test]
async fn duplicate_vault_share_is_a_conflict() {
    use crate::domain::vault::VaultShare;

    let store = setup_store().await;
    let owner = crate::domain::user::UserId(Uuid::new_v4());
    let target = crate::domain::user::UserId(Uuid::new_v4());
    insert_test_user(&store, &owner).await;
    insert_test_user(&store, &target).await;
    let share = |id: &str| VaultShare {
        id: id.to_string(),
        vault_id: crate::domain::vault::DEFAULT_VAULT_ID.to_string(),
        shared_with_user_id: target.clone(),
        permission_level: "read".to_string(),
        shared_by_user_id: owner.clone(),
        created_at: Utc::now(),
    };
    store.share_vault(&share("s1")).await.expect("first share");
    let err = store
        .share_vault(&share("s2"))
        .await
        .expect_err("same vault and user again");
    let message = conflict_message(err);
    assert!(message.contains("vault_shares"), "{message}");
}

// ---------------------------------------------------------------------------
// Store contracts: timestamps
//
// Every write uses one fixed-precision RFC 3339 form so `ORDER BY created_at`
// is chronological, and reads still accept the free-precision values earlier
// releases wrote.
// ---------------------------------------------------------------------------

async fn seed_credential_with_raw_created_at(
    store: &SqliteStore,
    name: &str,
    created_at: &str,
) -> CredentialId {
    let id = CredentialId(Uuid::new_v4());
    let id_str = id.0.hyphenated().to_string();
    let name = name.to_string();
    let created_at = created_at.to_string();
    store
        .conn()
        .call(move |conn| {
            conn.execute(
                "INSERT INTO credentials (id, name, service, encrypted_value, nonce, created_at, updated_at) \
                 VALUES (?1, ?2, 'svc', X'00', X'00', ?3, ?3)",
                rusqlite::params![id_str, name, created_at],
            )?;
            Ok(())
        })
        .await
        .expect("seed credential");
    id
}

async fn raw_created_at(store: &SqliteStore, id: &CredentialId) -> String {
    let id_str = id.0.hyphenated().to_string();
    store
        .conn()
        .call(move |conn| {
            Ok(conn.query_row(
                "SELECT created_at FROM credentials WHERE id = ?1",
                rusqlite::params![id_str],
                |r| r.get::<_, String>(0),
            )?)
        })
        .await
        .expect("read created_at")
}

#[tokio::test]
async fn timestamps_sort_and_round_trip_across_old_and_new_formats() {
    use chrono::TimeZone;

    let store = setup_store().await;
    let base = Utc.with_ymd_and_hms(2026, 3, 1, 12, 0, 0).unwrap();

    // Rows written by earlier releases: free precision, "+00:00" offset.
    let old_zero =
        seed_credential_with_raw_created_at(&store, "ts", "2026-03-01T12:00:00+00:00").await;
    let old_nanos =
        seed_credential_with_raw_created_at(&store, "ts", "2026-03-01T12:00:00.750000000+00:00")
            .await;

    // A row written by this release, between the two.
    let new = make_credential("ts", base + chrono::Duration::milliseconds(250));
    store.store_credential(&new).await.expect("store");

    let written = raw_created_at(&store, &new.id).await;
    assert_eq!(
        written, "2026-03-01T12:00:00.250000Z",
        "writes use fixed microsecond precision with a Z suffix"
    );

    let rows = store
        .list_stored_credentials_by_name("ts")
        .await
        .expect("list ordered by created_at");
    let ids: Vec<CredentialId> = rows.iter().map(|c| c.id.clone()).collect();
    assert_eq!(
        ids,
        vec![old_zero, new.id.clone(), old_nanos],
        "ORDER BY created_at is chronological across old and new rows"
    );
    assert_eq!(rows[0].created_at, base);
    assert_eq!(rows[1].created_at, new.created_at);
    assert_eq!(
        rows[2].created_at,
        base + chrono::Duration::milliseconds(750)
    );
}

// ---------------------------------------------------------------------------
// Store contracts: atomic multi-step writes
//
// Consume-then-mint, archive-then-replace, and delete-then-insert are single
// store operations in one immediate transaction. A failure in the second
// step leaves the first invisible; the compare-and-swap of the first step
// still makes a second caller lose and mint nothing.
// ---------------------------------------------------------------------------

use crate::oauth2::types::{
    DeviceCode, DeviceCodeStatus, OAuthAccessToken, OAuthAuthCode, OAuthClient, OAuthRefreshToken,
};
use crate::storage::{DeviceCodeStore, OAuthStore};

/// The public bootstrap client seeded by migration 006.
const BOOTSTRAP_CLIENT: &str = "agentcordon-broker";

async fn exec_raw(store: &SqliteStore, sql: &str) {
    let sql = sql.to_string();
    store
        .conn()
        .call(move |conn| {
            conn.execute_batch(&sql)?;
            Ok(())
        })
        .await
        .expect("raw sql");
}

async fn count_raw(store: &SqliteStore, sql: &str) -> i64 {
    let sql = sql.to_string();
    store
        .conn()
        .call(move |conn| Ok(conn.query_row(&sql, [], |r| r.get::<_, i64>(0))?))
        .await
        .expect("raw count")
}

fn token_pair(client_id: &str, suffix: &str) -> (OAuthAccessToken, OAuthRefreshToken) {
    let now = Utc::now();
    let user_id = crate::domain::user::UserId(Uuid::new_v4());
    let access = OAuthAccessToken {
        token_hash: format!("at-{suffix}"),
        client_id: client_id.to_string(),
        user_id: user_id.clone(),
        scopes: vec![],
        created_at: now,
        expires_at: now + chrono::Duration::minutes(15),
        revoked_at: None,
    };
    let refresh = OAuthRefreshToken {
        token_hash: format!("rt-{suffix}"),
        client_id: client_id.to_string(),
        user_id,
        scopes: vec![],
        access_token_hash: access.token_hash.clone(),
        family_id: format!("rt-{suffix}"),
        created_at: now,
        expires_at: now + chrono::Duration::days(30),
        revoked_at: None,
    };
    (access, refresh)
}

async fn approved_device_code(store: &SqliteStore, hash: &str) {
    let now = Utc::now();
    store
        .insert_device_code(&DeviceCode {
            device_code: hash.to_string(),
            user_code: format!("uc-{hash}"),
            client_id: BOOTSTRAP_CLIENT.to_string(),
            scopes: vec![],
            status: DeviceCodeStatus::Pending,
            workspace_name_prefill: None,
            pk_hash_prefill: None,
            approved_user_id: None,
            last_polled_at: None,
            interval_secs: 5,
            created_at: now,
            expires_at: now + chrono::Duration::minutes(10),
        })
        .await
        .expect("insert device code");
    assert!(store
        .approve_device_code(&format!("uc-{hash}"), "u1")
        .await
        .expect("approve"));
}

async fn device_code_status(store: &SqliteStore, hash: &str) -> DeviceCodeStatus {
    store
        .get_device_code_by_device_code(hash)
        .await
        .expect("lookup")
        .expect("row")
        .status
}

#[tokio::test]
async fn device_code_consume_and_mint_is_all_or_nothing() {
    let store = setup_store().await;
    approved_device_code(&store, "dc1").await;

    // The refresh token names a client that does not exist, so its insert
    // fails on the foreign key after the code was marked consumed.
    let (access, mut refresh) = token_pair(BOOTSTRAP_CLIENT, "bad");
    refresh.client_id = "no-such-client".to_string();
    let err = store
        .consume_device_code_and_issue_tokens("dc1", &access, &refresh)
        .await
        .expect_err("the mint fails");
    assert!(matches!(err, StoreError::Conflict { .. }), "{err:?}");
    assert_eq!(
        device_code_status(&store, "dc1").await,
        DeviceCodeStatus::Approved
    );
    assert_eq!(
        count_raw(&store, "SELECT COUNT(*) FROM oauth_access_tokens").await,
        0
    );

    // The same code then exchanges cleanly.
    let (access, refresh) = token_pair(BOOTSTRAP_CLIENT, "ok");
    assert!(store
        .consume_device_code_and_issue_tokens("dc1", &access, &refresh)
        .await
        .expect("consume and mint"));
    assert_eq!(
        device_code_status(&store, "dc1").await,
        DeviceCodeStatus::Consumed
    );
    assert!(store
        .get_oauth_access_token("at-ok")
        .await
        .unwrap()
        .is_some());
    assert!(store
        .get_oauth_refresh_token("rt-ok")
        .await
        .unwrap()
        .is_some());

    // A second consume loses the compare-and-swap and mints nothing.
    let (access, refresh) = token_pair(BOOTSTRAP_CLIENT, "late");
    assert!(!store
        .consume_device_code_and_issue_tokens("dc1", &access, &refresh)
        .await
        .expect("second consume"));
    assert_eq!(
        count_raw(&store, "SELECT COUNT(*) FROM oauth_access_tokens").await,
        1
    );
    assert_eq!(
        count_raw(&store, "SELECT COUNT(*) FROM oauth_refresh_tokens").await,
        1
    );
}

#[tokio::test]
async fn auth_code_consume_and_mint_is_all_or_nothing() {
    let store = setup_store().await;
    let now = Utc::now();
    store
        .create_oauth_auth_code(&OAuthAuthCode {
            code_hash: "code-1".to_string(),
            client_id: BOOTSTRAP_CLIENT.to_string(),
            user_id: crate::domain::user::UserId(Uuid::new_v4()),
            redirect_uri: "http://localhost:1/cb".to_string(),
            scopes: vec![],
            code_challenge: None,
            created_at: now,
            expires_at: now + chrono::Duration::minutes(5),
            consumed_at: None,
        })
        .await
        .expect("auth code");

    let (mut access, refresh) = token_pair(BOOTSTRAP_CLIENT, "bad");
    access.client_id = "no-such-client".to_string();
    let err = store
        .consume_oauth_auth_code_and_issue_tokens("code-1", &access, &refresh)
        .await
        .expect_err("the mint fails");
    assert!(matches!(err, StoreError::Conflict { .. }), "{err:?}");
    let code = store.get_oauth_auth_code("code-1").await.unwrap().unwrap();
    assert!(code.consumed_at.is_none(), "the code is not consumed");
    assert_eq!(
        count_raw(&store, "SELECT COUNT(*) FROM oauth_refresh_tokens").await,
        0
    );

    let (access, refresh) = token_pair(BOOTSTRAP_CLIENT, "ok");
    assert!(store
        .consume_oauth_auth_code_and_issue_tokens("code-1", &access, &refresh)
        .await
        .expect("consume and mint"));
    let code = store.get_oauth_auth_code("code-1").await.unwrap().unwrap();
    assert!(code.consumed_at.is_some());

    let (access, refresh) = token_pair(BOOTSTRAP_CLIENT, "late");
    assert!(!store
        .consume_oauth_auth_code_and_issue_tokens("code-1", &access, &refresh)
        .await
        .expect("second consume"));
    assert_eq!(
        count_raw(&store, "SELECT COUNT(*) FROM oauth_access_tokens").await,
        1
    );
}

fn secret_update(
    value: &[u8],
    nonce: &[u8],
    key_version: i64,
) -> crate::domain::credential::CredentialUpdate {
    crate::domain::credential::CredentialUpdate {
        name: None,
        service: None,
        scopes: None,
        metadata: None,
        allowed_url_pattern: None,
        expires_at: None,
        transform_script: None,
        transform_name: None,
        vault_id: None,
        tags: None,
        description: None,
        target_identity: None,
        encrypted_value: Some(value.to_vec()),
        nonce: Some(nonce.to_vec()),
        key_version: Some(key_version),
    }
}

#[tokio::test]
async fn secret_rotation_archives_and_replaces_in_one_transaction() {
    let store = setup_store().await;
    let mut cred = make_credential("rot", Utc::now());
    cred.key_version = 3;
    store.store_credential(&cred).await.expect("store");

    // A write that fails leaves no history row and the old ciphertext.
    exec_raw(
        &store,
        "CREATE TRIGGER fail_update BEFORE UPDATE ON credentials \
         BEGIN SELECT RAISE(ABORT, 'injected'); END;",
    )
    .await;
    let err = store
        .rotate_credential_secret(
            &cred.id,
            &secret_update(b"new", b"n2", 4),
            Some("alice"),
            None,
        )
        .await
        .expect_err("the write fails");
    assert!(matches!(err, StoreError::Database(_)), "{err:?}");
    assert!(store
        .list_secret_history(&cred.id)
        .await
        .unwrap()
        .is_empty());
    let unchanged = store.get_credential(&cred.id).await.unwrap().unwrap();
    assert_eq!(unchanged.encrypted_value, cred.encrypted_value);
    exec_raw(&store, "DROP TRIGGER fail_update;").await;

    // The rotation archives what the row held, under the row's key version.
    assert!(store
        .rotate_credential_secret(
            &cred.id,
            &secret_update(b"new", b"n2", 4),
            Some("alice"),
            None
        )
        .await
        .expect("rotate"));
    let history = store.list_secret_history(&cred.id).await.unwrap();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].changed_by_user.as_deref(), Some("alice"));
    let archived = store
        .get_secret_history_value(&cred.id, &history[0].id.to_string())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(archived.encrypted_value, cred.encrypted_value);
    assert_eq!(archived.nonce, cred.nonce);
    assert_eq!(archived.key_version, 3);
    let rotated = store.get_credential(&cred.id).await.unwrap().unwrap();
    assert_eq!(rotated.encrypted_value, b"new");
    assert_eq!(rotated.nonce, b"n2");
    assert_eq!(rotated.key_version, 4);

    // A credential that does not exist archives nothing.
    let missing = CredentialId(Uuid::new_v4());
    assert!(!store
        .rotate_credential_secret(&missing, &secret_update(b"x", b"y", 1), None, None)
        .await
        .expect("no row"));
    assert_eq!(
        count_raw(&store, "SELECT COUNT(*) FROM credential_secret_history").await,
        1
    );

    // An update without a new ciphertext is refused outright.
    let mut no_secret = secret_update(b"x", b"y", 1);
    no_secret.encrypted_value = None;
    assert!(store
        .rotate_credential_secret(&cred.id, &no_secret, None, None)
        .await
        .is_err());
}

fn make_client(client_id: &str, pk_hash: &str) -> OAuthClient {
    OAuthClient {
        id: Uuid::new_v4(),
        client_id: client_id.to_string(),
        client_secret_hash: None,
        workspace_name: "ws".to_string(),
        public_key_hash: pk_hash.to_string(),
        workspace_id: None,
        redirect_uris: vec![],
        allowed_scopes: vec![],
        created_by_user: crate::domain::user::UserId(Uuid::new_v4()),
        created_at: Utc::now(),
        revoked_at: None,
    }
}

#[tokio::test]
async fn client_replacement_deletes_and_inserts_in_one_transaction() {
    let store = setup_store().await;
    let old = make_client("client-old", "hash-1");
    store.create_oauth_client(&old).await.expect("old client");
    let (access, refresh) = token_pair("client-old", "old");
    store.create_oauth_access_token(&access).await.unwrap();
    store.create_oauth_refresh_token(&refresh).await.unwrap();

    // A failed insert leaves the old client and its tokens alone.
    exec_raw(
        &store,
        "CREATE TRIGGER fail_insert BEFORE INSERT ON oauth_clients \
         BEGIN SELECT RAISE(ABORT, 'injected'); END;",
    )
    .await;
    let err = store
        .replace_oauth_client(&make_client("client-new", "hash-1"))
        .await
        .expect_err("the insert fails");
    assert!(matches!(err, StoreError::Database(_)), "{err:?}");
    assert!(store
        .get_oauth_client_by_client_id("client-old")
        .await
        .unwrap()
        .is_some());
    assert!(store
        .get_oauth_access_token("at-old")
        .await
        .unwrap()
        .is_some());
    exec_raw(&store, "DROP TRIGGER fail_insert;").await;

    // The replacement removes the old client with everything that referred to it.
    let replaced = store
        .replace_oauth_client(&make_client("client-new", "hash-1"))
        .await
        .expect("replace");
    assert_eq!(replaced.as_deref(), Some("client-old"));
    assert!(store
        .get_oauth_client_by_client_id("client-old")
        .await
        .unwrap()
        .is_none());
    assert!(store
        .get_oauth_access_token("at-old")
        .await
        .unwrap()
        .is_none());
    assert!(store
        .get_oauth_refresh_token("rt-old")
        .await
        .unwrap()
        .is_none());
    let current = store
        .get_oauth_client_by_public_key_hash("hash-1")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(current.client_id, "client-new");

    // With nothing to replace it is a plain insert.
    let fresh = store
        .replace_oauth_client(&make_client("client-other", "hash-2"))
        .await
        .expect("insert");
    assert_eq!(fresh, None);
}
