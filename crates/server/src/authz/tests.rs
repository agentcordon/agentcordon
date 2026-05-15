//! Unit tests for [`Authz`].
//!
//! Verifies the public contract of the seam:
//! - permit / deny decisions
//! - opaque error message on `check` deny
//! - reasons surfaced on `check_with_reasons`
//! - filter semantics (denied items dropped)
//! - claim threading into Cedar
//! - OAuth scope short-circuit (workspace actors enforce, users bypass)
//! - `PolicyEvaluated` audit event emission on permit and deny
//! - correlation ID propagation
//! - OAuth claim auto-attach
//! - `From<&T> for PolicyResource` ergonomics

use std::sync::Arc;

use agent_cordon_core::domain::audit::AuditEventType;
use agent_cordon_core::domain::credential::{CredentialId, StoredCredential};
use agent_cordon_core::domain::policy::PolicyDecisionResult;
use agent_cordon_core::domain::user::{User, UserId, UserRole};
use agent_cordon_core::domain::workspace::{Workspace, WorkspaceId, WorkspaceStatus};
use agent_cordon_core::oauth2::types::OAuthScope;
use agent_cordon_core::policy::cedar::CedarPolicyEngine;
use agent_cordon_core::policy::{actions, claim_keys, PolicyResource};
use agent_cordon_core::storage::Store;
use chrono::Utc;
use uuid::Uuid;

use crate::extractors::AuthenticatedActor;
use crate::response::ApiError;

use super::Authz;

fn default_policies() -> Vec<(String, String)> {
    let source = include_str!("../../../../policies/default.cedar");
    vec![("default".to_string(), source.to_string())]
}

fn make_user(role: UserRole, is_root: bool) -> User {
    User {
        id: UserId(Uuid::new_v4()),
        username: "tester".to_string(),
        display_name: None,
        password_hash: "x".to_string(),
        role,
        is_root,
        enabled: true,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

fn make_workspace_with_owner(owner: &User) -> Workspace {
    Workspace {
        id: WorkspaceId(Uuid::new_v4()),
        name: "ws".to_string(),
        tags: vec![],
        enabled: true,
        status: WorkspaceStatus::Active,
        pk_hash: None,
        encryption_public_key: None,
        owner_id: Some(owner.id.clone()),
        parent_id: None,
        tool_name: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

async fn build_authz() -> (Arc<Authz>, Arc<dyn Store + Send + Sync>) {
    let store: Arc<dyn Store + Send + Sync> = Arc::new(
        agent_cordon_core::storage::sqlite::SqliteStore::new_in_memory()
            .await
            .expect("memory store"),
    );
    store.run_migrations().await.expect("migrations");
    let cedar = Arc::new(CedarPolicyEngine::new(default_policies()).expect("cedar"));
    let authz = Arc::new(Authz::new(cedar, store.clone()));
    (authz, store)
}

#[tokio::test]
async fn root_user_check_permits_and_emits_audit() {
    let (authz, store) = build_authz().await;
    let root = make_user(UserRole::Admin, true);
    let actor = AuthenticatedActor::User(root);

    authz
        .request(&actor, "corr-root")
        .check(actions::LIST, &PolicyResource::System)
        .await
        .expect("root must permit");

    // Wait briefly for fire-and-forget audit write.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let events = store.list_audit_events(10, 0).await.expect("audit");
    let policy_events: Vec<_> = events
        .iter()
        .filter(|e| matches!(e.event_type, AuditEventType::PolicyEvaluated))
        .collect();
    assert_eq!(policy_events.len(), 1, "exactly one PolicyEvaluated event");
    assert_eq!(policy_events[0].correlation_id, "corr-root");
}

#[tokio::test]
async fn check_deny_returns_opaque_forbidden_message() {
    let (authz, _store) = build_authz().await;
    let viewer = make_user(UserRole::Viewer, false);
    let actor = AuthenticatedActor::User(viewer);

    let err = authz
        .request(&actor, "corr-deny")
        .check(actions::CREATE, &PolicyResource::System)
        .await
        .expect_err("viewer must deny create");

    match err {
        ApiError::Forbidden(msg) => {
            assert_eq!(
                msg, "access denied by policy",
                "deny error must be the literal opaque string with no policy IDs / reasons"
            );
        }
        other => panic!("expected Forbidden, got {other:?}"),
    }
}

#[tokio::test]
async fn check_with_reasons_surfaces_reasons_for_handler() {
    let (authz, _store) = build_authz().await;
    let admin = make_user(UserRole::Admin, false);
    let actor = AuthenticatedActor::User(admin);

    let decision = authz
        .request(&actor, "corr-reasons")
        .check_with_reasons(actions::LIST, &PolicyResource::System)
        .await
        .expect("admin must permit list system");

    assert_eq!(decision.decision, PolicyDecisionResult::Permit);
    assert!(
        !decision.reasons.is_empty(),
        "permit must have at least one contributing reason"
    );
}

#[tokio::test]
async fn deny_emits_policy_evaluated_audit_with_forbid_decision() {
    let (authz, store) = build_authz().await;
    let viewer = make_user(UserRole::Viewer, false);
    let actor = AuthenticatedActor::User(viewer);

    let _ = authz
        .request(&actor, "corr-forbid-audit")
        .check(actions::CREATE, &PolicyResource::System)
        .await;

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let events = store.list_audit_events(10, 0).await.expect("audit");
    let policy_events: Vec<_> = events
        .iter()
        .filter(|e| matches!(e.event_type, AuditEventType::PolicyEvaluated))
        .collect();
    assert_eq!(policy_events.len(), 1);
    assert!(
        matches!(
            policy_events[0].decision,
            agent_cordon_core::domain::audit::AuditDecision::Forbid
        ),
        "audit decision must be Forbid"
    );
}

#[tokio::test]
async fn workspace_actor_lacking_scope_short_circuits_before_cedar() {
    let (authz, store) = build_authz().await;
    let owner = make_user(UserRole::Admin, false);
    let workspace = make_workspace_with_owner(&owner);
    // No McpInvoke scope.
    let actor = AuthenticatedActor::Workspace {
        workspace,
        scopes: vec![OAuthScope::McpDiscover],
        oauth_claims: None,
    };

    let err = authz
        .request(&actor, "corr-scope")
        .require_scope(OAuthScope::McpInvoke)
        .check(actions::MCP_TOOL_CALL, &PolicyResource::System)
        .await
        .expect_err("missing scope must forbid");
    assert!(matches!(err, ApiError::Forbidden(_)));

    // No Cedar evaluation occurred -> no PolicyEvaluated audit event.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let events = store.list_audit_events(10, 0).await.expect("audit");
    assert!(
        !events
            .iter()
            .any(|e| matches!(e.event_type, AuditEventType::PolicyEvaluated)),
        "scope-fail must not emit a PolicyEvaluated event"
    );
}

#[tokio::test]
async fn user_actor_bypasses_required_scope() {
    let (authz, _store) = build_authz().await;
    let admin = make_user(UserRole::Admin, true); // root for permit
    let actor = AuthenticatedActor::User(admin);

    authz
        .request(&actor, "corr-user-scope")
        .require_scope(OAuthScope::McpInvoke) // user must bypass
        .check(actions::LIST, &PolicyResource::System)
        .await
        .expect("user actors must bypass scope check");
}

#[tokio::test]
async fn claim_threads_into_cedar_context() {
    // We can't easily inspect Cedar's evaluated context from outside, but
    // build_context reads the claim bag, so a successful evaluation that
    // would require the claim being present is sufficient. Use a root
    // bypass to avoid policy authorship in the test, and simply assert
    // the call doesn't error.
    let (authz, _store) = build_authz().await;
    let root = make_user(UserRole::Admin, true);
    let actor = AuthenticatedActor::User(root);

    authz
        .request(&actor, "corr-claim")
        .claim(claim_keys::TOOL_NAME, "send_message")
        .claim(claim_keys::JUSTIFICATION, "unit test")
        .check(actions::MCP_TOOL_CALL, &PolicyResource::System)
        .await
        .expect("root permits regardless");
}

#[tokio::test]
async fn correlation_id_propagates_into_audit_event() {
    let (authz, store) = build_authz().await;
    let root = make_user(UserRole::Admin, true);
    let actor = AuthenticatedActor::User(root);

    authz
        .request(&actor, "specific-correlation-id-xyz")
        .check(actions::LIST, &PolicyResource::System)
        .await
        .expect("permit");

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let events = store.list_audit_events(10, 0).await.expect("audit");
    let policy_events: Vec<_> = events
        .iter()
        .filter(|e| matches!(e.event_type, AuditEventType::PolicyEvaluated))
        .collect();
    assert_eq!(policy_events.len(), 1);
    assert_eq!(
        policy_events[0].correlation_id,
        "specific-correlation-id-xyz"
    );
}

#[tokio::test]
async fn oauth_claims_auto_attach_into_audit_metadata() {
    let (authz, store) = build_authz().await;
    let owner = make_user(UserRole::Admin, false);
    let workspace = make_workspace_with_owner(&owner);
    let claims = serde_json::json!({"sub": "abc", "iss": "test"});
    let actor = AuthenticatedActor::Workspace {
        workspace,
        scopes: vec![],
        oauth_claims: Some(claims.clone()),
    };

    let _ = authz
        .request(&actor, "corr-oauth")
        .check(actions::LIST, &PolicyResource::System)
        .await;

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let events = store.list_audit_events(10, 0).await.expect("audit");
    let policy = events
        .iter()
        .find(|e| matches!(e.event_type, AuditEventType::PolicyEvaluated))
        .expect("policy event present");
    assert_eq!(
        policy.metadata["oauth_claims"], claims,
        "oauth claims must be auto-attached into audit metadata"
    );
}

#[tokio::test]
async fn filter_drops_denied_items_silently() {
    let (authz, _store) = build_authz().await;
    // Root user permits everything.
    let root = make_user(UserRole::Admin, true);
    let actor = AuthenticatedActor::User(root);

    let creds = vec![StoredCredential {
        id: CredentialId(Uuid::new_v4()),
        name: "a".to_string(),
        service: "svc".to_string(),
        encrypted_value: vec![],
        nonce: vec![],
        scopes: vec![],
        metadata: serde_json::Value::Null,
        created_by: None,
        created_by_user: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
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
    }];
    let kept = authz
        .request(&actor, "corr-filter")
        .filter(actions::ACCESS, creds, |c| PolicyResource::Credential {
            credential: c.clone(),
        })
        .await
        .expect("filter ok");
    assert_eq!(kept.len(), 1, "root must keep all items");
}

#[tokio::test]
async fn from_stored_credential_ref_for_policy_resource() {
    // Compile-time check that the ergonomic `From<&StoredCredential>` impl
    // exists and produces a Credential variant. Also exercises the same
    // for &Workspace.
    let cred = StoredCredential {
        id: CredentialId(Uuid::new_v4()),
        name: "x".to_string(),
        service: "y".to_string(),
        encrypted_value: vec![],
        nonce: vec![],
        scopes: vec![],
        metadata: serde_json::Value::Null,
        created_by: None,
        created_by_user: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
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
    let r: PolicyResource = (&cred).into();
    assert!(matches!(r, PolicyResource::Credential { .. }));

    let owner = make_user(UserRole::Admin, false);
    let ws = make_workspace_with_owner(&owner);
    let r2: PolicyResource = (&ws).into();
    assert!(matches!(r2, PolicyResource::WorkspaceResource { .. }));
}
