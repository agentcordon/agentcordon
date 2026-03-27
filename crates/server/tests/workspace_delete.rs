//! Integration tests for DELETE /api/v1/workspaces/{id}.
//!
//! Coverage:
//! - Happy path: create workspace, delete it, verify response
//! - Not found: DELETE non-existent workspace returns 404
//! - Policy cascade: grant policies referencing workspace are deleted on workspace deletion
//! - Audit trail: workspace deletion emits a WorkspaceDeleted audit event
//! - Unauthenticated: DELETE without auth returns 401

use axum::http::{Method, StatusCode};
use serde_json::json;
use uuid::Uuid;

use agent_cordon_core::domain::policy::{PolicyId, StoredPolicy};
use agent_cordon_core::domain::user::UserRole;
use agent_cordon_core::domain::workspace::{Workspace, WorkspaceId, WorkspaceStatus};
use agent_cordon_core::storage::AuditFilter;

use crate::common::*;
use agent_cordon_server::test_helpers::TestAppBuilder;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const TEST_PASSWORD: &str = "delete-test-pass-123!";

/// Create a workspace directly in the store with the given name and optional owner.
async fn create_workspace_in_db(
    store: &(dyn agent_cordon_core::storage::Store + Send + Sync),
    name: &str,
    owner_id: Option<agent_cordon_core::domain::user::UserId>,
) -> Workspace {
    let now = chrono::Utc::now();
    let ws = Workspace {
        id: WorkspaceId(Uuid::new_v4()),
        name: name.to_string(),
        enabled: true,
        status: WorkspaceStatus::Active,
        pk_hash: None,
        encryption_public_key: None,
        tags: vec![],
        owner_id,
        parent_id: None,
        tool_name: None,
        created_at: now,
        updated_at: now,
    };
    store.create_workspace(&ws).await.expect("create workspace");
    ws
}

// ===========================================================================
// 1. Happy path: DELETE workspace returns 200 with {"deleted": true}
// ===========================================================================

#[tokio::test]
async fn delete_workspace_happy_path() {
    let ctx = TestAppBuilder::new().build().await;
    let admin = create_user_in_db(
        &*ctx.store,
        "admin-del-happy",
        TEST_PASSWORD,
        UserRole::Admin,
        true,
        true,
    )
    .await;
    let cookie = login_user_combined(&ctx.app, "admin-del-happy", TEST_PASSWORD).await;

    let ws = create_workspace_in_db(&*ctx.store, "to-delete", Some(admin.id.clone())).await;

    // DELETE the workspace
    let (status, body) = send_json_auto_csrf(
        &ctx.app,
        Method::DELETE,
        &format!("/api/v1/workspaces/{}", ws.id.0),
        None,
        Some(&cookie),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::OK, "delete response: {}", body);
    assert_eq!(body["data"]["deleted"], json!(true));

    // Verify workspace is gone
    let fetched = ctx.store.get_workspace(&ws.id).await.expect("store call");
    assert!(fetched.is_none(), "workspace should be deleted from store");
}

// ===========================================================================
// 2. Not found: DELETE non-existent workspace returns 404
// ===========================================================================

#[tokio::test]
async fn delete_workspace_not_found() {
    let ctx = TestAppBuilder::new().build().await;
    let _admin = create_user_in_db(
        &*ctx.store,
        "admin-del-404",
        TEST_PASSWORD,
        UserRole::Admin,
        true,
        true,
    )
    .await;
    let cookie = login_user_combined(&ctx.app, "admin-del-404", TEST_PASSWORD).await;

    let fake_id = Uuid::new_v4();
    let (status, body) = send_json_auto_csrf(
        &ctx.app,
        Method::DELETE,
        &format!("/api/v1/workspaces/{}", fake_id),
        None,
        Some(&cookie),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::NOT_FOUND, "response: {}", body);
}

// ===========================================================================
// 3. Policy cascade: grant policies are deleted with the workspace
// ===========================================================================

#[tokio::test]
async fn delete_workspace_cascades_grant_policies() {
    let ctx = TestAppBuilder::new().build().await;
    let admin = create_user_in_db(
        &*ctx.store,
        "admin-del-cascade",
        TEST_PASSWORD,
        UserRole::Admin,
        true,
        true,
    )
    .await;
    let cookie = login_user_combined(&ctx.app, "admin-del-cascade", TEST_PASSWORD).await;

    let ws = create_workspace_in_db(&*ctx.store, "cascade-ws", Some(admin.id.clone())).await;
    let ws_id_str = ws.id.0.to_string();

    // Create grant policies that reference this workspace
    let now = chrono::Utc::now();
    for i in 0..2 {
        let policy = StoredPolicy {
            id: PolicyId(Uuid::new_v4()),
            name: format!("grant:{}:test-scope-{}", ws_id_str, i),
            description: Some(format!("Grant policy {} for workspace", i)),
            cedar_policy: format!(
                "permit(principal == AgentCordon::Workspace::\"{}\", action, resource);",
                ws_id_str
            ),
            enabled: true,
            is_system: false,
            created_at: now,
            updated_at: now,
        };
        ctx.store
            .store_policy(&policy)
            .await
            .expect("store grant policy");
    }

    // Also create an unrelated policy that should NOT be deleted
    let unrelated_policy_id = PolicyId(Uuid::new_v4());
    let unrelated = StoredPolicy {
        id: unrelated_policy_id.clone(),
        name: "grant:unrelated-workspace:scope".to_string(),
        description: Some("Unrelated grant policy".to_string()),
        cedar_policy: "permit(principal, action, resource);".to_string(),
        enabled: true,
        is_system: false,
        created_at: now,
        updated_at: now,
    };
    ctx.store
        .store_policy(&unrelated)
        .await
        .expect("store unrelated policy");

    // DELETE the workspace
    let (status, body) = send_json_auto_csrf(
        &ctx.app,
        Method::DELETE,
        &format!("/api/v1/workspaces/{}", ws.id.0),
        None,
        Some(&cookie),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "delete response: {}", body);

    // Verify grant policies for the workspace are gone
    let remaining_policies = ctx.store.list_policies().await.expect("list policies");
    let ws_grant_policies: Vec<_> = remaining_policies
        .iter()
        .filter(|p| p.name.starts_with("grant:") && p.name.contains(&ws_id_str))
        .collect();
    assert!(
        ws_grant_policies.is_empty(),
        "grant policies for deleted workspace should be removed, found: {:?}",
        ws_grant_policies
            .iter()
            .map(|p| &p.name)
            .collect::<Vec<_>>()
    );

    // Verify unrelated policy still exists
    let unrelated_still_exists = remaining_policies
        .iter()
        .any(|p| p.id == unrelated_policy_id);
    assert!(
        unrelated_still_exists,
        "unrelated grant policy should not be deleted"
    );
}

// ===========================================================================
// 4. Audit trail: deletion records a WorkspaceDeleted audit event
// ===========================================================================

#[tokio::test]
async fn delete_workspace_records_audit_event() {
    let ctx = TestAppBuilder::new().build().await;
    let admin = create_user_in_db(
        &*ctx.store,
        "admin-del-audit",
        TEST_PASSWORD,
        UserRole::Admin,
        true,
        true,
    )
    .await;
    let cookie = login_user_combined(&ctx.app, "admin-del-audit", TEST_PASSWORD).await;

    let ws = create_workspace_in_db(&*ctx.store, "audit-ws", Some(admin.id.clone())).await;
    let ws_id_str = ws.id.0.to_string();

    // DELETE the workspace
    let (status, _body) = send_json_auto_csrf(
        &ctx.app,
        Method::DELETE,
        &format!("/api/v1/workspaces/{}", ws.id.0),
        None,
        Some(&cookie),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Check audit events for a WorkspaceDeleted event
    let filter = AuditFilter {
        event_type: Some("workspace_deleted".to_string()),
        limit: 50,
        ..Default::default()
    };
    let events = ctx
        .store
        .list_audit_events_filtered(&filter)
        .await
        .expect("list audit events");

    let delete_event = events
        .iter()
        .find(|e| e.resource_id.as_deref() == Some(&ws_id_str));

    assert!(
        delete_event.is_some(),
        "should have a workspace_deleted audit event for workspace {}",
        ws_id_str
    );

    let evt = delete_event.unwrap();
    assert_eq!(evt.action, "delete");
    assert!(
        matches!(
            evt.decision,
            agent_cordon_core::domain::audit::AuditDecision::Permit
        ),
        "decision should be Permit"
    );
}

// ===========================================================================
// 5. Unauthenticated: DELETE without auth returns 401
// ===========================================================================

#[tokio::test]
async fn delete_workspace_unauthenticated_returns_401() {
    let ctx = TestAppBuilder::new().build().await;
    let ws = create_workspace_in_db(&*ctx.store, "noauth-ws", None).await;

    let (status, _body) = send_json(
        &ctx.app,
        Method::DELETE,
        &format!("/api/v1/workspaces/{}", ws.id.0),
        None,
        None,
        None,
        None,
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Workspace should still exist
    let fetched = ctx.store.get_workspace(&ws.id).await.expect("store call");
    assert!(
        fetched.is_some(),
        "workspace should NOT be deleted without auth"
    );
}

// ===========================================================================
// 6. Forbidden: non-admin user cannot delete workspaces
// ===========================================================================

#[tokio::test]
async fn delete_workspace_non_admin_forbidden() {
    let ctx = TestAppBuilder::new().build().await;
    let _viewer = create_user_in_db(
        &*ctx.store,
        "viewer-del",
        TEST_PASSWORD,
        UserRole::Viewer,
        false,
        true,
    )
    .await;
    let cookie = login_user_combined(&ctx.app, "viewer-del", TEST_PASSWORD).await;

    let ws = create_workspace_in_db(&*ctx.store, "viewer-target-ws", None).await;

    let (status, _body) = send_json_auto_csrf(
        &ctx.app,
        Method::DELETE,
        &format!("/api/v1/workspaces/{}", ws.id.0),
        None,
        Some(&cookie),
        None,
    )
    .await;

    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "viewer should not be able to delete workspaces: {}",
        _body
    );

    // Workspace should still exist
    let fetched = ctx.store.get_workspace(&ws.id).await.expect("store call");
    assert!(
        fetched.is_some(),
        "workspace should NOT be deleted by viewer"
    );
}
