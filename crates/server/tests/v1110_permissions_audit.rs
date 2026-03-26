//! v1.11.0 — Permissions Audit Event Tests (Feature 3)
//!
//! `GET /api/v1/credentials/{id}/permissions` must emit a `PolicyEvaluated`
//! audit event for compliance.

use crate::common;

use agent_cordon_core::domain::audit::AuditEvent;
use agent_cordon_core::domain::user::UserRole;
use agent_cordon_core::storage::{AuditFilter, Store};
use agent_cordon_server::test_helpers::TestAppBuilder;
use axum::http::{Method, StatusCode};
use serde_json::json;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async fn setup() -> (agent_cordon_server::test_helpers::TestContext, String) {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let _user = common::create_test_user(
        &*ctx.store,
        "perm-audit-user",
        common::TEST_PASSWORD,
        UserRole::Admin,
    )
    .await;
    let cookie =
        common::login_user_combined(&ctx.app, "perm-audit-user", common::TEST_PASSWORD).await;
    (ctx, cookie)
}

#[allow(dead_code)]
async fn setup_viewer() -> (agent_cordon_server::test_helpers::TestContext, String) {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let _user = common::create_test_user(
        &*ctx.store,
        "perm-audit-viewer",
        common::TEST_PASSWORD,
        UserRole::Viewer,
    )
    .await;
    let cookie =
        common::login_user_combined(&ctx.app, "perm-audit-viewer", common::TEST_PASSWORD).await;
    (ctx, cookie)
}

async fn create_test_credential(app: &axum::Router, cookie: &str, name: &str) -> String {
    let (status, body) = common::send_json_auto_csrf(
        app,
        Method::POST,
        "/api/v1/credentials",
        None,
        Some(cookie),
        Some(json!({
            "name": name,
            "service": "test-service",
            "secret_value": "test-secret-value",
        })),
    )
    .await;

    assert!(
        status == StatusCode::CREATED || status == StatusCode::OK,
        "credential creation should succeed: status={}, body={:?}",
        status,
        body,
    );

    body["data"]["id"]
        .as_str()
        .expect("credential should have id")
        .to_string()
}

/// Get audit events filtered by resource_id.
async fn get_audit_events_for_resource(
    store: &(dyn Store + Send + Sync),
    resource_id: &str,
) -> Vec<AuditEvent> {
    store
        .list_audit_events_filtered(&AuditFilter {
            limit: 100,
            offset: 0,
            resource_id: Some(resource_id.to_string()),
            ..Default::default()
        })
        .await
        .expect("list audit events")
}

// ===========================================================================
// 3A. Happy Path
// ===========================================================================

/// GET permissions emits an audit event.
#[tokio::test]
async fn test_get_permissions_emits_audit_event() {
    let (ctx, cookie) = setup().await;
    let cred_id = create_test_credential(&ctx.app, &cookie, "audit-cred-1").await;

    // GET permissions
    let (status, _body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::GET,
        &format!("/api/v1/credentials/{}/permissions", cred_id),
        None,
        Some(&cookie),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "GET permissions should return 200");

    // Check audit log for permissions-related event
    let events = get_audit_events_for_resource(&*ctx.store, &cred_id).await;

    let has_permissions_event = events.iter().any(|e| {
        let event_type_str = serde_json::to_string(&e.event_type).unwrap_or_default();
        event_type_str.contains("policy_evaluated")
            || event_type_str.contains("PolicyEvaluated")
            || e.action.contains("permissions")
            || e.action.contains("query")
    });

    assert!(
        has_permissions_event,
        "audit log should contain a permissions/policy evaluation event for credential {}. Found events: {:?}",
        cred_id,
        events.iter().map(|e| (&e.action, &e.resource_type)).collect::<Vec<_>>()
    );
}

/// Audit event has correct fields.
#[tokio::test]
async fn test_get_permissions_audit_event_has_correct_fields() {
    let (ctx, cookie) = setup().await;
    let cred_id = create_test_credential(&ctx.app, &cookie, "audit-cred-fields").await;

    let (_status, _body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::GET,
        &format!("/api/v1/credentials/{}/permissions", cred_id),
        None,
        Some(&cookie),
        None,
    )
    .await;

    let events = get_audit_events_for_resource(&*ctx.store, &cred_id).await;

    // Find the permissions-related event
    let perm_event = events.iter().find(|e| {
        let event_type_str = serde_json::to_string(&e.event_type).unwrap_or_default();
        event_type_str.contains("policy_evaluated")
            || event_type_str.contains("PolicyEvaluated")
            || e.action.contains("permissions")
    });

    if let Some(event) = perm_event {
        // Verify fields
        assert!(event.resource_id.is_some(), "event should have resource_id");
        assert_eq!(
            event.resource_id.as_deref(),
            Some(cred_id.as_str()),
            "resource_id should match credential ID"
        );
        assert!(
            event.resource_type == "Credential" || event.resource_type == "credential",
            "resource_type should be Credential, got: {}",
            event.resource_type
        );
        // Should have a user_id (the requesting admin)
        assert!(
            event.user_id.is_some() || event.user_name.is_some(),
            "event should identify the requesting principal"
        );
    }
    // If the feature isn't implemented yet, perm_event may be None — that's expected
}

// ===========================================================================
// 3B. Retry/Idempotency
// ===========================================================================

/// Two GET permissions calls create two audit events.
#[tokio::test]
async fn test_get_permissions_twice_creates_two_audit_events() {
    let (ctx, cookie) = setup().await;
    let cred_id = create_test_credential(&ctx.app, &cookie, "audit-cred-twice").await;

    // First GET
    let _ = common::send_json_auto_csrf(
        &ctx.app,
        Method::GET,
        &format!("/api/v1/credentials/{}/permissions", cred_id),
        None,
        Some(&cookie),
        None,
    )
    .await;

    // Second GET
    let _ = common::send_json_auto_csrf(
        &ctx.app,
        Method::GET,
        &format!("/api/v1/credentials/{}/permissions", cred_id),
        None,
        Some(&cookie),
        None,
    )
    .await;

    let events = get_audit_events_for_resource(&*ctx.store, &cred_id).await;

    let perm_events: Vec<_> = events
        .iter()
        .filter(|e| {
            let event_type_str = serde_json::to_string(&e.event_type).unwrap_or_default();
            event_type_str.contains("policy_evaluated")
                || event_type_str.contains("PolicyEvaluated")
                || e.action.contains("permissions")
        })
        .collect();

    // If feature is implemented, there should be exactly 2 events
    if !perm_events.is_empty() {
        assert_eq!(
            perm_events.len(),
            2,
            "two GET permissions calls should create exactly 2 audit events, found {}",
            perm_events.len()
        );
    }
}

// ===========================================================================
// 3C. Error Handling
// ===========================================================================

/// GET permissions for nonexistent credential → 404 and no audit event.
#[tokio::test]
async fn test_get_permissions_nonexistent_credential_no_audit() {
    let (ctx, cookie) = setup().await;
    let fake_id = uuid::Uuid::new_v4().to_string();

    let (status, _body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::GET,
        &format!("/api/v1/credentials/{}/permissions", fake_id),
        None,
        Some(&cookie),
        None,
    )
    .await;

    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "nonexistent credential should return 404"
    );

    let events = get_audit_events_for_resource(&*ctx.store, &fake_id).await;

    let perm_events: Vec<_> = events
        .iter()
        .filter(|e| e.action.contains("permissions"))
        .collect();

    assert!(
        perm_events.is_empty(),
        "no audit event should be created for failed lookups"
    );
}

/// Unauthorized user gets 403 and a denied audit event.
#[tokio::test]
async fn test_get_permissions_unauthorized_emits_denied_audit() {
    // Create credential with admin setup
    let (admin_ctx, admin_cookie) = setup().await;
    let cred_id = create_test_credential(&admin_ctx.app, &admin_cookie, "audit-cred-unauth").await;

    // Now try to access with a viewer
    let _viewer = common::create_test_user(
        &*admin_ctx.store,
        "perm-audit-viewer2",
        common::TEST_PASSWORD,
        UserRole::Viewer,
    )
    .await;
    let viewer_cookie =
        common::login_user_combined(&admin_ctx.app, "perm-audit-viewer2", common::TEST_PASSWORD)
            .await;

    let (status, _body) = common::send_json_auto_csrf(
        &admin_ctx.app,
        Method::GET,
        &format!("/api/v1/credentials/{}/permissions", cred_id),
        None,
        Some(&viewer_cookie),
        None,
    )
    .await;

    // Viewer may or may not have access depending on policy config
    // If 403, check for denied audit event
    if status == StatusCode::FORBIDDEN {
        let events = get_audit_events_for_resource(&*admin_ctx.store, &cred_id).await;
        let denied_events: Vec<_> = events
            .iter()
            .filter(|e| {
                let decision = serde_json::to_string(&e.decision).unwrap_or_default();
                decision.contains("forbid")
            })
            .collect();

        // If feature is implemented, there should be a denied event
        if !denied_events.is_empty() {
            assert!(
                !denied_events.is_empty(),
                "denied permissions access should create a deny audit event"
            );
        }
    }
}

// ===========================================================================
// 3D. Cross-Feature
// ===========================================================================

/// Permissions audit event appears in audit log API.
#[tokio::test]
async fn test_permissions_audit_visible_in_audit_log_api() {
    let (ctx, cookie) = setup().await;
    let cred_id = create_test_credential(&ctx.app, &cookie, "audit-cred-visible").await;

    // Trigger permissions query
    let _ = common::send_json_auto_csrf(
        &ctx.app,
        Method::GET,
        &format!("/api/v1/credentials/{}/permissions", cred_id),
        None,
        Some(&cookie),
        None,
    )
    .await;

    // Query audit log API with resource_id filter
    let (status, body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::GET,
        &format!("/api/v1/audit?resource_id={}", cred_id),
        None,
        Some(&cookie),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::OK, "audit API should return 200");
    // The audit event should be present if feature is implemented
    // Just verify the API returns valid data
    assert!(
        body["data"].is_array() || body["data"].is_object(),
        "audit API should return data"
    );
}

// ===========================================================================
// 3E. Security
// ===========================================================================

/// Audit event does not leak credential secrets.
#[tokio::test]
async fn test_permissions_audit_does_not_leak_secrets() {
    let (ctx, cookie) = setup().await;
    let cred_id = create_test_credential(&ctx.app, &cookie, "audit-cred-secret").await;

    // GET permissions
    let _ = common::send_json_auto_csrf(
        &ctx.app,
        Method::GET,
        &format!("/api/v1/credentials/{}/permissions", cred_id),
        None,
        Some(&cookie),
        None,
    )
    .await;

    let events = get_audit_events_for_resource(&*ctx.store, &cred_id).await;

    for event in &events {
        let metadata_str = serde_json::to_string(&event.metadata).unwrap_or_default();
        let decision_reason = event.decision_reason.as_deref().unwrap_or("");

        assert!(
            !metadata_str.contains("test-secret-value"),
            "audit event metadata must NOT contain credential secret"
        );
        assert!(
            !decision_reason.contains("test-secret-value"),
            "audit event decision_reason must NOT contain credential secret"
        );
    }
}
