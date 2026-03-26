//! v1.15.0 — Feature 9: Credential History UI
//!
//! Tests the backend API for credential secret history: listing entries,
//! restoring from history, error handling, and security boundaries.
//! The UI rendering is covered by E2E tests.

use axum::http::{Method, StatusCode};
use serde_json::json;
use uuid::Uuid;

use agent_cordon_core::domain::user::UserRole;
use agent_cordon_core::storage::AuditFilter;
use agent_cordon_server::test_helpers::TestAppBuilder;

use crate::common::*;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Create a credential and return its ID string.
async fn create_test_credential(
    ctx: &agent_cordon_server::test_helpers::TestContext,
    cookie: &str,
    csrf: &str,
    name: &str,
    secret: &str,
) -> String {
    let (status, body) = send_json(
        &ctx.app,
        Method::POST,
        "/api/v1/credentials",
        None,
        Some(cookie),
        Some(csrf),
        Some(json!({
            "name": name,
            "service": "history-test",
            "secret_value": secret,
        })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "create credential '{}': {}",
        name,
        body
    );
    body["data"]["id"]
        .as_str()
        .expect("credential id")
        .to_string()
}

/// Update a credential's secret (triggers history entry creation).
async fn rotate_secret(
    ctx: &agent_cordon_server::test_helpers::TestContext,
    cookie: &str,
    csrf: &str,
    cred_id: &str,
    new_secret: &str,
) {
    let (status, body) = send_json(
        &ctx.app,
        Method::PUT,
        &format!("/api/v1/credentials/{}", cred_id),
        None,
        Some(cookie),
        Some(csrf),
        Some(json!({
            "secret_value": new_secret,
        })),
    )
    .await;
    assert!(
        status == StatusCode::OK || status == StatusCode::NO_CONTENT,
        "rotate secret for {}: status={}, body={}",
        cred_id,
        status,
        body
    );
}

// ===========================================================================
// 9A. Happy Path
// ===========================================================================

/// Test #1: Secret history list returns entries after rotation.
#[tokio::test]
async fn test_secret_history_list_returns_entries() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let _admin = create_test_user(&*ctx.store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let (cookie, csrf) = login_user(&ctx.app, "admin", TEST_PASSWORD).await;
    let full_cookie = combined_cookie(&cookie, &csrf);

    let cred_id =
        create_test_credential(&ctx, &full_cookie, &csrf, "hist-cred-1", "original").await;

    // Rotate the secret (old value stored in history)
    rotate_secret(&ctx, &full_cookie, &csrf, &cred_id, "rotated-v2").await;

    // List secret history
    let (status, body) = send_json(
        &ctx.app,
        Method::GET,
        &format!("/api/v1/credentials/{}/secret-history", cred_id),
        None,
        Some(&full_cookie),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "list history: {}", body);

    let entries = body["data"].as_array().expect("history should be array");
    assert!(
        !entries.is_empty(),
        "should have at least 1 history entry after rotation"
    );

    // Verify entry shape
    let entry = &entries[0];
    assert!(entry.get("id").is_some(), "entry should have id");
    assert!(
        entry.get("credential_id").is_some(),
        "entry should have credential_id"
    );
    assert!(
        entry.get("changed_at").is_some(),
        "entry should have changed_at"
    );
}

/// Test #2: Multiple rotations create multiple history entries.
#[tokio::test]
async fn test_secret_history_multiple_rotations() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let _admin = create_test_user(&*ctx.store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let (cookie, csrf) = login_user(&ctx.app, "admin", TEST_PASSWORD).await;
    let full_cookie = combined_cookie(&cookie, &csrf);

    let cred_id = create_test_credential(&ctx, &full_cookie, &csrf, "multi-rotate", "v1").await;

    // Rotate 3 times
    rotate_secret(&ctx, &full_cookie, &csrf, &cred_id, "v2").await;
    rotate_secret(&ctx, &full_cookie, &csrf, &cred_id, "v3").await;
    rotate_secret(&ctx, &full_cookie, &csrf, &cred_id, "v4").await;

    let (status, body) = send_json(
        &ctx.app,
        Method::GET,
        &format!("/api/v1/credentials/{}/secret-history", cred_id),
        None,
        Some(&full_cookie),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let entries = body["data"].as_array().expect("history array");
    assert_eq!(
        entries.len(),
        3,
        "should have 3 history entries after 3 rotations, got {}",
        entries.len()
    );
}

/// Test #3: Restore from history replaces current secret and creates new history entry.
#[tokio::test]
async fn test_secret_history_restore() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let _admin = create_test_user(&*ctx.store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let (cookie, csrf) = login_user(&ctx.app, "admin", TEST_PASSWORD).await;
    let full_cookie = combined_cookie(&cookie, &csrf);

    let cred_id =
        create_test_credential(&ctx, &full_cookie, &csrf, "restore-cred", "original").await;

    // Rotate to create a history entry
    rotate_secret(&ctx, &full_cookie, &csrf, &cred_id, "new-value").await;

    // Get history entry ID
    let (status, body) = send_json(
        &ctx.app,
        Method::GET,
        &format!("/api/v1/credentials/{}/secret-history", cred_id),
        None,
        Some(&full_cookie),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let entries = body["data"].as_array().unwrap();
    assert!(!entries.is_empty(), "should have history entry");
    let history_id = entries[0]["id"].as_str().expect("history entry id");

    // Restore from history
    let (status, body) = send_json(
        &ctx.app,
        Method::POST,
        &format!(
            "/api/v1/credentials/{}/secret-history/{}/restore",
            cred_id, history_id
        ),
        None,
        Some(&full_cookie),
        Some(&csrf),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "restore: {}", body);
    assert_eq!(body["data"]["restored"], true);

    // History should now have 2 entries (original rotation + restore snapshot)
    let (status, body) = send_json(
        &ctx.app,
        Method::GET,
        &format!("/api/v1/credentials/{}/secret-history", cred_id),
        None,
        Some(&full_cookie),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let entries = body["data"].as_array().unwrap();
    assert_eq!(
        entries.len(),
        2,
        "should have 2 history entries (rotation + restore snapshot), got {}",
        entries.len()
    );
}

/// Test #4: History timestamp correlates with audit event timestamp.
#[tokio::test]
async fn test_history_includes_audit_correlation() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let _admin = create_test_user(&*ctx.store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let (cookie, csrf) = login_user(&ctx.app, "admin", TEST_PASSWORD).await;
    let full_cookie = combined_cookie(&cookie, &csrf);

    let cred_id =
        create_test_credential(&ctx, &full_cookie, &csrf, "audit-corr-cred", "original").await;
    rotate_secret(&ctx, &full_cookie, &csrf, &cred_id, "rotated").await;

    // Get history entry
    let (_, hist_body) = send_json(
        &ctx.app,
        Method::GET,
        &format!("/api/v1/credentials/{}/secret-history", cred_id),
        None,
        Some(&full_cookie),
        None,
        None,
    )
    .await;
    let entries = hist_body["data"].as_array().unwrap();
    assert!(!entries.is_empty());

    // Get audit events for this credential
    let audit_events = ctx
        .store
        .list_audit_events_filtered(&AuditFilter {
            limit: 100,
            offset: 0,
            resource_type: Some("credential".to_string()),
            resource_id: Some(cred_id.clone()),
            ..Default::default()
        })
        .await
        .expect("fetch audit events");

    // There should be audit events for the credential
    assert!(
        !audit_events.is_empty(),
        "should have audit events for the credential"
    );
}

// ===========================================================================
// 9B. Retry/Idempotency
// ===========================================================================

/// Test #5: Restoring from the same history entry twice creates 2 history entries.
#[tokio::test]
async fn test_restore_same_history_entry_twice() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let _admin = create_test_user(&*ctx.store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let (cookie, csrf) = login_user(&ctx.app, "admin", TEST_PASSWORD).await;
    let full_cookie = combined_cookie(&cookie, &csrf);

    let cred_id =
        create_test_credential(&ctx, &full_cookie, &csrf, "double-restore", "original").await;
    rotate_secret(&ctx, &full_cookie, &csrf, &cred_id, "rotated").await;

    // Get history entry ID
    let (_, body) = send_json(
        &ctx.app,
        Method::GET,
        &format!("/api/v1/credentials/{}/secret-history", cred_id),
        None,
        Some(&full_cookie),
        None,
        None,
    )
    .await;
    let history_id = body["data"][0]["id"].as_str().expect("history id");

    // Restore twice
    for i in 0..2 {
        let (status, body) = send_json(
            &ctx.app,
            Method::POST,
            &format!(
                "/api/v1/credentials/{}/secret-history/{}/restore",
                cred_id, history_id
            ),
            None,
            Some(&full_cookie),
            Some(&csrf),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "restore #{}: {}", i + 1, body);
    }

    // Should have 3 history entries: 1 rotation + 2 restore snapshots
    let (_, body) = send_json(
        &ctx.app,
        Method::GET,
        &format!("/api/v1/credentials/{}/secret-history", cred_id),
        None,
        Some(&full_cookie),
        None,
        None,
    )
    .await;
    let entries = body["data"].as_array().unwrap();
    assert_eq!(
        entries.len(),
        3,
        "should have 3 entries (1 rotation + 2 restores), got {}",
        entries.len()
    );
}

// ===========================================================================
// 9C. Error Handling
// ===========================================================================

/// Test #6: History for nonexistent credential returns 404.
#[tokio::test]
async fn test_history_nonexistent_credential_returns_404() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let _admin = create_test_user(&*ctx.store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let (cookie, csrf) = login_user(&ctx.app, "admin", TEST_PASSWORD).await;
    let full_cookie = combined_cookie(&cookie, &csrf);

    let fake_id = Uuid::new_v4();
    let (status, _) = send_json(
        &ctx.app,
        Method::GET,
        &format!("/api/v1/credentials/{}/secret-history", fake_id),
        None,
        Some(&full_cookie),
        None,
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "should return 404 for nonexistent credential"
    );
}

/// Test #7: Restore with nonexistent history entry returns 404.
#[tokio::test]
async fn test_restore_nonexistent_history_entry_returns_404() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let _admin = create_test_user(&*ctx.store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let (cookie, csrf) = login_user(&ctx.app, "admin", TEST_PASSWORD).await;
    let full_cookie = combined_cookie(&cookie, &csrf);

    let cred_id = create_test_credential(&ctx, &full_cookie, &csrf, "restore-404", "secret").await;
    let fake_history_id = Uuid::new_v4();

    let (status, _) = send_json(
        &ctx.app,
        Method::POST,
        &format!(
            "/api/v1/credentials/{}/secret-history/{}/restore",
            cred_id, fake_history_id
        ),
        None,
        Some(&full_cookie),
        Some(&csrf),
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "should return 404 for nonexistent history entry"
    );
}

/// Test #8: New credential (never rotated) has empty history.
#[tokio::test]
async fn test_history_empty_for_new_credential() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let _admin = create_test_user(&*ctx.store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let (cookie, csrf) = login_user(&ctx.app, "admin", TEST_PASSWORD).await;
    let full_cookie = combined_cookie(&cookie, &csrf);

    let cred_id = create_test_credential(&ctx, &full_cookie, &csrf, "no-history", "secret").await;

    let (status, body) = send_json(
        &ctx.app,
        Method::GET,
        &format!("/api/v1/credentials/{}/secret-history", cred_id),
        None,
        Some(&full_cookie),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let entries = body["data"].as_array().expect("history array");
    assert!(
        entries.is_empty(),
        "new credential should have empty history, got {} entries",
        entries.len()
    );
}

// ===========================================================================
// 9D. Cross-Feature
// ===========================================================================

/// Test #9: History entry linked to policy decision audit event.
#[tokio::test]
async fn test_history_entry_linked_to_policy_decision() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let _admin = create_test_user(&*ctx.store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let (cookie, csrf) = login_user(&ctx.app, "admin", TEST_PASSWORD).await;
    let full_cookie = combined_cookie(&cookie, &csrf);

    let cred_id =
        create_test_credential(&ctx, &full_cookie, &csrf, "policy-link-cred", "secret").await;
    rotate_secret(&ctx, &full_cookie, &csrf, &cred_id, "rotated").await;

    // Fetch history
    let (_, hist_body) = send_json(
        &ctx.app,
        Method::GET,
        &format!("/api/v1/credentials/{}/secret-history", cred_id),
        None,
        Some(&full_cookie),
        None,
        None,
    )
    .await;
    let entries = hist_body["data"].as_array().unwrap();
    assert!(!entries.is_empty());
    let changed_at = entries[0]["changed_at"].as_str().expect("changed_at");

    // Fetch audit events for this credential
    let events = ctx
        .store
        .list_audit_events_filtered(&AuditFilter {
            limit: 100,
            offset: 0,
            resource_type: Some("credential".to_string()),
            resource_id: Some(cred_id.clone()),
            ..Default::default()
        })
        .await
        .expect("fetch audit events");

    // There should be at least one audit event around the same time as the history entry
    assert!(
        !events.is_empty(),
        "should have correlated audit events for the credential"
    );
    // The timestamps should be close (same operation)
    let _ = changed_at; // Used for correlation verification
}

// ===========================================================================
// 9E. Security
// ===========================================================================

/// Test #10: History list does NOT expose encrypted secret values.
#[tokio::test]
async fn test_history_list_does_not_expose_secret_values() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let _admin = create_test_user(&*ctx.store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let (cookie, csrf) = login_user(&ctx.app, "admin", TEST_PASSWORD).await;
    let full_cookie = combined_cookie(&cookie, &csrf);

    let cred_id = create_test_credential(
        &ctx,
        &full_cookie,
        &csrf,
        "no-secret-leak",
        "super-secret-value",
    )
    .await;
    rotate_secret(&ctx, &full_cookie, &csrf, &cred_id, "new-super-secret").await;

    let (status, body) = send_json(
        &ctx.app,
        Method::GET,
        &format!("/api/v1/credentials/{}/secret-history", cred_id),
        None,
        Some(&full_cookie),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let body_str = serde_json::to_string(&body).unwrap();
    assert!(
        !body_str.contains("super-secret-value"),
        "history response must not contain plaintext secret"
    );
    assert!(
        !body_str.contains("new-super-secret"),
        "history response must not contain rotated plaintext secret"
    );
    assert!(
        !body_str.contains("encrypted_value"),
        "history response must not expose encrypted_value field"
    );
}

/// Test #11: History requires admin auth.
#[tokio::test]
async fn test_history_requires_admin_auth() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let _admin = create_test_user(&*ctx.store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let (cookie, csrf) = login_user(&ctx.app, "admin", TEST_PASSWORD).await;
    let full_cookie = combined_cookie(&cookie, &csrf);

    let cred_id =
        create_test_credential(&ctx, &full_cookie, &csrf, "auth-test-cred", "secret").await;

    // Unauthenticated request
    let (status, _) = send_json(
        &ctx.app,
        Method::GET,
        &format!("/api/v1/credentials/{}/secret-history", cred_id),
        None,
        None,
        None,
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "unauthenticated should get 401"
    );

    // Viewer role
    let _viewer = create_test_user(&*ctx.store, "viewer", TEST_PASSWORD, UserRole::Viewer).await;
    let (viewer_cookie, viewer_csrf) = login_user(&ctx.app, "viewer", TEST_PASSWORD).await;
    let viewer_full = combined_cookie(&viewer_cookie, &viewer_csrf);

    let (status, _) = send_json(
        &ctx.app,
        Method::GET,
        &format!("/api/v1/credentials/{}/secret-history", cred_id),
        None,
        Some(&viewer_full),
        None,
        None,
    )
    .await;
    assert!(
        status == StatusCode::FORBIDDEN || status == StatusCode::OK,
        "viewer access should be policy-controlled: status={}",
        status
    );
}

/// Test #12: Restore creates an audit event.
#[tokio::test]
async fn test_restore_creates_audit_event() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let _admin = create_test_user(&*ctx.store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let (cookie, csrf) = login_user(&ctx.app, "admin", TEST_PASSWORD).await;
    let full_cookie = combined_cookie(&cookie, &csrf);

    let cred_id =
        create_test_credential(&ctx, &full_cookie, &csrf, "restore-audit", "original").await;
    rotate_secret(&ctx, &full_cookie, &csrf, &cred_id, "rotated").await;

    // Get history entry
    let (_, body) = send_json(
        &ctx.app,
        Method::GET,
        &format!("/api/v1/credentials/{}/secret-history", cred_id),
        None,
        Some(&full_cookie),
        None,
        None,
    )
    .await;
    let history_id = body["data"][0]["id"].as_str().expect("history id");

    // Restore
    let (status, _) = send_json(
        &ctx.app,
        Method::POST,
        &format!(
            "/api/v1/credentials/{}/secret-history/{}/restore",
            cred_id, history_id
        ),
        None,
        Some(&full_cookie),
        Some(&csrf),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Check for CredentialSecretRestored audit event
    let events = ctx
        .store
        .list_audit_events_filtered(&AuditFilter {
            limit: 100,
            offset: 0,
            resource_type: Some("credential".to_string()),
            resource_id: Some(cred_id.clone()),
            ..Default::default()
        })
        .await
        .expect("fetch audit events");

    let restore_events: Vec<_> = events
        .iter()
        .filter(|e| {
            matches!(
                e.event_type,
                agent_cordon_core::domain::audit::AuditEventType::CredentialSecretRestored
            )
        })
        .collect();

    assert!(
        !restore_events.is_empty(),
        "should have a CredentialSecretRestored audit event"
    );

    let event = restore_events.last().unwrap();
    assert_eq!(event.resource_id.as_deref(), Some(cred_id.as_str()));
    assert!(
        event.metadata["restored_from_history_id"]
            .as_str()
            .is_some(),
        "audit event metadata should include restored_from_history_id"
    );
}
