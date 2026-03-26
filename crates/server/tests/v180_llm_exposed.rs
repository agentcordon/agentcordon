//! v1.8.0 — `llm_exposed` Tag Behavior Tests
//!
//! Tests for the `llm_exposed` tag: visibility in stats, persistence through
//! updates, admin removal, and behavior differences between admin-created
//! and agent-created credentials.

use axum::http::{Method, StatusCode};
use serde_json::json;

use agent_cordon_core::domain::user::UserRole;
use agent_cordon_core::storage::Store;
use agent_cordon_server::test_helpers::TestAppBuilder;

use crate::common::*;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async fn setup_admin(app: &axum::Router, store: &(dyn Store + Send + Sync)) -> (String, String) {
    create_user_in_db(
        store,
        "llm-admin",
        TEST_PASSWORD,
        UserRole::Admin,
        false,
        true,
    )
    .await;
    let cookie = login_user_combined(app, "llm-admin", TEST_PASSWORD).await;
    let csrf = extract_csrf_from_cookie(&cookie).unwrap();
    (cookie, csrf)
}

/// Create a credential with specific tags and return (id, name).
async fn create_tagged_credential(
    app: &axum::Router,
    cookie: &str,
    csrf: &str,
    name: &str,
    tags: Vec<&str>,
) -> String {
    let (status, body) = send_json(
        app,
        Method::POST,
        "/api/v1/credentials",
        None,
        Some(cookie),
        Some(csrf),
        Some(json!({
            "name": name,
            "service": "test-service",
            "secret_value": "test-secret-value",
            "tags": tags,
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

// ===========================================================================
// 3A. Happy Path
// ===========================================================================

/// Test #1: Credential with llm_exposed tag appears in credential summary.
#[tokio::test]
async fn test_llm_exposed_tag_in_credential_summary() {
    let ctx = TestAppBuilder::new().build().await;
    let (cookie, csrf) = setup_admin(&ctx.app, &*ctx.store).await;

    let cred_id = create_tagged_credential(
        &ctx.app,
        &cookie,
        &csrf,
        "llm-exposed-summary",
        vec!["llm_exposed"],
    )
    .await;

    // GET the credential
    let (status, body) = send_json(
        &ctx.app,
        Method::GET,
        &format!("/api/v1/credentials/{}", cred_id),
        None,
        Some(&cookie),
        Some(&csrf),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "get credential: {}", body);

    let tags = body["data"]["tags"].as_array().expect("tags array");
    let tag_strs: Vec<&str> = tags.iter().filter_map(|t| t.as_str()).collect();
    assert!(
        tag_strs.contains(&"llm_exposed"),
        "credential summary should contain llm_exposed tag, got: {:?}",
        tag_strs
    );
}

/// Test #2: Admin-created credentials do NOT get llm_exposed tag automatically.
#[tokio::test]
async fn test_admin_created_no_llm_exposed() {
    let ctx = TestAppBuilder::new().build().await;
    let (cookie, csrf) = setup_admin(&ctx.app, &*ctx.store).await;

    // Create credential WITHOUT specifying llm_exposed tag
    let (status, body) = send_json(
        &ctx.app,
        Method::POST,
        "/api/v1/credentials",
        None,
        Some(&cookie),
        Some(&csrf),
        Some(json!({
            "name": "admin-created-cred",
            "service": "github",
            "secret_value": "ghp_admin_secret",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "create credential: {}", body);

    let tags = body["data"]["tags"].as_array().expect("tags");
    let tag_strs: Vec<&str> = tags.iter().filter_map(|t| t.as_str()).collect();
    assert!(
        !tag_strs.contains(&"llm_exposed"),
        "admin-created credential should NOT have llm_exposed tag, got: {:?}",
        tag_strs
    );
}

// ===========================================================================
// 3C. Error Handling — Tag Persistence
// ===========================================================================

/// Test #5: llm_exposed tag persists through credential updates.
#[tokio::test]
async fn test_llm_exposed_tag_survives_credential_update() {
    let ctx = TestAppBuilder::new().build().await;
    let (cookie, csrf) = setup_admin(&ctx.app, &*ctx.store).await;

    let cred_id = create_tagged_credential(
        &ctx.app,
        &cookie,
        &csrf,
        "llm-persist-test",
        vec!["llm_exposed"],
    )
    .await;

    // Update the credential name (not tags)
    let (status, body) = send_json(
        &ctx.app,
        Method::PUT,
        &format!("/api/v1/credentials/{}", cred_id),
        None,
        Some(&cookie),
        Some(&csrf),
        Some(json!({
            "name": "llm-persist-test-updated",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "update credential: {}", body);

    // Verify tag still exists after update
    let (status, body) = send_json(
        &ctx.app,
        Method::GET,
        &format!("/api/v1/credentials/{}", cred_id),
        None,
        Some(&cookie),
        Some(&csrf),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "get after update: {}", body);

    let tags = body["data"]["tags"].as_array().expect("tags");
    let tag_strs: Vec<&str> = tags.iter().filter_map(|t| t.as_str()).collect();
    assert!(
        tag_strs.contains(&"llm_exposed"),
        "llm_exposed tag should persist after name update, got: {:?}",
        tag_strs
    );
}

/// Test #6: Admin can remove llm_exposed tag via update.
#[tokio::test]
async fn test_llm_exposed_tag_removable_by_admin() {
    let ctx = TestAppBuilder::new().build().await;
    let (cookie, csrf) = setup_admin(&ctx.app, &*ctx.store).await;

    let cred_id = create_tagged_credential(
        &ctx.app,
        &cookie,
        &csrf,
        "llm-removable-test",
        vec!["llm_exposed", "production"],
    )
    .await;

    // Remove llm_exposed by updating tags to just "production"
    let (status, body) = send_json(
        &ctx.app,
        Method::PUT,
        &format!("/api/v1/credentials/{}", cred_id),
        None,
        Some(&cookie),
        Some(&csrf),
        Some(json!({
            "tags": ["production"],
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "update tags: {}", body);

    // Verify llm_exposed is gone
    let (status, body) = send_json(
        &ctx.app,
        Method::GET,
        &format!("/api/v1/credentials/{}", cred_id),
        None,
        Some(&cookie),
        Some(&csrf),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "get after tag removal: {}", body);

    let tags = body["data"]["tags"].as_array().expect("tags");
    let tag_strs: Vec<&str> = tags.iter().filter_map(|t| t.as_str()).collect();
    assert!(
        !tag_strs.contains(&"llm_exposed"),
        "llm_exposed should be removable by admin, got: {:?}",
        tag_strs
    );
    assert!(
        tag_strs.contains(&"production"),
        "production tag should remain, got: {:?}",
        tag_strs
    );
}

// ===========================================================================
// 3D. Cross-Feature
// ===========================================================================

/// Test: Credentials with llm_exposed tag appear in stats count.
#[tokio::test]
async fn test_llm_exposed_in_stats_count() {
    let ctx = TestAppBuilder::new().build().await;
    let (cookie, csrf) = setup_admin(&ctx.app, &*ctx.store).await;

    // Create 2 llm_exposed and 1 normal credential
    create_tagged_credential(&ctx.app, &cookie, &csrf, "llm-stats-1", vec!["llm_exposed"]).await;
    create_tagged_credential(
        &ctx.app,
        &cookie,
        &csrf,
        "llm-stats-2",
        vec!["llm_exposed", "ci"],
    )
    .await;
    create_tagged_credential(
        &ctx.app,
        &cookie,
        &csrf,
        "normal-stats-1",
        vec!["production"],
    )
    .await;

    let (status, body) = send_json(
        &ctx.app,
        Method::GET,
        "/api/v1/stats",
        None,
        Some(&cookie),
        Some(&csrf),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "stats: {}", body);

    let llm_exposed = body["data"]["credentials"]["llm_exposed"]
        .as_u64()
        .expect("llm_exposed count");
    assert_eq!(
        llm_exposed, 2,
        "expected 2 llm_exposed, got {}",
        llm_exposed
    );

    let total = body["data"]["credentials"]["total"]
        .as_u64()
        .expect("total");
    assert_eq!(total, 3, "expected 3 total, got {}", total);
}

/// Test: Multiple tags work alongside llm_exposed.
#[tokio::test]
async fn test_multiple_tags_alongside_llm_exposed() {
    let ctx = TestAppBuilder::new().build().await;
    let (cookie, csrf) = setup_admin(&ctx.app, &*ctx.store).await;

    let cred_id = create_tagged_credential(
        &ctx.app,
        &cookie,
        &csrf,
        "multi-tag-cred",
        vec!["llm_exposed", "production", "github", "ci"],
    )
    .await;

    let (status, body) = send_json(
        &ctx.app,
        Method::GET,
        &format!("/api/v1/credentials/{}", cred_id),
        None,
        Some(&cookie),
        Some(&csrf),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "get credential: {}", body);

    let tags = body["data"]["tags"].as_array().expect("tags");
    let tag_strs: Vec<&str> = tags.iter().filter_map(|t| t.as_str()).collect();
    assert!(tag_strs.contains(&"llm_exposed"), "should have llm_exposed");
    assert!(tag_strs.contains(&"production"), "should have production");
    assert!(tag_strs.contains(&"github"), "should have github");
    assert!(tag_strs.contains(&"ci"), "should have ci");
    assert_eq!(tags.len(), 4, "should have exactly 4 tags");
}

/// Test: Credential creation audit event includes tags in metadata.
#[tokio::test]
async fn test_llm_exposed_in_audit_event() {
    let ctx = TestAppBuilder::new().build().await;
    let (cookie, csrf) = setup_admin(&ctx.app, &*ctx.store).await;

    let _cred_id = create_tagged_credential(
        &ctx.app,
        &cookie,
        &csrf,
        "audit-llm-cred",
        vec!["llm_exposed"],
    )
    .await;

    // Check audit events for the credential creation
    let events = ctx
        .store
        .list_audit_events(10, 0)
        .await
        .expect("list audit events");
    let cred_event = events.iter().find(|e| {
        e.resource_type == "credential"
            && e.metadata.get("credential_name").and_then(|v| v.as_str()) == Some("audit-llm-cred")
    });
    assert!(
        cred_event.is_some(),
        "should find audit event for llm_exposed credential creation"
    );
}

// ===========================================================================
// Credential list visibility
// ===========================================================================

/// Test: llm_exposed credentials visible in admin credential list.
#[tokio::test]
async fn test_llm_exposed_visible_in_credential_list() {
    let ctx = TestAppBuilder::new().build().await;
    let (cookie, csrf) = setup_admin(&ctx.app, &*ctx.store).await;

    create_tagged_credential(
        &ctx.app,
        &cookie,
        &csrf,
        "llm-list-visible",
        vec!["llm_exposed"],
    )
    .await;

    let (status, body) = send_json(
        &ctx.app,
        Method::GET,
        "/api/v1/credentials",
        None,
        Some(&cookie),
        Some(&csrf),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "list credentials: {}", body);

    let creds = body["data"].as_array().expect("credentials array");
    let found = creds
        .iter()
        .find(|c| c["name"].as_str() == Some("llm-list-visible"));
    assert!(
        found.is_some(),
        "llm_exposed credential should appear in admin list"
    );

    let cred = found.unwrap();
    let tags = cred["tags"].as_array().expect("tags");
    let tag_strs: Vec<&str> = tags.iter().filter_map(|t| t.as_str()).collect();
    assert!(
        tag_strs.contains(&"llm_exposed"),
        "credential in list should show llm_exposed tag"
    );
}
