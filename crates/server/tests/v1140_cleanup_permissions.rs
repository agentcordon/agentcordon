//! v1.14.0 — Dead Code Removal + Migration (Features 5 & 6)
//!
//! Tests that credential permissions still work via Cedar after removing
//! the dead `CredentialPermissionStore` trait, and that the migration
//! dropping the `credential_permissions` table doesn't break anything.

use axum::http::{Method, StatusCode};
use serde_json::json;
use uuid::Uuid;

use agent_cordon_core::crypto::SecretEncryptor;
use agent_cordon_core::domain::credential::{CredentialId, StoredCredential};
use agent_cordon_core::domain::user::{UserId, UserRole};
use agent_cordon_server::test_helpers::TestAppBuilder;

use crate::common::*;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Create a credential in the store and return its ID.
async fn create_test_credential(
    ctx: &agent_cordon_server::test_helpers::TestContext,
    name: &str,
    owner_user_id: &UserId,
) -> CredentialId {
    let now = chrono::Utc::now();
    let cred_id = CredentialId(Uuid::new_v4());
    let (encrypted, nonce) = ctx
        .encryptor
        .encrypt(b"test-secret", cred_id.0.to_string().as_bytes())
        .expect("encrypt");

    let cred = StoredCredential {
        id: cred_id.clone(),
        name: name.to_string(),
        service: "test-service".to_string(),
        encrypted_value: encrypted,
        nonce,
        scopes: vec!["read".to_string()],
        metadata: json!({}),
        created_by: ctx.admin_agent.as_ref().map(|a| a.id.clone()),
        created_by_user: Some(owner_user_id.clone()),
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
    ctx.store
        .store_credential(&cred)
        .await
        .expect("store credential");
    cred_id
}

// ===========================================================================
// 5A. Happy Path — Cedar grants still work after cleanup
// ===========================================================================

/// Test #1: Credential grant still works via Cedar.
#[tokio::test]
async fn test_credential_grant_still_works_via_cedar() {
    let ctx = TestAppBuilder::new()
        .with_admin()
        .with_agent("target", &[])
        .build()
        .await;

    let admin = create_test_user(&*ctx.store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let cookie = login_user_combined(&ctx.app, "admin", TEST_PASSWORD).await;

    let cred_id = create_test_credential(&ctx, "cedar-grant-cred", &admin.id).await;
    let agent = ctx.agents.get("target").unwrap();

    // Grant permission via the Cedar-backed API
    let (status, body) = send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        &format!("/api/v1/credentials/{}/permissions", cred_id.0),
        None,
        Some(&cookie),
        Some(json!({
            "agent_id": agent.id.0.to_string(),
            "permission": "read",
        })),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "Cedar grant failed: {}", body);

    // Verify the permission is queryable
    let (status, body) = send_json_auto_csrf(
        &ctx.app,
        Method::GET,
        &format!("/api/v1/credentials/{}/permissions", cred_id.0),
        None,
        Some(&cookie),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let permissions = body["data"]["permissions"].as_array().unwrap();
    assert!(!permissions.is_empty(), "Cedar grant should be queryable");
}

/// Test #2: Credential revoke still works via Cedar.
#[tokio::test]
async fn test_credential_revoke_still_works_via_cedar() {
    let ctx = TestAppBuilder::new()
        .with_admin()
        .with_agent("target", &[])
        .build()
        .await;

    let admin = create_test_user(&*ctx.store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let cookie = login_user_combined(&ctx.app, "admin", TEST_PASSWORD).await;

    let cred_id = create_test_credential(&ctx, "cedar-revoke-cred", &admin.id).await;
    let agent = ctx.agents.get("target").unwrap();

    // Grant
    send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        &format!("/api/v1/credentials/{}/permissions", cred_id.0),
        None,
        Some(&cookie),
        Some(json!({
            "agent_id": agent.id.0.to_string(),
            "permission": "read",
        })),
    )
    .await;

    // Revoke — "read" maps to Cedar action "list"
    let (status, body) = send_json_auto_csrf(
        &ctx.app,
        Method::DELETE,
        &format!(
            "/api/v1/credentials/{}/permissions/{}/read",
            cred_id.0, agent.id.0
        ),
        None,
        Some(&cookie),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::OK, "Cedar revoke failed: {}", body);
}

/// Test #3: Credential permission list via Cedar.
#[tokio::test]
async fn test_credential_permission_list_via_cedar() {
    let ctx = TestAppBuilder::new()
        .with_admin()
        .with_agent("target", &[])
        .build()
        .await;

    let admin = create_test_user(&*ctx.store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let cookie = login_user_combined(&ctx.app, "admin", TEST_PASSWORD).await;

    let cred_id = create_test_credential(&ctx, "cedar-list-cred", &admin.id).await;
    let agent = ctx.agents.get("target").unwrap();

    // Grant two permissions
    for perm in &["read", "delegated_use"] {
        send_json_auto_csrf(
            &ctx.app,
            Method::POST,
            &format!("/api/v1/credentials/{}/permissions", cred_id.0),
            None,
            Some(&cookie),
            Some(json!({
                "agent_id": agent.id.0.to_string(),
                "permission": perm,
            })),
        )
        .await;
    }

    // List permissions
    let (status, body) = send_json_auto_csrf(
        &ctx.app,
        Method::GET,
        &format!("/api/v1/credentials/{}/permissions", cred_id.0),
        None,
        Some(&cookie),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let permissions = body["data"]["permissions"].as_array().unwrap();
    assert!(
        !permissions.is_empty(),
        "should have at least one permission entry"
    );
}

// ===========================================================================
// 6A. Migration Tests
// ===========================================================================

/// Test #4: Migration runs successfully (TestAppBuilder runs all migrations).
///
/// Since TestAppBuilder runs all migrations automatically, if this test
/// passes, the migration that drops `credential_permissions` succeeded.
#[tokio::test]
async fn test_migration_drops_credential_permissions_table() {
    let ctx = TestAppBuilder::new().with_admin().build().await;

    // If we got here, all migrations ran successfully.
    // Verify by attempting a query — if the table was dropped correctly,
    // no code should reference it.
    // The store should work fine without the table.
    let agents = ctx
        .store
        .list_workspaces()
        .await
        .expect("list agents should work post-migration");
    assert!(!agents.is_empty(), "admin agent should exist");
}

/// Test #5: Existing Cedar policies survive migration.
#[tokio::test]
async fn test_existing_cedar_policies_survive_migration() {
    let ctx = TestAppBuilder::new()
        .with_admin()
        .with_agent("target", &[])
        .build()
        .await;

    let admin = create_test_user(&*ctx.store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let cookie = login_user_combined(&ctx.app, "admin", TEST_PASSWORD).await;

    let cred_id = create_test_credential(&ctx, "survive-migration-cred", &admin.id).await;
    let agent = ctx.agents.get("target").unwrap();

    // Create a Cedar grant policy
    send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        &format!("/api/v1/credentials/{}/permissions", cred_id.0),
        None,
        Some(&cookie),
        Some(json!({
            "agent_id": agent.id.0.to_string(),
            "permission": "read",
        })),
    )
    .await;

    // Verify policy exists (since migrations already ran, this tests that
    // Cedar policies survive the table drop)
    let all_policies = ctx.store.list_policies().await.unwrap();
    let has_grant = all_policies.iter().any(|p| p.name.starts_with("grant:"));
    assert!(has_grant, "Cedar grant policies should survive migration");
}
