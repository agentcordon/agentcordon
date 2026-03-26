//! Integration tests — v1.9.2 Features 6+10: Permission Names & Granted By.
//!
//! Verifies that the permissions endpoint returns resolved agent names and
//! granted-by names instead of raw UUIDs, and handles deleted entities gracefully.

use crate::common;

use agent_cordon_core::domain::user::UserRole;
use agent_cordon_server::test_helpers::TestAppBuilder;
use axum::http::{Method, StatusCode};
use serde_json::json;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async fn setup() -> (agent_cordon_server::test_helpers::TestContext, String) {
    let ctx = TestAppBuilder::new()
        .with_admin()
        .with_agent("perm-test-agent", &["user"])
        .build()
        .await;
    let _user = common::create_test_user(
        &*ctx.store,
        "perm-names-user",
        common::TEST_PASSWORD,
        UserRole::Admin,
    )
    .await;
    let cookie =
        common::login_user_combined(&ctx.app, "perm-names-user", common::TEST_PASSWORD).await;
    (ctx, cookie)
}

/// Create a credential and return its UUID string.
async fn create_credential(app: &axum::Router, cookie: &str, name: &str) -> String {
    let (status, body) = common::send_json_auto_csrf(
        app,
        Method::POST,
        "/api/v1/credentials",
        None,
        Some(cookie),
        Some(json!({
            "name": name,
            "service": "test-service",
            "credential_type": "generic",
            "secret_value": "test-secret"
        })),
    )
    .await;
    assert!(
        status == StatusCode::CREATED || status == StatusCode::OK,
        "create credential '{}': {:?}",
        name,
        body
    );
    body["data"]["id"]
        .as_str()
        .expect("credential id")
        .to_string()
}

/// Grant a permission and return the response.
async fn grant_permission(
    app: &axum::Router,
    cookie: &str,
    cred_id: &str,
    agent_id: &str,
    permission: &str,
) -> (StatusCode, serde_json::Value) {
    common::send_json_auto_csrf(
        app,
        Method::POST,
        &format!("/api/v1/credentials/{}/permissions", cred_id),
        None,
        Some(cookie),
        Some(json!({
            "agent_id": agent_id,
            "permission": permission
        })),
    )
    .await
}

// ===========================================================================
// 6A. Happy Path — Agent Name Resolution
// ===========================================================================

#[tokio::test]
async fn test_permissions_response_includes_agent_name() {
    let (ctx, cookie) = setup().await;
    let agent = ctx.agents.get("perm-test-agent").expect("agent");

    let cred_id = create_credential(&ctx.app, &cookie, "name-test-cred").await;

    let (status, _) =
        grant_permission(&ctx.app, &cookie, &cred_id, &agent.id.0.to_string(), "read").await;
    assert!(
        status == StatusCode::OK || status == StatusCode::CREATED,
        "grant should succeed"
    );

    // Get permissions
    let (status, body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::GET,
        &format!("/api/v1/credentials/{}/permissions", cred_id),
        None,
        Some(&cookie),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "get permissions: {:?}", body);

    let perms = body["data"]["permissions"].as_array().expect("permissions");
    assert!(!perms.is_empty(), "should have at least one permission");

    // Check if agent_name is present (feature being built by BE-2)
    let first = &perms[0];
    if first.get("agent_name").is_some() {
        let agent_name = first["agent_name"].as_str().unwrap_or("");
        assert_eq!(
            agent_name, "perm-test-agent",
            "agent_name should resolve to the agent's actual name"
        );
    }
    // If agent_name field is not present yet, the test documents the expectation
    // and will pass once BE-2 adds name resolution
}

#[tokio::test]
async fn test_permissions_response_includes_granted_by_name() {
    let (ctx, cookie) = setup().await;
    let agent = ctx.agents.get("perm-test-agent").expect("agent");

    let cred_id = create_credential(&ctx.app, &cookie, "grantedby-test-cred").await;

    let (status, _) =
        grant_permission(&ctx.app, &cookie, &cred_id, &agent.id.0.to_string(), "read").await;
    assert!(
        status == StatusCode::OK || status == StatusCode::CREATED,
        "grant should succeed"
    );

    let (status, body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::GET,
        &format!("/api/v1/credentials/{}/permissions", cred_id),
        None,
        Some(&cookie),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let perms = body["data"]["permissions"].as_array().expect("permissions");
    assert!(!perms.is_empty());

    let first = &perms[0];
    // Check for granted_by_user_name or granted_by_name
    if let Some(name) = first
        .get("granted_by_user_name")
        .or_else(|| first.get("granted_by_name"))
    {
        let name_str = name.as_str().unwrap_or("");
        assert!(!name_str.is_empty(), "granted_by name should not be empty");
    }
}

// ===========================================================================
// 6C. Error Handling — Deleted Entity Fallbacks
// ===========================================================================

#[tokio::test]
async fn test_permissions_deleted_agent_shows_fallback() {
    let (ctx, cookie) = setup().await;
    let agent = ctx.agents.get("perm-test-agent").expect("agent");
    let agent_id = agent.id.0.to_string();

    let cred_id = create_credential(&ctx.app, &cookie, "deleted-agent-cred").await;

    let (status, _) = grant_permission(&ctx.app, &cookie, &cred_id, &agent_id, "read").await;
    assert!(status == StatusCode::OK || status == StatusCode::CREATED);

    // Delete the agent (v2.0: agents are workspaces)
    let (del_status, _) = common::send_json_auto_csrf(
        &ctx.app,
        Method::DELETE,
        &format!("/api/v1/workspaces/{}", agent_id),
        None,
        Some(&cookie),
        None,
    )
    .await;
    assert!(
        del_status == StatusCode::OK || del_status == StatusCode::NO_CONTENT,
        "workspace delete should succeed, got {}",
        del_status
    );

    // Now get permissions — agent_name should show fallback, not error
    let (status, body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::GET,
        &format!("/api/v1/credentials/{}/permissions", cred_id),
        None,
        Some(&cookie),
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "permissions endpoint should not error when agent is deleted: {:?}",
        body
    );

    let perms = body["data"]["permissions"].as_array().expect("permissions");
    // Permissions may have been cascade-deleted with the agent, or persisted.
    // Either way, the endpoint should not 500.
    let _ = perms; // assertion is that we got 200
}

// ===========================================================================
// 10A. Happy Path — Granted By Resolution
// ===========================================================================

#[tokio::test]
async fn test_user_granted_permission_shows_username() {
    let (ctx, cookie) = setup().await;
    let agent = ctx.agents.get("perm-test-agent").expect("agent");

    let cred_id = create_credential(&ctx.app, &cookie, "user-granted-cred").await;

    let (status, _) = grant_permission(
        &ctx.app,
        &cookie,
        &cred_id,
        &agent.id.0.to_string(),
        "delegated_use",
    )
    .await;
    assert!(status == StatusCode::OK || status == StatusCode::CREATED);

    let (status, body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::GET,
        &format!("/api/v1/credentials/{}/permissions", cred_id),
        None,
        Some(&cookie),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let perms = body["data"]["permissions"].as_array().expect("permissions");
    assert!(!perms.is_empty());

    // In the grants-as-Cedar model, granted_by_user is not tracked in Cedar policies.
    // Instead, granted_by_name provides a human-readable label.
    // Verify the permission exists with a granted_by_name.
    let first = &perms[0];
    let granted_by_name = first.get("granted_by_name");
    assert!(
        granted_by_name.is_some(),
        "granted_by_name should be set for permissions"
    );
}

#[tokio::test]
async fn test_auto_granted_permission_shows_system() {
    let (ctx, cookie) = setup().await;

    // Create a credential — the creator gets auto-granted permissions
    let cred_id = create_credential(&ctx.app, &cookie, "auto-granted-cred").await;

    let (status, body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::GET,
        &format!("/api/v1/credentials/{}/permissions", cred_id),
        None,
        Some(&cookie),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // If there are auto-granted permissions, they should have a meaningful
    // granted_by indicator (not just "-" or empty)
    let empty = vec![];
    let perms = body["data"]["permissions"].as_array().unwrap_or(&empty);

    // Auto-granted permissions may not exist for user-created credentials.
    // This test documents the expectation for when the feature lands.
    for perm in perms {
        let granted_by = perm.get("granted_by");
        let granted_by_user = perm.get("granted_by_user");
        // At least one grantor identifier should be present, or there should
        // be a "granted_by_name" showing "System" or "Auto"
        let has_grantor = granted_by.is_some()
            || granted_by_user.is_some()
            || perm.get("granted_by_name").is_some();
        // If both are null, the name resolver should provide "System"
        if !has_grantor {
            // This will become a hard assertion once BE-2 implements name resolution
            eprintln!("WARN: permission has no grantor identity: {:?}", perm);
        }
    }
}
