//! Integration tests — v1.9.2 Feature 1: Demo Seed Data.
//!
//! Verifies that demo data (device, credential, agent, audit events) is created
//! on first boot when `seed_demo = true`, and that seeding is idempotent.

use crate::common;

use agent_cordon_core::domain::user::UserRole;
use agent_cordon_server::test_helpers::TestAppBuilder;
use axum::http::{Method, StatusCode};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build a test context with demo seeding enabled.
/// Uses a root user so Cedar owner-scoping doesn't hide demo credentials
/// (which have no owner).
async fn setup_with_seed() -> (agent_cordon_server::test_helpers::TestContext, String) {
    // NOTE: Do NOT use .with_admin() here — it creates an agent in the DB,
    // which causes seed_demo_data() to skip seeding (it checks list_agents().is_empty()).
    let ctx = TestAppBuilder::new()
        .with_config(|c| {
            c.seed_demo = true;
        })
        .build()
        .await;

    // Run the seed function against the store (DB is empty so seeding proceeds)
    agent_cordon_server::seed::seed_demo_data(
        &ctx.store,
        &ctx.encryptor,
        &ctx.state.config,
        &ctx.jwt_issuer,
    )
    .await
    .expect("seed demo data should succeed");

    // Use root user so Cedar owner-scoping doesn't hide ownerless demo credentials.
    let _user = common::create_user_in_db(
        &*ctx.store,
        "seed-user",
        common::TEST_PASSWORD,
        UserRole::Admin,
        true,
        true,
    )
    .await;
    let cookie = common::login_user_combined(&ctx.app, "seed-user", common::TEST_PASSWORD).await;
    (ctx, cookie)
}

/// Build a test context WITHOUT demo seeding but with seed_demo config enabled.
/// Uses .with_admin() so agents exist, causing seed to skip the "empty DB" guard.
async fn setup_no_seed() -> (agent_cordon_server::test_helpers::TestContext, String) {
    let ctx = TestAppBuilder::new()
        .with_admin()
        .with_config(|c| {
            c.seed_demo = true;
        })
        .build()
        .await;
    let _user = common::create_test_user(
        &*ctx.store,
        "noseed-user",
        common::TEST_PASSWORD,
        UserRole::Admin,
    )
    .await;
    let cookie = common::login_user_combined(&ctx.app, "noseed-user", common::TEST_PASSWORD).await;
    (ctx, cookie)
}

// ===========================================================================
// 1A. Happy Path
// ===========================================================================

#[tokio::test]
async fn test_fresh_db_creates_demo_device() {
    let (ctx, cookie) = setup_with_seed().await;

    let (status, body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::GET,
        "/api/v1/workspaces",
        None,
        Some(&cookie),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "list devices: {:?}", body);

    let devices = body["data"].as_array().expect("data should be array");
    let has_demo = devices.iter().any(|d| {
        d["name"]
            .as_str()
            .map(|n| n.contains("demo"))
            .unwrap_or(false)
    });
    assert!(has_demo, "should have a demo device, got: {:?}", devices);
}

#[tokio::test]
async fn test_fresh_db_creates_demo_credential() {
    let (ctx, cookie) = setup_with_seed().await;

    let (status, body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::GET,
        "/api/v1/credentials",
        None,
        Some(&cookie),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "list credentials: {:?}", body);

    let creds = body["data"].as_array().expect("data should be array");
    let has_demo = creds.iter().any(|c| {
        c["allowed_url_pattern"]
            .as_str()
            .map(|u| u.contains("httpbin.org"))
            .unwrap_or(false)
            || c["name"]
                .as_str()
                .map(|n| n.contains("demo"))
                .unwrap_or(false)
    });
    assert!(
        has_demo,
        "should have a demo credential targeting httpbin.org, got: {:?}",
        creds
    );
}

#[tokio::test]
async fn test_fresh_db_creates_demo_agent() {
    let (ctx, cookie) = setup_with_seed().await;

    let (status, body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::GET,
        "/api/v1/workspaces",
        None,
        Some(&cookie),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "list agents: {:?}", body);

    let agents = body["data"].as_array().expect("data should be array");
    let has_demo = agents.iter().any(|a| {
        a["name"]
            .as_str()
            .map(|n| n.contains("demo"))
            .unwrap_or(false)
    });
    assert!(has_demo, "should have a demo agent, got: {:?}", agents);
}

#[tokio::test]
async fn test_fresh_db_has_audit_events() {
    let (ctx, cookie) = setup_with_seed().await;

    let (status, body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::GET,
        "/api/v1/audit?limit=50",
        None,
        Some(&cookie),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "list audit events: {:?}", body);

    let events = body["data"].as_array().expect("data should be array");
    assert!(
        !events.is_empty(),
        "should have pre-populated audit events after seeding"
    );
}

#[tokio::test]
async fn test_demo_device_is_active() {
    let (ctx, cookie) = setup_with_seed().await;

    let (status, body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::GET,
        "/api/v1/workspaces",
        None,
        Some(&cookie),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let devices = body["data"].as_array().expect("data");
    let demo = devices
        .iter()
        .find(|d| {
            d["name"]
                .as_str()
                .map(|n| n.contains("demo"))
                .unwrap_or(false)
        })
        .expect("demo device must exist");

    let status_str = demo["status"].as_str().unwrap_or("");
    assert!(
        status_str == "active" || status_str == "Active",
        "demo device should be active, got: {}",
        status_str
    );
}

#[tokio::test]
async fn test_demo_credential_has_permission_grant() {
    let (ctx, cookie) = setup_with_seed().await;

    // Find demo credential
    let (status, body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::GET,
        "/api/v1/credentials",
        None,
        Some(&cookie),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let creds = body["data"].as_array().expect("data");
    let demo_cred = creds
        .iter()
        .find(|c| {
            c["name"]
                .as_str()
                .map(|n| n.contains("demo"))
                .unwrap_or(false)
        })
        .expect("demo credential must exist");

    let cred_id = demo_cred["id"].as_str().expect("credential id");

    // Check permissions
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

    let perms = body["data"]["permissions"]
        .as_array()
        .expect("permissions array");
    // Demo seed grants vend_credential + list (agents should never get raw "access")
    let has_vend = perms.iter().any(|p| {
        p["permission"]
            .as_str()
            .map(|perm| perm == "vend_credential")
            .unwrap_or(false)
    });
    assert!(
        has_vend,
        "demo agent should have 'vend_credential' permission on demo credential, got: {:?}",
        perms
    );
}

// ===========================================================================
// 1B. Retry/Idempotency
// ===========================================================================

#[tokio::test]
async fn test_seed_data_not_duplicated_on_restart() {
    let (ctx, cookie) = setup_with_seed().await;

    // Run seed again (simulating restart)
    agent_cordon_server::seed::seed_demo_data(
        &ctx.store,
        &ctx.encryptor,
        &ctx.state.config,
        &ctx.jwt_issuer,
    )
    .await
    .expect("second seed should succeed");

    // Verify no duplicate devices
    let (status, body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::GET,
        "/api/v1/workspaces",
        None,
        Some(&cookie),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let devices = body["data"].as_array().expect("data");
    let demo_count = devices
        .iter()
        .filter(|d| {
            d["name"]
                .as_str()
                .map(|n| n.contains("demo"))
                .unwrap_or(false)
        })
        .count();
    assert_eq!(
        demo_count, 1,
        "should have exactly 1 demo device after double seed, got {}",
        demo_count
    );
}

#[tokio::test]
async fn test_seed_skipped_when_data_exists() {
    let (ctx, cookie) = setup_no_seed().await;

    // Manually create a workspace directly in the store (v2.0: no POST /api/v1/workspaces)
    {
        use agent_cordon_core::domain::workspace::{Workspace, WorkspaceId, WorkspaceStatus};
        let now = chrono::Utc::now();
        let ws = Workspace {
            id: WorkspaceId(uuid::Uuid::new_v4()),
            name: "pre-existing-device".to_string(),
            enabled: true,
            status: WorkspaceStatus::Active,
            pk_hash: None,
            encryption_public_key: None,
            tags: vec![],
            owner_id: None,
            parent_id: None,
            tool_name: None,
            created_at: now,
            updated_at: now,
        };
        ctx.store
            .create_workspace(&ws)
            .await
            .expect("create workspace");
    }

    // Now run seed with existing data
    agent_cordon_server::seed::seed_demo_data(
        &ctx.store,
        &ctx.encryptor,
        &ctx.state.config,
        &ctx.jwt_issuer,
    )
    .await
    .expect("seed with existing data should succeed");

    // Verify pre-existing device not overwritten
    let (status, body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::GET,
        "/api/v1/workspaces",
        None,
        Some(&cookie),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let devices = body["data"].as_array().expect("data");
    let has_preexisting = devices
        .iter()
        .any(|d| d["name"].as_str() == Some("pre-existing-device"));
    assert!(
        has_preexisting,
        "pre-existing device should still exist after seed"
    );
}

// ===========================================================================
// 1C. Error Handling
// ===========================================================================

#[tokio::test]
async fn test_demo_credential_secret_is_encrypted() {
    let (ctx, _cookie) = setup_with_seed().await;

    // Find demo credential ID via summary list
    let creds = ctx
        .store
        .list_credentials()
        .await
        .expect("list credentials");
    let demo_summary = creds
        .iter()
        .find(|c| c.name.contains("demo"))
        .expect("demo credential must exist in store");

    // Fetch full credential with encrypted_value
    let demo_cred = ctx
        .store
        .get_credential(&demo_summary.id)
        .await
        .expect("get credential")
        .expect("demo credential exists");

    assert!(
        !demo_cred.encrypted_value.is_empty(),
        "demo credential should have an encrypted_value"
    );
    // The encrypted value should not be the plaintext secret
    let as_utf8 = String::from_utf8(demo_cred.encrypted_value.clone());
    if let Ok(plaintext) = as_utf8 {
        assert!(
            !plaintext.contains("demo-token-not-real"),
            "encrypted_value should not contain plaintext secret"
        );
    }
}

// ===========================================================================
// 1D. Cross-Feature
// ===========================================================================

#[tokio::test]
async fn test_demo_data_visible_in_ui_list_pages() {
    let (ctx, cookie) = setup_with_seed().await;

    // Check devices page
    let resp = axum::body::Body::empty();
    let _ = resp; // unused, we use the helper below

    let (status, body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::GET,
        "/api/v1/workspaces",
        None,
        Some(&cookie),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let devices = body["data"].as_array().expect("devices");
    assert!(!devices.is_empty(), "devices list should not be empty");

    // Check agents page
    let (status, body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::GET,
        "/api/v1/workspaces",
        None,
        Some(&cookie),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let agents = body["data"].as_array().expect("agents");
    assert!(!agents.is_empty(), "agents list should not be empty");

    // Check credentials page
    let (status, body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::GET,
        "/api/v1/credentials",
        None,
        Some(&cookie),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let creds = body["data"].as_array().expect("credentials");
    assert!(!creds.is_empty(), "credentials list should not be empty");
}

// ===========================================================================
// 1E. Security
// ===========================================================================

#[tokio::test]
async fn test_demo_credential_not_llm_exposed() {
    let (ctx, cookie) = setup_with_seed().await;

    let (status, body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::GET,
        "/api/v1/credentials",
        None,
        Some(&cookie),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let creds = body["data"].as_array().expect("data");
    let demo_cred = creds
        .iter()
        .find(|c| {
            c["name"]
                .as_str()
                .map(|n| n.contains("demo"))
                .unwrap_or(false)
        })
        .expect("demo credential must exist");

    let tags = demo_cred["tags"]
        .as_array()
        .map(|t| t.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>())
        .unwrap_or_default();

    assert!(
        !tags.contains(&"llm_exposed"),
        "demo credential should NOT have llm_exposed tag, got: {:?}",
        tags
    );
}

#[tokio::test]
async fn test_demo_agent_has_minimal_permissions() {
    let (ctx, cookie) = setup_with_seed().await;

    // Find demo credential
    let (_, body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::GET,
        "/api/v1/credentials",
        None,
        Some(&cookie),
        None,
    )
    .await;

    let creds = body["data"].as_array().expect("data");
    let demo_cred = creds
        .iter()
        .find(|c| {
            c["name"]
                .as_str()
                .map(|n| n.contains("demo"))
                .unwrap_or(false)
        })
        .expect("demo credential");

    let cred_id = demo_cred["id"].as_str().expect("id");

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

    // In the grants-as-Cedar model, demo agent should have:
    //   "vend_credential" (from delegated_use) and "list" (from read)
    //   Agents never get raw "access". Should NOT have "update" or "delete" either.
    let forbidden_actions = ["update", "delete"];
    for perm in perms {
        let perm_type = perm["permission"].as_str().unwrap_or("");
        assert!(
            !forbidden_actions.contains(&perm_type),
            "demo agent should not have '{}' permission, got: {}",
            perm_type,
            perm_type
        );
    }
}
