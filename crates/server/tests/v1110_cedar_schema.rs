//! Integration tests for P1 Cedar Schema Clarity (v1.11.0)
//!
//! Features 4 & 5: Document access vs vend_credential, human-readable
//! descriptions for all Cedar actions.
//!
//! These tests validate the schema reference endpoint returns correct metadata.

use axum::http::{Method, StatusCode};
use serde_json::json;
use std::collections::HashSet;
use uuid::Uuid;

use agent_cordon_core::crypto::SecretEncryptor;
use agent_cordon_core::domain::credential::{CredentialId, StoredCredential};
use agent_cordon_core::domain::user::UserRole;

use crate::common::*;
use agent_cordon_server::test_helpers::TestAppBuilder;

// ---------------------------------------------------------------------------
// Feature 4: Document `access` vs `vend_credential`
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_schema_reference_includes_access_description() {
    // GET schema reference. Assert `access` action has description mentioning
    // "direct" or "credential access".
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let _admin = create_test_user(&*ctx.store, "admin1", TEST_PASSWORD, UserRole::Admin).await;
    let cookie = login_user_combined(&ctx.app, "admin1", TEST_PASSWORD).await;

    let (status, body) = send_json(
        &ctx.app,
        Method::GET,
        "/api/v1/policies/schema/reference",
        None,
        Some(&cookie),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "schema: {}", body);

    let actions = body["data"]["actions"].as_array().expect("actions array");
    let access_action = actions
        .iter()
        .find(|a| a["name"].as_str() == Some("access"))
        .expect("access action must exist");

    let desc = access_action["description"]
        .as_str()
        .expect("access must have description");
    assert!(
        desc.to_lowercase().contains("direct") || desc.to_lowercase().contains("credential"),
        "access description should mention direct credential use: '{}'",
        desc
    );
}

#[tokio::test]
async fn test_schema_reference_includes_vend_credential_description() {
    // GET schema reference. Assert `vend_credential` has description mentioning
    // "device" or "vending" or "proxy".
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let _admin = create_test_user(&*ctx.store, "admin1", TEST_PASSWORD, UserRole::Admin).await;
    let cookie = login_user_combined(&ctx.app, "admin1", TEST_PASSWORD).await;

    let (status, body) = send_json(
        &ctx.app,
        Method::GET,
        "/api/v1/policies/schema/reference",
        None,
        Some(&cookie),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let actions = body["data"]["actions"].as_array().expect("actions array");
    let vend_action = actions
        .iter()
        .find(|a| a["name"].as_str() == Some("vend_credential"))
        .expect("vend_credential action must exist");

    let desc = vend_action["description"]
        .as_str()
        .expect("vend_credential must have description");
    assert!(
        desc.to_lowercase().contains("device")
            || desc.to_lowercase().contains("vend")
            || desc.to_lowercase().contains("proxy"),
        "vend_credential description should mention device/vending: '{}'",
        desc
    );
}

#[tokio::test]
async fn test_delegated_use_grant_creates_both_cedar_policies() {
    // Grant "delegated_use" to agent A1 for credential C1.
    // Assert Cedar policies for both `access` and `vend_credential`.
    let ctx = TestAppBuilder::new()
        .with_admin()
        .with_agent("agent1", &["user"])
        .build()
        .await;
    // Create credential directly in store
    let now = chrono::Utc::now();
    let cred_id = CredentialId(Uuid::new_v4());
    let (encrypted, nonce) = ctx
        .encryptor
        .encrypt(b"sk-test-123", cred_id.0.to_string().as_bytes())
        .expect("encrypt");
    let cred = StoredCredential {
        id: cred_id.clone(),
        name: "test-cred".to_string(),
        service: "test-service".to_string(),
        encrypted_value: encrypted,
        nonce,
        scopes: vec![],
        metadata: json!({}),
        created_by: None,
        created_by_user: None,
        created_at: now,
        updated_at: now,
        allowed_url_pattern: None,
        expires_at: None,
        transform_script: None,
        transform_name: None,
        vault: "default".to_string(),
        credential_type: "api_key".to_string(),
        tags: vec![],
        description: None,
        target_identity: None,
        key_version: 1,
    };
    ctx.store
        .store_credential(&cred)
        .await
        .expect("store credential");

    let agent1 = ctx.agents.get("agent1").unwrap();

    // Grant delegated_use
    grant_cedar_permission(&ctx.state, &cred_id, &agent1.id, "delegated_use").await;

    // Check policies
    let policies = ctx.store.get_all_enabled_policies().await.unwrap();
    let agent_id = agent1.id.0.to_string();

    let cred_id_str = cred_id.0.to_string();
    // v2.0: delegated_use grant creates only vend_credential Cedar policy (not access)
    let vend_policy = policies.iter().find(|p| {
        p.name.contains(&cred_id_str)
            && p.name.contains("vend_credential")
            && p.cedar_policy.contains(&agent_id)
    });

    assert!(
        vend_policy.is_some(),
        "delegated_use should create vend_credential policy"
    );
}

// ---------------------------------------------------------------------------
// Feature 5: Human-Readable Descriptions for All Actions
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_all_actions_have_descriptions() {
    // GET schema reference. Assert all actions have non-empty descriptions.
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let _admin = create_test_user(&*ctx.store, "admin1", TEST_PASSWORD, UserRole::Admin).await;
    let cookie = login_user_combined(&ctx.app, "admin1", TEST_PASSWORD).await;

    let (status, body) = send_json(
        &ctx.app,
        Method::GET,
        "/api/v1/policies/schema/reference",
        None,
        Some(&cookie),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let actions = body["data"]["actions"].as_array().expect("actions array");

    // Expected actions (at least these)
    // v2.0: manage_agents -> manage_workspaces, manage_devices/enroll_agent/manage_enrollments removed
    let expected_actions: HashSet<&str> = [
        "access",
        "vend_credential",
        "list",
        "create",
        "update",
        "delete",
        "manage_permissions",
        "manage_policies",
        "manage_users",
        "manage_workspaces",
        "view_audit",
        "rotate_key",
        "manage_oidc_providers",
        "manage_vaults",
        "rotate_encryption_key",
        "manage_mcp_servers",
        "mcp_tool_call",
        "mcp_list_tools",
        "manage_tags",
        "unprotect",
    ]
    .into_iter()
    .collect();

    let actual_names: HashSet<String> = actions
        .iter()
        .filter_map(|a| a["name"].as_str().map(String::from))
        .collect();

    // Every expected action should be present
    for expected in &expected_actions {
        assert!(
            actual_names.contains(*expected),
            "expected action '{}' missing from schema",
            expected
        );
    }

    // Every action should have a non-empty description
    for action in actions {
        let name = action["name"].as_str().unwrap_or("unknown");
        let desc = action["description"].as_str().unwrap_or("");
        assert!(!desc.is_empty(), "action '{}' has empty description", name);
    }
}

#[tokio::test]
async fn test_action_descriptions_are_human_readable() {
    // Assert descriptions are >10 chars, contain English words, and are distinct.
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let _admin = create_test_user(&*ctx.store, "admin1", TEST_PASSWORD, UserRole::Admin).await;
    let cookie = login_user_combined(&ctx.app, "admin1", TEST_PASSWORD).await;

    let (status, body) = send_json(
        &ctx.app,
        Method::GET,
        "/api/v1/policies/schema/reference",
        None,
        Some(&cookie),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let actions = body["data"]["actions"].as_array().expect("actions array");
    let mut descriptions = HashSet::new();

    for action in actions {
        let name = action["name"].as_str().unwrap_or("unknown");
        let desc = action["description"].as_str().unwrap_or("");

        // Must be >10 chars
        assert!(
            desc.len() > 10,
            "action '{}' description too short: '{}'",
            name,
            desc
        );

        // Must contain spaces (English words, not a UUID)
        assert!(
            desc.contains(' '),
            "action '{}' description doesn't look human-readable: '{}'",
            name,
            desc
        );

        // Must be distinct
        assert!(
            descriptions.insert(desc.to_string()),
            "action '{}' has duplicate description: '{}'",
            name,
            desc
        );
    }
}
