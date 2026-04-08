//! v1.10.0 — Curated Policy Tests (Feature 2)
//!
//! Verifies the 5 curated Cedar policies seeded by `seed_demo_data`:
//! 1. Tag-Based Credential Access
//! 2. Read-Only Agents (forbid mutations)
//! 3. Device Environment Isolation
//! 4. MCP Tool Restriction
//! 5. Owner-Only Credential Access
//!
//! Tests cover: existence, disabled-by-default, valid Cedar, policy test
//! endpoint evaluation, descriptions, and idempotent seeding.

use crate::common;

use agent_cordon_core::domain::user::UserRole;
use agent_cordon_server::test_helpers::TestAppBuilder;
use axum::http::{Method, StatusCode};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async fn setup_with_seed() -> (agent_cordon_server::test_helpers::TestContext, String) {
    let ctx = TestAppBuilder::new()
        .with_config(|c| {
            c.seed_demo = true;
        })
        .build()
        .await;

    agent_cordon_server::seed::seed_demo_data(
        &ctx.store,
        &ctx.encryptor,
        &ctx.state.config,
        &ctx.jwt_issuer,
    )
    .await
    .expect("seed demo data");

    let _user = common::create_test_user(
        &*ctx.store,
        "curated-policy-user",
        common::TEST_PASSWORD,
        UserRole::Admin,
    )
    .await;
    let cookie =
        common::login_user_combined(&ctx.app, "curated-policy-user", common::TEST_PASSWORD).await;
    (ctx, cookie)
}

/// Fetch all policies and return only the curated ones (non-default, non-demo-allow).
async fn get_curated_policies(
    ctx: &agent_cordon_server::test_helpers::TestContext,
    cookie: &str,
) -> Vec<serde_json::Value> {
    let (status, body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::GET,
        "/api/v1/policies",
        None,
        Some(cookie),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "list policies: {:?}", body);

    let policies = body["data"].as_array().expect("data should be array");
    policies
        .iter()
        .filter(|p| {
            let name = p["name"].as_str().unwrap_or("");
            name != "default" && !name.starts_with("demo-") && !name.starts_with("grant:")
        })
        .cloned()
        .collect()
}

const CURATED_POLICY_NAMES: &[&str] = &[
    "Tag-Based Credential Vending",
    "Read-Only Workspaces",
    "Workspace Environment Isolation",
    "MCP Tool Restriction",
    "Owner-Only Credential Access",
];

// ===========================================================================
// 2A. All 5 curated policies exist after seeding
// ===========================================================================

#[tokio::test]
async fn test_all_curated_policies_exist() {
    let (ctx, cookie) = setup_with_seed().await;
    let curated = get_curated_policies(&ctx, &cookie).await;

    for expected_name in CURATED_POLICY_NAMES {
        let found = curated
            .iter()
            .any(|p| p["name"].as_str() == Some(expected_name));
        assert!(
            found,
            "curated policy '{}' should exist after seeding. Found: {:?}",
            expected_name,
            curated
                .iter()
                .map(|p| p["name"].as_str())
                .collect::<Vec<_>>()
        );
    }
}

// ===========================================================================
// 2B. All curated policies are disabled by default
// ===========================================================================

#[tokio::test]
async fn test_curated_policies_disabled_by_default() {
    let (ctx, cookie) = setup_with_seed().await;
    let curated = get_curated_policies(&ctx, &cookie).await;

    for policy in &curated {
        let enabled = policy["enabled"].as_bool().unwrap_or(true);
        let name = policy["name"].as_str().unwrap_or("unknown");
        assert!(
            !enabled,
            "curated policy '{}' should be disabled by default",
            name
        );
    }
}

// ===========================================================================
// 2C. All curated policies have non-empty descriptions
// ===========================================================================

#[tokio::test]
async fn test_curated_policies_have_descriptions() {
    let (ctx, cookie) = setup_with_seed().await;
    let curated = get_curated_policies(&ctx, &cookie).await;

    for policy in &curated {
        let description = policy["description"].as_str().unwrap_or("");
        let name = policy["name"].as_str().unwrap_or("unknown");
        assert!(
            !description.is_empty(),
            "curated policy '{}' should have a non-empty description",
            name
        );
    }
}

// ===========================================================================
// 2D. All curated policies parse as valid Cedar (can be enabled)
// ===========================================================================

#[tokio::test]
async fn test_curated_policies_valid_cedar() {
    let (ctx, cookie) = setup_with_seed().await;
    let curated = get_curated_policies(&ctx, &cookie).await;

    for policy in &curated {
        let policy_id = policy["id"].as_str().expect("policy id");
        let name = policy["name"].as_str().unwrap_or("unknown");

        let (enable_status, enable_body) = common::send_json_auto_csrf(
            &ctx.app,
            Method::PUT,
            &format!("/api/v1/policies/{}", policy_id),
            None,
            Some(&cookie),
            Some(serde_json::json!({
                "enabled": true
            })),
        )
        .await;
        assert!(
            enable_status == StatusCode::OK || enable_status == StatusCode::NO_CONTENT,
            "enabling curated policy '{}' should succeed (valid Cedar): status={}, body={:?}",
            name,
            enable_status,
            enable_body
        );
    }
}

// ===========================================================================
// 2E. Tag-Based Credential Access: agents with matching tags get access
// ===========================================================================

#[tokio::test]
async fn test_tag_based_policy_matching_tags_permit() {
    let (ctx, cookie) = setup_with_seed().await;

    // Enable the tag-based policy
    let curated = get_curated_policies(&ctx, &cookie).await;
    let tag_policy = curated
        .iter()
        .find(|p| p["name"].as_str() == Some("Tag-Based Credential Vending"))
        .expect("Tag-Based Credential Access policy");
    let policy_id = tag_policy["id"].as_str().expect("id");

    let (status, _) = common::send_json_auto_csrf(
        &ctx.app,
        Method::PUT,
        &format!("/api/v1/policies/{}", policy_id),
        None,
        Some(&cookie),
        Some(serde_json::json!({ "enabled": true })),
    )
    .await;
    assert!(status == StatusCode::OK || status == StatusCode::NO_CONTENT);

    // Test via policy test endpoint: agent with "ci" tag vs credential with "ci" tag.
    // The curated "Tag-Based Credential Vending" policy permits vend_credential and list,
    // not "access". Use vend_credential to test the intended behavior.
    let (status, body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        "/api/v1/policies/test",
        None,
        Some(&cookie),
        Some(serde_json::json!({
            "principal": { "type": "Agent", "id": "test-agent", "attributes": { "tags": ["ci"], "enabled": true } },
            "action": "vend_credential",
            "resource": { "type": "Credential", "attributes": { "name": "test-cred", "service": "test", "tags": ["ci"] } }
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "policy test: {:?}", body);
    assert_eq!(
        body["data"]["decision"].as_str(),
        Some("permit"),
        "agent with matching tag should be permitted for vend_credential"
    );
}

#[tokio::test]
async fn test_tag_based_policy_no_matching_tags_deny() {
    let (ctx, cookie) = setup_with_seed().await;

    // Enable the tag-based policy
    let curated = get_curated_policies(&ctx, &cookie).await;
    let tag_policy = curated
        .iter()
        .find(|p| p["name"].as_str() == Some("Tag-Based Credential Vending"))
        .expect("Tag-Based Credential Access policy");
    let policy_id = tag_policy["id"].as_str().expect("id");

    let (status, _) = common::send_json_auto_csrf(
        &ctx.app,
        Method::PUT,
        &format!("/api/v1/policies/{}", policy_id),
        None,
        Some(&cookie),
        Some(serde_json::json!({ "enabled": true })),
    )
    .await;
    assert!(status == StatusCode::OK || status == StatusCode::NO_CONTENT);

    // Test: agent with "deploy" tag vs credential with "ci" tag — no overlap
    let (status, body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        "/api/v1/policies/test",
        None,
        Some(&cookie),
        Some(serde_json::json!({
            "principal": { "type": "Agent", "id": "deploy-agent", "attributes": { "tags": ["deploy"], "enabled": true } },
            "action": "access",
            "resource": { "type": "Credential", "attributes": { "name": "ci-cred", "service": "test", "tags": ["ci"] } }
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "policy test: {:?}", body);
    // Without blanket policy 5c, an agent with non-matching tags is denied.
    // Tags ["deploy"] do not overlap with credential tags ["ci"], so deny.
    assert_eq!(
        body["data"]["decision"].as_str(),
        Some("deny"),
        "non-matching tags should deny access without blanket permit"
    );
}

// ===========================================================================
// 2F. Read-Only Agents: forbid mutations
// ===========================================================================

#[tokio::test]
async fn test_read_only_agents_forbids_update() {
    let (ctx, cookie) = setup_with_seed().await;

    // Enable read-only policy
    let curated = get_curated_policies(&ctx, &cookie).await;
    let ro_policy = curated
        .iter()
        .find(|p| p["name"].as_str() == Some("Read-Only Workspaces"))
        .expect("Read-Only Agents policy");
    let policy_id = ro_policy["id"].as_str().expect("id");

    let (status, _) = common::send_json_auto_csrf(
        &ctx.app,
        Method::PUT,
        &format!("/api/v1/policies/{}", policy_id),
        None,
        Some(&cookie),
        Some(serde_json::json!({ "enabled": true })),
    )
    .await;
    assert!(status == StatusCode::OK || status == StatusCode::NO_CONTENT);

    // Test: agent trying to update a credential
    let (status, body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        "/api/v1/policies/test",
        None,
        Some(&cookie),
        Some(serde_json::json!({
            "principal": { "type": "Agent", "id": "normal-agent", "attributes": { "tags": ["ci"], "enabled": true } },
            "action": "update",
            "resource": { "type": "Credential", "attributes": { "name": "test-cred", "service": "test" } }
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "policy test: {:?}", body);
    assert_eq!(
        body["data"]["decision"].as_str(),
        Some("forbid"),
        "read-only policy should forbid agent updates"
    );
}

#[tokio::test]
async fn test_read_only_agents_forbids_delete() {
    let (ctx, cookie) = setup_with_seed().await;

    let curated = get_curated_policies(&ctx, &cookie).await;
    let ro_policy = curated
        .iter()
        .find(|p| p["name"].as_str() == Some("Read-Only Workspaces"))
        .expect("Read-Only Agents policy");
    let policy_id = ro_policy["id"].as_str().expect("id");

    let (status, _) = common::send_json_auto_csrf(
        &ctx.app,
        Method::PUT,
        &format!("/api/v1/policies/{}", policy_id),
        None,
        Some(&cookie),
        Some(serde_json::json!({ "enabled": true })),
    )
    .await;
    assert!(status == StatusCode::OK || status == StatusCode::NO_CONTENT);

    let (status, body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        "/api/v1/policies/test",
        None,
        Some(&cookie),
        Some(serde_json::json!({
            "principal": { "type": "Agent", "id": "normal-agent", "attributes": { "tags": ["ci"], "enabled": true } },
            "action": "delete",
            "resource": { "type": "Credential", "attributes": { "name": "test-cred", "service": "test" } }
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "policy test: {:?}", body);
    assert_eq!(
        body["data"]["decision"].as_str(),
        Some("forbid"),
        "read-only policy should forbid agent deletes"
    );
}

// ===========================================================================
// 2G. Device Environment Isolation
// ===========================================================================

#[tokio::test]
async fn test_device_isolation_non_prod_device_denied() {
    let (ctx, cookie) = setup_with_seed().await;

    let curated = get_curated_policies(&ctx, &cookie).await;
    let isolation_policy = curated
        .iter()
        .find(|p| p["name"].as_str() == Some("Workspace Environment Isolation"))
        .expect("Device Environment Isolation policy");
    let policy_id = isolation_policy["id"].as_str().expect("id");

    let (status, _) = common::send_json_auto_csrf(
        &ctx.app,
        Method::PUT,
        &format!("/api/v1/policies/{}", policy_id),
        None,
        Some(&cookie),
        Some(serde_json::json!({ "enabled": true })),
    )
    .await;
    assert!(status == StatusCode::OK || status == StatusCode::NO_CONTENT);

    // Non-production device trying to vend a production credential
    let (status, body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        "/api/v1/policies/test",
        None,
        Some(&cookie),
        Some(serde_json::json!({
            "principal": { "type": "Device", "id": "dev-device", "attributes": { "name": "dev-device", "tags": ["development"], "enabled": true } },
            "action": "vend_credential",
            "resource": { "type": "Credential", "attributes": { "name": "prod-cred", "service": "aws", "tags": ["production"] } }
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "policy test: {:?}", body);
    assert_eq!(
        body["data"]["decision"].as_str(),
        Some("forbid"),
        "non-production device should be forbidden access to production credentials"
    );
}

#[tokio::test]
async fn test_device_isolation_prod_device_allowed() {
    let (ctx, cookie) = setup_with_seed().await;

    let curated = get_curated_policies(&ctx, &cookie).await;

    // Enable both the tag-based vending policy (provides the permit) and the
    // environment isolation policy (provides the forbid for non-prod). Together
    // they mean: tag-matching workspaces can vend, but non-prod is blocked from prod.
    let tag_policy = curated
        .iter()
        .find(|p| p["name"].as_str() == Some("Tag-Based Credential Vending"))
        .expect("Tag-Based Credential Vending policy");
    let tag_policy_id = tag_policy["id"].as_str().expect("id");
    let (status, _) = common::send_json_auto_csrf(
        &ctx.app,
        Method::PUT,
        &format!("/api/v1/policies/{}", tag_policy_id),
        None,
        Some(&cookie),
        Some(serde_json::json!({ "enabled": true })),
    )
    .await;
    assert!(status == StatusCode::OK || status == StatusCode::NO_CONTENT);

    let isolation_policy = curated
        .iter()
        .find(|p| p["name"].as_str() == Some("Workspace Environment Isolation"))
        .expect("Device Environment Isolation policy");
    let policy_id = isolation_policy["id"].as_str().expect("id");
    let (status, _) = common::send_json_auto_csrf(
        &ctx.app,
        Method::PUT,
        &format!("/api/v1/policies/{}", policy_id),
        None,
        Some(&cookie),
        Some(serde_json::json!({ "enabled": true })),
    )
    .await;
    assert!(status == StatusCode::OK || status == StatusCode::NO_CONTENT);

    // Production device vending a production credential — tag-based permit applies
    // and the forbid rule does not trigger (principal has "production" tag).
    let (status, body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        "/api/v1/policies/test",
        None,
        Some(&cookie),
        Some(serde_json::json!({
            "principal": { "type": "Device", "id": "prod-device", "attributes": { "name": "prod-device", "tags": ["production"], "enabled": true } },
            "action": "vend_credential",
            "resource": { "type": "Credential", "attributes": { "name": "prod-cred", "service": "aws", "tags": ["production"] } }
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "policy test: {:?}", body);
    assert_eq!(
        body["data"]["decision"].as_str(),
        Some("permit"),
        "production device should be allowed to vend production credentials"
    );
}

// ===========================================================================
// 2H. MCP Tool Restriction
// ===========================================================================

#[tokio::test]
async fn test_mcp_restriction_no_matching_tags_denied() {
    let (ctx, cookie) = setup_with_seed().await;

    let curated = get_curated_policies(&ctx, &cookie).await;
    let mcp_policy = curated
        .iter()
        .find(|p| p["name"].as_str() == Some("MCP Tool Restriction"))
        .expect("MCP Tool Restriction policy");
    let policy_id = mcp_policy["id"].as_str().expect("id");

    let (status, _) = common::send_json_auto_csrf(
        &ctx.app,
        Method::PUT,
        &format!("/api/v1/policies/{}", policy_id),
        None,
        Some(&cookie),
        Some(serde_json::json!({ "enabled": true })),
    )
    .await;
    assert!(status == StatusCode::OK || status == StatusCode::NO_CONTENT);

    // Agent without matching tags calling a restricted MCP server
    let (status, body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        "/api/v1/policies/test",
        None,
        Some(&cookie),
        Some(serde_json::json!({
            "principal": { "type": "Agent", "id": "untagged-agent", "attributes": { "tags": ["general"], "enabled": true } },
            "action": "mcp_tool_call",
            "resource": { "type": "McpServer", "attributes": { "name": "secret-server", "tags": ["restricted", "internal"], "enabled": true } }
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "policy test: {:?}", body);
    assert_eq!(
        body["data"]["decision"].as_str(),
        Some("forbid"),
        "agent without matching tags should be forbidden on restricted MCP server"
    );
}

#[tokio::test]
async fn test_mcp_restriction_matching_tags_permitted() {
    let (ctx, cookie) = setup_with_seed().await;

    let curated = get_curated_policies(&ctx, &cookie).await;
    let mcp_policy = curated
        .iter()
        .find(|p| p["name"].as_str() == Some("MCP Tool Restriction"))
        .expect("MCP Tool Restriction policy");
    let policy_id = mcp_policy["id"].as_str().expect("id");

    let (status, _) = common::send_json_auto_csrf(
        &ctx.app,
        Method::PUT,
        &format!("/api/v1/policies/{}", policy_id),
        None,
        Some(&cookie),
        Some(serde_json::json!({ "enabled": true })),
    )
    .await;
    assert!(status == StatusCode::OK || status == StatusCode::NO_CONTENT);

    // Agent with matching tag calling a restricted MCP server.
    // Both must share an owner for the default owner-based MCP permit to apply.
    let shared_owner = "00000000-0000-0000-0000-000000000001";
    let (status, body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        "/api/v1/policies/test",
        None,
        Some(&cookie),
        Some(serde_json::json!({
            "principal": { "type": "Agent", "id": "internal-agent", "attributes": { "tags": ["internal"], "enabled": true, "owner": shared_owner } },
            "action": "mcp_tool_call",
            "resource": { "type": "McpServer", "attributes": { "name": "secret-server", "tags": ["restricted", "internal"], "enabled": true, "owner": shared_owner } }
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "policy test: {:?}", body);
    assert_eq!(
        body["data"]["decision"].as_str(),
        Some("permit"),
        "agent with matching tags and shared owner should be permitted on restricted MCP server"
    );
}

// ===========================================================================
// 2I. Owner-Only Credential Access
// ===========================================================================

#[tokio::test]
async fn test_owner_isolation_different_owners_denied() {
    let (ctx, cookie) = setup_with_seed().await;

    let curated = get_curated_policies(&ctx, &cookie).await;
    let owner_policy = curated
        .iter()
        .find(|p| p["name"].as_str() == Some("Owner-Only Credential Access"))
        .expect("Owner-Only Credential Access policy");
    let policy_id = owner_policy["id"].as_str().expect("id");

    let (status, _) = common::send_json_auto_csrf(
        &ctx.app,
        Method::PUT,
        &format!("/api/v1/policies/{}", policy_id),
        None,
        Some(&cookie),
        Some(serde_json::json!({ "enabled": true })),
    )
    .await;
    assert!(status == StatusCode::OK || status == StatusCode::NO_CONTENT);

    // Agent owned by user-a trying to access credential owned by user-b
    let (status, body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        "/api/v1/policies/test",
        None,
        Some(&cookie),
        Some(serde_json::json!({
            "principal": { "type": "Agent", "id": "agent-a", "attributes": { "tags": [], "enabled": true, "owner": "user-a" } },
            "action": "access",
            "resource": { "type": "Credential", "attributes": { "name": "cred-b", "service": "test", "owner": "user-b" } }
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "policy test: {:?}", body);
    assert_eq!(
        body["data"]["decision"].as_str(),
        Some("forbid"),
        "agent should be forbidden access to credentials owned by a different user"
    );
}

#[tokio::test]
async fn test_owner_isolation_same_owner_allowed() {
    let (ctx, cookie) = setup_with_seed().await;

    let curated = get_curated_policies(&ctx, &cookie).await;
    let owner_policy = curated
        .iter()
        .find(|p| p["name"].as_str() == Some("Owner-Only Credential Access"))
        .expect("Owner-Only Credential Access policy");
    let policy_id = owner_policy["id"].as_str().expect("id");

    let (status, _) = common::send_json_auto_csrf(
        &ctx.app,
        Method::PUT,
        &format!("/api/v1/policies/{}", policy_id),
        None,
        Some(&cookie),
        Some(serde_json::json!({ "enabled": true })),
    )
    .await;
    assert!(status == StatusCode::OK || status == StatusCode::NO_CONTENT);

    // Policy 1b excludes `access` — workspaces must NEVER see raw secrets.
    // Same-owner should still be denied for `access`.
    let (status, body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        "/api/v1/policies/test",
        None,
        Some(&cookie),
        Some(serde_json::json!({
            "principal": { "type": "Agent", "id": "agent-a", "attributes": { "tags": [], "enabled": true, "owner": "user-a" } },
            "action": "access",
            "resource": { "type": "Credential", "attributes": { "name": "cred-a", "service": "test", "owner": "user-a" } }
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "policy test: {:?}", body);
    assert_eq!(
        body["data"]["decision"].as_str(),
        Some("deny"),
        "access is excluded from owner-match (policy 1b) — workspaces must never see raw secrets"
    );

    // But vend_credential IS allowed for same-owner via policy 1b
    let (status, body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        "/api/v1/policies/test",
        None,
        Some(&cookie),
        Some(serde_json::json!({
            "principal": { "type": "Agent", "id": "agent-a", "attributes": { "tags": [], "enabled": true, "owner": "user-a" } },
            "action": "vend_credential",
            "resource": { "type": "Credential", "attributes": { "name": "cred-a", "service": "test", "owner": "user-a" } }
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "policy test: {:?}", body);
    assert_eq!(
        body["data"]["decision"].as_str(),
        Some("permit"),
        "vend_credential should be permitted for same-owner via policy 1b"
    );
}

// ===========================================================================
// 2J. Seeding is idempotent — no duplicates
// ===========================================================================

#[tokio::test]
async fn test_curated_policies_not_duplicated_on_reseed() {
    let (ctx, cookie) = setup_with_seed().await;

    let curated1 = get_curated_policies(&ctx, &cookie).await;
    let count1 = curated1.len();

    // Re-seed
    agent_cordon_server::seed::seed_demo_data(
        &ctx.store,
        &ctx.encryptor,
        &ctx.state.config,
        &ctx.jwt_issuer,
    )
    .await
    .expect("second seed");

    let curated2 = get_curated_policies(&ctx, &cookie).await;
    let count2 = curated2.len();

    assert_eq!(
        count1, count2,
        "curated policy count should be unchanged after double seed ({} vs {})",
        count1, count2
    );
}

// ===========================================================================
// 2K. Schema endpoint requires auth
// ===========================================================================

#[tokio::test]
async fn test_schema_endpoint_requires_auth() {
    let (ctx, _cookie) = setup_with_seed().await;

    let (status, _body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::GET,
        "/api/v1/policies/schema",
        None,
        None, // no cookie
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "schema endpoint should require authentication"
    );
}

// ===========================================================================
// 2L. Curated policies use only schema-valid attributes
// ===========================================================================

#[tokio::test]
async fn test_curated_policies_do_not_use_deprecated_attributes() {
    let (ctx, cookie) = setup_with_seed().await;
    let curated = get_curated_policies(&ctx, &cookie).await;

    let deprecated = ["proxy_access", "allowed_agents", "api_key"];

    for policy in &curated {
        let cedar = policy["cedar_policy"].as_str().unwrap_or("");
        let name = policy["name"].as_str().unwrap_or("unknown");

        for dep in &deprecated {
            assert!(
                !cedar.contains(dep),
                "curated policy '{}' should not use deprecated attribute '{}'",
                name,
                dep
            );
        }
    }
}
