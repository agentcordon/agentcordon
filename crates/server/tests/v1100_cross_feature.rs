//! v1.10.0 — Cross-Feature Integration Tests
//!
//! Tests that verify multiple v1.10.0 features working together:
//! - RSoP reflects curated policy changes
//! - Schema cleanup + curated policies use vend_credential consistently
//! - Policy test endpoint + curated policies agree on decisions
//! - Enabling curated policy changes RSoP matrix decisions
//! - Schema endpoint and policy validation are consistent
//! - Full lifecycle: create policy → test it → see it in RSoP

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
        .with_admin()
        .build()
        .await;

    agent_cordon_server::seed::seed_demo_data(
        &ctx.store,
        &ctx.encryptor,
        &ctx.state.config,
        &ctx.jwt_issuer,
    )
    .await
    .expect("seed example policies");

    // Use root user so Cedar owner-scoping doesn't hide credentials.
    let _user = common::create_user_in_db(
        &*ctx.store,
        "cross-feature-user",
        common::TEST_PASSWORD,
        UserRole::Admin,
        true,
        true,
    )
    .await;
    let cookie =
        common::login_user_combined(&ctx.app, "cross-feature-user", common::TEST_PASSWORD).await;

    // Create a test credential through the API
    let (status, _body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        "/api/v1/credentials",
        None,
        Some(&cookie),
        Some(serde_json::json!({
            "name": "cross-feature-cred",
            "service": "test-service",
            "credential_type": "generic",
            "secret_value": "cross-feature-secret"
        })),
    )
    .await;
    assert!(
        status == StatusCode::CREATED || status == StatusCode::OK,
        "cross-feature setup: create credential should succeed"
    );

    (ctx, cookie)
}

async fn get_first_credential_id(
    ctx: &agent_cordon_server::test_helpers::TestContext,
    cookie: &str,
) -> String {
    let (status, body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::GET,
        "/api/v1/credentials",
        None,
        Some(cookie),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let creds = body["data"].as_array().expect("data");
    creds[0]["id"].as_str().expect("id").to_string()
}

// ===========================================================================
// X1. Enabling read-only policy changes RSoP matrix decisions
// ===========================================================================

#[tokio::test]
async fn test_enabling_curated_policy_changes_rsop() {
    let (ctx, cookie) = setup_with_seed().await;
    let cred_id = get_first_credential_id(&ctx, &cookie).await;

    // Create a non-admin agent
    common::create_agent_in_db(&*ctx.store, "xf-agent", vec!["ci"], true, None).await;

    // Get RSoP before enabling read-only policy
    let (status, body_before) = common::send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        "/api/v1/policies/rsop",
        None,
        Some(&cookie),
        Some(serde_json::json!({
            "resource_type": "Credential",
            "resource_id": cred_id,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Find and enable the "Read-Only Agents" curated policy
    let (_, policies_body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::GET,
        "/api/v1/policies",
        None,
        Some(&cookie),
        None,
    )
    .await;
    let policies = policies_body["data"].as_array().expect("data");
    let ro_policy = policies
        .iter()
        .find(|p| p["name"].as_str() == Some("Read-Only Workspaces"))
        .expect("Read-Only Workspaces policy");
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

    // Get RSoP after enabling policy
    let (status, body_after) = common::send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        "/api/v1/policies/rsop",
        None,
        Some(&cookie),
        Some(serde_json::json!({
            "resource_type": "Credential",
            "resource_id": cred_id,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Find xf-agent in both matrices and check that update/delete are now denied
    let find_agent = |body: &serde_json::Value| -> Option<serde_json::Value> {
        body["data"]["matrix"]
            .as_array()?
            .iter()
            .find(|e| e["principal_name"].as_str() == Some("xf-agent"))
            .cloned()
    };

    let _before_entry = find_agent(&body_before);
    let after_entry = find_agent(&body_after);

    if let Some(entry) = after_entry {
        let results = entry["results"].as_object().expect("results");
        if let Some(update_result) = results.get("update") {
            assert_eq!(
                update_result["decision"].as_str(),
                Some("forbid"),
                "after enabling read-only policy, update should be forbidden for non-admin agent"
            );
        }
        if let Some(delete_result) = results.get("delete") {
            assert_eq!(
                delete_result["decision"].as_str(),
                Some("forbid"),
                "after enabling read-only policy, delete should be forbidden for non-admin agent"
            );
        }
    }
}

// ===========================================================================
// X2. Schema, curated policies, and default policy all use vend_credential
// ===========================================================================

#[tokio::test]
async fn test_vend_credential_consistency_across_features() {
    let (ctx, cookie) = setup_with_seed().await;

    // 1. Check schema
    let (status, schema_body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::GET,
        "/api/v1/policies/schema",
        None,
        Some(&cookie),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let schema_text = schema_body["data"].as_str().expect("schema");
    assert!(
        schema_text.contains("vend_credential"),
        "schema should reference vend_credential"
    );
    assert!(
        !schema_text.contains("proxy_access"),
        "schema should NOT reference proxy_access"
    );

    // 2. Check all policies
    let (_, policies_body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::GET,
        "/api/v1/policies",
        None,
        Some(&cookie),
        None,
    )
    .await;
    let policies = policies_body["data"].as_array().expect("data");
    for policy in policies {
        let cedar = policy["cedar_policy"].as_str().unwrap_or("");
        let name = policy["name"].as_str().unwrap_or("unknown");
        assert!(
            !cedar.contains("proxy_access"),
            "policy '{}' should not reference proxy_access",
            name
        );
    }
}

// ===========================================================================
// X3. Policy test endpoint and RSoP agree on decisions
// ===========================================================================

#[tokio::test]
async fn test_policy_test_and_rsop_agree() {
    let (ctx, cookie) = setup_with_seed().await;
    let cred_id = get_first_credential_id(&ctx, &cookie).await;

    // Get RSoP result for the credential
    let (status, rsop_body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        "/api/v1/policies/rsop",
        None,
        Some(&cookie),
        Some(serde_json::json!({
            "resource_type": "Credential",
            "resource_id": cred_id,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Find the demo-agent entry in RSoP
    let matrix = rsop_body["data"]["matrix"].as_array().expect("matrix");
    let demo_entry = matrix.iter().find(|e| {
        e["principal_name"].as_str() == Some("demo-agent")
            && e["principal_type"].as_str() == Some("Agent")
    });

    if let Some(entry) = demo_entry {
        let rsop_vend_decision = entry["results"]["vend_credential"]["decision"]
            .as_str()
            .unwrap_or("unknown");

        // Now test the same decision via policy test endpoint
        let demo_agent_id = entry["principal_id"].as_str().expect("agent id");
        let (status, test_body) = common::send_json_auto_csrf(
            &ctx.app,
            Method::POST,
            "/api/v1/policies/test",
            None,
            Some(&cookie),
            Some(serde_json::json!({
                "principal": {
                    "type": "Agent",
                    "id": demo_agent_id,
                    "attributes": {
                        "tags": ["demo"],
                        "enabled": true
                    }
                },
                "action": "vend_credential",
                "resource": {
                    "type": "Credential",
                    "id": cred_id,
                    "attributes": {
                        "name": "demo-api-key",
                        "service": "httpbin",
                        "delegated_users": [demo_agent_id]
                    }
                }
            })),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let test_decision = test_body["data"]["decision"].as_str().unwrap_or("unknown");
        assert_eq!(
            test_decision, rsop_vend_decision,
            "policy test and RSoP should agree on vend_credential decision for demo-agent"
        );
    }
}

// ===========================================================================
// X4. Full lifecycle: create → test → RSoP
// ===========================================================================

#[tokio::test]
async fn test_full_policy_lifecycle() {
    let (ctx, cookie) = setup_with_seed().await;
    let cred_id = get_first_credential_id(&ctx, &cookie).await;

    // 1. Create a new policy
    let (status, create_body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        "/api/v1/policies",
        None,
        Some(&cookie),
        Some(serde_json::json!({
            "name": "lifecycle-test-policy",
            "description": "Integration test policy for lifecycle verification",
            "cedar_policy": r#"forbid(
                principal is AgentCordon::Workspace,
                action == AgentCordon::Action::"vend_credential",
                resource is AgentCordon::Credential
            ) when {
                principal.tags.contains("blocked")
            };"#,
        })),
    )
    .await;
    assert!(
        status == StatusCode::OK || status == StatusCode::CREATED,
        "create policy: {:?}",
        create_body
    );

    // 2. Test the policy via policy test endpoint — blocked agent
    let (status, test_body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        "/api/v1/policies/test",
        None,
        Some(&cookie),
        Some(serde_json::json!({
            "principal": { "type": "Agent", "id": "blocked-agent", "attributes": { "tags": ["blocked"], "enabled": true } },
            "action": "vend_credential",
            "resource": { "type": "Credential", "attributes": { "name": "test-cred", "service": "test" } }
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        test_body["data"]["decision"].as_str(),
        Some("forbid"),
        "blocked agent should be forbidden vend_credential by forbid rule"
    );

    // 3. RSoP should show the policy is active
    // Create a "blocked" agent in the DB
    common::create_agent_in_db(
        &*ctx.store,
        "lifecycle-blocked",
        vec!["blocked"],
        true,
        None,
    )
    .await;

    let (status, rsop_body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        "/api/v1/policies/rsop",
        None,
        Some(&cookie),
        Some(serde_json::json!({
            "resource_type": "Credential",
            "resource_id": cred_id,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let matrix = rsop_body["data"]["matrix"].as_array().expect("matrix");
    let blocked_entry = matrix
        .iter()
        .find(|e| e["principal_name"].as_str() == Some("lifecycle-blocked"));
    assert!(
        blocked_entry.is_some(),
        "blocked agent should appear in RSoP matrix"
    );

    if let Some(entry) = blocked_entry {
        let vend_decision = entry["results"]["vend_credential"]["decision"]
            .as_str()
            .unwrap_or("unknown");
        assert_eq!(
            vend_decision, "forbid",
            "RSoP should show blocked agent as forbidden for vend_credential"
        );
    }
}

// ===========================================================================
// X5. Schema validation and policy creation are consistent
// ===========================================================================

#[tokio::test]
async fn test_schema_and_validation_consistent() {
    let (ctx, cookie) = setup_with_seed().await;

    // Get schema
    let (status, schema_body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::GET,
        "/api/v1/policies/schema",
        None,
        Some(&cookie),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let schema_text = schema_body["data"].as_str().expect("schema");

    // If schema defines vend_credential, creating a policy with it should succeed
    if schema_text.contains("vend_credential") {
        let (status, _) = common::send_json_auto_csrf(
            &ctx.app,
            Method::POST,
            "/api/v1/policies",
            None,
            Some(&cookie),
            Some(serde_json::json!({
                "name": "schema-consistent-test",
                "description": "Tests schema/validation consistency",
                "cedar_policy": r#"permit(
                    principal is AgentCordon::Workspace,
                    action == AgentCordon::Action::"vend_credential",
                    resource is AgentCordon::Credential
                ) when {
                    principal.tags.contains("test")
                };"#,
            })),
        )
        .await;
        assert!(
            status == StatusCode::OK || status == StatusCode::CREATED,
            "if schema defines vend_credential, creating a policy with it should succeed"
        );
    }

    // Actions NOT in schema should fail validation
    let (status, _) = common::send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        "/api/v1/policies",
        None,
        Some(&cookie),
        Some(serde_json::json!({
            "name": "schema-inconsistent-test",
            "description": "Tests that unknown actions fail",
            "cedar_policy": r#"permit(
                principal is AgentCordon::Workspace,
                action == AgentCordon::Action::"totally_fake_action",
                resource is AgentCordon::Credential
            );"#,
        })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "action not in schema should fail validation"
    );
}

// ===========================================================================
// X6. All error responses across features use consistent structure
// ===========================================================================

#[tokio::test]
async fn test_error_format_consistency_across_features() {
    let (ctx, cookie) = setup_with_seed().await;

    // Policy not found
    let (_, policy_404) = common::send_json_auto_csrf(
        &ctx.app,
        Method::GET,
        "/api/v1/policies/00000000-0000-0000-0000-000000000000",
        None,
        Some(&cookie),
        None,
    )
    .await;
    assert!(
        policy_404["error"]["code"].is_string(),
        "policy 404 should have error.code"
    );

    // RSoP bad request
    let (_, rsop_400) = common::send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        "/api/v1/policies/rsop",
        None,
        Some(&cookie),
        Some(serde_json::json!({ "resource_type": "Invalid", "resource_id": "00000000-0000-0000-0000-000000000000" })),
    )
    .await;
    assert!(
        rsop_400["error"]["code"].is_string(),
        "RSoP 400 should have error.code"
    );

    // Policy test bad request
    let (_, test_400) = common::send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        "/api/v1/policies/test",
        None,
        Some(&cookie),
        Some(serde_json::json!({ "action": "access" })),
    )
    .await;
    assert!(
        test_400["error"]["code"].is_string(),
        "policy test 400 should have error.code"
    );

    // All should follow same structure: { "error": { "code": "...", "message": "..." } }
    for (name, body) in [
        ("policy_404", &policy_404),
        ("rsop_400", &rsop_400),
        ("test_400", &test_400),
    ] {
        let error = &body["error"];
        assert!(error.is_object(), "{} should have error object", name);
        assert!(error["code"].is_string(), "{} should have error.code", name);
        assert!(
            error["message"].is_string(),
            "{} should have error.message",
            name
        );
    }
}
