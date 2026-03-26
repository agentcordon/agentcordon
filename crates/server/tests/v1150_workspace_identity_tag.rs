//! v1.15.0 — Feature 1: Stop Adding 'workspace-identity' Tag to Agents
//!
//! Tests that new agents created via workspace identity enrollment have
//! empty tags (no auto-assigned "workspace-identity" tag), and that the
//! tag system still works correctly for manual tag operations.

use axum::http::{Method, StatusCode};
use serde_json::json;

use agent_cordon_core::domain::user::UserRole;
use agent_cordon_server::test_helpers::TestAppBuilder;

use crate::common::*;

// ===========================================================================
// 1A. Happy Path
// ===========================================================================

/// Test #1: Register a new workspace identity. Assert agent has no auto-tags.
#[tokio::test]
async fn test_new_agent_has_no_workspace_identity_tag() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let _admin = create_test_user(&*ctx.store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let (cookie, csrf) = login_user(&ctx.app, "admin", TEST_PASSWORD).await;
    let full_cookie = combined_cookie(&cookie, &csrf);

    // Register a workspace identity through the full API flow
    let ws = register_workspace_full_context(&ctx.app, &full_cookie, &csrf).await;

    // Fetch the created agent and verify no tags
    let (status, body) = send_json(
        &ctx.app,
        Method::GET,
        &format!("/api/v1/workspaces/{}", ws.agent_id),
        None,
        Some(&full_cookie),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "fetch agent: {}", body);

    let tags = body["data"]["tags"]
        .as_array()
        .expect("tags should be an array");
    assert!(
        tags.is_empty(),
        "newly enrolled agent should have no auto-tags, got: {:?}",
        tags
    );
    // Specifically verify "workspace-identity" is NOT present
    assert!(
        !tags
            .iter()
            .any(|t| t.as_str() == Some("workspace-identity")),
        "agent must not have 'workspace-identity' tag"
    );
}

/// Test #2: After enrollment (no auto-tag), admin can still add custom tags.
#[tokio::test]
async fn test_agent_tags_can_still_be_added_manually() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let _admin = create_test_user(&*ctx.store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let (cookie, csrf) = login_user(&ctx.app, "admin", TEST_PASSWORD).await;
    let full_cookie = combined_cookie(&cookie, &csrf);

    let ws = register_workspace_full_context(&ctx.app, &full_cookie, &csrf).await;

    // Add a custom tag via API
    let url = format!("/api/v1/workspaces/{}/tags", ws.agent_id);
    let (status, body) = send_json(
        &ctx.app,
        Method::POST,
        &url,
        None,
        Some(&full_cookie),
        Some(&csrf),
        Some(json!({ "tag": "production" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "add tag: {}", body);

    let tags = body["data"]["tags"].as_array().expect("tags array");
    assert!(
        tags.iter().any(|t| t == "production"),
        "agent should have the manually-added 'production' tag"
    );
}

/// Test #3: Enroll 3 agents. All should have empty tags.
#[tokio::test]
async fn test_multiple_enrollments_no_auto_tags() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let _admin = create_test_user(&*ctx.store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let (cookie, csrf) = login_user(&ctx.app, "admin", TEST_PASSWORD).await;
    let full_cookie = combined_cookie(&cookie, &csrf);

    let mut agent_ids = Vec::new();
    for _ in 0..3 {
        let ws = register_workspace_full_context(&ctx.app, &full_cookie, &csrf).await;
        agent_ids.push(ws.agent_id);
    }

    for agent_id in &agent_ids {
        let (status, body) = send_json(
            &ctx.app,
            Method::GET,
            &format!("/api/v1/workspaces/{}", agent_id),
            None,
            Some(&full_cookie),
            None,
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "fetch agent {}: {}", agent_id, body);

        let tags = body["data"]["tags"].as_array().expect("tags array");
        assert!(
            tags.is_empty(),
            "agent {} should have no auto-tags, got: {:?}",
            agent_id,
            tags
        );
    }
}

// ===========================================================================
// 1D. Cross-Feature
// ===========================================================================

/// Test #4: Cedar policies work for agents without the workspace-identity tag.
#[tokio::test]
async fn test_cedar_policies_work_without_workspace_identity_tag() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let _admin = create_test_user(&*ctx.store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let (cookie, csrf) = login_user(&ctx.app, "admin", TEST_PASSWORD).await;
    let full_cookie = combined_cookie(&cookie, &csrf);

    let ws = register_workspace_full_context(&ctx.app, &full_cookie, &csrf).await;

    // Create a credential
    let (status, cred_body) = send_json(
        &ctx.app,
        Method::POST,
        "/api/v1/credentials",
        None,
        Some(&full_cookie),
        Some(&csrf),
        Some(json!({
            "name": "test-cred-for-tag-test",
            "service": "test-service",
            "secret_value": "test-secret-value-12345",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "create credential: {}", cred_body);
    let cred_id_str = cred_body["data"]["id"].as_str().expect("credential id");

    // Grant the agent access via Cedar (agent has no tags — that's fine)
    let _agent_id = agent_cordon_core::domain::agent::AgentId(
        cred_id_str
            .parse::<uuid::Uuid>()
            .ok()
            .unwrap_or_else(|| ws.agent_id.parse().expect("parse agent_id")),
    );
    // Use the actual agent_id for the grant
    let agent_id =
        agent_cordon_core::domain::agent::AgentId(ws.agent_id.parse().expect("parse agent_id"));
    let cred_id = agent_cordon_core::domain::credential::CredentialId(
        cred_id_str.parse().expect("parse credential_id"),
    );
    grant_cedar_permission(&ctx.state, &cred_id, &agent_id, "delegated_use").await;

    // The Cedar policy should work regardless of whether agent has tags or not.
    // Verify by checking the policy tester endpoint.
    let (status, body) = send_json(
        &ctx.app,
        Method::POST,
        "/api/v1/policies/test",
        None,
        Some(&full_cookie),
        Some(&csrf),
        Some(json!({
            "principal": { "type": "Agent", "id": ws.agent_id, "attributes": { "name": "test-agent", "enabled": true } },
            "action": "vend_credential",
            "resource": { "type": "Credential", "id": cred_id_str, "attributes": { "name": "test-cred-for-tag-test", "service": "test-service" } },
            "context": {},
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "policy test: {}", body);
    assert_eq!(
        body["data"]["decision"], "permit",
        "Cedar should permit vend_credential — tags are not required for authorization"
    );
}

/// Test #5: Existing agents with workspace-identity tag still work.
#[tokio::test]
async fn test_existing_agents_with_tag_still_functional() {
    // Manually create an agent WITH the old tag to simulate a pre-existing agent
    let ctx = TestAppBuilder::new()
        .with_admin()
        .with_agent("legacy-agent", &["workspace-identity"])
        .build()
        .await;
    let _admin = create_test_user(&*ctx.store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let (cookie, csrf) = login_user(&ctx.app, "admin", TEST_PASSWORD).await;
    let full_cookie = combined_cookie(&cookie, &csrf);

    let agent = ctx.agents.get("legacy-agent").expect("legacy agent");

    // Fetch the agent — should still work and have the tag
    let (status, body) = send_json(
        &ctx.app,
        Method::GET,
        &format!("/api/v1/workspaces/{}", agent.id.0),
        None,
        Some(&full_cookie),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "fetch legacy agent: {}", body);

    let tags = body["data"]["tags"].as_array().expect("tags array");
    assert!(
        tags.iter().any(|t| t == "workspace-identity"),
        "legacy agent should still have its workspace-identity tag"
    );
}
