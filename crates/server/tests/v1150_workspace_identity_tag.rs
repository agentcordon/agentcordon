//! v1.15.0 — Feature 1: Stop Adding 'workspace-identity' Tag to Agents
//!
//! Tests that existing agents with the old tag still work correctly.

use axum::http::{Method, StatusCode};

use agent_cordon_core::domain::user::UserRole;
use agent_cordon_server::test_helpers::TestAppBuilder;

use crate::common::*;

/// Test: Existing agents with workspace-identity tag still work.
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

    let tags = body["data"]["tags"]
        .as_array()
        .expect("tags should be an array");
    assert!(
        tags.iter().any(|t| t == "workspace-identity"),
        "legacy agent should still have its workspace-identity tag"
    );
}
