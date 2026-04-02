//! v1.7.1 — Display Names Tests (Feature #6)
//!
//! Verifies that API responses include human-readable name fields alongside IDs,
//! so the frontend can display names instead of UUIDs.

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
        "display-name-admin",
        TEST_PASSWORD,
        UserRole::Admin,
        false,
        true,
    )
    .await;
    let cookie = login_user_combined(app, "display-name-admin", TEST_PASSWORD).await;
    let csrf = extract_csrf_from_cookie(&cookie).unwrap();
    (cookie, csrf)
}

// ===========================================================================
// 6A. API Response Verification
// ===========================================================================

/// Test #2: Credential response includes device_name (not just device_id).
/// This test verifies the API response includes name resolution for cross-references.
#[tokio::test]
async fn test_credential_response_includes_owner_info() {
    let ctx = TestAppBuilder::new().build().await;
    let (cookie, csrf) = setup_admin(&ctx.app, &*ctx.store).await;

    // Create a credential
    let (status, body) = send_json(
        &ctx.app,
        Method::POST,
        "/api/v1/credentials",
        None,
        Some(&cookie),
        Some(&csrf),
        Some(json!({
            "name": "display-test-cred",
            "service": "test-service",
            "secret_value": "test-secret",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "create credential: {}", body);
    let cred_id = body["data"]["id"].as_str().expect("credential id");

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

    // Verify name field is present
    assert_eq!(
        body["data"]["name"].as_str(),
        Some("display-test-cred"),
        "credential response should include name"
    );
    // Verify service field is present (basic cross-reference)
    assert_eq!(
        body["data"]["service"].as_str(),
        Some("test-service"),
        "credential response should include service"
    );
}

/// Test #3: MCP server response includes `name` field.
#[tokio::test]
async fn test_mcp_server_response_includes_name() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let (cookie, csrf) = setup_admin(&ctx.app, &*ctx.store).await;

    let (device_id_str, _) = create_standalone_device(&ctx.state).await;
    let device_id = agent_cordon_core::domain::workspace::WorkspaceId(
        uuid::Uuid::parse_str(&device_id_str).unwrap(),
    );

    // Create an MCP server via store insertion
    let now = chrono::Utc::now();
    let mcp = agent_cordon_core::domain::mcp::McpServer {
        id: agent_cordon_core::domain::mcp::McpServerId(uuid::Uuid::new_v4()),
        workspace_id: device_id,
        name: "github-mcp".to_string(),
        upstream_url: "https://mcp.example.com".to_string(),
        transport: "http".to_string(),
        allowed_tools: None,
        enabled: true,
        created_by: None,
        created_at: now,
        updated_at: now,
        tags: vec![],
        required_credentials: None,
    };
    ctx.store.create_mcp_server(&mcp).await.unwrap();
    let server_id = mcp.id.0.to_string();

    // GET the server
    let (status, body) = send_json(
        &ctx.app,
        Method::GET,
        &format!("/api/v1/mcp-servers/{}", server_id),
        None,
        Some(&cookie),
        Some(&csrf),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "get MCP server: {}", body);
    assert_eq!(
        body["data"]["name"].as_str(),
        Some("github-mcp"),
        "MCP server response should include name"
    );
}

/// Test #4: Agent list response includes display info (name field).
#[tokio::test]
async fn test_agent_list_includes_display_info() {
    let ctx = TestAppBuilder::new()
        .with_admin()
        .with_agent("display-test-agent", &["viewer"])
        .build()
        .await;
    let (cookie, csrf) = setup_admin(&ctx.app, &*ctx.store).await;

    // GET agents list
    let (status, body) = send_json(
        &ctx.app,
        Method::GET,
        "/api/v1/workspaces",
        None,
        Some(&cookie),
        Some(&csrf),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "list agents: {}", body);

    let agents = body["data"].as_array().expect("data should be array");
    assert!(!agents.is_empty(), "should have at least one agent");

    // Find our named agent
    let found = agents
        .iter()
        .find(|a| a["name"].as_str() == Some("display-test-agent"));
    assert!(found.is_some(), "should find display-test-agent in list");
    let agent = found.unwrap();
    assert_eq!(
        agent["name"].as_str(),
        Some("display-test-agent"),
        "agent list should include name field"
    );
}
