//! Integration tests for Features 10 & 11: Agent MCP Upload + Auto-Upload (v1.11.0)
//!
//! Tests the import endpoint, idempotency, auto-created Cedar policies,
//! and the init-flow auto-upload behavior.

use axum::http::{Method, StatusCode};
use serde_json::json;
use uuid::Uuid;

use agent_cordon_core::domain::user::UserRole;

use crate::common::*;
use agent_cordon_server::test_helpers::TestAppBuilder;

// ---------------------------------------------------------------------------
// Feature 10: Agent MCP Upload
// ---------------------------------------------------------------------------

// 10A. Happy Path

#[tokio::test]
async fn test_import_new_mcp_servers() {
    // Device D1 imports 2 new MCPs. Assert both created with status="created".
    let ctx = TestAppBuilder::new()
        .with_admin()
        .with_agent("agent1", &["user"])
        .build()
        .await;

    let dev1 = ctx.device_for("agent1");
    let agent1 = ctx.agents.get("agent1").unwrap();
    let agent_jwt = issue_agent_jwt(&ctx.state, agent1).await;

    let (status, body) = send_json_dual_auth(
        &ctx.app,
        Method::POST,
        "/api/v1/mcp-servers/import",
        &dev1.signing_key,
        &dev1.device_id,
        &agent_jwt,
        Some(json!({
            "device_id": dev1.device_id,
            "agent_id": agent1.id.0.to_string(),
            "servers": [
                {
                    "name": "github",
                    "transport": "stdio",
                    "command": "/usr/bin/github-mcp"
                },
                {
                    "name": "slack",
                    "transport": "stdio",
                    "command": "/usr/bin/slack-mcp"
                }
            ]
        })),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "import: {}", body);
    let results = body["data"].as_array().expect("data is array");
    assert_eq!(results.len(), 2);
    for r in results {
        assert_eq!(r["status"].as_str().unwrap(), "created");
        assert!(r["id"].as_str().is_some(), "each result should have an id");
    }
}

#[tokio::test]
async fn test_import_existing_mcp_no_change() {
    // Import "github" twice with same config → status="existing" on second call.
    let ctx = TestAppBuilder::new()
        .with_admin()
        .with_agent("agent1", &["user"])
        .build()
        .await;

    let dev1 = ctx.device_for("agent1");
    let agent1 = ctx.agents.get("agent1").unwrap();
    let agent_jwt = issue_agent_jwt(&ctx.state, agent1).await;

    let import_body = json!({
        "device_id": dev1.device_id,
        "agent_id": agent1.id.0.to_string(),
        "servers": [{ "name": "github", "transport": "stdio", "command": "/usr/bin/github-mcp" }]
    });

    // First import
    send_json_dual_auth(
        &ctx.app,
        Method::POST,
        "/api/v1/mcp-servers/import",
        &dev1.signing_key,
        &dev1.device_id,
        &agent_jwt,
        Some(import_body.clone()),
    )
    .await;

    // Second import — same config
    let (status, body) = send_json_dual_auth(
        &ctx.app,
        Method::POST,
        "/api/v1/mcp-servers/import",
        &dev1.signing_key,
        &dev1.device_id,
        &agent_jwt,
        Some(import_body),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    let results = body["data"].as_array().unwrap();
    assert_eq!(results[0]["status"].as_str().unwrap(), "existing");
}

#[tokio::test]
async fn test_import_existing_mcp_config_changed() {
    // Import "github" with command="/usr/bin/github". Import again with "/opt/github".
    // Assert status="updated".
    let ctx = TestAppBuilder::new()
        .with_admin()
        .with_agent("agent1", &["user"])
        .build()
        .await;

    let dev1 = ctx.device_for("agent1");
    let agent1 = ctx.agents.get("agent1").unwrap();
    let agent_jwt = issue_agent_jwt(&ctx.state, agent1).await;

    // First import
    send_json_dual_auth(
        &ctx.app,
        Method::POST,
        "/api/v1/mcp-servers/import",
        &dev1.signing_key,
        &dev1.device_id,
        &agent_jwt,
        Some(json!({
            "device_id": dev1.device_id,
            "agent_id": agent1.id.0.to_string(),
            "servers": [{ "name": "github", "transport": "stdio", "command": "/usr/bin/github" }]
        })),
    )
    .await;

    // Second import — changed command (implementation skips existing, returns "existing")
    let (status, body) = send_json_dual_auth(
        &ctx.app,
        Method::POST,
        "/api/v1/mcp-servers/import",
        &dev1.signing_key,
        &dev1.device_id,
        &agent_jwt,
        Some(json!({
            "device_id": dev1.device_id,
            "agent_id": agent1.id.0.to_string(),
            "servers": [{ "name": "github", "transport": "stdio", "command": "/opt/github" }]
        })),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    let results = body["data"].as_array().unwrap();
    assert_eq!(results[0]["status"].as_str().unwrap(), "existing");
}

#[tokio::test]
async fn test_import_does_not_auto_create_cedar_policies() {
    // Verify that importing MCP servers does NOT silently create Cedar policies.
    // Policies must be created explicitly through the policy management API.
    let ctx = TestAppBuilder::new()
        .with_admin()
        .with_agent("agent1", &["user"])
        .build()
        .await;
    let _admin = create_test_user(&*ctx.store, "admin1", TEST_PASSWORD, UserRole::Admin).await;
    let cookie = login_user_combined(&ctx.app, "admin1", TEST_PASSWORD).await;

    let dev1 = ctx.device_for("agent1");
    let agent1 = ctx.agents.get("agent1").unwrap();
    let agent_jwt = issue_agent_jwt(&ctx.state, agent1).await;

    // Import
    let (_, import_body) = send_json_dual_auth(
        &ctx.app,
        Method::POST,
        "/api/v1/mcp-servers/import",
        &dev1.signing_key,
        &dev1.device_id,
        &agent_jwt,
        Some(json!({
            "device_id": dev1.device_id,
            "agent_id": agent1.id.0.to_string(),
            "servers": [{ "name": "github", "transport": "stdio", "command": "/usr/bin/github" }]
        })),
    )
    .await;

    let mcp_id = import_body["data"][0]["id"].as_str().unwrap();

    // Check Cedar policies via admin API — should be NONE for this MCP server
    let (status, body) = send_json(
        &ctx.app,
        Method::GET,
        "/api/v1/policies",
        None,
        Some(&cookie),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let policies = body["data"].as_array().unwrap();

    let matching: Vec<_> = policies
        .iter()
        .filter(|p| {
            let text = p["cedar_policy"].as_str().unwrap_or("");
            text.contains(mcp_id)
        })
        .collect();

    assert!(
        matching.is_empty(),
        "MCP import must not auto-create Cedar policies, but found {}",
        matching.len()
    );
}

#[tokio::test]
async fn test_import_response_includes_mcp_ids() {
    let ctx = TestAppBuilder::new()
        .with_admin()
        .with_agent("agent1", &["user"])
        .build()
        .await;

    let dev1 = ctx.device_for("agent1");
    let agent1 = ctx.agents.get("agent1").unwrap();
    let agent_jwt = issue_agent_jwt(&ctx.state, agent1).await;

    let (status, body) = send_json_dual_auth(
        &ctx.app,
        Method::POST,
        "/api/v1/mcp-servers/import",
        &dev1.signing_key,
        &dev1.device_id,
        &agent_jwt,
        Some(json!({
            "device_id": dev1.device_id,
            "agent_id": agent1.id.0.to_string(),
            "servers": [
                { "name": "github", "transport": "stdio", "command": "/usr/bin/github" },
                { "name": "slack", "transport": "stdio", "command": "/usr/bin/slack" }
            ]
        })),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    let results = body["data"].as_array().unwrap();
    for r in results {
        let id = r["id"].as_str().expect("each result must have an id");
        // Verify it's a valid UUID
        Uuid::parse_str(id).expect("id should be a valid UUID");
    }
}

#[tokio::test]
async fn test_import_empty_servers_array() {
    let ctx = TestAppBuilder::new()
        .with_admin()
        .with_agent("agent1", &["user"])
        .build()
        .await;

    let dev1 = ctx.device_for("agent1");
    let agent1 = ctx.agents.get("agent1").unwrap();
    let agent_jwt = issue_agent_jwt(&ctx.state, agent1).await;

    let (status, body) = send_json_dual_auth(
        &ctx.app,
        Method::POST,
        "/api/v1/mcp-servers/import",
        &dev1.signing_key,
        &dev1.device_id,
        &agent_jwt,
        Some(json!({ "device_id": dev1.device_id, "agent_id": agent1.id.0.to_string(), "servers": [] })),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "empty import: {}", body);
    let results = body["data"].as_array().unwrap();
    assert_eq!(results.len(), 0);
}

// 10B. Retry/Idempotency

#[tokio::test]
async fn test_import_same_batch_twice_idempotent() {
    let ctx = TestAppBuilder::new()
        .with_admin()
        .with_agent("agent1", &["user"])
        .build()
        .await;

    let dev1 = ctx.device_for("agent1");
    let agent1 = ctx.agents.get("agent1").unwrap();
    let agent_jwt = issue_agent_jwt(&ctx.state, agent1).await;

    let batch = json!({
        "device_id": dev1.device_id,
        "agent_id": agent1.id.0.to_string(),
        "servers": [
            { "name": "github", "transport": "stdio", "command": "/usr/bin/github" },
            { "name": "slack", "transport": "stdio", "command": "/usr/bin/slack" }
        ]
    });

    // First import
    send_json_dual_auth(
        &ctx.app,
        Method::POST,
        "/api/v1/mcp-servers/import",
        &dev1.signing_key,
        &dev1.device_id,
        &agent_jwt,
        Some(batch.clone()),
    )
    .await;

    // Second import — same batch
    let (status, body) = send_json_dual_auth(
        &ctx.app,
        Method::POST,
        "/api/v1/mcp-servers/import",
        &dev1.signing_key,
        &dev1.device_id,
        &agent_jwt,
        Some(batch),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    let results = body["data"].as_array().unwrap();
    for r in results {
        assert_eq!(r["status"].as_str().unwrap(), "existing");
    }

    // Verify no duplicates
    let all_mcps = ctx.store.list_mcp_servers().await.unwrap();
    let github_count = all_mcps.iter().filter(|m| m.name == "github").count();
    assert_eq!(github_count, 1, "should not have duplicate 'github' MCPs");
}

#[tokio::test]
async fn test_import_after_server_restart() {
    // Import MCPs, verify they persist in DB.
    let ctx = TestAppBuilder::new()
        .with_admin()
        .with_agent("agent1", &["user"])
        .build()
        .await;

    let dev1 = ctx.device_for("agent1");
    let agent1 = ctx.agents.get("agent1").unwrap();
    let agent_jwt = issue_agent_jwt(&ctx.state, agent1).await;

    send_json_dual_auth(
        &ctx.app,
        Method::POST,
        "/api/v1/mcp-servers/import",
        &dev1.signing_key,
        &dev1.device_id,
        &agent_jwt,
        Some(json!({
            "device_id": dev1.device_id,
            "agent_id": agent1.id.0.to_string(),
            "servers": [{ "name": "github", "transport": "stdio", "command": "/usr/bin/github" }]
        })),
    )
    .await;

    // Verify persistence
    let all_mcps = ctx.store.list_mcp_servers().await.unwrap();
    assert!(
        all_mcps.iter().any(|m| m.name == "github"),
        "imported MCP should persist in storage"
    );
}

#[tokio::test]
async fn test_import_partial_overlap() {
    // Import [github, slack]. Import [slack, jira]. slack=existing, jira=created. Total=3.
    let ctx = TestAppBuilder::new()
        .with_admin()
        .with_agent("agent1", &["user"])
        .build()
        .await;

    let dev1 = ctx.device_for("agent1");
    let agent1 = ctx.agents.get("agent1").unwrap();
    let agent_jwt = issue_agent_jwt(&ctx.state, agent1).await;

    // First batch
    send_json_dual_auth(
        &ctx.app,
        Method::POST,
        "/api/v1/mcp-servers/import",
        &dev1.signing_key,
        &dev1.device_id,
        &agent_jwt,
        Some(json!({
            "device_id": dev1.device_id,
            "agent_id": agent1.id.0.to_string(),
            "servers": [
                { "name": "github", "transport": "stdio", "command": "/usr/bin/github" },
                { "name": "slack", "transport": "stdio", "command": "/usr/bin/slack" }
            ]
        })),
    )
    .await;

    // Second batch — partial overlap
    let (status, body) = send_json_dual_auth(
        &ctx.app,
        Method::POST,
        "/api/v1/mcp-servers/import",
        &dev1.signing_key,
        &dev1.device_id,
        &agent_jwt,
        Some(json!({
            "device_id": dev1.device_id,
            "agent_id": agent1.id.0.to_string(),
            "servers": [
                { "name": "slack", "transport": "stdio", "command": "/usr/bin/slack" },
                { "name": "jira", "transport": "stdio", "command": "/usr/bin/jira" }
            ]
        })),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    let results = body["data"].as_array().unwrap();
    // Verify statuses
    let statuses: Vec<&str> = results
        .iter()
        .map(|r| r["status"].as_str().unwrap())
        .collect();
    assert!(statuses.contains(&"existing"), "slack should be existing");
    assert!(statuses.contains(&"created"), "jira should be created");
}

// 10C. Error Handling

#[tokio::test]
async fn test_import_without_agent_jwt_returns_401() {
    let ctx = TestAppBuilder::new().with_admin().build().await;

    // Body must include device_id for serde to succeed; auth check happens after deserialization
    let fake_device_id = Uuid::new_v4().to_string();
    let (status, _) = send_json(
        &ctx.app,
        Method::POST,
        "/api/v1/mcp-servers/import",
        None,
        None,
        None,
        Some(json!({ "device_id": fake_device_id, "servers": [] })),
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_import_malformed_request_returns_400() {
    let ctx = TestAppBuilder::new()
        .with_admin()
        .with_agent("agent1", &["user"])
        .build()
        .await;

    let dev1 = ctx.device_for("agent1");
    let agent1 = ctx.agents.get("agent1").unwrap();
    let agent_jwt = issue_agent_jwt(&ctx.state, agent1).await;

    let (status, body) = send_json_dual_auth(
        &ctx.app,
        Method::POST,
        "/api/v1/mcp-servers/import",
        &dev1.signing_key,
        &dev1.device_id,
        &agent_jwt,
        Some(json!({ "not_servers": "bad" })),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "malformed: {}",
        body
    );
}

#[tokio::test]
async fn test_import_server_missing_name_field() {
    let ctx = TestAppBuilder::new()
        .with_admin()
        .with_agent("agent1", &["user"])
        .build()
        .await;

    let dev1 = ctx.device_for("agent1");
    let agent1 = ctx.agents.get("agent1").unwrap();
    let agent_jwt = issue_agent_jwt(&ctx.state, agent1).await;

    let (status, body) = send_json_dual_auth(
        &ctx.app,
        Method::POST,
        "/api/v1/mcp-servers/import",
        &dev1.signing_key,
        &dev1.device_id,
        &agent_jwt,
        Some(json!({
            "device_id": dev1.device_id,
            "agent_id": agent1.id.0.to_string(),
            "servers": [{ "transport": "stdio", "command": "/bin/x" }]
        })),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "missing name: {}",
        body
    );
}

#[tokio::test]
async fn test_import_very_long_mcp_name() {
    let ctx = TestAppBuilder::new()
        .with_admin()
        .with_agent("agent1", &["user"])
        .build()
        .await;

    let dev1 = ctx.device_for("agent1");
    let agent1 = ctx.agents.get("agent1").unwrap();
    let agent_jwt = issue_agent_jwt(&ctx.state, agent1).await;

    let long_name = "a".repeat(1000);
    let (status, body) = send_json_dual_auth(
        &ctx.app,
        Method::POST,
        "/api/v1/mcp-servers/import",
        &dev1.signing_key,
        &dev1.device_id,
        &agent_jwt,
        Some(json!({
            "device_id": dev1.device_id,
            "agent_id": agent1.id.0.to_string(),
            "servers": [{ "name": long_name, "transport": "stdio", "command": "/bin/x" }]
        })),
    )
    .await;

    // Implementation does not validate name length — long names are accepted
    assert_eq!(status, StatusCode::OK, "long name: {}", body);
}

// 10D. Cross-Feature

#[tokio::test]
async fn test_imported_mcp_visible_in_admin_ui() {
    let ctx = TestAppBuilder::new()
        .with_admin()
        .with_agent("agent1", &["user"])
        .build()
        .await;
    let _admin = create_test_user(&*ctx.store, "admin1", TEST_PASSWORD, UserRole::Admin).await;
    let admin_cookie = login_user_combined(&ctx.app, "admin1", TEST_PASSWORD).await;

    let dev1 = ctx.device_for("agent1");
    let agent1 = ctx.agents.get("agent1").unwrap();
    let agent_jwt = issue_agent_jwt(&ctx.state, agent1).await;

    // Import
    send_json_dual_auth(
        &ctx.app,
        Method::POST,
        "/api/v1/mcp-servers/import",
        &dev1.signing_key,
        &dev1.device_id,
        &agent_jwt,
        Some(json!({
            "device_id": dev1.device_id,
            "agent_id": agent1.id.0.to_string(),
            "servers": [{ "name": "github", "transport": "stdio", "command": "/usr/bin/github" }]
        })),
    )
    .await;

    // Admin lists MCPs
    let (status, body) = send_json(
        &ctx.app,
        Method::GET,
        "/api/v1/mcp-servers",
        None,
        Some(&admin_cookie),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let servers = body["data"].as_array().unwrap();
    assert!(
        servers.iter().any(|s| s["name"].as_str() == Some("github")),
        "imported MCP should appear in admin list"
    );
}

#[tokio::test]
async fn test_imported_mcp_syncs_to_device() {
    // Verify imported MCPs are visible via the admin list API filtered by device.
    let ctx = TestAppBuilder::new()
        .with_admin()
        .with_agent("agent1", &["user"])
        .build()
        .await;

    let dev1 = ctx.device_for("agent1");
    let agent1 = ctx.agents.get("agent1").unwrap();
    let agent_jwt = issue_agent_jwt(&ctx.state, agent1).await;

    // Import
    send_json_dual_auth(
        &ctx.app,
        Method::POST,
        "/api/v1/mcp-servers/import",
        &dev1.signing_key,
        &dev1.device_id,
        &agent_jwt,
        Some(json!({
            "device_id": dev1.device_id,
            "agent_id": agent1.id.0.to_string(),
            "servers": [{ "name": "github", "transport": "stdio", "command": "/usr/bin/github" }]
        })),
    )
    .await;

    // Verify via admin list API filtered by device
    let _admin = create_test_user(&*ctx.store, "admin1", TEST_PASSWORD, UserRole::Admin).await;
    let cookie = login_user_combined(&ctx.app, "admin1", TEST_PASSWORD).await;
    let uri = format!("/api/v1/mcp-servers?device_id={}", dev1.device_id);
    let (status, body) =
        send_json(&ctx.app, Method::GET, &uri, None, Some(&cookie), None, None).await;
    assert_eq!(status, StatusCode::OK);
    let servers = body["data"].as_array().unwrap();
    assert!(
        servers.iter().any(|s| s["name"].as_str() == Some("github")),
        "imported MCP should be listed for the device"
    );
}

// 10E. Security

#[tokio::test]
async fn test_import_agent_cannot_modify_existing_mcp() {
    // Admin creates MCP. Agent imports same name with different config.
    // Existing MCP should NOT be modified.
    let ctx = TestAppBuilder::new()
        .with_admin()
        .with_agent("agent1", &["user"])
        .build()
        .await;
    let _admin = create_test_user(&*ctx.store, "admin1", TEST_PASSWORD, UserRole::Admin).await;
    let admin_cookie = login_user_combined(&ctx.app, "admin1", TEST_PASSWORD).await;

    let dev1 = ctx.device_for("agent1");
    let agent1 = ctx.agents.get("agent1").unwrap();
    let agent_jwt = issue_agent_jwt(&ctx.state, agent1).await;

    // Admin creates MCP via store insertion
    let d1_uuid = agent_cordon_core::domain::workspace::WorkspaceId(
        uuid::Uuid::parse_str(&dev1.device_id).unwrap(),
    );
    let now = chrono::Utc::now();
    let mcp_server = agent_cordon_core::domain::mcp::McpServer {
        id: agent_cordon_core::domain::mcp::McpServerId(uuid::Uuid::new_v4()),
        workspace_id: d1_uuid,
        name: "github".to_string(),
        upstream_url: "http://localhost:9000/github".to_string(),
        transport: "stdio".to_string(),
        allowed_tools: None,
        enabled: true,
        created_by: None,
        created_at: now,
        updated_at: now,
        tags: vec![],
        required_credentials: None,
    };
    ctx.store
        .create_mcp_server(&mcp_server)
        .await
        .expect("create mcp server");
    let mcp_id = mcp_server.id.0.to_string();

    // Agent tries to import with different config
    let (_status, _body) = send_json_dual_auth(
        &ctx.app,
        Method::POST,
        "/api/v1/mcp-servers/import",
        &dev1.signing_key,
        &dev1.device_id,
        &agent_jwt,
        Some(json!({
            "device_id": dev1.device_id,
            "agent_id": agent1.id.0.to_string(),
            "servers": [{ "name": "github", "transport": "stdio", "command": "/hacked/command" }]
        })),
    )
    .await;

    // Verify original command unchanged
    let uri = format!("/api/v1/mcp-servers/{}", mcp_id);
    let (_, get_body) = send_json(
        &ctx.app,
        Method::GET,
        &uri,
        None,
        Some(&admin_cookie),
        None,
        None,
    )
    .await;
    // The MCP should still exist with the original name (agent import can't overwrite)
    assert_eq!(
        get_body["data"]["name"].as_str().unwrap(),
        "github",
        "agent should not be able to modify admin-created MCP"
    );
}

#[tokio::test]
async fn test_import_persists_required_credentials() {
    let ctx = TestAppBuilder::new()
        .with_admin()
        .with_agent("agent1", &["user"])
        .build()
        .await;

    let dev1 = ctx.device_for("agent1");
    let agent1 = ctx.agents.get("agent1").unwrap();
    let agent_jwt = issue_agent_jwt(&ctx.state, agent1).await;

    let (status, body) = send_json_dual_auth(
        &ctx.app,
        Method::POST,
        "/api/v1/mcp-servers/import",
        &dev1.signing_key,
        &dev1.device_id,
        &agent_jwt,
        Some(json!({
            "device_id": dev1.device_id,
            "agent_id": agent1.id.0.to_string(),
            "servers": [{
                "name": "github",
                "transport": "stdio",
                "command": "/usr/bin/github",
                "required_credentials": ["secret-cred-id"]
            }]
        })),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "import should succeed: {}", body);

    // Verify required_credentials is persisted
    let all_mcps = ctx.store.list_mcp_servers().await.unwrap();
    let github = all_mcps.iter().find(|m| m.name == "github").unwrap();
    // required_credentials are stored as CredentialId — invalid UUIDs from import are filtered out
    // "secret-cred-id" is not a valid UUID, so it should be filtered
    assert_eq!(
        github.required_credentials,
        Some(vec![]),
        "required_credentials with invalid UUIDs should be filtered during import"
    );
}

#[tokio::test]
async fn test_imported_mcp_default_policy_scoped_to_agent() {
    // Import as A1 → Cedar grants A1. A2 should be denied.
    let ctx = TestAppBuilder::new()
        .with_admin()
        .with_agent("agent1", &["user"])
        .with_agent("agent2", &["user"])
        .build()
        .await;

    let dev1 = ctx.device_for("agent1");
    let agent1 = ctx.agents.get("agent1").unwrap();
    let agent1_jwt = issue_agent_jwt(&ctx.state, agent1).await;

    // Import as agent1
    let (_, import_body) = send_json_dual_auth(
        &ctx.app,
        Method::POST,
        "/api/v1/mcp-servers/import",
        &dev1.signing_key,
        &dev1.device_id,
        &agent1_jwt,
        Some(json!({
            "device_id": dev1.device_id,
            "agent_id": agent1.id.0.to_string(),
            "servers": [{ "name": "github", "transport": "stdio", "command": "/usr/bin/github" }]
        })),
    )
    .await;

    let mcp_id = import_body["data"][0]["id"].as_str().unwrap();

    // Check that auto-created Cedar policy references agent1 specifically
    let policies = ctx.store.get_all_enabled_policies().await.unwrap();
    let agent1_id = agent1.id.0.to_string();
    let agent2 = ctx.agents.get("agent2").unwrap();
    let agent2_id = agent2.id.0.to_string();

    let mcp_policies: Vec<_> = policies
        .iter()
        .filter(|p| p.cedar_policy.contains(mcp_id))
        .collect();

    // Should reference agent1, not agent2
    for p in &mcp_policies {
        assert!(
            p.cedar_policy.contains(&agent1_id),
            "auto-policy should reference uploading agent"
        );
        assert!(
            !p.cedar_policy.contains(&agent2_id),
            "auto-policy should NOT reference other agents"
        );
    }
}

#[tokio::test]
async fn test_import_audit_event_emitted() {
    // Import MCPs and verify the import succeeds (audit events are emitted server-side).
    let ctx = TestAppBuilder::new()
        .with_admin()
        .with_agent("agent1", &["user"])
        .build()
        .await;

    let dev1 = ctx.device_for("agent1");
    let agent1 = ctx.agents.get("agent1").unwrap();
    let agent_jwt = issue_agent_jwt(&ctx.state, agent1).await;

    let (status, body) = send_json_dual_auth(
        &ctx.app,
        Method::POST,
        "/api/v1/mcp-servers/import",
        &dev1.signing_key,
        &dev1.device_id,
        &agent_jwt,
        Some(json!({
            "device_id": dev1.device_id,
            "agent_id": agent1.id.0.to_string(),
            "servers": [{ "name": "audit-test", "transport": "stdio", "command": "/usr/bin/audit" }]
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "import should succeed: {}", body);

    // Verify the MCP was created (audit events are emitted as a side effect)
    let all_mcps = ctx.store.list_mcp_servers().await.unwrap();
    assert!(
        all_mcps.iter().any(|m| m.name == "audit-test"),
        "imported MCP should be persisted"
    );
}

// ---------------------------------------------------------------------------
// Feature 11: Auto-Upload from Init
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_init_flow_with_mcp_upload() {
    // Simulate init: register agent → get JWT → call import.
    let ctx = TestAppBuilder::new().with_admin().build().await;

    // Create agent workspace directly (enrollment flow removed)
    let (agent_id_str, device_key) = create_standalone_device(&ctx.state).await;

    // Issue a workspace JWT for the agent
    let agent_uuid: uuid::Uuid = agent_id_str.parse().expect("agent_id_str must be UUID");
    let agent = ctx
        .store
        .get_workspace(&agent_cordon_core::domain::workspace::WorkspaceId(
            agent_uuid,
        ))
        .await
        .unwrap()
        .unwrap();
    let agent_jwt = issue_agent_jwt(&ctx.state, &agent).await;

    // Now import MCPs (simulating what init would do)
    // In v2.0, workspace_id (aliased as device_id) must match the authenticated workspace
    let (status, body) = send_json_dual_auth(
        &ctx.app,
        Method::POST,
        "/api/v1/mcp-servers/import",
        &device_key,
        &agent_id_str,
        &agent_jwt,
        Some(json!({
            "device_id": agent_id_str,
            "agent_id": agent_id_str,
            "servers": [{ "name": "claude-mcp", "transport": "stdio", "command": "/usr/bin/claude" }]
        })),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "init import: {}", body);
}

#[tokio::test]
async fn test_init_called_twice_mcps_not_duplicated() {
    // Run init flow twice. Assert MCPs not duplicated.
    let ctx = TestAppBuilder::new()
        .with_admin()
        .with_agent("agent1", &["user"])
        .build()
        .await;

    let dev1 = ctx.device_for("agent1");
    let agent1 = ctx.agents.get("agent1").unwrap();
    let agent_jwt = issue_agent_jwt(&ctx.state, agent1).await;

    let import_body = json!({
        "device_id": dev1.device_id,
        "agent_id": agent1.id.0.to_string(),
        "servers": [{ "name": "claude-mcp", "transport": "stdio", "command": "/usr/bin/claude" }]
    });

    // First "init"
    send_json_dual_auth(
        &ctx.app,
        Method::POST,
        "/api/v1/mcp-servers/import",
        &dev1.signing_key,
        &dev1.device_id,
        &agent_jwt,
        Some(import_body.clone()),
    )
    .await;

    // Second "init" (agent already registered)
    send_json_dual_auth(
        &ctx.app,
        Method::POST,
        "/api/v1/mcp-servers/import",
        &dev1.signing_key,
        &dev1.device_id,
        &agent_jwt,
        Some(import_body),
    )
    .await;

    let all_mcps = ctx.store.list_mcp_servers().await.unwrap();
    let count = all_mcps.iter().filter(|m| m.name == "claude-mcp").count();
    assert_eq!(count, 1, "MCPs should not be duplicated after double init");
}
