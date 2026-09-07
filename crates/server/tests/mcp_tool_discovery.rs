//! Discovered MCP tools keep their description and input schema.
//!
//! `tools/list` answers in the MCP spec's camelCase (`inputSchema`); the
//! domain type read snake_case only, so every discovered schema was dropped
//! on the floor. The MCP detail endpoint then rebuilt its tool list from
//! `allowed_tools` — bare names — and hardcoded `description: None`, so
//! neither an admin nor an agent could learn what a tool does or what
//! arguments it takes.

use axum::http::{Method, StatusCode};
use serde_json::{json, Value};
use wiremock::matchers::{body_string_contains, method};
use wiremock::{Mock, MockServer, ResponseTemplate};

use agent_cordon_core::domain::mcp::McpTool;
use agent_cordon_core::domain::user::UserRole;
use agent_cordon_server::templates::McpServerTemplate;
use agent_cordon_server::test_helpers::{TestAppBuilder, TestContext};

use crate::common::{
    create_test_user, ctx_admin_jwt, login_user_combined, send_json, send_json_auto_csrf,
    TEST_PASSWORD,
};

const ECHO_DESCRIPTION: &str = "Echo a message back to the caller";

fn echo_schema() -> Value {
    json!({
        "type": "object",
        "properties": { "message": { "type": "string" } },
        "required": ["message"],
    })
}

/// The `tools/list` result an MCP server actually sends, camelCase and all.
fn tools_list_result() -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": 2,
        "result": {
            "tools": [
                {
                    "name": "echo",
                    "description": ECHO_DESCRIPTION,
                    "inputSchema": echo_schema(),
                },
                {
                    "name": "whoami",
                    "description": "Report the authenticated identity",
                    "inputSchema": { "type": "object", "properties": {} },
                }
            ]
        }
    })
}

fn template_for(upstream_url: &str) -> McpServerTemplate {
    McpServerTemplate {
        key: "discovery-mcp".to_string(),
        name: "Discovery MCP".to_string(),
        description: "Synthetic MCP template for tool-discovery tests.".to_string(),
        upstream_url: upstream_url.to_string(),
        transport: "http".to_string(),
        auth_method: "none".to_string(),
        credential_template_key: None,
        api_key_header: None,
        api_key_query: None,
        category: "testing".to_string(),
        tags: vec!["test".to_string()],
        icon: "beaker".to_string(),
        sort_order: 9999,
        oauth2_authorize_url: None,
        oauth2_token_url: None,
        oauth2_scopes: None,
        oauth2_app_credential_template_key: None,
        oauth2_resource_url: None,
        oauth2_prefer_dcr: None,
    }
}

/// Stand up an MCP server that speaks the full `initialize` →
/// `notifications/initialized` → `tools/list` handshake.
async fn mock_mcp_server() -> MockServer {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(body_string_contains("\"method\":\"initialize\""))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "protocolVersion": "2025-06-18",
                "capabilities": { "tools": {} },
                "serverInfo": { "name": "mock-mcp", "version": "1.0" },
            }
        })))
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(body_string_contains("notifications/initialized"))
        .respond_with(ResponseTemplate::new(202))
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(body_string_contains("\"method\":\"tools/list\""))
        .respond_with(ResponseTemplate::new(200).set_body_json(tools_list_result()))
        .mount(&server)
        .await;

    server
}

/// Provision the template and return `(context, admin cookie, server id)`.
async fn provision(upstream_url: &str) -> (TestContext, String, String) {
    let ctx = TestAppBuilder::new()
        .with_admin()
        .with_mcp_template(template_for(upstream_url))
        .with_config(|c| c.proxy_allow_loopback = true)
        .build()
        .await;
    create_test_user(&*ctx.store, "mcp-admin", TEST_PASSWORD, UserRole::Admin).await;
    let cookie = login_user_combined(&ctx.app, "mcp-admin", TEST_PASSWORD).await;
    let ws_id = ctx
        .admin_agent
        .as_ref()
        .expect("admin workspace")
        .id
        .0
        .to_string();

    let (status, body) = send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        "/api/v1/mcp-servers/provision",
        None,
        Some(&cookie),
        Some(json!({ "template_key": "discovery-mcp", "workspace_id": ws_id })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "provision: {body}");
    let id = body["data"]["id"].as_str().expect("server id").to_string();
    (ctx, cookie, id)
}

/// `inputSchema` on the wire becomes `input_schema` in the domain type.
/// AgentCordon's own wire format keeps the snake_case name; the alias is
/// only for reading an MCP server's answer.
#[test]
fn mcp_tool_reads_the_spec_camel_case_input_schema() {
    let tools: Vec<McpTool> =
        serde_json::from_value(tools_list_result()["result"]["tools"].clone())
            .expect("tools/list deserialises");

    let echo = &tools[0];
    assert_eq!(echo.name, "echo");
    assert_eq!(echo.description.as_deref(), Some(ECHO_DESCRIPTION));
    assert_eq!(
        echo.input_schema.as_ref(),
        Some(&echo_schema()),
        "the MCP spec sends inputSchema; it must not be dropped"
    );

    // The AgentCordon-side name still round-trips and is still what we emit.
    let emitted = serde_json::to_value(echo).expect("serialise");
    assert_eq!(emitted["input_schema"], echo_schema());
    assert!(emitted.get("inputSchema").is_none());
    let round_tripped: McpTool = serde_json::from_value(emitted).expect("round trip");
    assert_eq!(round_tripped.input_schema, Some(echo_schema()));
}

/// `GET /api/v1/mcp-servers/{id}` reports what discovery found, not a list
/// of names rebuilt from `allowed_tools`.
#[tokio::test]
async fn mcp_server_detail_reports_discovered_tool_metadata() {
    let upstream = mock_mcp_server().await;
    let (ctx, cookie, id) = provision(&upstream.uri()).await;

    let (status, body) = send_json(
        &ctx.app,
        Method::GET,
        &format!("/api/v1/mcp-servers/{id}"),
        None,
        Some(&cookie),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let tools = body["data"]["tools"].as_array().expect("tools array");
    assert_eq!(tools.len(), 2, "both discovered tools: {body}");
    let echo = tools
        .iter()
        .find(|t| t["name"] == "echo")
        .unwrap_or_else(|| panic!("echo tool: {body}"));
    assert_eq!(
        echo["description"], ECHO_DESCRIPTION,
        "the description discovery found: {echo}"
    );
    assert_eq!(
        echo["input_schema"],
        echo_schema(),
        "the input schema discovery found: {echo}"
    );
}

/// The broker's tool sync carries the same metadata, so `agentcordon
/// mcp-tools` can show an agent what a tool does and what it takes.
#[tokio::test]
async fn workspace_tool_sync_carries_description_and_input_schema() {
    let upstream = mock_mcp_server().await;
    let (ctx, _cookie, _id) = provision(&upstream.uri()).await;

    let jwt = ctx_admin_jwt(&ctx).await;
    let (status, body) = send_json(
        &ctx.app,
        Method::GET,
        "/api/v1/workspaces/mcp-tools",
        Some(&jwt),
        None,
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let entries = body["data"].as_array().expect("tool array");
    let echo = entries
        .iter()
        .find(|t| t["tool"] == "echo")
        .unwrap_or_else(|| panic!("echo tool in sync: {body}"));
    assert_eq!(echo["server"], "discovery-mcp", "{echo}");
    assert_eq!(echo["description"], ECHO_DESCRIPTION, "{echo}");
    assert_eq!(echo["input_schema"], echo_schema(), "{echo}");
}

/// Tool discovery is an outbound call like any other, so the MCP server it
/// probes is told which AgentCordon is probing it. The discovery client used
/// to send no user agent at all.
#[tokio::test]
async fn tool_discovery_identifies_the_running_server_version() {
    let upstream = mock_mcp_server().await;
    let (_ctx, _cookie, _id) = provision(&upstream.uri()).await;

    let probe = &upstream.received_requests().await.expect("requests")[0];
    let user_agent = probe
        .headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .expect("the discovery probe carries a user agent");
    assert_eq!(
        user_agent,
        format!("AgentCordon/{} (mcp-discovery)", env!("CARGO_PKG_VERSION")),
        "an MCP server must see the version this server actually is"
    );
}
