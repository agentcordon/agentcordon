//! An imported MCP server keeps its tools' descriptions and input schemas.
//!
//! `POST /api/v1/mcp-servers/import` is the workspace-driven path behind
//! `agentcordon mcp-servers` and the broker's sync: a workspace uploads the
//! servers it knows about, tool metadata and all. The import handler parsed
//! `description` and `input_schema` and then dropped both on the floor, so an
//! imported server's tools were bare names — `agentcordon mcp-tools` could not
//! say what a tool does or what arguments it takes, while a marketplace
//! provisioned server (which goes through discovery) could.

use axum::http::{Method, StatusCode};
use serde_json::{json, Value};

use agent_cordon_core::domain::user::UserRole;
use agent_cordon_server::test_helpers::{TestAppBuilder, TestContext};

use crate::common::{
    create_test_user, ctx_admin_jwt, login_user_combined, send_json, TEST_PASSWORD,
};

const ECHO_DESCRIPTION: &str = "Echo a message back to the caller";
const WHOAMI_DESCRIPTION: &str = "Report the authenticated identity";

fn echo_schema() -> Value {
    json!({
        "type": "object",
        "properties": { "message": { "type": "string" } },
        "required": ["message"],
    })
}

fn whoami_schema() -> Value {
    json!({ "type": "object", "properties": {} })
}

/// Import one server carrying two fully described tools, as a workspace.
/// Returns `(context, admin cookie, imported server id)`.
async fn import_server_with_tools() -> (TestContext, String, String) {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    create_test_user(&*ctx.store, "mcp-admin", TEST_PASSWORD, UserRole::Admin).await;
    let cookie = login_user_combined(&ctx.app, "mcp-admin", TEST_PASSWORD).await;

    let workspace_id = ctx
        .admin_agent
        .as_ref()
        .expect("admin workspace")
        .id
        .0
        .to_string();
    let jwt = ctx_admin_jwt(&ctx).await;

    let (status, body) = send_json(
        &ctx.app,
        Method::POST,
        "/api/v1/mcp-servers/import",
        Some(&jwt),
        None,
        None,
        Some(json!({
            "workspace_id": workspace_id,
            "servers": [{
                "name": "notes",
                "transport": "http",
                "url": "https://notes.test/mcp",
                "tools": [
                    {
                        "name": "echo",
                        "description": ECHO_DESCRIPTION,
                        "input_schema": echo_schema(),
                    },
                    {
                        "name": "whoami",
                        "description": WHOAMI_DESCRIPTION,
                        "input_schema": whoami_schema(),
                    }
                ]
            }]
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "import: {body}");

    let id = body["data"][0]["id"]
        .as_str()
        .unwrap_or_else(|| panic!("imported server id: {body}"))
        .to_string();
    (ctx, cookie, id)
}

/// `GET /api/v1/mcp-servers/{id}` reports what the import supplied, not a
/// list of names.
#[tokio::test]
async fn imported_server_detail_reports_tool_description_and_schema() {
    let (ctx, cookie, id) = import_server_with_tools().await;

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

    let tools = body["data"]["tools"]
        .as_array()
        .unwrap_or_else(|| panic!("tools array: {body}"));
    assert_eq!(tools.len(), 2, "both imported tools: {body}");

    let echo = tools
        .iter()
        .find(|t| t["name"] == "echo")
        .unwrap_or_else(|| panic!("echo tool: {body}"));
    assert_eq!(
        echo["description"], ECHO_DESCRIPTION,
        "the description the import carried: {echo}"
    );
    assert_eq!(
        echo["input_schema"],
        echo_schema(),
        "the input schema the import carried: {echo}"
    );

    let whoami = tools
        .iter()
        .find(|t| t["name"] == "whoami")
        .unwrap_or_else(|| panic!("whoami tool: {body}"));
    assert_eq!(whoami["description"], WHOAMI_DESCRIPTION, "{whoami}");
    assert_eq!(whoami["input_schema"], whoami_schema(), "{whoami}");
}

/// The broker's server sync still names every imported tool, and its tool
/// sync carries the metadata `agentcordon mcp-tools` prints.
#[tokio::test]
async fn imported_tools_reach_the_broker_sync_with_their_metadata() {
    let (ctx, _cookie, _id) = import_server_with_tools().await;
    let jwt = ctx_admin_jwt(&ctx).await;

    let (status, body) = send_json(
        &ctx.app,
        Method::GET,
        "/api/v1/workspaces/mcp-servers",
        Some(&jwt),
        None,
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let entry = body["data"]["servers"]
        .as_array()
        .unwrap_or_else(|| panic!("servers array: {body}"))
        .iter()
        .find(|s| s["name"] == "notes")
        .unwrap_or_else(|| panic!("imported server in sync: {body}"))
        .clone();
    let names: Vec<&str> = entry["tools"]
        .as_array()
        .unwrap_or_else(|| panic!("tools: {entry}"))
        .iter()
        .filter_map(|t| t.as_str())
        .collect();
    assert!(
        names.contains(&"echo") && names.contains(&"whoami"),
        "both tools in the server sync entry: {entry}"
    );

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
    let entries = body["data"]
        .as_array()
        .unwrap_or_else(|| panic!("tool array: {body}"));
    let echo = entries
        .iter()
        .find(|t| t["tool"] == "echo")
        .unwrap_or_else(|| panic!("echo tool in sync: {body}"));
    assert_eq!(echo["server"], "notes", "{echo}");
    assert_eq!(echo["description"], ECHO_DESCRIPTION, "{echo}");
    assert_eq!(echo["input_schema"], echo_schema(), "{echo}");

    let whoami = entries
        .iter()
        .find(|t| t["tool"] == "whoami")
        .unwrap_or_else(|| panic!("whoami tool in sync: {body}"));
    assert_eq!(whoami["description"], WHOAMI_DESCRIPTION, "{whoami}");
    assert_eq!(whoami["input_schema"], whoami_schema(), "{whoami}");
}

/// The MCP spec spells the field `inputSchema`; a workspace forwarding what
/// its own `tools/list` returned must not have to rewrite it.
#[tokio::test]
async fn import_accepts_the_spec_camel_case_input_schema() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    create_test_user(&*ctx.store, "mcp-admin", TEST_PASSWORD, UserRole::Admin).await;
    let cookie = login_user_combined(&ctx.app, "mcp-admin", TEST_PASSWORD).await;

    let workspace_id = ctx
        .admin_agent
        .as_ref()
        .expect("admin workspace")
        .id
        .0
        .to_string();
    let jwt = ctx_admin_jwt(&ctx).await;

    let (status, body) = send_json(
        &ctx.app,
        Method::POST,
        "/api/v1/mcp-servers/import",
        Some(&jwt),
        None,
        None,
        Some(json!({
            "workspace_id": workspace_id,
            "servers": [{
                "name": "camel",
                "transport": "http",
                "url": "https://camel.test/mcp",
                "tools": [{
                    "name": "echo",
                    "description": ECHO_DESCRIPTION,
                    "inputSchema": echo_schema(),
                }]
            }]
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "import: {body}");
    let id = body["data"][0]["id"]
        .as_str()
        .unwrap_or_else(|| panic!("imported server id: {body}"))
        .to_string();

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
    let echo = &body["data"]["tools"][0];
    assert_eq!(echo["name"], "echo", "{body}");
    assert_eq!(
        echo["input_schema"],
        echo_schema(),
        "inputSchema on the wire is the same schema: {echo}"
    );
}
