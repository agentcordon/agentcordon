use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::broker::BrokerClient;
use crate::error::CliError;

// --- MCP Servers ---

#[derive(Deserialize)]
struct McpServersResponse {
    data: Vec<McpServer>,
}

#[derive(Deserialize)]
struct McpServer {
    name: String,
    description: Option<String>,
    tools: Vec<String>,
    transport: String,
}

/// List available MCP servers, deduplicated by name.
///
/// Multiple workspaces may import the same server, so the server-side catalog
/// can contain duplicates. We deduplicate by keeping the first occurrence of
/// each server name.
pub async fn list_servers() -> Result<(), CliError> {
    let client = BrokerClient::connect().await?;
    let resp: McpServersResponse = client
        .post("/mcp/list-servers", &serde_json::json!({}))
        .await?;

    if resp.data.is_empty() {
        println!("No MCP servers available.");
        return Ok(());
    }

    // Deduplicate by server name (keep first occurrence)
    let mut seen = HashSet::new();
    let deduped: Vec<&McpServer> = resp.data.iter().filter(|s| seen.insert(&s.name)).collect();

    let name_w = deduped
        .iter()
        .map(|s| s.name.len())
        .max()
        .unwrap_or(4)
        .max(4);
    let desc_w = deduped
        .iter()
        .map(|s| s.description.as_deref().unwrap_or("-").len())
        .max()
        .unwrap_or(11)
        .max(11);

    println!(
        "{:<name_w$}  {:<desc_w$}  TRANSPORT  TOOLS",
        "NAME", "DESCRIPTION"
    );

    for server in &deduped {
        let desc = server.description.as_deref().unwrap_or("-");
        let tools = server.tools.join(", ");
        println!(
            "{:<name_w$}  {:<desc_w$}  {:<9}  {tools}",
            server.name, desc, server.transport
        );
    }

    Ok(())
}

// --- MCP Tools ---

#[derive(Deserialize)]
struct McpToolsResponse {
    data: Vec<McpTool>,
}

#[derive(Deserialize)]
struct McpTool {
    server: String,
    tool: String,
    description: Option<String>,
}

/// List all available MCP tools.
pub async fn list_tools() -> Result<(), CliError> {
    let client = BrokerClient::connect().await?;
    let resp: McpToolsResponse = client
        .post("/mcp/list-tools", &serde_json::json!({}))
        .await?;

    if resp.data.is_empty() {
        println!("No MCP tools available.");
        return Ok(());
    }

    let server_w = resp
        .data
        .iter()
        .map(|t| t.server.len())
        .max()
        .unwrap_or(6)
        .max(6);
    let tool_w = resp
        .data
        .iter()
        .map(|t| t.tool.len())
        .max()
        .unwrap_or(4)
        .max(4);

    println!("{:<server_w$}  {:<tool_w$}  DESCRIPTION", "SERVER", "TOOL");

    for tool in &resp.data {
        let desc = tool.description.as_deref().unwrap_or("-");
        println!("{:<server_w$}  {:<tool_w$}  {desc}", tool.server, tool.tool);
    }

    Ok(())
}

// --- MCP Call ---

#[derive(Serialize)]
struct McpCallRequest {
    server: String,
    tool: String,
    arguments: HashMap<String, String>,
}

#[derive(Deserialize)]
struct McpCallResponse {
    data: McpCallResult,
}

#[derive(Deserialize)]
struct McpCallResult {
    content: Vec<McpContent>,
    #[serde(rename = "isError", default)]
    is_error: bool,
}

#[derive(Deserialize)]
struct McpContent {
    text: Option<String>,
}

/// Call an MCP tool.
pub async fn call(server: String, tool: String, args: Vec<String>) -> Result<(), CliError> {
    let client = BrokerClient::connect().await?;

    // Parse --arg KEY=VALUE pairs
    let mut arguments = HashMap::new();
    for arg in &args {
        let (key, value) = arg.split_once('=').ok_or_else(|| {
            CliError::general(format!(
                "invalid argument format: {arg} (expected KEY=VALUE)"
            ))
        })?;
        arguments.insert(key.to_string(), value.to_string());
    }

    let req = McpCallRequest {
        server,
        tool,
        arguments,
    };

    let resp: McpCallResponse = client.post("/mcp/call", &req).await?;

    if resp.data.is_error {
        eprintln!("MCP tool returned an error:");
    }

    for content in &resp.data.content {
        if let Some(text) = &content.text {
            println!("{text}");
        }
    }

    if resp.data.is_error {
        return Err(CliError::upstream_error("MCP tool returned an error"));
    }

    Ok(())
}
