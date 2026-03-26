use crate::audit::AuditSender;
use crate::identity::WorkspaceIdentity;
use crate::mcp_sync::{self, respawn_from_config, sync_mcp_servers_from_cp};
use crate::stdio::StdioProcessPool;

use super::auth;
use super::client::ApiClient;
use super::mcp_servers;
use super::state::{self, WorkspaceState};
use super::GlobalFlags;

pub async fn run(flags: &GlobalFlags, server_filter: Option<&str>) -> Result<(), String> {
    let token = auth::ensure_jwt(flags).await?;
    let st = WorkspaceState::load();
    let server_url = st.resolve_server_url(&flags.server);

    let client = ApiClient::new(&server_url);

    // Get MCP server list from the control plane
    let servers_resp: serde_json::Value = client
        .get_auth("/api/v1/mcp-servers", &token)
        .await
        .map_err(|e| format!("failed to list MCP servers: {}", e))?;

    let servers = mcp_servers::extract_servers(&servers_resp);
    if servers.is_empty() {
        eprintln!("No MCP servers registered.");
        eprintln!("Hint: run 'agentcordon init' to migrate credentials from .mcp.json");
        return Ok(());
    }

    // Collect server names
    let server_names: Vec<String> = servers
        .iter()
        .filter_map(|s| s.get("name").and_then(|n| n.as_str()).map(String::from))
        .collect();

    // Filter if requested
    if let Some(filter) = server_filter {
        if !server_names.iter().any(|n| n == filter) {
            return Err(format!(
                "MCP server '{}' not found. Available: {}",
                filter,
                server_names.join(", ")
            ));
        }
    }

    let names_to_query: Vec<&str> = if let Some(filter) = server_filter {
        vec![filter]
    } else {
        server_names.iter().map(|s| s.as_str()).collect()
    };

    // First pass: extract from allowed_tools metadata (fast, no subprocess needed)
    let mut all_tools: Vec<serde_json::Value> = Vec::new();
    let mut servers_with_tools: Vec<String> = Vec::new();
    for srv in &servers {
        let srv_name = srv.get("name").and_then(|n| n.as_str()).unwrap_or("");
        if !names_to_query.contains(&srv_name) {
            continue;
        }
        if let Some(tools) = srv.get("allowed_tools").and_then(|t| t.as_array()) {
            if !tools.is_empty() {
                servers_with_tools.push(srv_name.to_string());
                for tool in tools {
                    if let Some(tool_name) = tool.as_str() {
                        all_tools.push(serde_json::json!({
                            "name": tool_name,
                            "description": "",
                            "server": srv_name,
                        }));
                    }
                }
            }
        }
    }

    // Second pass: discover tools live for servers that didn't have cached tools.
    let names_needing_discovery: Vec<&str> = names_to_query
        .iter()
        .filter(|n| !servers_with_tools.contains(&n.to_string()))
        .copied()
        .collect();

    if !names_needing_discovery.is_empty() {
        match discover_tools_live(&server_url, &token, &names_needing_discovery).await {
            Ok(tools) => all_tools.extend(tools),
            Err(e) => {
                eprintln!("Note: live tool discovery failed: {}", e);
            }
        }
    }

    // Report discovered tools back to the server so they appear in the web UI.
    if !all_tools.is_empty() {
        let http_client = reqwest::Client::new();
        // Group tools by server name and report each group.
        let mut by_server: std::collections::HashMap<String, Vec<serde_json::Value>> =
            std::collections::HashMap::new();
        for tool in &all_tools {
            let srv = tool
                .get("server")
                .and_then(|s| s.as_str())
                .unwrap_or("")
                .to_string();
            if !srv.is_empty() {
                by_server.entry(srv).or_default().push(tool.clone());
            }
        }
        for (srv_name, tools) in &by_server {
            mcp_sync::report_discovered_tools(
                &server_url,
                &token,
                &http_client,
                srv_name,
                tools,
            )
            .await;
        }
    }

    if flags.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&all_tools).expect("JSON serialization cannot fail")
        );
        return Ok(());
    }

    if all_tools.is_empty() {
        println!("MCP servers registered: {}", server_names.join(", "));
        eprintln!("No tools discovered. STDIO servers require local config to discover tools.");
        eprintln!("Hint: use 'agentcordon mcp-call <server> <tool>' to call a tool directly,");
        eprintln!("      or check .agentcordon/mcp-servers.json has command/args configured.");
        return Ok(());
    }

    println!("Discovered MCP tools:");
    for tool in &all_tools {
        let name = tool.get("name").and_then(|n| n.as_str()).unwrap_or("?");
        let server = tool.get("server").and_then(|s| s.as_str()).unwrap_or("?");
        let desc = tool
            .get("description")
            .and_then(|d| d.as_str())
            .unwrap_or("");
        if desc.is_empty() {
            println!("  {} ({})", name, server);
        } else {
            println!("  {} ({}) — {}", name, server, desc);
        }
    }

    Ok(())
}

/// Discover tools from MCP servers — supports both STDIO and HTTP transports.
async fn discover_tools_live(
    server_url: &str,
    jwt: &str,
    target_names: &[&str],
) -> Result<Vec<serde_json::Value>, String> {
    let dir = state::workspace_dir();
    let identity = WorkspaceIdentity::load_from_dir(&dir)
        .map_err(|e| format!("workspace identity not found: {}", e))?;

    let http_client = reqwest::Client::new();
    let (audit_sender, _audit_rx) = AuditSender::new();
    let stdio_pool = StdioProcessPool::new(audit_sender.clone());

    // Merge server configs from control plane + local
    let mut cp_configs = match sync_mcp_servers_from_cp(server_url, jwt, &http_client).await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("warning: failed to fetch MCP configs from server: {}", e);
            vec![]
        }
    };

    let local_path = std::path::Path::new(".agentcordon").join("mcp-servers.json");
    let local_configs = if local_path.exists() {
        mcp_sync::load_local_mcp_configs(&local_path).unwrap_or_default()
    } else {
        vec![]
    };

    // Merge: local command/args/url into CP configs
    for cp in &mut cp_configs {
        if let Some(local) = local_configs.iter().find(|l| l.name == cp.name) {
            if cp.command.is_none() && local.command.is_some() {
                cp.command = local.command.clone();
                cp.args = local.args.clone();
            }
            if cp.env.is_none() && local.env.is_some() {
                cp.env = local.env.clone();
            }
            if cp.url.is_none() && local.url.is_some() {
                cp.url = local.url.clone();
            }
            if cp.headers.is_none() && local.headers.is_some() {
                cp.headers = local.headers.clone();
            }
            if local.required_credentials.is_some() {
                cp.required_credentials = local.required_credentials.clone();
            }
        }
    }

    // Add local-only configs
    for local in &local_configs {
        if !cp_configs.iter().any(|c| c.name == local.name) {
            cp_configs.push(local.clone());
        }
    }

    let mut all_tools = Vec::new();

    for config in &cp_configs {
        if !target_names.contains(&config.name.as_str()) {
            continue;
        }

        let transport = config.transport().to_lowercase();
        match transport.as_str() {
            "http" | "https" | "streamable-http" | "url" => {
                match discover_tools_via_http(
                    config,
                    server_url,
                    jwt,
                    &identity,
                    &http_client,
                    &audit_sender,
                )
                .await
                {
                    Ok(tools) => all_tools.extend(tools),
                    Err(e) => {
                        eprintln!("  {} — HTTP tool discovery failed: {}", config.name, e);
                    }
                }
            }
            "stdio" => {
                if config.command.is_none() {
                    eprintln!("  {} — skipped (no command configured)", config.name);
                    continue;
                }

                match respawn_from_config(
                    config,
                    server_url,
                    jwt,
                    &identity.encryption_key,
                    &http_client,
                    &stdio_pool,
                    &audit_sender,
                )
                .await
                {
                    Ok(()) => {}
                    Err(e) => {
                        eprintln!("  {} — spawn failed: {}", config.name, e);
                        continue;
                    }
                }

                let tools_list_req = serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/list",
                    "params": {}
                });

                match stdio_pool.send_jsonrpc(&config.name, &tools_list_req).await {
                    Ok(response) => {
                        extract_tools_from_response(&response, &config.name, &mut all_tools);
                    }
                    Err(e) => {
                        eprintln!("  {} — tools/list failed: {}", config.name, e);
                    }
                }
            }
            other => {
                eprintln!(
                    "  {} — skipped (unsupported transport '{}')",
                    config.name, other
                );
            }
        }
    }

    stdio_pool.shutdown().await;

    Ok(all_tools)
}

/// Discover tools from an HTTP MCP server.
async fn discover_tools_via_http(
    config: &mcp_sync::McpServerConfig,
    server_url: &str,
    jwt: &str,
    identity: &WorkspaceIdentity,
    http_client: &reqwest::Client,
    audit_sender: &AuditSender,
) -> Result<Vec<serde_json::Value>, String> {
    use crate::http_mcp::HttpMcpClientPool;
    use std::collections::HashMap;

    let url = config.url.as_deref().ok_or_else(|| {
        format!(
            "server '{}' uses HTTP transport but has no URL configured",
            config.name
        )
    })?;

    let mut headers: HashMap<String, String> = config.headers.clone().unwrap_or_default();

    // Resolve credentials for header injection.
    if let Some(ref cred_names) = config.required_credentials {
        for cred_name in cred_names {
            let secret = mcp_sync::vend_and_decrypt_credential(
                server_url,
                cred_name,
                jwt,
                &identity.encryption_key,
                http_client,
            )
            .await
            .map_err(|e| format!("failed to resolve credential '{}': {}", cred_name, e))?;

            let material = crate::cp_client::CredentialMaterial {
                credential_type: Some("bearer".to_string()),
                value: secret,
                username: None,
                metadata: HashMap::new(),
            };
            let transformed = crate::credential_transform::apply(
                &material,
                None,
                "POST",
                url,
                &headers,
                None,
            )
            .map_err(|e| format!("credential transform failed: {}", e))?;

            for (k, v) in transformed.headers {
                headers.insert(k, v);
            }
        }
    }

    let http_pool = HttpMcpClientPool::new(audit_sender.clone());

    http_pool
        .connect(&config.name, url, headers)
        .await
        .map_err(|e| format!("failed to connect: {}", e))?;

    let tools_list_req = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/list",
        "params": {}
    });

    let response = http_pool
        .send_jsonrpc(&config.name, &tools_list_req)
        .await
        .map_err(|e| format!("tools/list failed: {}", e))?;

    http_pool.shutdown().await;

    let mut tools = Vec::new();
    extract_tools_from_response(&response, &config.name, &mut tools);
    Ok(tools)
}

/// Extract tool entries from a JSON-RPC tools/list response.
fn extract_tools_from_response(
    response: &serde_json::Value,
    server_name: &str,
    out: &mut Vec<serde_json::Value>,
) {
    if let Some(tools) = response
        .get("result")
        .and_then(|r| r.get("tools"))
        .and_then(|t| t.as_array())
    {
        for tool in tools {
            let name = tool.get("name").and_then(|n| n.as_str()).unwrap_or("?");
            let desc = tool
                .get("description")
                .and_then(|d| d.as_str())
                .unwrap_or("");
            out.push(serde_json::json!({
                "name": name,
                "description": desc,
                "server": server_name,
            }));
        }
    }
}
