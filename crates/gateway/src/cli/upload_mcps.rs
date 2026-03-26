use super::auth;
use super::client::ApiClient;
use super::output;
use super::state::WorkspaceState;
use super::GlobalFlags;
use crate::mcp_sync::discover_tools_for_servers;

pub async fn run(flags: &GlobalFlags, file: Option<&str>) -> Result<(), String> {
    let token = auth::ensure_jwt(flags).await?;
    let st = WorkspaceState::load();
    let server_url = st.resolve_server_url(&flags.server);

    // Discover config file
    let (config_path, _format) = find_config_file(file)?;

    // Parse the config file
    let contents = std::fs::read_to_string(&config_path)
        .map_err(|e| format!("failed to read {}: {}", config_path, e))?;
    let parsed: serde_json::Value = serde_json::from_str(&contents)
        .map_err(|e| format!("failed to parse {}: {}", config_path, e))?;

    // Convert to upload format
    let mut servers = convert_to_upload_format(&parsed);

    if servers.is_empty() {
        output::print_result(
            flags.json,
            &format!("No MCP servers found in {}", config_path),
            &serde_json::json!({
                "status": "skipped",
                "reason": "no servers in config",
                "file": config_path,
            }),
        );
        return Ok(());
    }

    // Discover tools from each STDIO server by spawning it briefly.
    // This is best-effort: if discovery fails, we still upload without tools.
    let discovered = discover_tools_for_servers(&servers).await;
    for server in &mut servers {
        if let Some(name) = server.get("name").and_then(|n| n.as_str()) {
            if let Some(tools) = discovered.get(name) {
                let tools_json: Vec<serde_json::Value> = tools
                    .iter()
                    .map(|t| {
                        serde_json::json!({
                            "name": t.name,
                            "description": t.description,
                        })
                    })
                    .collect();
                server
                    .as_object_mut()
                    .map(|obj| obj.insert("tools".to_string(), serde_json::json!(tools_json)));
            }
        }
    }

    let server_count = servers.len();
    let upload_body = serde_json::json!({"servers": servers});

    let client = ApiClient::new(&server_url);
    let (status, resp_body) = client
        .post_auth_raw("/api/v1/mcp-servers/import", &token, &upload_body)
        .await
        .map_err(|e| format!("upload failed: {}", e))?;

    if status == 200 {
        if flags.json {
            println!("{}", resp_body);
        } else {
            println!(
                "Uploaded {} MCP server(s) from {}",
                server_count, config_path
            );
            if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&resp_body) {
                if let Some(arr) = parsed.get("data").and_then(|d| d.as_array()) {
                    for item in arr {
                        let name = item.get("name").and_then(|n| n.as_str()).unwrap_or("?");
                        let s = item.get("status").and_then(|s| s.as_str()).unwrap_or("?");
                        println!("  {}: {}", name, s);
                    }
                }
            }
        }
        Ok(())
    } else {
        if flags.json {
            println!(
                "{}",
                serde_json::json!({
                    "status": "error",
                    "http_code": status,
                    "body": resp_body,
                })
            );
        }
        Err(format!("upload-mcps failed (HTTP {})", status))
    }
}

/// Find the MCP config file to use.
/// Returns (path, format) where format is "claude", "cursor", or "auto".
fn find_config_file(explicit: Option<&str>) -> Result<(String, &'static str), String> {
    if let Some(path) = explicit {
        if !std::path::Path::new(path).exists() {
            return Err(format!("File not found: {}", path));
        }
        return Ok((path.to_string(), "auto"));
    }

    if std::path::Path::new(".mcp.json").exists() {
        return Ok((".mcp.json".to_string(), "claude"));
    }
    if std::path::Path::new(".cursor/mcp.json").exists() {
        return Ok((".cursor/mcp.json".to_string(), "cursor"));
    }

    Err(
        "No MCP config files found. Checked:\n  .mcp.json\n  .cursor/mcp.json\n\nUse --file to specify a config file explicitly."
            .to_string(),
    )
}

/// Convert various MCP config formats to the upload format.
fn convert_to_upload_format(parsed: &serde_json::Value) -> Vec<serde_json::Value> {
    // Claude Code format: { "mcpServers": { "name": { "command", "args", "env" } } }
    if let Some(mcp_servers) = parsed.get("mcpServers").and_then(|m| m.as_object()) {
        return mcp_servers
            .iter()
            .map(|(name, config)| {
                serde_json::json!({
                    "name": name,
                    "transport": "stdio",
                    "command": config.get("command").cloned().unwrap_or(serde_json::Value::Null),
                    "args": config.get("args").cloned().unwrap_or(serde_json::json!([])),
                    "env": config.get("env").cloned().unwrap_or(serde_json::json!({})),
                })
            })
            .collect();
    }

    // Bare array format
    if let Some(arr) = parsed.as_array() {
        return arr.clone();
    }

    // { "servers": [...] } format
    if let Some(arr) = parsed.get("servers").and_then(|s| s.as_array()) {
        return arr.clone();
    }

    vec![]
}
