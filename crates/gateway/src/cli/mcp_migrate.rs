use std::collections::HashMap;
use std::path::Path;

use super::client::ApiClient;
use super::cred_classify::{format_credential_name, is_credential_env_var, is_credential_header};
use super::state::WorkspaceState;
use super::GlobalFlags;
use crate::mcp_sync::discover_tools_for_servers;

/// Result of migrating MCP credentials from `.mcp.json`.
pub struct MigrationReport {
    /// Names of MCP servers whose credentials were migrated.
    pub migrated_servers: Vec<String>,
    /// Names of servers that were skipped (already migrated or agentcordon).
    pub skipped_servers: Vec<String>,
    /// Errors encountered (non-fatal).
    pub warnings: Vec<String>,
}

/// Migrate MCP credentials from `.mcp.json` into AgentCordon.
///
/// Reads `.mcp.json`, detects credential env vars and headers, stores them
/// via the server, and writes templated configs to `.agentcordon/mcp-servers.json`.
pub async fn migrate_mcp_credentials(
    _flags: &GlobalFlags,
    server_url: &str,
    token: &str,
) -> Result<MigrationReport, String> {
    let mcp_json_path = Path::new(".mcp.json");
    if !mcp_json_path.exists() {
        return Ok(MigrationReport {
            migrated_servers: vec![],
            skipped_servers: vec![],
            warnings: vec!["No .mcp.json found".to_string()],
        });
    }

    // Parse .mcp.json (Claude Code format)
    let contents = std::fs::read_to_string(mcp_json_path)
        .map_err(|e| format!("failed to read .mcp.json: {}", e))?;
    let parsed: serde_json::Value =
        serde_json::from_str(&contents).map_err(|e| format!("failed to parse .mcp.json: {}", e))?;

    let mcp_servers = match parsed.get("mcpServers").and_then(|m| m.as_object()) {
        Some(servers) => servers,
        None => {
            return Ok(MigrationReport {
                migrated_servers: vec![],
                skipped_servers: vec![],
                warnings: vec!["No mcpServers found in .mcp.json".to_string()],
            });
        }
    };

    // Load existing local config to skip already-migrated servers
    let existing_names = load_existing_server_names();

    let client = ApiClient::new(server_url);
    let st = WorkspaceState::load();
    let workspace_id = st.agent_id.clone().unwrap_or_default();

    let mut report = MigrationReport {
        migrated_servers: vec![],
        skipped_servers: vec![],
        warnings: vec![],
    };

    // Collect new local config entries to merge
    let mut new_configs: Vec<serde_json::Value> = Vec::new();
    // Track required_credentials per server for import
    let mut server_cred_map: HashMap<String, Vec<String>> = HashMap::new();

    for (server_name, config) in mcp_servers {
        // Skip agentcordon itself
        if server_name == "agentcordon" {
            report.skipped_servers.push(server_name.clone());
            continue;
        }

        // Skip already-migrated servers
        if existing_names.contains(server_name) {
            report.skipped_servers.push(server_name.clone());
            continue;
        }

        let mut required_credentials: Vec<String> = Vec::new();

        let templated_env = migrate_env_credentials(
            config,
            server_name,
            &client,
            token,
            &mut report,
            &mut required_credentials,
        )
        .await;

        let templated_headers = migrate_header_credentials(
            config,
            server_name,
            &client,
            token,
            &mut report,
            &mut required_credentials,
        )
        .await;

        // Determine transport type from original config
        let transport = config
            .get("type")
            .and_then(|t| t.as_str())
            .unwrap_or("stdio");

        // Build local config entry (McpServerConfig format)
        let local_config = serde_json::json!({
            "name": server_name,
            "transport": transport,
            "command": config.get("command").and_then(|c| c.as_str()).unwrap_or_default(),
            "args": config.get("args").cloned().unwrap_or(serde_json::json!([])),
            "env": templated_env,
            "headers": templated_headers,
            "url": config.get("url").and_then(|u| u.as_str()).unwrap_or_default(),
            "required_credentials": required_credentials,
        });

        new_configs.push(local_config);
        if !required_credentials.is_empty() {
            server_cred_map.insert(server_name.clone(), required_credentials);
        }
        report.migrated_servers.push(server_name.clone());
    }

    if new_configs.is_empty() {
        return Ok(report);
    }

    // Merge into .agentcordon/mcp-servers.json
    merge_local_configs(&new_configs)?;

    // Upload MCP server metadata to server (with required_credentials)
    if !workspace_id.is_empty() {
        upload_server_metadata(
            &client,
            token,
            &workspace_id,
            mcp_servers,
            &report.migrated_servers,
            &server_cred_map,
        )
        .await;
    }

    Ok(report)
}

/// Process env vars from an MCP server config, storing credentials and returning templated env.
async fn migrate_env_credentials(
    config: &serde_json::Value,
    server_name: &str,
    client: &ApiClient,
    token: &str,
    report: &mut MigrationReport,
    required_credentials: &mut Vec<String>,
) -> HashMap<String, String> {
    let env_map = config
        .get("env")
        .and_then(|e| e.as_object())
        .cloned()
        .unwrap_or_default();

    let mut templated_env: HashMap<String, String> = HashMap::new();

    for (env_name, env_value) in &env_map {
        let value_str = env_value.as_str().unwrap_or_default();

        if is_credential_env_var(env_name, value_str) {
            let cred_name = format_credential_name(server_name, env_name);
            store_credential(
                client,
                token,
                &cred_name,
                server_name,
                env_name,
                value_str,
                report,
                false,
            )
            .await;
            templated_env.insert(env_name.clone(), format!("cred:{}", cred_name));
            required_credentials.push(cred_name);
        } else {
            templated_env.insert(env_name.clone(), value_str.to_string());
        }
    }

    templated_env
}

/// Process headers from an MCP server config, storing credentials and returning templated headers.
async fn migrate_header_credentials(
    config: &serde_json::Value,
    server_name: &str,
    client: &ApiClient,
    token: &str,
    report: &mut MigrationReport,
    required_credentials: &mut Vec<String>,
) -> HashMap<String, String> {
    let headers_map = config
        .get("headers")
        .and_then(|h| h.as_object())
        .cloned()
        .unwrap_or_default();

    let mut templated_headers: HashMap<String, String> = HashMap::new();

    for (header_name, header_value) in &headers_map {
        let value_str = header_value.as_str().unwrap_or_default();

        if is_credential_header(header_name, value_str) {
            let cred_name = format_credential_name(server_name, header_name);
            store_credential(
                client,
                token,
                &cred_name,
                server_name,
                header_name,
                value_str,
                report,
                true,
            )
            .await;
            templated_headers.insert(header_name.clone(), format!("cred:{}", cred_name));
            required_credentials.push(cred_name);
        } else {
            templated_headers.insert(header_name.clone(), value_str.to_string());
        }
    }

    templated_headers
}

/// Store a single credential via the server API.
async fn store_credential(
    client: &ApiClient,
    token: &str,
    cred_name: &str,
    server_name: &str,
    field_name: &str,
    value: &str,
    report: &mut MigrationReport,
    is_header: bool,
) {
    let body = serde_json::json!({
        "name": cred_name,
        "service": server_name,
        "secret_value": value,
        "credential_type": "generic",
        "scopes": [],
    });

    let source = if is_header {
        format!("{}.headers.{}", server_name, field_name)
    } else {
        format!("{}.{}", server_name, field_name)
    };

    match client
        .post_auth_raw("/api/v1/credentials/agent-store", token, &body)
        .await
    {
        Ok((status, _resp)) => {
            if status == 200 || status == 201 {
                eprintln!("  Stored credential: {} (from {})", cred_name, source);
            } else if status == 409 {
                eprintln!("  Credential already exists: {} (skipping)", cred_name);
            } else {
                let kind = if is_header {
                    "header credential"
                } else {
                    "credential"
                };
                report.warnings.push(format!(
                    "Failed to store {} {} (HTTP {})",
                    kind, cred_name, status
                ));
            }
        }
        Err(e) => {
            let kind = if is_header {
                "header credential"
            } else {
                "credential"
            };
            report
                .warnings
                .push(format!("Failed to store {} {}: {}", kind, cred_name, e));
        }
    }
}

/// Load existing server names from `.agentcordon/mcp-servers.json`.
fn load_existing_server_names() -> Vec<String> {
    let path = Path::new(".agentcordon/mcp-servers.json");
    if !path.exists() {
        return vec![];
    }
    let contents = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return vec![],
    };
    let configs: Vec<serde_json::Value> = match serde_json::from_str(&contents) {
        Ok(c) => c,
        Err(_) => return vec![],
    };
    configs
        .iter()
        .filter_map(|c| c.get("name").and_then(|n| n.as_str()).map(String::from))
        .collect()
}

/// Merge new config entries into `.agentcordon/mcp-servers.json` (append, don't overwrite).
fn merge_local_configs(new_configs: &[serde_json::Value]) -> Result<(), String> {
    let path = Path::new(".agentcordon/mcp-servers.json");

    // Ensure directory exists
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("failed to create .agentcordon/: {}", e))?;
    }

    let mut existing: Vec<serde_json::Value> = if path.exists() {
        let contents = std::fs::read_to_string(path)
            .map_err(|e| format!("failed to read mcp-servers.json: {}", e))?;
        serde_json::from_str(&contents).unwrap_or_default()
    } else {
        vec![]
    };

    // Append only configs whose name is not already present
    let existing_names: Vec<String> = existing
        .iter()
        .filter_map(|c| c.get("name").and_then(|n| n.as_str()).map(String::from))
        .collect();

    for config in new_configs {
        if let Some(name) = config.get("name").and_then(|n| n.as_str()) {
            if !existing_names.contains(&name.to_string()) {
                existing.push(config.clone());
            }
        }
    }

    let output = serde_json::to_string_pretty(&existing)
        .map_err(|e| format!("failed to serialize mcp-servers.json: {}", e))?;
    std::fs::write(path, output).map_err(|e| format!("failed to write mcp-servers.json: {}", e))?;

    Ok(())
}

/// Upload MCP server metadata to the server's import endpoint.
///
/// Discovers tools from each STDIO server (best-effort) and includes them
/// in the import payload so the server knows each server's tool inventory.
async fn upload_server_metadata(
    client: &ApiClient,
    token: &str,
    workspace_id: &str,
    mcp_servers: &serde_json::Map<String, serde_json::Value>,
    migrated_names: &[String],
    cred_map: &HashMap<String, Vec<String>>,
) {
    let ws_uuid = match uuid::Uuid::parse_str(workspace_id) {
        Ok(u) => u,
        Err(_) => return,
    };

    let mut servers: Vec<serde_json::Value> = migrated_names
        .iter()
        .filter_map(|name| {
            let config = mcp_servers.get(name)?;
            let transport = config
                .get("type")
                .and_then(|t| t.as_str())
                .unwrap_or("stdio");
            let mut entry = serde_json::json!({
                "name": name,
                "transport": transport,
                "command": config.get("command").cloned().unwrap_or(serde_json::Value::Null),
                "args": config.get("args").cloned().unwrap_or(serde_json::json!([])),
                "env": config.get("env").cloned().unwrap_or(serde_json::json!({})),
                "url": config.get("url").cloned().unwrap_or(serde_json::Value::Null),
                "headers": config.get("headers").cloned().unwrap_or(serde_json::json!({})),
            });
            if let Some(creds) = cred_map.get(name) {
                entry["required_credentials"] = serde_json::json!(creds);
            }
            Some(entry)
        })
        .collect();

    if servers.is_empty() {
        return;
    }

    // Best-effort tool discovery: spawn each STDIO server briefly to learn its tools.
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
                if let Some(obj) = server.as_object_mut() {
                    obj.insert("tools".to_string(), serde_json::json!(tools_json));
                }
            }
        }
    }

    let body = serde_json::json!({
        "workspace_id": ws_uuid,
        "uploading_workspace_id": ws_uuid,
        "servers": servers,
    });

    match client
        .post_auth_raw("/api/v1/mcp-servers/import", token, &body)
        .await
    {
        Ok((status, _)) => {
            if status == 200 {
                eprintln!("  Uploaded {} MCP server(s) to server", servers.len());
            } else {
                eprintln!("  Warning: MCP server import returned HTTP {}", status);
            }
        }
        Err(e) => {
            eprintln!("  Warning: MCP server import failed: {}", e);
        }
    }
}
