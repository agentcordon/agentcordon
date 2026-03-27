use std::collections::HashMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::audit::AuditSender;
use crate::cp_client::{decrypt_vend_envelope, CpClient, CpVendEnvelope};
use crate::stdio::StdioProcessPool;

// ---------------------------------------------------------------------------
// MCP tool-call authorization via Cedar policy evaluation
// ---------------------------------------------------------------------------

/// Response from the server's mcp-authorize endpoint.
#[derive(Debug, Deserialize)]
struct McpAuthorizeData {
    decision: String,
    correlation_id: String,
}

/// Call the server's Cedar policy evaluation for an MCP tool call.
///
/// Returns `(is_permitted, correlation_id)` on success.
/// On any error (network, 5xx, parse failure): returns `(false, "error")` — fail-closed.
pub async fn authorize_tool_call(
    cp_url: &str,
    workspace_jwt: &str,
    http_client: &reqwest::Client,
    server_name: &str,
    tool_name: &str,
) -> (bool, String) {
    let cp = CpClient::new(http_client, cp_url, workspace_jwt);
    let body = serde_json::json!({
        "server_name": server_name,
        "tool_name": tool_name,
    });

    match cp
        .post::<McpAuthorizeData, _>("/api/v1/workspaces/mcp-authorize", &body)
        .await
    {
        Ok(data) => {
            let is_permit = data.decision == "permit";
            (is_permit, data.correlation_id)
        }
        Err(e) => {
            tracing::warn!(
                server_name = server_name,
                tool_name = tool_name,
                error = %e,
                "mcp-authorize request failed — denying by default (fail-closed)"
            );
            (false, uuid::Uuid::new_v4().to_string())
        }
    }
}

/// Configuration for a single MCP server loaded from the local config file.
#[derive(Debug, Clone, Deserialize)]
pub struct McpServerConfig {
    pub name: String,
    pub transport: Option<String>,
    pub command: Option<String>,
    pub args: Option<Vec<String>>,
    pub env: Option<HashMap<String, String>>,
    pub required_credentials: Option<Vec<String>>,
    pub url: Option<String>,
    pub headers: Option<HashMap<String, String>>,
}

impl McpServerConfig {
    /// Returns the transport type, defaulting to "stdio".
    pub fn transport(&self) -> &str {
        self.transport.as_deref().unwrap_or("stdio")
    }
}

/// A discovered MCP tool to report back to the server.
#[derive(Debug, Clone, Serialize)]
pub struct DiscoveredTool {
    pub name: String,
    pub description: Option<String>,
    pub input_schema: Option<serde_json::Value>,
}

/// Errors from MCP operations.
#[derive(Debug, thiserror::Error)]
pub enum McpSyncError {
    #[error("request failed: {0}")]
    RequestFailed(String),
    #[error("invalid response: {0}")]
    InvalidResponse(String),
    #[error("missing command for STDIO server")]
    MissingCommand,
    #[error("credential vend failed: {0}")]
    CredentialVendFailed(String),
    #[error("decryption failed: {0}")]
    DecryptionFailed(String),
    #[error("subprocess spawn failed: {0}")]
    SpawnFailed(String),
    #[error("config file error: {0}")]
    ConfigFileError(String),
}

// ---------------------------------------------------------------------------
// Response types
// ---------------------------------------------------------------------------

/// CP response from credential vend-device endpoint.
#[derive(Debug, Deserialize)]
struct CpVendDeviceResponse {
    encrypted_envelope: CpVendEnvelope,
    #[allow(dead_code)]
    vend_id: String,
}

// ---------------------------------------------------------------------------
// Policy sync types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct CpPolicyEntry {
    id: String,
    #[allow(dead_code)]
    name: String,
    cedar_policy: String,
}

#[derive(Debug, Deserialize)]
struct CpPoliciesData {
    policies: Vec<CpPolicyEntry>,
}

// ---------------------------------------------------------------------------
// Local MCP config loading
// ---------------------------------------------------------------------------

/// Load MCP server configurations from a local JSON file.
pub fn load_local_mcp_configs(path: &Path) -> Result<Vec<McpServerConfig>, McpSyncError> {
    let content = std::fs::read_to_string(path).map_err(|e| {
        McpSyncError::ConfigFileError(format!("failed to read {}: {}", path.display(), e))
    })?;
    let configs: Vec<McpServerConfig> = serde_json::from_str(&content).map_err(|e| {
        McpSyncError::ConfigFileError(format!("invalid JSON in {}: {}", path.display(), e))
    })?;
    Ok(configs)
}

// ---------------------------------------------------------------------------
// Import registration request
// ---------------------------------------------------------------------------

/// Entry for each MCP server in the import request (name + transport + tools only).
#[derive(Debug, Serialize)]
struct ImportServerEntry {
    name: String,
    transport: String,
    tools: Vec<DiscoveredTool>,
}

/// Import request body for POST /api/v1/mcp-servers/import.
#[derive(Debug, Serialize)]
struct ImportRequest {
    servers: Vec<ImportServerEntry>,
}

/// Register locally-configured MCP servers with the control plane via import.
pub async fn register_mcp_servers_with_server(
    cp_url: &str,
    workspace_jwt: &str,
    http_client: &reqwest::Client,
    configs: &[McpServerConfig],
    discovered_tools: &HashMap<String, Vec<DiscoveredTool>>,
) -> Result<(), McpSyncError> {
    let cp = CpClient::new(http_client, cp_url, workspace_jwt);

    let servers: Vec<ImportServerEntry> = configs
        .iter()
        .map(|c| ImportServerEntry {
            name: c.name.clone(),
            transport: c.transport().to_string(),
            tools: discovered_tools.get(&c.name).cloned().unwrap_or_default(),
        })
        .collect();

    let body = ImportRequest { servers };

    let resp = cp
        .raw_post("/api/v1/mcp-servers/import", &body)
        .await
        .map_err(|e| McpSyncError::RequestFailed(format!("import failed: {}", e)))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        tracing::warn!(
            status = %status,
            "failed to register MCP servers with control plane: {}",
            text
        );
    } else {
        tracing::info!(
            count = configs.len(),
            "registered MCP servers with control plane via import"
        );
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// MCP server sync response types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct CpMcpServerEntry {
    #[allow(dead_code)]
    id: String,
    name: String,
    transport: String,
    #[allow(dead_code)]
    tools: Vec<String>,
    #[allow(dead_code)]
    enabled: bool,
    required_credentials: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct CpMcpServersData {
    servers: Vec<CpMcpServerEntry>,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Fetch MCP server configs from the control plane.
///
/// Returns configs suitable for inserting into the gateway's `mcp_configs` cache.
pub async fn sync_mcp_servers_from_cp(
    cp_url: &str,
    workspace_jwt: &str,
    http_client: &reqwest::Client,
) -> Result<Vec<McpServerConfig>, McpSyncError> {
    let cp = CpClient::new(http_client, cp_url, workspace_jwt);

    let data: CpMcpServersData = cp
        .get("/api/v1/workspaces/mcp-servers")
        .await
        .map_err(|e| McpSyncError::RequestFailed(e.to_string()))?;

    let configs: Vec<McpServerConfig> = data
        .servers
        .into_iter()
        .map(|s| McpServerConfig {
            name: s.name,
            transport: Some(s.transport),
            command: None,
            args: None,
            env: None,
            required_credentials: s.required_credentials,
            url: None,
            headers: None,
        })
        .collect();

    Ok(configs)
}

/// Sync Cedar policies from the control plane.
///
/// Returns a list of `(id, cedar_source)` pairs suitable for `PolicyEngine::reload_policies`.
pub async fn sync_policies(
    cp_url: &str,
    workspace_jwt: &str,
    http_client: &reqwest::Client,
) -> Result<Vec<(String, String)>, McpSyncError> {
    let cp = CpClient::new(http_client, cp_url, workspace_jwt);

    let data: CpPoliciesData = cp
        .get("/api/v1/workspaces/policies")
        .await
        .map_err(|e| McpSyncError::RequestFailed(e.to_string()))?;

    let policies: Vec<(String, String)> = data
        .policies
        .into_iter()
        .map(|p| (p.id, p.cedar_policy))
        .collect();

    Ok(policies)
}

/// Attempt to respawn an MCP subprocess from cached config.
pub async fn respawn_from_config(
    config: &McpServerConfig,
    cp_url: &str,
    workspace_jwt: &str,
    encryption_key: &p256::SecretKey,
    http_client: &reqwest::Client,
    stdio_pool: &StdioProcessPool,
    audit: &AuditSender,
) -> Result<(), McpSyncError> {
    if config.transport().to_lowercase() != "stdio" {
        return Err(McpSyncError::SpawnFailed(format!(
            "only STDIO transport supports respawn (got '{}')",
            config.transport()
        )));
    }

    let command = config
        .command
        .as_ref()
        .ok_or(McpSyncError::MissingCommand)?;

    let mut env_vars = config.env.clone().unwrap_or_default();
    if let Some(ref creds) = config.required_credentials {
        for cred_name in creds {
            let value = vend_and_decrypt_credential(
                cp_url,
                cred_name,
                workspace_jwt,
                encryption_key,
                http_client,
            )
            .await?;
            let placeholder = format!("cred:{}", cred_name);
            for (_, v) in env_vars.iter_mut() {
                if *v == placeholder {
                    *v = value.clone();
                }
            }
        }
    }

    let args = config.args.clone().unwrap_or_default();
    let pid = stdio_pool
        .spawn(&config.name, command, &args, env_vars)
        .await
        .map_err(|e| McpSyncError::SpawnFailed(e.to_string()))?;

    // Brief delay to let the subprocess start and be ready for I/O.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Send MCP initialize handshake.
    let init_request = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 0,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": {
                "name": "agentcordon",
                "version": env!("CARGO_PKG_VERSION")
            }
        }
    });

    match stdio_pool.send_jsonrpc(&config.name, &init_request).await {
        Ok(_) => {
            tracing::debug!(server = config.name, "MCP initialize handshake completed");
        }
        Err(e) => {
            tracing::warn!(
                server = config.name,
                error = %e,
                "MCP initialize handshake failed (subprocess may still work)"
            );
        }
    }

    audit.emit(
        "subprocess_respawned",
        serde_json::json!({
            "server_name": config.name,
            "command": command,
            "pid": pid,
        }),
    );

    Ok(())
}

/// Discover tools from a running STDIO MCP server via JSON-RPC `tools/list`.
pub async fn discover_tools(
    stdio_pool: &StdioProcessPool,
    server_name: &str,
) -> Result<Vec<DiscoveredTool>, McpSyncError> {
    let request = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/list",
        "params": {}
    });

    let response = stdio_pool
        .send_jsonrpc(server_name, &request)
        .await
        .map_err(|e| {
            McpSyncError::RequestFailed(format!("tools/list failed for '{}': {}", server_name, e))
        })?;

    let tools = response
        .get("result")
        .and_then(|r| r.get("tools"))
        .and_then(|t| t.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|t| {
                    let name = t.get("name")?.as_str()?.to_string();
                    let description = t
                        .get("description")
                        .and_then(|d| d.as_str())
                        .map(|s| s.to_string());
                    let input_schema = t.get("inputSchema").cloned();
                    Some(DiscoveredTool {
                        name,
                        description,
                        input_schema,
                    })
                })
                .collect()
        })
        .unwrap_or_default();

    Ok(tools)
}

// ---------------------------------------------------------------------------
// Tool discovery for server configs
// ---------------------------------------------------------------------------

/// Spawn each STDIO MCP server briefly to discover its tools via `tools/list`.
///
/// Returns a map of server name -> discovered tools. Servers that fail to spawn
/// or respond are silently skipped (best-effort discovery).
pub async fn discover_tools_for_servers(
    servers: &[serde_json::Value],
) -> HashMap<String, Vec<DiscoveredTool>> {
    let mut results = HashMap::new();
    let (audit_sender, _audit_rx) = AuditSender::new();
    let pool = StdioProcessPool::new(audit_sender);

    for server in servers {
        let name = match server.get("name").and_then(|n| n.as_str()) {
            Some(n) => n,
            None => continue,
        };
        let transport = server
            .get("transport")
            .and_then(|t| t.as_str())
            .unwrap_or("stdio");
        if transport != "stdio" {
            continue;
        }
        let command = match server.get("command").and_then(|c| c.as_str()) {
            Some(c) => c.to_string(),
            None => continue,
        };
        let args: Vec<String> = server
            .get("args")
            .and_then(|a| a.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();
        let env_vars: HashMap<String, String> = server
            .get("env")
            .and_then(|e| e.as_object())
            .map(|obj| {
                obj.iter()
                    .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                    .collect()
            })
            .unwrap_or_default();

        match discover_single_server(&pool, name, &command, &args, env_vars).await {
            Ok(tools) => {
                eprintln!("info: discovered {} tool(s) from '{}'", tools.len(), name);
                results.insert(name.to_string(), tools);
            }
            Err(e) => {
                eprintln!("warning: tool discovery failed for '{}': {}", name, e);
            }
        }
    }

    pool.shutdown().await;
    results
}

/// Spawn a single MCP server, run initialize + tools/list, return discovered tools.
async fn discover_single_server(
    pool: &StdioProcessPool,
    name: &str,
    command: &str,
    args: &[String],
    env_vars: HashMap<String, String>,
) -> Result<Vec<DiscoveredTool>, String> {
    pool.spawn(name, command, args, env_vars)
        .await
        .map_err(|e| format!("spawn failed: {}", e))?;

    // Brief delay to let the subprocess start.
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // Send MCP initialize handshake.
    let init_request = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 0,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": {
                "name": "agentcordon",
                "version": env!("CARGO_PKG_VERSION")
            }
        }
    });

    pool.send_jsonrpc(name, &init_request)
        .await
        .map_err(|e| format!("initialize failed: {}", e))?;

    // Discover tools.
    let tools = discover_tools(pool, name)
        .await
        .map_err(|e| format!("tools/list failed: {}", e))?;

    // Clean up: remove the process (it will be killed on drop).
    pool.remove(name).await;

    Ok(tools)
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Vend a credential from the control plane and decrypt the ECIES envelope.
pub async fn vend_and_decrypt_credential(
    cp_url: &str,
    cred_name: &str,
    workspace_jwt: &str,
    encryption_key: &p256::SecretKey,
    http_client: &reqwest::Client,
) -> Result<String, McpSyncError> {
    let cp = CpClient::new(http_client, cp_url, workspace_jwt);

    let path = format!("/api/v1/credentials/vend-device/{}", cred_name);
    let vend_data: CpVendDeviceResponse = cp
        .post_empty(&path)
        .await
        .map_err(|e| McpSyncError::CredentialVendFailed(e.to_string()))?;

    let material = decrypt_vend_envelope(&vend_data.encrypted_envelope, encryption_key)
        .await
        .map_err(|e| McpSyncError::DecryptionFailed(e.to_string()))?;

    Ok(material.value)
}

/// Report discovered tools for an MCP server back to the control plane.
///
/// Calls `POST /api/v1/workspaces/mcp-report-tools` so the server stores
/// the tool list and the web UI can display it.
pub async fn report_discovered_tools(
    cp_url: &str,
    workspace_jwt: &str,
    http_client: &reqwest::Client,
    server_name: &str,
    tools: &[serde_json::Value],
) {
    let url = format!("{}/api/v1/workspaces/mcp-report-tools", cp_url);

    let tool_entries: Vec<serde_json::Value> = tools
        .iter()
        .map(|t| {
            serde_json::json!({
                "name": t.get("name").and_then(|n| n.as_str()).unwrap_or(""),
                "description": t.get("description").and_then(|d| d.as_str()),
            })
        })
        .collect();

    let body = serde_json::json!({
        "server_name": server_name,
        "tools": tool_entries,
    });

    match http_client
        .post(&url)
        .bearer_auth(workspace_jwt)
        .json(&body)
        .send()
        .await
    {
        Ok(resp) => {
            if resp.status().is_success() {
                eprintln!(
                    "  Reported {} tool(s) for '{}' to server",
                    tool_entries.len(),
                    server_name
                );
            } else {
                eprintln!(
                    "  Warning: report-tools for '{}' returned HTTP {}",
                    server_name,
                    resp.status()
                );
            }
        }
        Err(e) => {
            eprintln!(
                "  Warning: failed to report tools for '{}': {}",
                server_name, e
            );
        }
    }
}
