use crate::audit::AuditSender;
use crate::identity::WorkspaceIdentity;
use crate::mcp_sync::{self, respawn_from_config, sync_mcp_servers_from_cp, McpServerConfig};
use crate::stdio::StdioProcessPool;

use super::auth;
use super::state::{self, WorkspaceState};
use super::GlobalFlags;

pub async fn run(
    flags: &GlobalFlags,
    server: &str,
    tool: &str,
    args: &[String],
) -> Result<(), String> {
    let jwt = auth::ensure_jwt(flags).await?;
    let st = WorkspaceState::load();
    let server_url = st.resolve_server_url(&flags.server);

    // Load workspace identity for ECIES credential decryption.
    let dir = state::workspace_dir();
    let identity = WorkspaceIdentity::load_from_dir(&dir)
        .map_err(|e| format!("failed to load workspace identity: {}", e))?;

    let http_client = reqwest::Client::new();
    let (audit_sender, audit_rx) = AuditSender::new();

    // Forward audit events to the server via REST POST (same pattern as mcp_serve).
    let forwarder_url = server_url.clone();
    let forwarder_jwt = jwt.clone();
    let forwarder_handle = tokio::spawn(async move {
        crate::audit::run_audit_forwarder(audit_rx, forwarder_url, forwarder_jwt).await;
    });

    // Load and merge MCP configs (server + local), then find the target server.
    let config = load_target_config(server, &server_url, &jwt, &http_client).await?;

    // Parse --arg key=value pairs into a JSON object.
    let mut arguments = serde_json::Map::new();
    for arg in args {
        if let Some((k, v)) = arg.split_once('=') {
            let json_val = serde_json::from_str(v)
                .unwrap_or_else(|_| serde_json::Value::String(v.to_string()));
            arguments.insert(k.to_string(), json_val);
        }
    }

    // Cedar policy check — deny-by-default.
    let (permitted, correlation_id) =
        crate::mcp_sync::authorize_tool_call(&server_url, &jwt, &http_client, server, tool).await;

    if !permitted {
        audit_sender.emit(
            "mcp_tool_call",
            serde_json::json!({
                "mcp_server": server,
                "tool_name": tool,
                "workspace_pk_hash": identity.pk_hash,
                "allowed": false,
                "outcome": "cedar_policy_forbid",
                "correlation_id": correlation_id,
            }),
        );
        drop(audit_sender);
        let _ = forwarder_handle.await;
        return Err(format!("policy forbids tool call: {}/{}", server, tool));
    }

    // Branch on transport type.
    let transport = config.transport().to_lowercase();
    let response = match transport.as_str() {
        "http" | "https" | "streamable-http" | "url" => {
            run_http_transport(
                &config,
                server,
                tool,
                &arguments,
                &server_url,
                &jwt,
                &identity,
                &http_client,
                &audit_sender,
            )
            .await?
        }
        "stdio" => {
            run_stdio_transport(
                &config,
                server,
                tool,
                &arguments,
                &server_url,
                &jwt,
                &identity,
                &http_client,
                &audit_sender,
            )
            .await?
        }
        other => {
            drop(audit_sender);
            let _ = forwarder_handle.await;
            return Err(format!(
                "server '{}' uses unsupported transport '{}' (supported: stdio, http)",
                server, other
            ));
        }
    };

    // Emit mcp_tool_call audit event.
    let (outcome, error_detail) = if response.get("error").is_some() {
        let err_msg = response
            .get("error")
            .and_then(|e| e.get("message"))
            .and_then(|m| m.as_str())
            .unwrap_or("unknown error");
        ("error", Some(err_msg.to_string()))
    } else {
        ("success", None)
    };
    let mut details = serde_json::json!({
        "mcp_server": server,
        "tool_name": tool,
        "workspace_pk_hash": identity.pk_hash,
        "allowed": true,
        "outcome": outcome,
        "correlation_id": correlation_id,
        "transport": transport,
    });
    if let Some(err) = &error_detail {
        details
            .as_object_mut()
            .unwrap()
            .insert("error".to_string(), serde_json::Value::String(err.clone()));
    }
    audit_sender.emit("mcp_tool_call", details);

    // Release all AuditSender clones so the forwarder channel closes.
    drop(audit_sender);
    let _ = forwarder_handle.await;

    // Output the result.
    if flags.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&response).expect("JSON serialization cannot fail")
        );
        return Ok(());
    }

    if let Some(result) = response.get("result") {
        println!(
            "{}",
            serde_json::to_string_pretty(result).expect("JSON serialization cannot fail")
        );
    } else if let Some(error) = response.get("error") {
        let code = error
            .get("code")
            .and_then(|c| c.as_i64())
            .map(|c| c.to_string())
            .unwrap_or_else(|| "?".to_string());
        let msg = error
            .get("message")
            .and_then(|m| m.as_str())
            .unwrap_or("unknown error");
        return Err(format!("MCP error (code {}): {}", code, msg));
    } else {
        println!(
            "{}",
            serde_json::to_string_pretty(&response).expect("JSON serialization cannot fail")
        );
    }

    Ok(())
}

/// Execute a tool call via STDIO transport (spawn subprocess).
async fn run_stdio_transport(
    config: &McpServerConfig,
    server: &str,
    tool: &str,
    arguments: &serde_json::Map<String, serde_json::Value>,
    server_url: &str,
    jwt: &str,
    identity: &WorkspaceIdentity,
    http_client: &reqwest::Client,
    audit_sender: &AuditSender,
) -> Result<serde_json::Value, String> {
    if config.command.is_none() {
        return Err(format!(
            "server '{}' has no command configured — add it to .agentcordon/mcp-servers.json",
            server
        ));
    }

    let stdio_pool = StdioProcessPool::new(audit_sender.clone());

    respawn_from_config(
        config,
        server_url,
        jwt,
        &identity.encryption_key,
        http_client,
        &stdio_pool,
        audit_sender,
    )
    .await
    .map_err(|e| format!("failed to spawn MCP server '{}': {}", server, e))?;

    let jsonrpc_request = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": tool,
            "arguments": arguments,
        }
    });

    let response = stdio_pool
        .send_jsonrpc(&config.name, &jsonrpc_request)
        .await
        .map_err(|e| format!("MCP call failed: {}", e))?;

    stdio_pool.shutdown().await;

    Ok(response)
}

/// Execute a tool call via HTTP transport (Streamable HTTP / SSE).
async fn run_http_transport(
    config: &McpServerConfig,
    server: &str,
    tool: &str,
    arguments: &serde_json::Map<String, serde_json::Value>,
    server_url: &str,
    jwt: &str,
    identity: &WorkspaceIdentity,
    http_client: &reqwest::Client,
    audit_sender: &AuditSender,
) -> Result<serde_json::Value, String> {
    use crate::http_mcp::HttpMcpClientPool;
    use std::collections::HashMap;

    let url = config.url.as_deref().ok_or_else(|| {
        format!(
            "server '{}' uses HTTP transport but has no URL configured",
            server
        )
    })?;

    // Resolve credentials for header injection.
    let mut headers: HashMap<String, String> = config.headers.clone().unwrap_or_default();

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

            // Apply credential transform to get headers.
            let material = crate::cp_client::CredentialMaterial {
                credential_type: Some("bearer".to_string()),
                value: secret,
                username: None,
                metadata: HashMap::new(),
            };
            let transformed =
                crate::credential_transform::apply(&material, None, "POST", url, &headers, None)
                    .map_err(|e| format!("credential transform failed: {}", e))?;

            for (k, v) in transformed.headers {
                headers.insert(k, v);
            }
        }
    }

    let http_pool = HttpMcpClientPool::new(audit_sender.clone());

    http_pool
        .connect(server, url, headers)
        .await
        .map_err(|e| format!("failed to connect to HTTP MCP server '{}': {}", server, e))?;

    let jsonrpc_request = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": tool,
            "arguments": arguments,
        }
    });

    let response = http_pool
        .send_jsonrpc(server, &jsonrpc_request)
        .await
        .map_err(|e| format!("MCP call failed: {}", e))?;

    http_pool.shutdown().await;

    Ok(response)
}

/// Load the MCP server config for a specific server by name.
///
/// Merges configs from the control plane and local file. If the CP config
/// has no command but the local config does, the local command/args are used.
async fn load_target_config(
    target_name: &str,
    server_url: &str,
    jwt: &str,
    http: &reqwest::Client,
) -> Result<McpServerConfig, String> {
    let mut cp_config: Option<McpServerConfig> = None;
    let mut local_config: Option<McpServerConfig> = None;

    // Fetch from control plane.
    match sync_mcp_servers_from_cp(server_url, jwt, http).await {
        Ok(configs) => {
            cp_config = configs.into_iter().find(|c| c.name == target_name);
        }
        Err(e) => {
            eprintln!("warning: failed to fetch MCP configs from server: {}", e);
        }
    }

    // Load local configs.
    let local_path = std::path::Path::new(".agentcordon").join("mcp-servers.json");
    if local_path.exists() {
        match mcp_sync::load_local_mcp_configs(&local_path) {
            Ok(configs) => {
                local_config = configs.into_iter().find(|c| c.name == target_name);
            }
            Err(e) => {
                eprintln!("warning: failed to load local MCP configs: {}", e);
            }
        }
    }

    match (cp_config, local_config) {
        // Both exist: merge — CP provides metadata, local provides command.
        (Some(mut cp), Some(local)) => {
            if cp.command.is_none() && local.command.is_some() {
                cp.command = local.command;
                cp.args = local.args;
            }
            if cp.env.is_none() && local.env.is_some() {
                cp.env = local.env;
            }
            // Prefer local required_credentials (name-based) over CP (UUID-based)
            // so that cred: placeholder resolution in respawn_from_config() matches.
            if local.required_credentials.is_some() {
                cp.required_credentials = local.required_credentials;
            }
            // Merge URL from local if CP doesn't have one
            if cp.url.is_none() && local.url.is_some() {
                cp.url = local.url;
            }
            // Merge headers from local if CP doesn't have any
            if cp.headers.is_none() && local.headers.is_some() {
                cp.headers = local.headers;
            }
            Ok(cp)
        }
        // Only CP config.
        (Some(cp), None) => Ok(cp),
        // Only local config.
        (None, Some(local)) => Ok(local),
        // Not found anywhere.
        (None, None) => Err(format!(
            "MCP server '{}' not found in server or local config",
            target_name
        )),
    }
}
