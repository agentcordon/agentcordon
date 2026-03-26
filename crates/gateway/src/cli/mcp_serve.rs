use std::collections::HashMap;
use std::io::{self, Write as _};

use serde_json::Value;
use tokio::io::BufReader;

use crate::audit::AuditSender;
use crate::identity::WorkspaceIdentity;
use crate::mcp_sync::{
    self, discover_tools, respawn_from_config, sync_mcp_servers_from_cp, McpServerConfig,
};
use crate::stdio::StdioProcessPool;

use super::auth;
use super::state::{self, WorkspaceState};
use super::GlobalFlags;

/// Run the self-contained MCP server: spawns MCP subprocesses locally,
/// reads JSON-RPC from stdin, dispatches to subprocesses, writes to stdout.
///
/// Talks directly to the server (control plane, port 3140) for config and
/// credentials — never to a gateway/device.
pub async fn run(flags: &GlobalFlags) -> Result<(), String> {
    let jwt = auth::ensure_jwt(flags).await?;
    let st = WorkspaceState::load();
    let server_url = st.resolve_server_url(&flags.server);

    // Load workspace identity for ECIES credential decryption.
    let dir = state::workspace_dir();
    let identity = WorkspaceIdentity::load_from_dir(&dir)
        .map_err(|e| format!("failed to load workspace identity: {}", e))?;

    let http_client = reqwest::Client::new();
    let (audit_sender, audit_rx) = AuditSender::new();
    let stdio_pool = StdioProcessPool::new(audit_sender.clone());

    // Forward audit events to the server via REST POST.
    let forwarder_url = server_url.clone();
    let forwarder_jwt = jwt.clone();
    tokio::spawn(async move {
        crate::audit::run_audit_forwarder(audit_rx, forwarder_url, forwarder_jwt).await;
    });

    // Fetch MCP server configs from control plane + local config.
    let configs = load_mcp_configs(&server_url, &jwt, &http_client).await?;

    if configs.is_empty() {
        eprintln!("warning: no MCP servers configured");
    }

    // Spawn STDIO subprocesses for all configured servers.
    let tool_index = spawn_and_index(
        &configs,
        &server_url,
        &jwt,
        &identity,
        &http_client,
        &stdio_pool,
        &audit_sender,
    )
    .await;

    // Build configs map for auto-respawn during dispatch.
    let configs_map: HashMap<String, McpServerConfig> =
        configs.into_iter().map(|c| (c.name.clone(), c)).collect();

    // Main JSON-RPC loop: read from stdin, dispatch, write to stdout.
    run_jsonrpc_loop(
        &stdio_pool,
        &tool_index,
        &configs_map,
        &server_url,
        &jwt,
        &identity,
        &http_client,
        &audit_sender,
    )
    .await
}

/// Load MCP server configs: merge control plane configs with local file configs.
///
/// Server configs provide authoritative metadata (name, required_credentials, transport).
/// Local configs provide local execution details (command, args, env).
/// When both exist for the same server name, fields are merged: server wins for
/// required_credentials/transport, local wins for command/args/env.
async fn load_mcp_configs(
    server_url: &str,
    jwt: &str,
    http: &reqwest::Client,
) -> Result<Vec<McpServerConfig>, String> {
    // Load local configs first into a lookup map.
    let mut local_map: HashMap<String, McpServerConfig> = HashMap::new();
    let local_path = std::path::Path::new(".agentcordon").join("mcp-servers.json");
    if local_path.exists() {
        match mcp_sync::load_local_mcp_configs(&local_path) {
            Ok(local_configs) => {
                for c in local_configs {
                    local_map.insert(c.name.clone(), c);
                }
            }
            Err(e) => {
                eprintln!("warning: failed to load local MCP configs: {}", e);
            }
        }
    }

    let mut configs = Vec::new();
    let mut seen = std::collections::HashSet::new();

    // Fetch from control plane and merge with matching local configs.
    match sync_mcp_servers_from_cp(server_url, jwt, http).await {
        Ok(cp_configs) => {
            for mut cp in cp_configs {
                seen.insert(cp.name.clone());
                if let Some(local) = local_map.remove(&cp.name) {
                    // Merge: local provides command/args/env, server provides
                    // required_credentials and transport.
                    if cp.command.is_none() {
                        cp.command = local.command;
                    }
                    if cp.args.is_none() {
                        cp.args = local.args;
                    }
                    if cp.env.is_none() {
                        cp.env = local.env;
                    }
                }
                configs.push(cp);
            }
        }
        Err(e) => {
            eprintln!("warning: failed to fetch MCP configs from server: {}", e);
        }
    }

    // Add any remaining local-only configs (not on the server).
    for (name, c) in local_map {
        if !seen.contains(&name) {
            configs.push(c);
        }
    }

    Ok(configs)
}

/// Tool entry tracking which subprocess owns it.
struct ToolEntry {
    server_name: String,
    tool: Value,
}

/// Spawn all STDIO subprocesses and build a tool index mapping tool names
/// to their owning server.
async fn spawn_and_index(
    configs: &[McpServerConfig],
    server_url: &str,
    jwt: &str,
    identity: &WorkspaceIdentity,
    http: &reqwest::Client,
    pool: &StdioProcessPool,
    audit: &AuditSender,
) -> Vec<ToolEntry> {
    let mut tool_entries = Vec::new();

    for config in configs {
        if config.transport().to_lowercase() != "stdio" {
            eprintln!(
                "warning: skipping non-STDIO server '{}' (transport: {})",
                config.name,
                config.transport()
            );
            continue;
        }

        if config.command.is_none() {
            eprintln!(
                "warning: skipping server '{}' — no command configured",
                config.name
            );
            continue;
        }

        if let Err(e) = respawn_from_config(
            config,
            server_url,
            jwt,
            &identity.encryption_key,
            http,
            pool,
            audit,
        )
        .await
        {
            eprintln!(
                "warning: failed to spawn MCP server '{}': {}",
                config.name, e
            );
            continue;
        }

        // Discover tools from the running subprocess.
        match discover_tools(pool, &config.name).await {
            Ok(tools) => {
                for t in &tools {
                    let tool_json = serde_json::json!({
                        "name": t.name,
                        "description": t.description,
                        "inputSchema": t.input_schema,
                    });
                    tool_entries.push(ToolEntry {
                        server_name: config.name.clone(),
                        tool: tool_json,
                    });
                }
                eprintln!(
                    "info: server '{}' spawned with {} tools",
                    config.name,
                    tools.len()
                );
            }
            Err(e) => {
                eprintln!(
                    "warning: failed to discover tools from '{}': {}",
                    config.name, e
                );
            }
        }
    }

    tool_entries
}

/// Main JSON-RPC loop: reads from stdin (async), dispatches, writes to stdout.
async fn run_jsonrpc_loop(
    pool: &StdioProcessPool,
    tool_index: &[ToolEntry],
    configs: &HashMap<String, McpServerConfig>,
    server_url: &str,
    jwt: &str,
    identity: &WorkspaceIdentity,
    http: &reqwest::Client,
    audit: &AuditSender,
) -> Result<(), String> {
    let mut stdin = BufReader::new(tokio::io::stdin());

    // Max request size: 10 MB (matches subprocess response limit).
    const MAX_REQUEST_BYTES: usize = 10 * 1024 * 1024;

    loop {
        let line = match read_stdin_line_bounded(&mut stdin, MAX_REQUEST_BYTES).await {
            Ok(line) => line,
            Err(e) if e.contains("EOF") => break,
            Err(e) => return Err(e),
        };
        let trimmed = line.trim().to_string();
        if trimmed.is_empty() {
            continue;
        }

        let request: Value = match serde_json::from_str(&trimmed) {
            Ok(v) => v,
            Err(e) => {
                let resp = make_error_response(&None, -32700, &format!("parse error: {}", e));
                write_response(&resp)?;
                continue;
            }
        };

        let method = request.get("method").and_then(|m| m.as_str()).unwrap_or("");
        let id = request.get("id").cloned();

        let response = match method {
            "initialize" => handle_initialize(&id),
            "notifications/initialized" => continue,
            "tools/list" => handle_tools_list(tool_index, &id),
            "tools/call" => {
                handle_tools_call(
                    pool, tool_index, configs, server_url, jwt, identity, http, audit, &request,
                    &id,
                )
                .await
            }
            _ => make_error_response(&id, -32601, &format!("method not found: {}", method)),
        };

        write_response(&response)?;
    }

    // Shutdown all subprocesses on exit.
    pool.shutdown().await;
    Ok(())
}

/// Write a JSON-RPC response to stdout.
fn write_response(response: &Value) -> Result<(), String> {
    let out =
        serde_json::to_string(response).map_err(|e| format!("JSON serialize error: {}", e))?;
    let mut stdout = io::stdout();
    writeln!(stdout, "{}", out).map_err(|e| format!("stdout write error: {}", e))?;
    stdout
        .flush()
        .map_err(|e| format!("stdout flush error: {}", e))?;
    Ok(())
}

fn handle_initialize(id: &Option<Value>) -> Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": {
            "protocolVersion": "2024-11-05",
            "capabilities": {
                "tools": { "listChanged": false }
            },
            "serverInfo": {
                "name": "agentcordon",
                "version": env!("CARGO_PKG_VERSION")
            }
        }
    })
}

fn handle_tools_list(tool_index: &[ToolEntry], id: &Option<Value>) -> Value {
    let tools: Vec<&Value> = tool_index.iter().map(|e| &e.tool).collect();
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": { "tools": tools }
    })
}

/// Emit an `mcp_tool_call` audit event with standard fields.
fn emit_tool_call_audit(
    audit: &AuditSender,
    server_name: &str,
    tool_name: &str,
    pk_hash: &str,
    allowed: bool,
    outcome: &str,
    error: Option<&str>,
    correlation_id: Option<&str>,
) {
    let mut details = serde_json::json!({
        "mcp_server": server_name,
        "tool_name": tool_name,
        "workspace_pk_hash": pk_hash,
        "allowed": allowed,
        "outcome": outcome,
    });
    if let Some(err) = error {
        details.as_object_mut().unwrap().insert(
            "error".to_string(),
            serde_json::Value::String(err.to_string()),
        );
    }
    if let Some(cid) = correlation_id {
        details.as_object_mut().unwrap().insert(
            "correlation_id".to_string(),
            serde_json::Value::String(cid.to_string()),
        );
    }
    audit.emit("mcp_tool_call", details);
}

/// Ensure the subprocess for `server_name` is running, auto-respawning if needed.
/// Returns `Ok(())` if ready, or an error response `Value` on failure.
async fn ensure_subprocess_running(
    pool: &StdioProcessPool,
    configs: &HashMap<String, McpServerConfig>,
    server_name: &str,
    server_url: &str,
    jwt: &str,
    identity: &WorkspaceIdentity,
    http: &reqwest::Client,
    audit: &AuditSender,
) -> Result<(), String> {
    if pool.has_process(server_name).await {
        return Ok(());
    }
    let config = configs.get(server_name).ok_or_else(|| {
        format!(
            "server '{}' is not running and no config to respawn",
            server_name
        )
    })?;

    eprintln!("info: auto-respawning MCP server '{}'", server_name);
    respawn_from_config(
        config,
        server_url,
        jwt,
        &identity.encryption_key,
        http,
        pool,
        audit,
    )
    .await
    .map_err(|e| format!("failed to respawn '{}': {}", server_name, e))
}

async fn handle_tools_call(
    pool: &StdioProcessPool,
    tool_index: &[ToolEntry],
    configs: &HashMap<String, McpServerConfig>,
    server_url: &str,
    jwt: &str,
    identity: &WorkspaceIdentity,
    http: &reqwest::Client,
    audit: &AuditSender,
    request: &Value,
    id: &Option<Value>,
) -> Value {
    let params = request
        .get("params")
        .cloned()
        .unwrap_or(Value::Object(Default::default()));
    let tool_name = params.get("name").and_then(|n| n.as_str()).unwrap_or("");
    let arguments = params
        .get("arguments")
        .cloned()
        .unwrap_or(Value::Object(Default::default()));

    if tool_name.is_empty() {
        return make_error_response(id, -32602, "missing tool name in params");
    }

    // Find which server owns this tool.
    let server_name = match tool_index.iter().find(|e| {
        e.tool
            .get("name")
            .and_then(|n| n.as_str())
            .map(|n| n == tool_name)
            .unwrap_or(false)
    }) {
        Some(entry) => entry.server_name.clone(),
        None => {
            audit.emit(
                "mcp_tool_denied",
                serde_json::json!({
                    "tool_name": tool_name,
                    "workspace_pk_hash": identity.pk_hash,
                    "reason": "unknown_tool",
                }),
            );
            return make_error_response(id, -32602, &format!("unknown tool: {}", tool_name));
        }
    };

    // Cedar policy check — deny-by-default if server unreachable.
    let (permitted, correlation_id) = crate::mcp_sync::authorize_tool_call(
        server_url, jwt, http, &server_name, tool_name,
    )
    .await;

    if !permitted {
        emit_tool_call_audit(
            audit,
            &server_name,
            tool_name,
            &identity.pk_hash,
            false,
            "cedar_policy_forbid",
            None,
            Some(&correlation_id),
        );
        return make_error_response(
            id,
            -32603,
            &format!("policy forbids tool call: {}/{}", server_name, tool_name),
        );
    }

    // Auto-respawn if the subprocess died.
    if let Err(e) = ensure_subprocess_running(
        pool,
        configs,
        &server_name,
        server_url,
        jwt,
        identity,
        http,
        audit,
    )
    .await
    {
        emit_tool_call_audit(
            audit,
            &server_name,
            tool_name,
            &identity.pk_hash,
            false,
            "server_unavailable",
            Some(&e),
            Some(&correlation_id),
        );
        return make_error_response(id, -32000, &e);
    }

    // Build JSON-RPC request for the subprocess.
    let jsonrpc_request = serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/call",
        "params": { "name": tool_name, "arguments": arguments }
    });

    match pool.send_jsonrpc(&server_name, &jsonrpc_request).await {
        Ok(response) => {
            let is_error = response.get("error").is_some();
            let outcome = if is_error {
                "subprocess_error"
            } else {
                "success"
            };
            emit_tool_call_audit(
                audit,
                &server_name,
                tool_name,
                &identity.pk_hash,
                !is_error,
                outcome,
                None,
                Some(&correlation_id),
            );
            response
        }
        Err(e) => {
            emit_tool_call_audit(
                audit,
                &server_name,
                tool_name,
                &identity.pk_hash,
                false,
                "execution_failed",
                Some(&e.to_string()),
                Some(&correlation_id),
            );
            make_error_response(id, -32000, &format!("subprocess call failed: {}", e))
        }
    }
}

/// Read a single newline-terminated line from stdin with a bounded size limit.
/// Returns an error containing "EOF" when stdin is closed.
async fn read_stdin_line_bounded(
    reader: &mut BufReader<tokio::io::Stdin>,
    max_bytes: usize,
) -> Result<String, String> {
    use tokio::io::AsyncBufReadExt;

    let mut buf = Vec::with_capacity(4096.min(max_bytes));
    loop {
        let available = reader
            .fill_buf()
            .await
            .map_err(|e| format!("stdin read error: {}", e))?;

        if available.is_empty() {
            return Err("EOF".to_string());
        }

        if let Some(pos) = available.iter().position(|&b| b == b'\n') {
            buf.extend_from_slice(&available[..=pos]);
            reader.consume(pos + 1);
            break;
        }

        buf.extend_from_slice(available);
        let len = available.len();
        reader.consume(len);

        if buf.len() > max_bytes {
            return Err(format!("request exceeded {} byte limit", max_bytes));
        }
    }

    String::from_utf8(buf).map_err(|e| format!("invalid UTF-8 on stdin: {}", e))
}

fn make_error_response(id: &Option<Value>, code: i32, message: &str) -> Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": code,
            "message": message
        }
    })
}
