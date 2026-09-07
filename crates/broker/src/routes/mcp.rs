use std::borrow::Cow;
use std::collections::HashMap;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use serde::{Deserialize, Serialize};

use agent_cordon_core::proxy::leak_scanner::{self, LeakScanner};
use agent_cordon_core::proxy::url_safety::validate_proxy_target_resolved;

use crate::auth::AuthenticatedWorkspace;
use crate::credential_transform::{self, CredentialMaterial};
use agent_cordon_core::wire::mcp::{McpServerSyncEntry, McpToolSyncEntry};

use crate::server_client::ServerClient;
use crate::state::{CachedCredential, SharedState};

use super::helpers::{error_response, ok_response, with_token_refresh};

type ErrorResponse = (StatusCode, axum::Json<serde_json::Value>);

/// What an agent is told about one MCP server.
///
/// A projection of the server's [`McpServerSyncEntry`], not a passthrough:
/// the sync entry also carries the ids of the credentials the server needs,
/// which is control-plane bookkeeping an agent has no use for. Built
/// field-by-field, so a rename on the sync endpoint is a compile error.
///
#[derive(Serialize)]
struct McpServerListEntry {
    name: String,
    description: Option<String>,
    tools: Vec<String>,
    transport: Option<String>,
    url: Option<String>,
}

impl From<McpServerSyncEntry> for McpServerListEntry {
    fn from(e: McpServerSyncEntry) -> Self {
        Self {
            name: e.name,
            description: e.description,
            tools: e.tools,
            transport: Some(e.transport),
            url: e.url,
        }
    }
}

/// What the broker knows about one MCP server for the calling workspace,
/// read from the sync cache.
#[derive(Clone)]
struct CachedTarget {
    url: Option<String>,
    auth_method: String,
    credential: Option<CachedCredential>,
}

/// Read the cache entry for `server_name` under `pk_hash`.
async fn cached_target(
    state: &SharedState,
    pk_hash: &str,
    server_name: &str,
) -> Option<CachedTarget> {
    let configs = state.mcp_configs.read().await;
    configs
        .get(pk_hash)?
        .iter()
        .find(|s| s.name == server_name)
        .map(|cached| CachedTarget {
            url: (!cached.url.is_empty()).then(|| cached.url.clone()),
            auth_method: cached.auth_method.clone(),
            credential: cached.credential.clone(),
        })
}

/// Resolve the target for a tool call, syncing with the server when the
/// cache has no usable entry: the server is unknown, a credential is
/// missing where one is expected, or the cached upstream access token is
/// about to expire. The broker never refreshes a token itself; the server
/// puts a fresh one in the next sync envelope.
async fn resolve_target(
    state: &SharedState,
    pk_hash: &str,
    server_name: &str,
) -> Option<CachedTarget> {
    let now = chrono::Utc::now();
    let cached = cached_target(state, pk_hash, server_name).await;
    let needs_sync = match &cached {
        None => true,
        Some(t) => {
            t.url.is_none()
                || (t.credential.is_none() && t.auth_method != "none")
                || t.credential.as_ref().is_some_and(|c| c.is_stale(now))
        }
    };
    if !needs_sync {
        tracing::debug!(server = %server_name, "using cached MCP config");
        return cached;
    }

    tracing::info!(
        server = %server_name,
        known = cached.is_some(),
        pk_hash = %pk_hash,
        "MCP cache miss or stale credential, syncing with server"
    );
    crate::mcp_sync::sync_workspace_now(state, pk_hash).await;
    let refreshed = cached_target(state, pk_hash, server_name).await;
    match &refreshed {
        Some(t) => tracing::info!(
            server = %server_name,
            has_url = t.url.is_some(),
            has_cred = t.credential.is_some(),
            "on-demand sync result"
        ),
        None => tracing::warn!(server = %server_name, "server not found in cache after sync"),
    }
    refreshed
}

/// Replace every value the scanner knows was injected, anywhere in `value`.
///
/// An MCP server that echoes its request — a debug tool, an error message,
/// a mirrored header — would otherwise hand the agent the very credential
/// the broker exists to keep from it. Serializing and re-scanning catches
/// the echo wherever it landed: free text, a nested JSON field, a tool
/// description. This is the same scan `routes/proxy.rs` runs on an upstream
/// response body.
fn redact_json(
    scanner: &LeakScanner,
    value: serde_json::Value,
    server_name: &str,
) -> serde_json::Value {
    let text = value.to_string();
    match scanner.redact(&text) {
        Cow::Borrowed(_) => value,
        Cow::Owned(redacted) => {
            tracing::warn!(
                server = %server_name,
                "MCP server echoed an injected credential value; redacted"
            );
            // Redaction never introduces a quote or a backslash, so the
            // result still parses. Falling back to the raw string keeps the
            // secret out of the response even if it somehow does not.
            serde_json::from_str(&redacted).unwrap_or(serde_json::Value::String(redacted))
        }
    }
}

/// Build the upstream JSON-RPC request with the credential injected, and the
/// scanner that recognises everything the injection put on the wire. The
/// cached value is used as-is: for OAuth-backed servers it is already the
/// upstream access token the server exchanged for.
fn build_upstream_request(
    state: &SharedState,
    server_name: &str,
    mcp_url: &str,
    credential: Option<&CachedCredential>,
    body: &serde_json::Value,
) -> Result<(reqwest::RequestBuilder, LeakScanner), ErrorResponse> {
    let mut url = reqwest::Url::parse(mcp_url).map_err(|e| {
        error_response(
            StatusCode::BAD_GATEWAY,
            "bad_gateway",
            &format!("invalid MCP server URL '{}': {}", server_name, e),
        )
    })?;
    let mut headers: Vec<(String, String)> = Vec::new();
    // The secret material the injection puts on the wire is a needle for the
    // response scan; `injected_needles` decides what counts as secret, the
    // same way the proxy route does.
    let mut needles: Vec<String> = Vec::new();

    if let Some(cred) = credential {
        let material = CredentialMaterial {
            credential_type: Some(cred.credential_type.clone()),
            value: cred.value.clone(),
            username: None,
            metadata: cred.metadata.clone(),
        };
        match credential_transform::apply(
            &material,
            cred.transform_name.as_deref(),
            "POST",
            mcp_url,
            &HashMap::new(),
            None,
        ) {
            Ok(transformed) => {
                needles.extend(leak_scanner::injected_needles(
                    &material.value,
                    transformed
                        .headers
                        .iter()
                        .map(|(k, v)| (k.as_str(), v.as_str())),
                    transformed.query_params.values().map(String::as_str),
                ));
                headers.extend(transformed.headers);
                // MCP servers normally take header auth; a query-param
                // credential is appended to the URL.
                for (k, v) in &transformed.query_params {
                    url.query_pairs_mut().append_pair(k, v);
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, server = %server_name, "credential transform failed, proceeding without injection");
                needles.extend(leak_scanner::injected_needles(&material.value, [], []));
            }
        }
    }

    let mut req = state
        .upstream_client
        .post(url)
        .header("Content-Type", "application/json");
    for (k, v) in &headers {
        req = req.header(k, v);
    }
    Ok((req.json(body), LeakScanner::new(needles)))
}

/// SSRF check for an MCP upstream, shared by the tool-list probe and the
/// tool call: resolve the host and refuse private or reserved addresses
/// unless the broker was started with `--proxy-allow-loopback`, exactly as
/// the proxy route does.
async fn check_upstream_target(
    state: &SharedState,
    server_name: &str,
    url: &str,
) -> Result<(), ErrorResponse> {
    if state.config.proxy_allow_loopback {
        return Ok(());
    }
    validate_proxy_target_resolved(url).await.map_err(|reason| {
        error_response(
            StatusCode::BAD_REQUEST,
            "ssrf_blocked",
            &format!(
                "Blocked by SSRF protection: MCP server '{server_name}': {reason}.{}",
                super::helpers::LOOPBACK_HINT
            ),
        )
    })
}

/// Parse a JSON-RPC response from an MCP server, handling both
/// `application/json` and `text/event-stream` (SSE) Content-Types.
async fn parse_mcp_response(resp: reqwest::Response) -> Result<serde_json::Value, String> {
    let status = resp.status();
    let content_type = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_lowercase();

    tracing::debug!(
        status = %status,
        content_type = %content_type,
        "parsing MCP response"
    );

    // Both branches read through the upstream cap so an MCP server cannot
    // make the broker buffer without bound.
    let mut resp = resp;
    let body_text = match crate::upstream::read_body_capped(&mut resp).await {
        Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
        Err(e) => return Err(format!("failed to read response body: {e}")),
    };

    if content_type.contains("text/event-stream") {
        for line in body_text.lines() {
            let line = line.trim();
            if let Some(data) = line.strip_prefix("data:") {
                let data = data.trim();
                if data.is_empty() {
                    continue;
                }
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(data) {
                    if json.get("result").is_some() || json.get("error").is_some() {
                        return Ok(json);
                    }
                }
            }
        }

        Err("no JSON-RPC response found in SSE stream".to_string())
    } else {
        tracing::debug!(
            body_len = body_text.len(),
            body_prefix = %body_text.chars().take(200).collect::<String>(),
            "MCP response body"
        );

        // Try JSON first
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&body_text) {
            return Ok(json);
        }

        // Fallback: try SSE parsing even without the header
        // (some servers don't set Content-Type correctly)
        for line in body_text.lines() {
            let line = line.trim();
            if let Some(data) = line.strip_prefix("data:") {
                let data = data.trim();
                if data.is_empty() {
                    continue;
                }
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(data) {
                    if json.get("result").is_some() || json.get("error").is_some() {
                        return Ok(json);
                    }
                }
            }
        }

        Err(format!(
            "failed to parse MCP response (len={}, prefix={})",
            body_text.len(),
            body_text.chars().take(100).collect::<String>()
        ))
    }
}

/// POST /mcp/list-servers
pub async fn list_servers(
    State(state): State<SharedState>,
    request: axum::extract::Request,
) -> impl IntoResponse {
    let auth = match request
        .extensions()
        .get::<AuthenticatedWorkspace>()
        .cloned()
    {
        Some(a) => a,
        None => {
            return error_response(
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                "missing workspace authentication",
            )
        }
    };

    let server_client = ServerClient::new(state.http_client.clone(), state.server_url.clone());

    match with_token_refresh(&state, &auth.pk_hash, |token| {
        let sc = server_client.clone();
        async move { sc.list_mcp_servers(&token).await }
    })
    .await
    {
        Ok(servers) => {
            let entries: Vec<McpServerListEntry> =
                servers.into_iter().map(McpServerListEntry::from).collect();
            ok_response(serde_json::json!(entries))
        }
        Err(e) => e,
    }
}

/// POST /mcp/list-tools
pub async fn list_tools(
    State(state): State<SharedState>,
    request: axum::extract::Request,
) -> impl IntoResponse {
    let auth = match request
        .extensions()
        .get::<AuthenticatedWorkspace>()
        .cloned()
    {
        Some(a) => a,
        None => {
            return error_response(
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                "missing workspace authentication",
            )
        }
    };

    let server_client = ServerClient::new(state.http_client.clone(), state.server_url.clone());

    let mut all_tools: Vec<McpToolSyncEntry> =
        match with_token_refresh(&state, &auth.pk_hash, |token| {
            let sc = server_client.clone();
            async move { sc.list_mcp_tools(&token).await }
        })
        .await
        {
            Ok(tools) => tools,
            Err(e) => return e,
        };

    // Live discovery: for servers with empty tools but cached credentials,
    // call tools/list on the upstream with auth injection. This handles servers
    // that require authentication for tool discovery. The sync just made
    // also gives every OAuth-backed server a fresh upstream token.
    crate::mcp_sync::sync_workspace_now(&state, &auth.pk_hash).await;

    // Collect servers needing live discovery (servers not already represented in all_tools)
    let servers_to_probe: Vec<(String, String, CachedCredential)> = {
        let configs = state.mcp_configs.read().await;
        if let Some(servers) = configs.get(&auth.pk_hash) {
            servers
                .iter()
                .filter(|cached| {
                    // Skip servers that already have tools in the server
                    // response, and servers whose tool list the control plane
                    // says is authoritative: that list is an `allowed_tools`
                    // allow-list, and probing the upstream would hand the
                    // agent every tool the operator narrowed away — including
                    // for a server narrowed to no tools at all, which is
                    // exactly the case that reaches here with nothing listed.
                    !cached.tools_are_authoritative
                        && !all_tools.iter().any(|t| t.server == cached.name)
                })
                .filter_map(|cached| {
                    // Only probe servers with credentials and non-empty URLs
                    let cred = cached.credential.as_ref()?;
                    if cached.url.is_empty() {
                        return None;
                    }
                    Some((cached.name.clone(), cached.url.clone(), cred.clone()))
                })
                .collect()
        } else {
            Vec::new()
        }
    };

    for (server_name, url, cred) in servers_to_probe {
        // The probe is an outbound request with a credential attached; it
        // gets the same SSRF check as a tool call.
        if let Err(e) = check_upstream_target(&state, &server_name, &url).await {
            return e;
        }

        let jsonrpc = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list",
            "params": {}
        });

        let (req, scanner) =
            match build_upstream_request(&state, &server_name, &url, Some(&cred), &jsonrpc) {
                Ok((r, s)) => (r.timeout(std::time::Duration::from_secs(5)), s),
                Err(_) => continue,
            };

        let resp = match req.send().await {
            Ok(r) if r.status().is_success() => r,
            _ => continue,
        };

        // The probe carried the credential, so its answer gets the same
        // scan a tool call's does before any of it is handed to the agent.
        let body: serde_json::Value = match parse_mcp_response(resp).await {
            Ok(v) => redact_json(&scanner, v, &server_name),
            Err(_) => continue,
        };

        if let Some(tools) = body
            .get("result")
            .and_then(|r| r.get("tools"))
            .and_then(|t| t.as_array())
        {
            for tool in tools {
                let name = tool
                    .get("name")
                    .and_then(|n| n.as_str())
                    .unwrap_or_default();
                let description = tool
                    .get("description")
                    .and_then(|d| d.as_str())
                    .map(|s| s.to_string());
                let input_schema = tool.get("inputSchema").cloned();
                all_tools.push(McpToolSyncEntry {
                    server: server_name.clone(),
                    tool: name.to_string(),
                    description,
                    input_schema,
                });
            }
        }
    }

    ok_response(serde_json::json!(all_tools))
}

#[derive(Debug, Deserialize)]
pub struct McpCallRequest {
    pub server: String,
    pub tool: String,
    pub arguments: Option<serde_json::Value>,
}

/// POST /mcp/call
pub async fn call_tool(
    State(state): State<SharedState>,
    request: axum::extract::Request,
) -> impl IntoResponse {
    let auth = match request
        .extensions()
        .get::<AuthenticatedWorkspace>()
        .cloned()
    {
        Some(a) => a,
        None => {
            return error_response(
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                "missing workspace authentication",
            )
        }
    };

    // Read body
    let body_bytes = match axum::body::to_bytes(request.into_body(), 10 * 1024 * 1024).await {
        Ok(b) => b,
        Err(_) => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "bad_request",
                "Failed to read request body",
            );
        }
    };

    let call_req: McpCallRequest = match serde_json::from_slice(&body_bytes) {
        Ok(r) => r,
        Err(_) => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "bad_request",
                "Invalid request body",
            );
        }
    };

    let server_client = ServerClient::new(state.http_client.clone(), state.server_url.clone());
    let server_name = call_req.server.clone();
    let tool_name = call_req.tool.clone();

    // Authorize via Cedar policy on the server (with 401 retry)
    let auth_resp = match with_token_refresh(&state, &auth.pk_hash, |token| {
        let sc = server_client.clone();
        let srv = server_name.clone();
        let tool = tool_name.clone();
        async move { sc.mcp_authorize(&srv, &tool, &token).await }
    })
    .await
    {
        Ok(r) => r,
        Err(e) => return e,
    };

    if !auth_resp.is_permit() {
        return error_response(
            StatusCode::FORBIDDEN,
            "forbidden",
            "MCP tool call denied by policy",
        );
    }

    let target = resolve_target(&state, &auth.pk_hash, &server_name).await;
    let (mcp_url, mut credential) = match target {
        Some(CachedTarget {
            url: Some(url),
            credential,
            ..
        }) => (url, credential),
        _ => {
            return error_response(
                StatusCode::NOT_FOUND,
                "not_found",
                &format!(
                    "MCP server '{}' not found or has no URL configured",
                    server_name
                ),
            );
        }
    };

    // SSRF validation — prevent MCP servers from targeting internal/cloud metadata endpoints
    if let Err(e) = check_upstream_target(&state, &server_name, &mcp_url).await {
        return e;
    }

    let jsonrpc_request = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": tool_name,
            "arguments": call_req.arguments.unwrap_or(serde_json::json!({})),
        }
    });

    // Send once; on a 401 with a credential injected, the token the server
    // gave us is no longer good (revoked, or expired early). Sync once more
    // for a fresh one and retry a single time.
    let mut retried = false;
    // The scanner comes back with the response it belongs to: a retry
    // injects a fresh token, and that is the value to look for in the reply.
    let (mcp_resp, scanner) = loop {
        let (req, scanner) = match build_upstream_request(
            &state,
            &server_name,
            &mcp_url,
            credential.as_ref(),
            &jsonrpc_request,
        ) {
            Ok(pair) => pair,
            Err(e) => return e,
        };

        let resp = match req.send().await {
            Ok(r) => r,
            Err(e) => {
                tracing::error!(error = %e, server = %server_name, url = %mcp_url, "HTTP MCP request failed");
                return error_response(
                    StatusCode::BAD_GATEWAY,
                    "bad_gateway",
                    &format!("Failed to connect to MCP server '{}': {}", server_name, e),
                );
            }
        };

        if resp.status() == reqwest::StatusCode::UNAUTHORIZED && credential.is_some() && !retried {
            retried = true;
            tracing::info!(
                server = %server_name,
                "MCP server rejected the upstream token; syncing for a fresh one and retrying"
            );
            crate::mcp_sync::sync_workspace_now(&state, &auth.pk_hash).await;
            match cached_target(&state, &auth.pk_hash, &server_name).await {
                Some(CachedTarget {
                    credential: Some(fresh),
                    ..
                }) => {
                    credential = Some(fresh);
                    continue;
                }
                _ => break (resp, scanner),
            }
        }
        break (resp, scanner);
    };

    let mcp_status = mcp_resp.status();
    // Redact before anything is read out of the result: an MCP server that
    // echoes what it was called with must not hand the agent the credential.
    let mcp_body: serde_json::Value = match parse_mcp_response(mcp_resp).await {
        Ok(v) => redact_json(&scanner, v, &server_name),
        Err(e) => {
            tracing::error!(error = %e, server = %server_name, "failed to parse MCP response");
            return error_response(
                StatusCode::BAD_GATEWAY,
                "bad_gateway",
                &format!("Failed to parse MCP response from '{}': {}", server_name, e),
            );
        }
    };

    if !mcp_status.is_success() {
        tracing::warn!(server = %server_name, status = %mcp_status, "MCP server returned error");
        return error_response(
            StatusCode::BAD_GATEWAY,
            "bad_gateway",
            &format!(
                "MCP server '{}' returned status {}",
                server_name, mcp_status
            ),
        );
    }

    // Extract the JSON-RPC result (or error).
    if let Some(error) = mcp_body.get("error") {
        tracing::info!(
            server_name = %server_name,
            tool_name = %tool_name,
            status = "jsonrpc_error",
            correlation_id = %auth_resp.correlation_id,
            "MCP tool call completed with JSON-RPC error"
        );
        return (
            StatusCode::OK,
            axum::Json(serde_json::json!({
                "data": {
                    "content": [{
                        "type": "text",
                        "text": format!("MCP error: {}", error),
                    }],
                    "isError": true,
                    "correlation_id": auth_resp.correlation_id,
                }
            })),
        );
    }

    let result = mcp_body
        .get("result")
        .cloned()
        .unwrap_or(serde_json::json!({}));

    tracing::info!(
        server_name = %server_name,
        tool_name = %tool_name,
        status = "success",
        correlation_id = %auth_resp.correlation_id,
        "MCP tool call completed successfully"
    );

    (
        StatusCode::OK,
        axum::Json(serde_json::json!({
            "data": {
                "content": result.get("content").cloned().unwrap_or(serde_json::json!([{
                    "type": "text",
                    "text": result.to_string(),
                }])),
                "isError": result.get("isError").and_then(|v| v.as_bool()).unwrap_or(false),
                "correlation_id": auth_resp.correlation_id,
            }
        })),
    )
}
