//! HTTP-based MCP client for connecting to remote MCP servers via Streamable HTTP.
//!
//! Mirrors the [`StdioProcessPool`](crate::stdio::StdioProcessPool) pattern but uses
//! HTTP POST with JSON-RPC bodies instead of subprocess STDIO.

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::{Mutex, RwLock};

use crate::audit::AuditSender;

/// Errors from HTTP MCP operations.
#[derive(Debug, thiserror::Error)]
pub enum HttpMcpError {
    /// Remote server connection or DNS resolution failure.
    #[error("connection failed: {0}")]
    ConnectionFailed(String),
    /// HTTP request returned a non-success status or transport error.
    #[error("request failed: {0}")]
    RequestFailed(String),
    /// The request exceeded the configured timeout.
    #[error("timeout: {0}")]
    Timeout(String),
    /// Response body could not be parsed as valid JSON-RPC.
    #[error("JSON-RPC parse error: {0}")]
    JsonRpcParse(String),
    /// Server returned 401/403 indicating invalid or expired credentials.
    #[error("unauthorized: {0}")]
    Unauthorized(String),
    /// The target URL failed SSRF validation.
    #[error("blocked URL: {0}")]
    BlockedUrl(String),
}

/// Validate that a URL target is safe to connect to.
///
/// Delegates to `agent_cordon_core::proxy::url_safety::validate_proxy_target_resolved`
/// which blocks non-HTTP schemes, loopback, private networks, link-local (cloud
/// metadata), and DNS rebinding attacks.
///
/// Set `AGTCRDN_PROXY_ALLOW_LOOPBACK=true` to bypass for local development.
async fn validate_url_target(url: &str) -> Result<(), HttpMcpError> {
    let allow_loopback = std::env::var("AGTCRDN_PROXY_ALLOW_LOOPBACK")
        .map(|v| v == "true")
        .unwrap_or(false);

    if allow_loopback {
        return Ok(());
    }

    agent_cordon_core::proxy::url_safety::validate_proxy_target_resolved(url)
        .await
        .map_err(|e| {
            HttpMcpError::BlockedUrl(format!(
                "{} (set AGTCRDN_PROXY_ALLOW_LOOPBACK=true to allow)",
                e
            ))
        })
}

/// An HTTP-based MCP client connecting to a remote MCP server via Streamable HTTP.
struct HttpMcpClient {
    url: String,
    headers: HashMap<String, String>,
    http: reqwest::Client,
    session_id: Option<String>,
}

/// Pool of HTTP MCP clients keyed by server name.
///
/// Uses per-client locking so that I/O to one MCP server does not block
/// concurrent requests to other servers.
pub struct HttpMcpClientPool {
    clients: RwLock<HashMap<String, Arc<Mutex<HttpMcpClient>>>>,
    audit: AuditSender,
}

impl HttpMcpClientPool {
    /// Create a new empty HTTP MCP client pool.
    pub fn new(audit: AuditSender) -> Self {
        Self {
            clients: RwLock::new(HashMap::new()),
            audit,
        }
    }

    /// Connect to a remote MCP server, perform the initialize handshake, and
    /// register the client in the pool.
    pub async fn connect(
        &self,
        server_name: &str,
        url: &str,
        headers: HashMap<String, String>,
    ) -> Result<(), HttpMcpError> {
        validate_url_target(url).await?;

        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .user_agent(format!("agentcordon/{}", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| {
                HttpMcpError::ConnectionFailed(format!("failed to build HTTP client: {}", e))
            })?;

        let mut client = HttpMcpClient {
            url: url.to_string(),
            headers,
            http,
            session_id: None,
        };

        // Send MCP initialize handshake (same as respawn_from_config in mcp_sync.rs).
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

        let resp = send_http_jsonrpc(&mut client, &init_request).await;

        match resp {
            Ok(_) => {
                tracing::debug!(
                    server = server_name,
                    url = url,
                    "HTTP MCP initialize handshake completed"
                );
            }
            Err(e) => {
                tracing::warn!(
                    server = server_name,
                    url = url,
                    error = %e,
                    "HTTP MCP initialize handshake failed (server may still work)"
                );
            }
        }

        let mut clients = self.clients.write().await;
        clients.insert(server_name.to_string(), Arc::new(Mutex::new(client)));

        self.audit.emit(
            "http_mcp_connected",
            serde_json::json!({
                "server_name": server_name,
                "url": url,
            }),
        );

        tracing::debug!(
            server_name = server_name,
            url = url,
            "HTTP MCP client connected"
        );

        Ok(())
    }

    /// Send a JSON-RPC request to a connected HTTP MCP server and return the
    /// parsed JSON response.
    ///
    /// Only locks the individual client, allowing concurrent requests to
    /// different MCP servers.
    pub(crate) async fn send_jsonrpc(
        &self,
        server_name: &str,
        request: &serde_json::Value,
    ) -> Result<serde_json::Value, HttpMcpError> {
        let client_handle = {
            let clients = self.clients.read().await;
            clients.get(server_name).cloned().ok_or_else(|| {
                HttpMcpError::ConnectionFailed(format!(
                    "no connected client for server '{}'",
                    server_name
                ))
            })?
        };

        let mut client = client_handle.lock().await;
        let result = send_http_jsonrpc(&mut client, request).await;

        if let Err(ref e) = result {
            // On connection/auth errors, remove the dead client so the next
            // request triggers reconnection.
            let should_remove = matches!(
                e,
                HttpMcpError::ConnectionFailed(_) | HttpMcpError::Unauthorized(_)
            );
            if should_remove {
                drop(client);
                drop(client_handle);
                self.remove(server_name).await;
                self.audit.emit(
                    "http_mcp_disconnected",
                    serde_json::json!({
                        "server_name": server_name,
                        "reason": e.to_string(),
                    }),
                );
                tracing::warn!(
                    server_name = server_name,
                    "removed disconnected HTTP MCP client from pool"
                );
            }
        }

        result
    }

    /// Check if a client is present in the pool for the given server name.
    pub async fn has_client(&self, server_name: &str) -> bool {
        let clients = self.clients.read().await;
        clients.contains_key(server_name)
    }

    /// Remove a client from the pool. Returns `true` if it existed.
    pub async fn remove(&self, server_name: &str) -> bool {
        let mut clients = self.clients.write().await;
        clients.remove(server_name).is_some()
    }

    /// Shutdown all clients by dropping them.
    pub async fn shutdown(&self) {
        let mut clients = self.clients.write().await;
        for (name, _) in clients.drain() {
            tracing::debug!(server_name = name, "shutting down HTTP MCP client");
        }
    }

    /// Execute an MCP tool call with Cedar policy authorization.
    ///
    /// Checks authorization via the server's mcp-authorize endpoint before
    /// forwarding the JSON-RPC `tools/call` request. Returns a JSON-RPC
    /// error response if the policy forbids the call.
    pub async fn call_tool(
        &self,
        server_name: &str,
        tool_name: &str,
        arguments: &serde_json::Value,
        id: &Option<serde_json::Value>,
        cp_url: &str,
        workspace_jwt: &str,
        cp_http: &reqwest::Client,
    ) -> Result<serde_json::Value, HttpMcpError> {
        // Cedar policy check — fail-closed.
        let (permitted, correlation_id) = crate::mcp_sync::authorize_tool_call(
            cp_url,
            workspace_jwt,
            cp_http,
            server_name,
            tool_name,
        )
        .await;

        if !permitted {
            self.audit.emit(
                "mcp_tool_denied",
                serde_json::json!({
                    "server_name": server_name,
                    "tool_name": tool_name,
                    "reason": "cedar_policy_forbid",
                    "correlation_id": correlation_id,
                }),
            );
            return Err(HttpMcpError::RequestFailed(format!(
                "policy forbids tool call: {}/{}",
                server_name, tool_name
            )));
        }

        // Build and send the JSON-RPC request.
        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "tools/call",
            "params": {
                "name": tool_name,
                "arguments": arguments,
            }
        });

        let result = self.send_jsonrpc(server_name, &request).await?;

        self.audit.emit(
            "mcp_tool_call",
            serde_json::json!({
                "server_name": server_name,
                "tool_name": tool_name,
                "outcome": if result.get("error").is_some() { "error" } else { "success" },
                "correlation_id": correlation_id,
            }),
        );

        Ok(result)
    }
}

/// Send a single JSON-RPC request over HTTP and parse the response.
///
/// Handles both plain JSON and SSE (`text/event-stream`) response formats.
/// Stores the `Mcp-Session-Id` header from responses for subsequent requests.
async fn send_http_jsonrpc(
    client: &mut HttpMcpClient,
    request: &serde_json::Value,
) -> Result<serde_json::Value, HttpMcpError> {
    // Content-Type is set automatically by .json() below — do not set it
    // manually to avoid duplicate headers (which causes 400 on some servers).
    let mut req_builder = client
        .http
        .post(&client.url)
        .header("Accept", "application/json, text/event-stream");

    // Add credential/custom headers (values are never logged).
    for (k, v) in &client.headers {
        req_builder = req_builder.header(k.as_str(), v.as_str());
    }

    // Add session ID if we have one from a previous response.
    if let Some(ref sid) = client.session_id {
        req_builder = req_builder.header("Mcp-Session-Id", sid.as_str());
    }

    let resp = req_builder.json(request).send().await.map_err(|e| {
        if e.is_timeout() {
            HttpMcpError::Timeout(format!("request to '{}' timed out after 30s", client.url))
        } else if e.is_connect() {
            HttpMcpError::ConnectionFailed(format!("failed to connect to '{}': {}", client.url, e))
        } else {
            HttpMcpError::RequestFailed(format!("HTTP request to '{}' failed: {}", client.url, e))
        }
    })?;

    let status = resp.status();

    // Store Mcp-Session-Id from response headers.
    if let Some(sid) = resp.headers().get("mcp-session-id") {
        if let Ok(sid_str) = sid.to_str() {
            client.session_id = Some(sid_str.to_string());
        }
    }

    if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
        return Err(HttpMcpError::Unauthorized(format!(
            "server returned {} for '{}'",
            status, client.url
        )));
    }

    if !status.is_success() {
        let body_preview = resp
            .text()
            .await
            .unwrap_or_default()
            .chars()
            .take(500)
            .collect::<String>();
        return Err(HttpMcpError::RequestFailed(format!(
            "server returned {} for '{}': {}",
            status, client.url, body_preview
        )));
    }

    // Determine response format from Content-Type.
    let content_type = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    if content_type.starts_with("text/event-stream") {
        // SSE: stream chunks incrementally. The server keeps the connection open,
        // so we cannot use resp.bytes().await (it would block forever). Instead,
        // read chunks and look for complete JSON-RPC data events.
        stream_sse_response(resp, &client.url).await
    } else {
        // Plain JSON: stream body incrementally with size limit.
        // Checks size as chunks arrive to prevent OOM on huge responses.
        use futures_util::StreamExt;
        const MAX_RESPONSE_BYTES: usize = 10 * 1024 * 1024;
        let mut body_bytes = Vec::new();
        let mut stream = resp.bytes_stream();

        while let Some(chunk_result) = stream.next().await {
            let chunk = chunk_result.map_err(|e| {
                HttpMcpError::RequestFailed(format!("failed to read response body: {}", e))
            })?;
            body_bytes.extend_from_slice(&chunk);
            if body_bytes.len() > MAX_RESPONSE_BYTES {
                return Err(HttpMcpError::RequestFailed(format!(
                    "response from '{}' exceeded {} byte limit",
                    client.url, MAX_RESPONSE_BYTES
                )));
            }
        }

        let body = String::from_utf8(body_bytes).map_err(|e| {
            HttpMcpError::JsonRpcParse(format!("response is not valid UTF-8: {}", e))
        })?;

        serde_json::from_str(&body)
            .map_err(|e| HttpMcpError::JsonRpcParse(format!("invalid JSON response: {}", e)))
    }
}

/// Stream an SSE response incrementally, returning the first complete JSON-RPC
/// result. Unlike `resp.bytes().await`, this does not wait for the connection
/// to close — it reads chunks as they arrive and returns as soon as a complete
/// `data:` event containing a JSON-RPC response (with `result` or `error`) is found.
async fn stream_sse_response(
    resp: reqwest::Response,
    url: &str,
) -> Result<serde_json::Value, HttpMcpError> {
    use futures_util::StreamExt;

    const MAX_RESPONSE_BYTES: usize = 10 * 1024 * 1024;
    let mut buf = String::new();
    let mut stream = resp.bytes_stream();

    while let Some(chunk_result) = stream.next().await {
        let chunk = chunk_result.map_err(|e| {
            HttpMcpError::RequestFailed(format!("error reading SSE stream from '{}': {}", url, e))
        })?;

        let chunk_str = std::str::from_utf8(&chunk).map_err(|e| {
            HttpMcpError::JsonRpcParse(format!("SSE chunk is not valid UTF-8: {}", e))
        })?;

        buf.push_str(chunk_str);

        tracing::debug!(
            chunk_len = chunk.len(),
            buf_len = buf.len(),
            "SSE chunk received"
        );

        if buf.len() > MAX_RESPONSE_BYTES {
            return Err(HttpMcpError::RequestFailed(format!(
                "SSE response from '{}' exceeded {} byte limit",
                url, MAX_RESPONSE_BYTES
            )));
        }

        // Try to extract a complete JSON-RPC response from accumulated data: lines.
        // SSE events are separated by blank lines (\n\n).
        if let Ok(value) = parse_sse_response(&buf) {
            if value.get("result").is_some() || value.get("error").is_some() {
                return Ok(value);
            }
        }
    }

    // Stream ended — try to parse whatever we have, but only accept
    // a JSON-RPC result or error (not notifications).
    if buf.is_empty() {
        return Err(HttpMcpError::JsonRpcParse(
            "SSE stream ended with no data".to_string(),
        ));
    }
    match parse_sse_response(&buf) {
        Ok(value) if value.get("result").is_some() || value.get("error").is_some() => Ok(value),
        Ok(_) => Err(HttpMcpError::JsonRpcParse(
            "SSE stream ended without a JSON-RPC result or error".to_string(),
        )),
        Err(e) => Err(e),
    }
}

/// Parse a Server-Sent Events response body, splitting on event boundaries
/// (`\n\n`) and returning the first valid JSON-RPC value found.
///
/// Each SSE event may contain `event:`, `data:`, and other fields. Only
/// `data:` lines within a single event are joined. This avoids concatenating
/// data from separate events (e.g. a notification followed by a result) into
/// invalid JSON.
fn parse_sse_response(body: &str) -> Result<serde_json::Value, HttpMcpError> {
    // Normalize \r\n → \n for cross-platform SSE compatibility.
    let normalized = body.replace("\r\n", "\n");

    // Split on blank lines — each segment is one SSE event.
    for event in normalized.split("\n\n") {
        let mut data_parts = Vec::new();

        for line in event.lines() {
            if let Some(data) = line.strip_prefix("data:") {
                let trimmed = data.trim();
                if !trimmed.is_empty() {
                    data_parts.push(trimmed);
                }
            }
        }

        if data_parts.is_empty() {
            continue;
        }

        let joined = data_parts.join("\n");
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(&joined) {
            return Ok(value);
        }
    }

    Err(HttpMcpError::JsonRpcParse(
        "SSE response contained no valid JSON data events".to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    #[test]
    fn parse_sse_single_data_line() {
        let body = "data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n\n";
        let result = parse_sse_response(body).unwrap();
        assert_eq!(result["jsonrpc"], "2.0");
        assert_eq!(result["id"], 1);
    }

    #[test]
    fn parse_sse_multiple_data_lines() {
        let body = "data: {\"jsonrpc\":\"2.0\",\ndata: \"id\":1,\"result\":{}}\n\n";
        let result = parse_sse_response(body).unwrap();
        assert_eq!(result["jsonrpc"], "2.0");
    }

    #[test]
    fn parse_sse_with_event_prefix_lines() {
        // SSE events may include `event:` lines before `data:` — they should be ignored.
        let body = "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n\n";
        let result = parse_sse_response(body).unwrap();
        assert_eq!(result["jsonrpc"], "2.0");
        assert_eq!(result["id"], 1);
        assert!(result.get("result").is_some());
    }

    #[test]
    fn parse_sse_multiple_events_returns_first_valid() {
        // Two SSE events: a notification (no id) then a result.
        // The parser should return the first valid JSON, not concatenate across events.
        let body = concat!(
            "event: message\n",
            "data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\"}\n",
            "\n",
            "event: message\n",
            "data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"ok\":true}}\n",
            "\n",
        );
        let result = parse_sse_response(body).unwrap();
        // Should get the first valid JSON — the notification.
        assert_eq!(result["method"], "notifications/progress");
    }

    #[test]
    fn parse_sse_crlf_line_endings() {
        let body = "data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\r\n\r\n";
        let result = parse_sse_response(body).unwrap();
        assert_eq!(result["id"], 1);
    }

    #[test]
    fn parse_sse_empty_returns_error() {
        let body = "event: message\n\n";
        assert!(parse_sse_response(body).is_err());
    }

    #[tokio::test]
    #[serial]
    async fn validate_url_blocks_localhost() {
        std::env::remove_var("AGTCRDN_PROXY_ALLOW_LOOPBACK");
        let result = validate_url_target("http://localhost:8080/mcp").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    #[serial]
    async fn validate_url_blocks_127() {
        std::env::remove_var("AGTCRDN_PROXY_ALLOW_LOOPBACK");
        let result = validate_url_target("http://127.0.0.1:8080/mcp").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    #[serial]
    async fn validate_url_allows_public() {
        std::env::remove_var("AGTCRDN_PROXY_ALLOW_LOOPBACK");
        // Use a domain that we know resolves to a public IP.
        let result = validate_url_target("https://api.github.com/mcp").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    #[serial]
    async fn validate_url_allows_loopback_when_env_set() {
        std::env::set_var("AGTCRDN_PROXY_ALLOW_LOOPBACK", "true");
        let result = validate_url_target("http://localhost:8080/mcp").await;
        assert!(result.is_ok());
        std::env::remove_var("AGTCRDN_PROXY_ALLOW_LOOPBACK");
    }

    #[tokio::test]
    #[serial]
    async fn validate_url_blocks_private_ranges() {
        std::env::remove_var("AGTCRDN_PROXY_ALLOW_LOOPBACK");
        // Cloud metadata endpoint
        assert!(
            validate_url_target("http://169.254.169.254/latest/meta-data/")
                .await
                .is_err()
        );
        // Private ranges
        assert!(validate_url_target("http://10.0.0.1/api").await.is_err());
        assert!(validate_url_target("http://172.16.0.1/api").await.is_err());
        assert!(validate_url_target("http://192.168.1.1/api").await.is_err());
    }

    #[tokio::test]
    #[serial]
    async fn validate_url_blocks_non_http_schemes() {
        std::env::remove_var("AGTCRDN_PROXY_ALLOW_LOOPBACK");
        assert!(validate_url_target("file:///etc/passwd").await.is_err());
        assert!(validate_url_target("ftp://example.com/file").await.is_err());
    }
}
