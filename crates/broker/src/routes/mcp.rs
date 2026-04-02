use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use serde::Deserialize;

use crate::auth::AuthenticatedWorkspace;
use crate::server_client::ServerClient;
use crate::state::SharedState;

use super::helpers::{error_response, ok_response, require_scope, with_token_refresh};

/// POST /mcp/list-servers
pub async fn list_servers(
    State(state): State<SharedState>,
    request: axum::extract::Request,
) -> impl IntoResponse {
    let auth = request
        .extensions()
        .get::<AuthenticatedWorkspace>()
        .cloned()
        .unwrap();

    if let Err(e) = require_scope(&state, &auth.pk_hash, "mcp:discover", "mcp.list_servers").await {
        return e;
    }

    let server_client = ServerClient::new(state.http_client.clone(), state.server_url.clone());

    match with_token_refresh(&state, &auth.pk_hash, |token| {
        let sc = server_client.clone();
        async move { sc.list_mcp_servers(&token).await }
    })
    .await
    {
        Ok(servers) => ok_response(serde_json::json!(servers)),
        Err(e) => e,
    }
}

/// POST /mcp/list-tools
pub async fn list_tools(
    State(state): State<SharedState>,
    request: axum::extract::Request,
) -> impl IntoResponse {
    let auth = request
        .extensions()
        .get::<AuthenticatedWorkspace>()
        .cloned()
        .unwrap();

    if let Err(e) = require_scope(&state, &auth.pk_hash, "mcp:discover", "mcp.list_tools").await {
        return e;
    }

    let server_client = ServerClient::new(state.http_client.clone(), state.server_url.clone());

    match with_token_refresh(&state, &auth.pk_hash, |token| {
        let sc = server_client.clone();
        async move { sc.list_mcp_tools(&token).await }
    })
    .await
    {
        Ok(tools) => ok_response(serde_json::json!(tools)),
        Err(e) => e,
    }
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
    let auth = request
        .extensions()
        .get::<AuthenticatedWorkspace>()
        .cloned()
        .unwrap();

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

    if let Err(e) = require_scope(&state, &auth.pk_hash, "mcp:invoke", "mcp.call_tool").await {
        return e;
    }

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

    if auth_resp.decision != "permit" {
        return error_response(
            StatusCode::FORBIDDEN,
            "forbidden",
            "MCP tool call denied by policy",
        );
    }

    // Fetch MCP server list to find the target server's transport and URL.
    let servers = match with_token_refresh(&state, &auth.pk_hash, |token| {
        let sc = server_client.clone();
        async move { sc.list_mcp_servers(&token).await }
    })
    .await
    {
        Ok(s) => s,
        Err(e) => return e,
    };

    let target = match servers.iter().find(|s| s.name == server_name) {
        Some(s) => s.clone(),
        None => {
            return error_response(
                StatusCode::NOT_FOUND,
                "not_found",
                &format!("MCP server '{}' not found", server_name),
            );
        }
    };

    let transport = target.transport.as_deref().unwrap_or("stdio");

    // STDIO servers are local-only — cannot be proxied via the broker.
    if transport == "stdio" {
        return error_response(
            StatusCode::BAD_REQUEST,
            "unsupported_transport",
            "STDIO MCP servers are local-only. Configure them in .mcp.json for native agent access.",
        );
    }

    // HTTP/SSE transport — POST JSON-RPC to the server URL.
    let mcp_url = match &target.url {
        Some(u) if !u.is_empty() => u.clone(),
        _ => {
            return error_response(
                StatusCode::BAD_GATEWAY,
                "bad_gateway",
                &format!("MCP server '{}' has no URL configured", server_name),
            );
        }
    };

    let jsonrpc_request = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": tool_name,
            "arguments": call_req.arguments.unwrap_or(serde_json::json!({})),
        }
    });

    let mcp_resp = match state
        .http_client
        .post(&mcp_url)
        .header("Content-Type", "application/json")
        .json(&jsonrpc_request)
        .send()
        .await
    {
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

    let mcp_status = mcp_resp.status();
    let mcp_body: serde_json::Value = match mcp_resp.json().await {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(error = %e, server = %server_name, "failed to parse MCP response");
            return error_response(
                StatusCode::BAD_GATEWAY,
                "bad_gateway",
                &format!("Invalid response from MCP server '{}': {}", server_name, e),
            );
        }
    };

    if !mcp_status.is_success() {
        tracing::warn!(server = %server_name, status = %mcp_status, "MCP server returned error");
        return error_response(
            StatusCode::BAD_GATEWAY,
            "bad_gateway",
            &format!("MCP server '{}' returned status {}", server_name, mcp_status),
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

    let result = mcp_body.get("result").cloned().unwrap_or(serde_json::json!({}));

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
