use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use serde::Deserialize;

use crate::auth::AuthenticatedWorkspace;
use crate::server_client::ServerClient;
use crate::state::SharedState;
use crate::token_refresh;

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

    let access_token = match get_access_token(&state, &auth.pk_hash).await {
        Some(t) => t,
        None => {
            return error_response(
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                "Workspace not registered",
            )
        }
    };

    let server_client = ServerClient::new(state.http_client.clone(), state.server_url.clone());

    match server_client.list_mcp_servers(&access_token).await {
        Ok(servers) => ok_response(serde_json::json!(servers)),
        Err(crate::server_client::ServerClientError::ServerError { status: 401, .. }) => {
            if let Some(token) = try_refresh_and_get_token(&state, &auth.pk_hash).await {
                match server_client.list_mcp_servers(&token).await {
                    Ok(servers) => ok_response(serde_json::json!(servers)),
                    Err(e) => {
                        error_response(StatusCode::BAD_GATEWAY, "bad_gateway", { tracing::error!(error = %e, "MCP request failed"); "Server request failed" })
                    }
                }
            } else {
                error_response(StatusCode::UNAUTHORIZED, "unauthorized", "Token expired")
            }
        }
        Err(e) => error_response(StatusCode::BAD_GATEWAY, "bad_gateway", { tracing::error!(error = %e, "MCP request failed"); "Server request failed" }),
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

    let access_token = match get_access_token(&state, &auth.pk_hash).await {
        Some(t) => t,
        None => {
            return error_response(
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                "Workspace not registered",
            )
        }
    };

    let server_client = ServerClient::new(state.http_client.clone(), state.server_url.clone());

    match server_client.list_mcp_tools(&access_token).await {
        Ok(tools) => ok_response(serde_json::json!(tools)),
        Err(crate::server_client::ServerClientError::ServerError { status: 401, .. }) => {
            if let Some(token) = try_refresh_and_get_token(&state, &auth.pk_hash).await {
                match server_client.list_mcp_tools(&token).await {
                    Ok(tools) => ok_response(serde_json::json!(tools)),
                    Err(e) => {
                        error_response(StatusCode::BAD_GATEWAY, "bad_gateway", { tracing::error!(error = %e, "MCP request failed"); "Server request failed" })
                    }
                }
            } else {
                error_response(StatusCode::UNAUTHORIZED, "unauthorized", "Token expired")
            }
        }
        Err(e) => error_response(StatusCode::BAD_GATEWAY, "bad_gateway", { tracing::error!(error = %e, "MCP request failed"); "Server request failed" }),
    }
}

#[derive(Debug, Deserialize)]
pub struct McpCallRequest {
    pub server: String,
    pub tool: String,
    #[allow(dead_code)]
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

    let access_token = match get_access_token(&state, &auth.pk_hash).await {
        Some(t) => t,
        None => {
            return error_response(
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                "Workspace not registered",
            )
        }
    };

    let server_client = ServerClient::new(state.http_client.clone(), state.server_url.clone());

    // Authorize via Cedar policy on the server
    let auth_resp = match server_client
        .mcp_authorize(&call_req.server, &call_req.tool, &access_token)
        .await
    {
        Ok(r) => r,
        Err(crate::server_client::ServerClientError::ServerError { status: 401, .. }) => {
            // Try reactive refresh
            if let Some(token) = try_refresh_and_get_token(&state, &auth.pk_hash).await {
                match server_client
                    .mcp_authorize(&call_req.server, &call_req.tool, &token)
                    .await
                {
                    Ok(r) => r,
                    Err(e) => {
                        return error_response(
                            StatusCode::BAD_GATEWAY,
                            "bad_gateway",
                            { tracing::error!(error = %e, "MCP request failed"); "Server request failed" },
                        );
                    }
                }
            } else {
                return error_response(StatusCode::UNAUTHORIZED, "unauthorized", "Token expired");
            }
        }
        Err(e) => {
            // Fail-closed: deny on error
            tracing::warn!(
                server = call_req.server,
                tool = call_req.tool,
                error = %e,
                "MCP authorize failed — denying (fail-closed)"
            );
            return error_response(
                StatusCode::FORBIDDEN,
                "forbidden",
                "Authorization check failed",
            );
        }
    };

    if auth_resp.decision != "permit" {
        return error_response(
            StatusCode::FORBIDDEN,
            "forbidden",
            "MCP tool call denied by policy",
        );
    }

    // TODO: Spawn or reuse MCP subprocess, send JSON-RPC tools/call.
    // For now, return a stub indicating authorization passed but subprocess
    // management is not yet implemented in the broker.
    (
        StatusCode::OK,
        axum::Json(serde_json::json!({
            "data": {
                "content": [{
                    "type": "text",
                    "text": "MCP tool call authorized. Subprocess management pending implementation."
                }],
                "isError": false,
                "correlation_id": auth_resp.correlation_id,
            }
        })),
    )
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async fn get_access_token(state: &SharedState, pk_hash: &str) -> Option<String> {
    let workspaces = state.workspaces.read().await;
    workspaces.get(pk_hash).map(|ws| ws.access_token.clone())
}

async fn try_refresh_and_get_token(state: &SharedState, pk_hash: &str) -> Option<String> {
    if token_refresh::try_reactive_refresh(state, pk_hash).await {
        get_access_token(state, pk_hash).await
    } else {
        None
    }
}

fn ok_response(data: serde_json::Value) -> (StatusCode, axum::Json<serde_json::Value>) {
    (
        StatusCode::OK,
        axum::Json(serde_json::json!({ "data": data })),
    )
}

fn error_response(
    status: StatusCode,
    code: &str,
    message: &str,
) -> (StatusCode, axum::Json<serde_json::Value>) {
    (
        status,
        axum::Json(serde_json::json!({
            "error": { "code": code, "message": message }
        })),
    )
}
