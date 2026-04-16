use std::collections::HashMap;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use serde::Deserialize;

use agent_cordon_core::proxy::url_safety::validate_proxy_target_resolved;

use crate::auth::AuthenticatedWorkspace;
use crate::credential_transform::{self, CredentialMaterial};
use crate::oauth2_refresh::{RotationCallback, RotationError};
use crate::server_client::ServerClient;
use crate::state::{CachedCredential, SharedState};

use super::helpers::{
    error_response, get_access_token, ok_response, require_scope, with_token_refresh,
};

/// Exchange an `oauth2_client_credentials` credential for an access token
/// via the provider's token endpoint, using the broker's `OAuth2TokenManager`.
async fn resolve_client_credentials_value(
    state: &SharedState,
    credential_name: &str,
    cred: &CachedCredential,
) -> Option<String> {
    let client_id = cred.metadata.get("oauth2_client_id")?;
    let token_endpoint = cred.metadata.get("oauth2_token_endpoint")?;
    let scopes = cred
        .metadata
        .get("oauth2_scopes")
        .cloned()
        .unwrap_or_default();

    // Build a minimal StoredCredential for the token manager's cache key.
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(credential_name.as_bytes());
    let cache_id = uuid::Uuid::from_bytes(hash[..16].try_into().unwrap());
    let cache_cred = agent_cordon_core::domain::credential::StoredCredential {
        id: agent_cordon_core::domain::credential::CredentialId(cache_id),
        name: credential_name.to_string(),
        service: String::new(),
        encrypted_value: vec![],
        nonce: vec![],
        scopes: vec![],
        metadata: serde_json::json!({
            "oauth2_client_id": client_id,
            "oauth2_token_endpoint": token_endpoint,
            "oauth2_scopes": scopes,
        }),
        created_by: None,
        created_by_user: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
        allowed_url_pattern: None,
        expires_at: None,
        transform_script: None,
        transform_name: None,
        vault: String::new(),
        credential_type: "oauth2_client_credentials".to_string(),
        tags: vec![],
        description: None,
        target_identity: None,
        key_version: 0,
    };

    match state.oauth2_cc.get_token(&cache_cred, &cred.value).await {
        Ok(result) => {
            tracing::debug!(
                credential = %credential_name,
                cached = !result.was_refreshed,
                "oauth2 client_credentials token acquired for MCP"
            );
            Some(result.access_token)
        }
        Err(e) => {
            tracing::warn!(
                credential = %credential_name,
                error = %e,
                "OAuth2 client_credentials token exchange failed for MCP credential"
            );
            None
        }
    }
}

/// Resolve the effective credential value for a cached credential.
///
/// For `oauth2_user_authorization` credentials, exchanges the stored refresh
/// token for an access token via the token endpoint. For `oauth2_client_credentials`,
/// exchanges the client secret for an access token via the client credentials grant.
/// For all other types, returns the raw value as-is.
async fn resolve_credential_value(
    state: &SharedState,
    pk_hash: &str,
    credential_name: &str,
    cred: &CachedCredential,
) -> Option<String> {
    if cred.credential_type == "oauth2_client_credentials" {
        return resolve_client_credentials_value(state, credential_name, cred).await;
    }

    if cred.credential_type != "oauth2_user_authorization" {
        return Some(cred.value.clone());
    }

    let token_url = cred.metadata.get("oauth2_token_url");
    let client_id = cred.metadata.get("oauth2_client_id");
    let client_secret = cred.metadata.get("oauth2_client_secret");

    match (token_url, client_id, client_secret) {
        (Some(token_url), Some(client_id), Some(client_secret)) => {
            // Build a rotation callback closing over the workspace context
            // so that when the provider rotates the refresh token, the new
            // value is (a) persisted on the server, then (b) reflected in
            // the broker's in-memory cache — both before the access token
            // is cached. See `OAuth2RefreshManager::get_access_token`.
            let state_cb = state.clone();
            let pk_hash_cb = pk_hash.to_string();
            let cred_name_cb = credential_name.to_string();
            let rotation_callback: RotationCallback = std::sync::Arc::new(
                move |new_refresh: String| {
                    let state = state_cb.clone();
                    let pk_hash = pk_hash_cb.clone();
                    let cred_name = cred_name_cb.clone();
                    Box::pin(async move {
                        let workspace_token = get_access_token(&state, &pk_hash).await.ok_or_else(
                        || {
                            RotationError(
                                "no workspace access token available to persist rotated refresh token"
                                    .to_string(),
                            )
                        },
                    )?;
                        let server_client =
                            ServerClient::new(state.http_client.clone(), state.server_url.clone());
                        server_client
                            .update_mcp_credential_refresh_token(
                                &workspace_token,
                                &cred_name,
                                &new_refresh,
                            )
                            .await
                            .map_err(|e| RotationError(e.to_string()))?;
                        // Persist succeeded — now update the broker's in-memory
                        // cache so the next refresh uses the rotated value.
                        state
                            .update_mcp_credential_value(&pk_hash, &cred_name, new_refresh.clone())
                            .await;
                        Ok(())
                    })
                },
            );

            match state
                .oauth2_refresh
                .get_access_token(
                    credential_name,
                    &cred.value,
                    token_url,
                    client_id,
                    client_secret,
                    Some(rotation_callback),
                )
                .await
            {
                Ok(token) => Some(token),
                Err(e) => {
                    tracing::warn!(
                        credential = %credential_name,
                        "OAuth2 token exchange failed, credential will not be injected"
                    );
                    tracing::debug!(error = %e, "token exchange error details");
                    None
                }
            }
        }
        _ => {
            tracing::warn!(
                credential = %credential_name,
                "OAuth2 authorization code credential missing required metadata, \
                 credential will not be injected"
            );
            None
        }
    }
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

    if content_type.contains("text/event-stream") {
        let body_text = resp
            .text()
            .await
            .map_err(|e| format!("failed to read SSE body: {e}"))?;

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
        // Try reading as text first — if json() fails on streaming responses,
        // we can still attempt SSE parsing as a fallback.
        let body_text = resp
            .text()
            .await
            .map_err(|e| format!("failed to read response body: {e}"))?;

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

    if let Err(e) = require_scope(&state, &auth.pk_hash, "mcp:discover", "mcp.list_tools").await {
        return e;
    }

    let server_client = ServerClient::new(state.http_client.clone(), state.server_url.clone());

    let mut all_tools: Vec<crate::server_client::McpToolSummary> =
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
    // that require authentication for tool discovery.
    crate::mcp_sync::sync_workspace_now(&state, &auth.pk_hash).await;

    // Collect servers needing live discovery (servers not already represented in all_tools)
    let servers_to_probe: Vec<(String, String, crate::state::CachedCredential)> = {
        let configs = state.mcp_configs.read().await;
        if let Some(servers) = configs.get(&auth.pk_hash) {
            servers
                .iter()
                .filter(|cached| {
                    // Skip servers that already have tools in the server response
                    !all_tools.iter().any(|t| t.server == cached.name)
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
        let jsonrpc = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list",
            "params": {}
        });

        let mut req = state
            .http_client
            .post(&url)
            .header("Content-Type", "application/json")
            .timeout(std::time::Duration::from_secs(5));

        // Resolve credential value (exchanges refresh token for access token if OAuth2 authz code)
        if let Some(effective_value) =
            resolve_credential_value(&state, &auth.pk_hash, &server_name, &cred).await
        {
            let material = CredentialMaterial {
                credential_type: Some(cred.credential_type.clone()),
                value: effective_value,
                username: None,
                metadata: cred.metadata.clone(),
            };
            if let Ok(transformed) = credential_transform::apply(
                &material,
                cred.transform_name.as_deref(),
                "POST",
                &url,
                &HashMap::new(),
                None,
            ) {
                for (k, v) in &transformed.headers {
                    req = req.header(k, v);
                }
            }
        }

        let resp = match req.json(&jsonrpc).send().await {
            Ok(r) if r.status().is_success() => r,
            _ => continue,
        };

        let body: serde_json::Value = match parse_mcp_response(resp).await {
            Ok(v) => v,
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
                all_tools.push(crate::server_client::McpToolSummary {
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

    // Look up target server: try cached config first, fall back to server fetch.
    let (mcp_url, cached_credential) = {
        let configs = state.mcp_configs.read().await;
        if let Some(servers) = configs.get(&auth.pk_hash) {
            if let Some(cached) = servers.iter().find(|s| s.name == server_name) {
                let url = if cached.url.is_empty() {
                    None
                } else {
                    Some(cached.url.clone())
                };
                (url, cached.credential.clone())
            } else {
                (None, None)
            }
        } else {
            (None, None)
        }
    };

    // If cache miss OR server found without credentials (stale sync), trigger
    // an on-demand sync and retry. This handles both "just provisioned" and
    // "background sync ran without include_credentials" scenarios.
    // For servers with auth_method "none", a missing credential is expected.
    let cached_auth_method = {
        let configs = state.mcp_configs.read().await;
        configs
            .get(&auth.pk_hash)
            .and_then(|servers| servers.iter().find(|s| s.name == server_name))
            .map(|s| s.auth_method.clone())
    };
    let needs_sync = mcp_url.is_none()
        || (cached_credential.is_none() && cached_auth_method.as_deref() != Some("none"));
    let (mcp_url, cached_credential) = if needs_sync {
        tracing::info!(
            server = %server_name,
            has_url = mcp_url.is_some(),
            has_cred = cached_credential.is_some(),
            pk_hash = %auth.pk_hash,
            "MCP cache miss/stale, triggering on-demand sync"
        );
        crate::mcp_sync::sync_workspace_now(&state, &auth.pk_hash).await;

        // Retry cache lookup after sync
        let configs = state.mcp_configs.read().await;
        if let Some(servers) = configs.get(&auth.pk_hash) {
            if let Some(cached) = servers.iter().find(|s| s.name == server_name) {
                let url = if cached.url.is_empty() {
                    None
                } else {
                    Some(cached.url.clone())
                };
                tracing::info!(
                    server = %server_name,
                    has_url_after = url.is_some(),
                    has_cred_after = cached.credential.is_some(),
                    "on-demand sync result"
                );
                (url, cached.credential.clone())
            } else {
                tracing::warn!(server = %server_name, "server not found in cache after sync");
                (None, None)
            }
        } else {
            tracing::warn!(pk_hash = %auth.pk_hash, "no cache entry for workspace after sync");
            (None, None)
        }
    } else {
        tracing::debug!(
            server = %server_name,
            has_cred = cached_credential.is_some(),
            "using cached MCP config"
        );
        (mcp_url, cached_credential)
    };

    let mcp_url = match mcp_url {
        Some(url) => url,
        None => {
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
    if !state.config.proxy_allow_loopback {
        if let Err(reason) = validate_proxy_target_resolved(&mcp_url).await {
            return error_response(
                StatusCode::BAD_REQUEST,
                "ssrf_blocked",
                &format!("Blocked by SSRF protection: {reason}"),
            );
        }
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

    // Build the request, injecting credentials if available
    let mut req_builder = state
        .http_client
        .post(&mcp_url)
        .header("Content-Type", "application/json");

    if let Some(ref cred) = cached_credential {
        // Resolve credential value (exchanges refresh token for access token if OAuth2 authz code)
        if let Some(effective_value) =
            resolve_credential_value(&state, &auth.pk_hash, &server_name, cred).await
        {
            let material = CredentialMaterial {
                credential_type: Some(cred.credential_type.clone()),
                value: effective_value,
                username: None,
                metadata: cred.metadata.clone(),
            };
            match credential_transform::apply(
                &material,
                cred.transform_name.as_deref(),
                "POST",
                &mcp_url,
                &HashMap::new(),
                None,
            ) {
                Ok(transformed) => {
                    for (k, v) in &transformed.headers {
                        req_builder = req_builder.header(k, v);
                    }
                    // Query params are not directly injectable on reqwest builder
                    // after URL construction, but MCP servers typically use header auth.
                    if !transformed.query_params.is_empty() {
                        let mut url_with_params = match reqwest::Url::parse(&mcp_url) {
                            Ok(u) => u,
                            Err(e) => {
                                return error_response(
                                    StatusCode::BAD_GATEWAY,
                                    "bad_gateway",
                                    &format!("invalid MCP server URL '{}': {}", server_name, e),
                                );
                            }
                        };
                        for (k, v) in &transformed.query_params {
                            url_with_params.query_pairs_mut().append_pair(k, v);
                        }
                        req_builder = state
                            .http_client
                            .post(url_with_params)
                            .header("Content-Type", "application/json");
                        // Re-add credential headers
                        for (k, v) in &transformed.headers {
                            req_builder = req_builder.header(k, v);
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, server = %server_name, "credential transform failed, proceeding without injection");
                }
            }
        } // if let Some(effective_value)
    }

    let mcp_resp = match req_builder.json(&jsonrpc_request).send().await {
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
    let mcp_body: serde_json::Value = match parse_mcp_response(mcp_resp).await {
        Ok(v) => v,
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
