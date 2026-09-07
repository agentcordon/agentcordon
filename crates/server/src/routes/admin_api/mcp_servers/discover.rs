use axum::{
    extract::{Path, State},
    Json,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use agent_cordon_core::domain::mcp::{McpServer, McpServerId, McpTool};
use agent_cordon_core::proxy::url_safety::validate_proxy_target_resolved;

use crate::config::AppConfig;
use crate::extractors::AuthenticatedUser;
use crate::middleware::request_id::CorrelationId;
use crate::response::{ApiError, ApiResponse};
use crate::state::AppState;

use super::is_safe_identifier;

// ---------------------------------------------------------------------------
// Tool Discovery (internal helper, used by import on re-registration)
// ---------------------------------------------------------------------------

/// Where an API key goes on the wire.
///
/// Discovery has to present the secret exactly the way the broker will once
/// the server is installed: probing with `Authorization: Bearer` a server that
/// wants `X-API-Key` earns a 401, and provisioning treats a 401 during
/// discovery as "wrong key pasted" and rolls the install back.
#[derive(Clone, Copy, Debug)]
pub(crate) enum ApiKeyPlacement<'a> {
    /// `Authorization: Bearer <secret>` — the default for templates that name
    /// no placement, and what an OAuth access token always uses.
    Bearer,
    /// A custom request header, e.g. `X-API-Key: <secret>`.
    Header(&'a str),
    /// A query parameter appended to the endpoint, e.g. `?api_key=<secret>`.
    Query(&'a str),
}

/// A secret and the placement it is presented under.
#[derive(Clone, Copy, Debug)]
pub(crate) struct DiscoveryCredential<'a> {
    pub secret: &'a str,
    pub placement: ApiKeyPlacement<'a>,
}

impl<'a> DiscoveryCredential<'a> {
    /// The bearer default, for callers with nothing but a secret.
    pub fn bearer(secret: &'a str) -> Self {
        Self {
            secret,
            placement: ApiKeyPlacement::Bearer,
        }
    }
}

/// The URL to POST to: a query-parameter credential lives in the URL, every
/// other placement leaves it alone.
fn request_url(url: &str, credential: Option<DiscoveryCredential<'_>>) -> String {
    let Some(DiscoveryCredential {
        secret,
        placement: ApiKeyPlacement::Query(param),
    }) = credential
    else {
        return url.to_string();
    };
    match reqwest::Url::parse(url) {
        Ok(mut parsed) => {
            parsed.query_pairs_mut().append_pair(param, secret);
            parsed.to_string()
        }
        Err(_) => url.to_string(),
    }
}

/// Best-effort tool discovery: connect to the MCP server and return tool metadata.
///
/// Streamable HTTP MCP servers (e.g. Notion) require the MCP `initialize`
/// handshake per the MCP spec before `tools/list` will respond. We perform:
///   1. POST `initialize`            (capture `Mcp-Session-Id` response header)
///   2. POST `notifications/initialized`
///   3. POST `tools/list`
///
/// If the initialize request itself returns a protocol-level error indicating
/// the server does not support the handshake, we fall back to a single
/// `tools/list` call to keep compatibility with simpler servers.
pub(crate) async fn attempt_tool_discovery(
    config: &AppConfig,
    server: &McpServer,
    credential: Option<DiscoveryCredential<'_>>,
) -> Result<Vec<McpTool>, String> {
    // SSRF protection: resolve the host and check every address, the same
    // check the broker applies to proxied and MCP calls.
    if !config.proxy_allow_loopback {
        validate_proxy_target_resolved(&server.upstream_url).await?;
    }

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .user_agent(agent_cordon_core::user_agent_for("mcp-discovery"))
        .build()
        .map_err(|e| e.to_string())?;

    // Step 1: initialize handshake
    let init_body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": { "name": "agentcordon", "version": "0.2" }
        }
    });

    match send_mcp_request(&client, &server.upstream_url, credential, None, &init_body).await {
        Ok((init_json, session_id)) => {
            if let Some(err) = init_json.get("error").and_then(|e| e.as_object()) {
                // Initialize was understood but refused — fall back to a single
                // tools/list attempt for servers that don't implement the handshake.
                let msg = err
                    .get("message")
                    .and_then(|m| m.as_str())
                    .unwrap_or("unknown");
                tracing::debug!(
                    server = %server.name,
                    error = %msg,
                    "MCP initialize returned error — falling back to plain tools/list"
                );
                return tools_list_only(&client, &server.upstream_url, credential).await;
            }

            // Step 2: notifications/initialized (no response id expected)
            let notify_body = serde_json::json!({
                "jsonrpc": "2.0",
                "method": "notifications/initialized"
            });
            let _ = send_mcp_request(
                &client,
                &server.upstream_url,
                credential,
                session_id.as_deref(),
                &notify_body,
            )
            .await;

            // Step 3: tools/list
            let list_body = serde_json::json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/list",
                "params": {}
            });
            let (list_json, _) = send_mcp_request(
                &client,
                &server.upstream_url,
                credential,
                session_id.as_deref(),
                &list_body,
            )
            .await?;
            extract_tools(&list_json)
        }
        Err(e) if e.starts_with("HTTP 401") || e.starts_with("HTTP 403") => {
            Err(format!("authorization rejected during initialize: {e}"))
        }
        Err(_) => {
            // Network/parse errors from initialize — try the plain path.
            tools_list_only(&client, &server.upstream_url, credential).await
        }
    }
}

/// Fallback: single `tools/list` call (legacy/simple MCP servers).
async fn tools_list_only(
    client: &reqwest::Client,
    url: &str,
    credential: Option<DiscoveryCredential<'_>>,
) -> Result<Vec<McpTool>, String> {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/list",
        "params": {}
    });
    let (json, _) = send_mcp_request(client, url, credential, None, &body).await?;
    if let Some(err) = json.get("error") {
        if err.is_object() {
            let msg = err
                .get("message")
                .and_then(|m| m.as_str())
                .unwrap_or("unknown");
            return Err(format!("JSON-RPC error: {}", msg));
        } else {
            return Err("upstream is not an MCP server (non-JSON-RPC error response)".to_string());
        }
    }
    extract_tools(&json)
}

/// Send a single JSON-RPC request to an MCP streamable-HTTP endpoint and parse
/// the response (handling both `application/json` and `text/event-stream`).
/// Returns the parsed JSON body (or `Value::Null` for empty notification
/// responses) and any `Mcp-Session-Id` header from the response.
async fn send_mcp_request(
    client: &reqwest::Client,
    url: &str,
    credential: Option<DiscoveryCredential<'_>>,
    session_id: Option<&str>,
    body: &serde_json::Value,
) -> Result<(serde_json::Value, Option<String>), String> {
    let mut req = client
        .post(request_url(url, credential))
        .header("Content-Type", "application/json")
        .header("Accept", "application/json, text/event-stream");
    if let Some(cred) = credential {
        match cred.placement {
            ApiKeyPlacement::Bearer => {
                req = req.header("Authorization", format!("Bearer {}", cred.secret));
            }
            ApiKeyPlacement::Header(name) => {
                req = req.header(name, cred.secret);
            }
            // Already in the URL.
            ApiKeyPlacement::Query(_) => {}
        }
    }
    if let Some(sid) = session_id {
        req = req.header("Mcp-Session-Id", sid);
    }

    let response = req.json(body).send().await.map_err(|e| e.to_string())?;
    let status = response.status();
    let session_id_out = response
        .headers()
        .get("mcp-session-id")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    if !status.is_success() {
        return Err(format!("HTTP {}", status.as_u16()));
    }

    // 202 Accepted (typical for notifications) has no body to parse.
    if status.as_u16() == 202 {
        return Ok((serde_json::Value::Null, session_id_out));
    }

    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_lowercase();

    let bytes = response.bytes().await.map_err(|e| e.to_string())?;
    if bytes.len() > 1_048_576 {
        return Err("response too large".to_string());
    }
    if bytes.is_empty() {
        return Ok((serde_json::Value::Null, session_id_out));
    }

    let json: serde_json::Value = if content_type.contains("text/event-stream") {
        let body_text = std::str::from_utf8(&bytes).map_err(|e| e.to_string())?;
        body_text
            .lines()
            .filter_map(|line| {
                line.trim()
                    .strip_prefix("data:")
                    .map(|d| d.trim().to_string())
            })
            .filter(|d| !d.is_empty())
            .find_map(|d| {
                serde_json::from_str::<serde_json::Value>(&d)
                    .ok()
                    .filter(|j| j.get("result").is_some() || j.get("error").is_some())
            })
            .ok_or_else(|| "no JSON-RPC response in SSE stream".to_string())?
    } else {
        serde_json::from_slice(&bytes).map_err(|e| e.to_string())?
    };

    Ok((json, session_id_out))
}

fn extract_tools(body: &serde_json::Value) -> Result<Vec<McpTool>, String> {
    let tools: Vec<McpTool> = body
        .get("result")
        .and_then(|r| r.get("tools"))
        .and_then(|t| serde_json::from_value(t.clone()).ok())
        .unwrap_or_default();
    Ok(tools)
}

// ---------------------------------------------------------------------------
// Rediscovery
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub(super) struct RediscoverResponse {
    /// How many tools the probe found and stored.
    tool_count: usize,
}

/// `POST /api/v1/mcp-servers/{id}/discover-tools`
///
/// Re-run tool discovery against the server's upstream. The install-time
/// probe is best-effort, so a server installed while its upstream was
/// unreachable — behind the SSRF guard, or simply down — is left with no
/// tools; before this route the only way back was delete and reinstall.
/// A probe that fails answers `502` with the reason.
pub(super) async fn rediscover_tools(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
    axum::Extension(corr): axum::Extension<CorrelationId>,
    Path(id): Path<Uuid>,
) -> Result<Json<ApiResponse<RediscoverResponse>>, ApiError> {
    let tool_count = state
        .services
        .mcp_servers
        .rediscover_tools(&auth, &corr.0, &McpServerId(id))
        .await?;

    Ok(Json(ApiResponse::ok(RediscoverResponse { tool_count })))
}

// ---------------------------------------------------------------------------
// Policy Generation
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub(super) struct GeneratePoliciesRequest {
    tools: Vec<String>,
    agent_tags: Vec<String>,
}

#[derive(Serialize)]
pub(super) struct GeneratePoliciesResponse {
    policies_created: Vec<crate::services::mcp_servers::GeneratedPolicy>,
}

/// `POST /api/v1/mcp-servers/{id}/generate-policies`
///
/// For each selected tool and agent tag, generates a Cedar policy that permits
/// agents with the specified tag to call that tool on this MCP server.
/// Stores each policy via the store and reloads the Cedar engine.
pub(super) async fn generate_policies(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
    axum::Extension(corr): axum::Extension<CorrelationId>,
    Path(id): Path<Uuid>,
    Json(req): Json<GeneratePoliciesRequest>,
) -> Result<Json<ApiResponse<GeneratePoliciesResponse>>, ApiError> {
    // Validate input
    if req.tools.is_empty() {
        return Err(ApiError::BadRequest(
            "tools list cannot be empty".to_string(),
        ));
    }
    if req.agent_tags.is_empty() {
        return Err(ApiError::BadRequest(
            "agent_tags list cannot be empty".to_string(),
        ));
    }

    // Limit array sizes to prevent abuse
    if req.tools.len() > 50 {
        return Err(ApiError::BadRequest(
            "maximum 50 tools per request".to_string(),
        ));
    }
    if req.agent_tags.len() > 50 {
        return Err(ApiError::BadRequest(
            "maximum 50 agent_tags per request".to_string(),
        ));
    }

    // Validate tool names and tags to prevent Cedar policy injection
    for tool_name in &req.tools {
        if !is_safe_identifier(tool_name) {
            return Err(ApiError::BadRequest(format!(
                "invalid tool name '{}': must be 1-128 alphanumeric, hyphen, underscore, or dot characters",
                tool_name
            )));
        }
    }
    for tag in &req.agent_tags {
        if !is_safe_identifier(tag) {
            return Err(ApiError::BadRequest(format!(
                "invalid agent tag '{}': must be 1-128 alphanumeric, hyphen, underscore, or dot characters",
                tag
            )));
        }
    }

    let created = state
        .services
        .mcp_servers
        .generate_policies(
            &auth,
            &corr.0,
            &McpServerId(id),
            &req.tools,
            &req.agent_tags,
        )
        .await?;

    Ok(Json(ApiResponse::ok(GeneratePoliciesResponse {
        policies_created: created,
    })))
}
