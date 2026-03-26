use axum::{
    extract::{Path, State},
    Json,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use agent_cordon_core::domain::audit::{AuditDecision, AuditEvent, AuditEventType};
use agent_cordon_core::domain::mcp::{McpServer, McpServerId, McpTool};
use agent_cordon_core::domain::policy::{PolicyId, StoredPolicy};
use agent_cordon_core::policy::PolicyEngine;
use agent_cordon_core::proxy::url_safety::validate_proxy_target;

use crate::extractors::AuthenticatedUser;
use crate::middleware::request_id::CorrelationId;
use crate::response::{ApiError, ApiResponse};
use crate::state::AppState;

use super::super::policies::reload_engine;
use super::check_manage_mcp_servers;
use super::is_safe_identifier;

// ---------------------------------------------------------------------------
// Tool Discovery (internal helper, used by import on re-registration)
// ---------------------------------------------------------------------------

/// Best-effort tool discovery: connect to the MCP server and return tool names.
/// Returns an empty vec on any failure (network, parse, etc.).
#[allow(dead_code)]
pub(super) async fn attempt_tool_discovery(
    state: &AppState,
    server: &McpServer,
) -> Result<Vec<String>, String> {
    // STDIO transport servers cannot be discovered via HTTP from the control plane
    if server.transport == "stdio" || server.upstream_url.starts_with("stdio://") {
        return Err(
            "STDIO transport servers cannot be discovered from the control plane. \
                    Use the device's MCP proxy endpoint to interact with STDIO servers."
                .to_string(),
        );
    }

    // SSRF protection
    if !state.config.proxy_allow_loopback {
        validate_proxy_target(&server.upstream_url).map_err(|e| e.to_string())?;
    }

    let jsonrpc_body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/list",
        "params": {}
    });

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .map_err(|e| e.to_string())?;

    let response = client
        .post(&server.upstream_url)
        .header("Content-Type", "application/json")
        .json(&jsonrpc_body)
        .send()
        .await
        .map_err(|e| e.to_string())?;

    if !response.status().is_success() {
        return Err(format!("HTTP {}", response.status().as_u16()));
    }

    let bytes = response.bytes().await.map_err(|e| e.to_string())?;
    if bytes.len() > 1_048_576 {
        return Err("response too large".to_string());
    }

    let body: serde_json::Value = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;

    // Only treat JSON-RPC error objects (not REST error strings) as errors
    if let Some(err) = body.get("error") {
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

    let tools: Vec<McpTool> = body
        .get("result")
        .and_then(|r| r.get("tools"))
        .and_then(|t| serde_json::from_value(t.clone()).ok())
        .unwrap_or_default();

    Ok(tools.into_iter().map(|t| t.name).collect())
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
    policies_created: Vec<GeneratedPolicyInfo>,
}

#[derive(Serialize)]
pub(super) struct GeneratedPolicyInfo {
    id: String,
    name: String,
    cedar_policy: String,
}

/// Generate a Cedar policy allowing agents with a given tag to call a
/// specific tool on a specific MCP server.
fn generate_cedar_policy(tag: &str, tool_name: &str, server_id: &str) -> String {
    format!(
        r#"// Auto-generated: Allow agents tagged "{tag}" to use tool "{tool_name}" on MCP server "{server_id}"
permit(
  principal is AgentCordon::Workspace,
  action == AgentCordon::Action::"mcp_tool_call",
  resource == AgentCordon::McpServer::"{server_id}"
) when {{
  principal.tags.contains("{tag}") &&
  context.tool_name == "{tool_name}"
}};"#,
        tag = tag,
        tool_name = tool_name,
        server_id = server_id
    )
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
    let policy_decision = check_manage_mcp_servers(&state, &auth)?;

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

    let server_id = McpServerId(id);
    let server = state
        .store
        .get_mcp_server(&server_id)
        .await?
        .ok_or_else(|| ApiError::NotFound("MCP server not found".to_string()))?;

    // Load existing policies to check for duplicates
    let existing_policies = state.store.list_policies().await?;
    let existing_names: std::collections::HashSet<String> =
        existing_policies.iter().map(|p| p.name.clone()).collect();

    let mut created_policies: Vec<GeneratedPolicyInfo> = Vec::new();

    let server_id_str = server.id.0.to_string();
    for tool_name in &req.tools {
        for tag in &req.agent_tags {
            let policy_name = format!("mcp-{}-{}-{}", server_id_str, tool_name, tag);

            // Skip if a policy with this name already exists
            if existing_names.contains(&policy_name) {
                tracing::info!(
                    policy_name = %policy_name,
                    "skipping duplicate policy — already exists"
                );
                continue;
            }

            let cedar_text = generate_cedar_policy(tag, tool_name, &server_id_str);

            // Validate the generated Cedar policy before storing
            state
                .policy_engine
                .validate_policy_text(&cedar_text)
                .map_err(|e| {
                    ApiError::Internal(format!(
                        "generated policy failed validation for tool '{}', tag '{}': {}",
                        tool_name, tag, e
                    ))
                })?;

            let now = chrono::Utc::now();

            let policy = StoredPolicy {
                id: PolicyId(Uuid::new_v4()),
                name: policy_name.clone(),
                description: Some(format!(
                    "Auto-generated: Allow agents tagged \"{}\" to use tool \"{}\" on MCP server \"{}\"",
                    tag, tool_name, server.name
                )),
                cedar_policy: cedar_text.clone(),
                enabled: true,
                is_system: false,
                created_at: now,
                updated_at: now,
            };

            state.store.store_policy(&policy).await?;

            created_policies.push(GeneratedPolicyInfo {
                id: policy.id.0.to_string(),
                name: policy_name,
                cedar_policy: cedar_text,
            });
        }
    }

    // Reload the Cedar engine after all policies are created
    reload_engine(&state).await?;

    // Emit UI event for browser auto-refresh
    for p in &created_policies {
        state
            .ui_event_bus
            .emit(crate::events::UiEvent::PolicyChanged {
                policy_name: p.name.clone(),
            });
    }

    let policy_count = created_policies.len();
    let policy_names: Vec<String> = created_policies.iter().map(|p| p.name.clone()).collect();

    // Audit event
    let event = AuditEvent::builder(AuditEventType::McpPoliciesGenerated)
        .action("generate_policies")
        .user_actor(&auth.user)
        .resource("mcp_server", &server.id.0.to_string())
        .correlation_id(&corr.0)
        .decision(
            AuditDecision::Permit,
            Some(&policy_decision.reasons.join(", ")),
        )
        .details(serde_json::json!({
            "server_name": server.name,
            "policy_count": policy_count,
            "policy_names": policy_names,
            "tools": req.tools,
            "agent_tags": req.agent_tags,
        }))
        .build();
    if let Err(e) = state.store.append_audit_event(&event).await {
        tracing::warn!(error = %e, "Failed to write audit event");
    }

    Ok(Json(ApiResponse::ok(GeneratePoliciesResponse {
        policies_created: created_policies,
    })))
}
