//! Server-side MCP tool-call authorization endpoint.
//!
//! `POST /api/v1/workspaces/mcp-authorize` — evaluates Cedar policy for an
//! MCP tool call and returns the permit/forbid decision with contributing
//! policy reasons.

use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use agent_cordon_core::domain::audit::{AuditDecision, AuditEvent, AuditEventType};
use agent_cordon_core::domain::policy::PolicyDecisionResult;
use agent_cordon_core::policy::{actions, claim_keys, PolicyPrincipal, PolicyResource};

use crate::extractors::AuthenticatedWorkspace;
use crate::response::{ApiError, ApiResponse};
use crate::state::AppState;

/// Request body for MCP tool-call authorization.
#[derive(Deserialize)]
pub struct McpAuthorizeRequest {
    server_name: String,
    tool_name: String,
}

/// Response for MCP tool-call authorization.
///
/// Reasons (`policy_id`, `policy_name`, `statement_index`) are
/// intentionally absent: this is an untrusted-caller-facing endpoint and
/// the reasons would let workspaces enumerate the policy graph. The full
/// reasons are still recorded in the `PolicyEvaluated` audit event,
/// retrievable by admins via the correlation ID through the audit query
/// path. Privileged channel for privileged consumers; opaque response
/// for untrusted callers.
#[derive(Serialize)]
pub struct McpAuthorizeResponse {
    decision: String,
    correlation_id: String,
}

/// POST /api/v1/workspaces/mcp-authorize — evaluate Cedar policy for an MCP tool call.
///
/// Auth: workspace identity JWT (Authorization: Bearer).
/// Returns the permit/forbid decision (no reasons).
pub(super) async fn authorize(
    State(state): State<AppState>,
    workspace: AuthenticatedWorkspace,
    Json(req): Json<McpAuthorizeRequest>,
) -> Result<Json<ApiResponse<McpAuthorizeResponse>>, ApiError> {
    workspace.require_scope(agent_cordon_core::oauth2::types::OAuthScope::McpInvoke)?;
    let correlation_id = Uuid::new_v4().to_string();

    // Validate inputs.
    let server_name = req.server_name.trim().to_string();
    let tool_name = req.tool_name.trim().to_string();
    if server_name.is_empty() || server_name.len() > 128 {
        return Err(ApiError::BadRequest(
            "server_name must be 1-128 characters".into(),
        ));
    }
    if tool_name.is_empty() || tool_name.len() > 128 {
        return Err(ApiError::BadRequest(
            "tool_name must be 1-128 characters".into(),
        ));
    }

    // MCP servers are scoped by owner. Multiple workspaces (and multiple users)
    // can have an MCP server with the same name (e.g., "mock-mcp"). When a
    // workspace asks for "mock-mcp", we must resolve to a server it actually
    // owns, not the first global match. Look up servers belonging to the
    // workspace's owner first; fall back to any same-name enabled server only
    // if the workspace has no owner (legacy data).
    let all_servers = state.store.list_mcp_servers().await?;
    let workspace_owner = workspace.workspace.owner_id.as_ref();
    let mcp_server = all_servers
        .iter()
        .find(|s| {
            s.name == server_name
                && s.enabled
                && match (workspace_owner, s.created_by_user.as_ref()) {
                    (Some(ws_owner), Some(srv_owner)) => ws_owner == srv_owner,
                    _ => false,
                }
        })
        .cloned()
        .or_else(|| {
            // Fallback for legacy data with no owner: take any same-name enabled server.
            // Cedar will still deny via implicit deny since the principal/resource won't
            // share an owner.
            all_servers
                .into_iter()
                .find(|s| s.name == server_name && s.enabled)
        });

    let mcp_server = match mcp_server {
        Some(s) => s,
        None => {
            // Unknown server — forbid and audit.
            let event = AuditEvent::builder(AuditEventType::McpToolCallDenied)
                .action(&format!("mcp_tool_call/{}", tool_name))
                .resource("mcp_server", &server_name)
                .workspace_actor(&workspace.workspace.id, &workspace.workspace.name)
                .decision(AuditDecision::Forbid, Some("unknown_server"))
                .details(serde_json::json!({
                    "server_name": server_name,
                    "tool_name": tool_name,
                    "policy_decision": "forbid",
                }))
                .correlation_id(&correlation_id)
                .build();

            if let Err(e) = state.store.append_audit_event(&event).await {
                tracing::warn!(error = %e, "failed to write mcp-authorize audit event");
            }

            return Ok(Json(ApiResponse::ok(McpAuthorizeResponse {
                decision: "forbid".to_string(),
                correlation_id,
            })));
        }
    };

    // Evaluate Cedar policy via the Authz seam.
    let resource = PolicyResource::McpServer {
        id: mcp_server.id.0.to_string(),
        name: mcp_server.name.clone(),
        enabled: mcp_server.enabled,
        tags: mcp_server.tags.clone(),
        owner: mcp_server.created_by_user.clone(),
    };

    let decision = state
        .authz
        .request(
            crate::authz::PolicyCaller::Principal {
                principal: PolicyPrincipal::Workspace(&workspace.workspace),
                oauth_claims: workspace.oauth_claims.clone(),
            },
            &correlation_id,
        )
        .with_claim(claim_keys::TOOL_NAME, serde_json::json!(tool_name.clone()))
        .check_with_reasons(actions::MCP_TOOL_CALL, &resource)
        .await?;

    let is_permit = decision.decision == PolicyDecisionResult::Permit;
    let decision_str = if is_permit { "permit" } else { "forbid" };

    // Authz auto-emits the PolicyEvaluated audit event with full reasons.
    // Emit a domain-specific McpToolCalled event on permit for observability.
    // Reasons are deliberately NOT serialised into the HTTP response — they
    // remain in the audit log only (retrievable by admins via correlation_id).
    if is_permit {
        let event = AuditEvent::builder(AuditEventType::McpToolCalled)
            .action("mcp_tool_call")
            .workspace_actor(&workspace.workspace.id, &workspace.workspace.name)
            .resource("mcp_server", &mcp_server.id.0.to_string())
            .correlation_id(&correlation_id)
            .decision(AuditDecision::Permit, None)
            .details(serde_json::json!({
                "server_name": server_name,
                "tool_name": tool_name,
            }))
            .build();
        if let Err(e) = state.store.append_audit_event(&event).await {
            tracing::warn!(error = %e, "failed to write McpToolCalled audit event");
        }
    }

    Ok(Json(ApiResponse::ok(McpAuthorizeResponse {
        decision: decision_str.to_string(),
        correlation_id,
    })))
}
