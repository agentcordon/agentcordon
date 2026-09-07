//! Server-side MCP tool-call authorization endpoint.
//!
//! `POST /api/v1/workspaces/mcp-authorize` — evaluates Cedar policy for an
//! MCP tool call and returns the permit/forbid decision with contributing
//! policy reasons.

use axum::{extract::State, Json};
use uuid::Uuid;

use agent_cordon_core::domain::policy::PolicyDecisionResult;
use agent_cordon_core::policy::{actions, claim_keys, PolicyPrincipal, PolicyResource};

use crate::extractors::AuthenticatedWorkspace;
use crate::response::{ApiError, ApiResponse};
use crate::services::mcp_servers::ToolCallDenial;
use crate::state::AppState;

pub use agent_cordon_core::wire::mcp::{McpAuthorizeRequest, McpAuthorizeResponse};

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
                .iter()
                .find(|s| s.name == server_name && s.enabled)
                .cloned()
        });

    let mcp_server = match mcp_server {
        Some(s) => s,
        None => {
            // Nothing resolved. A server that exists but is switched off is
            // the documented revocation path and not a typo, and the audit row
            // has to say which of the two it was.
            let disabled = all_servers.iter().find(|s| s.name == server_name);
            let denial = match disabled {
                Some(_) => ToolCallDenial::ServerDisabled,
                None => ToolCallDenial::UnknownServer,
            };
            state
                .services
                .mcp_servers
                .record_tool_call_denied(
                    &workspace.workspace,
                    &correlation_id,
                    disabled,
                    &server_name,
                    &tool_name,
                    denial,
                )
                .await;

            return Ok(Json(ApiResponse::ok(McpAuthorizeResponse {
                decision: McpAuthorizeResponse::FORBID.to_string(),
                correlation_id,
            })));
        }
    };

    // The allow-list is checked before Cedar, and independently of it: a tool
    // outside `allowed_tools` is not exposed to this workspace at all, so
    // there is no policy question to ask about it. A Cedar permit on the
    // server as a whole must not reach a tool an operator has excluded.
    if let Some(allowed) = mcp_server.allowed_tools.as_deref() {
        if !allowed.iter().any(|t| t == &tool_name) {
            state
                .services
                .mcp_servers
                .record_tool_call_denied(
                    &workspace.workspace,
                    &correlation_id,
                    Some(&mcp_server),
                    &server_name,
                    &tool_name,
                    ToolCallDenial::ToolNotAllowed,
                )
                .await;
            return Ok(Json(ApiResponse::ok(McpAuthorizeResponse {
                decision: McpAuthorizeResponse::FORBID.to_string(),
                correlation_id,
            })));
        }
    }

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
    let decision_str = if is_permit {
        McpAuthorizeResponse::PERMIT
    } else {
        McpAuthorizeResponse::FORBID
    };

    // Authz auto-emits the PolicyEvaluated audit event with full reasons.
    // Emit a domain-specific McpToolCalled event on permit for observability.
    // Reasons are deliberately NOT serialised into the HTTP response — they
    // remain in the audit log only (retrievable by admins via correlation_id).
    if is_permit {
        state
            .services
            .mcp_servers
            .record_tool_called(
                &workspace.workspace,
                &correlation_id,
                &mcp_server,
                &server_name,
                &tool_name,
            )
            .await;
    } else {
        // A refusal is a domain event too. Without this a per-tool Deny left
        // only a generic `policy_evaluated` forbid, so the one thing the deny
        // exists to produce was invisible to every MCP surface in the UI.
        state
            .services
            .mcp_servers
            .record_tool_call_denied(
                &workspace.workspace,
                &correlation_id,
                Some(&mcp_server),
                &server_name,
                &tool_name,
                ToolCallDenial::Policy(&decision.reasons),
            )
            .await;
    }

    Ok(Json(ApiResponse::ok(McpAuthorizeResponse {
        decision: decision_str.to_string(),
        correlation_id,
    })))
}
