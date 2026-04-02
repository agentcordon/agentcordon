use axum::{
    extract::{Path, State},
    Json,
};
use serde::Deserialize;
use uuid::Uuid;

use agent_cordon_core::domain::audit::{AuditDecision, AuditEvent, AuditEventType};
use agent_cordon_core::domain::mcp::McpServerId;
use agent_cordon_core::domain::policy::PolicyDecisionResult;
use agent_cordon_core::policy::{
    actions, PolicyContext, PolicyEngine, PolicyPrincipal, PolicyResource,
};

use crate::events::UiEvent;
use crate::extractors::{AuthenticatedActor, AuthenticatedUser};
use crate::middleware::request_id::CorrelationId;
use crate::response::{ApiError, ApiResponse};
use crate::state::AppState;

use super::{
    check_manage_mcp_servers, enrich_mcp_server_responses, InstalledWorkspaceInfo,
    McpServerDetailResponse, McpServerResponse, ToolEntry, UpdateMcpServerRequest,
};

/// Query parameters for listing MCP servers.
#[derive(Deserialize)]
pub(super) struct ListMcpServersQuery {
    /// Optional workspace_id filter — only return MCPs for this workspace.
    #[serde(alias = "device_id")]
    workspace_id: Option<Uuid>,
}

pub(super) async fn list_mcp_servers(
    State(state): State<AppState>,
    actor: AuthenticatedActor,
    axum::extract::Query(query): axum::extract::Query<ListMcpServersQuery>,
) -> Result<Json<ApiResponse<Vec<McpServerResponse>>>, ApiError> {
    // Capture the user for tenant scoping
    let calling_user = match &actor {
        AuthenticatedActor::User(user) => {
            // Users require manage_mcp_servers policy
            let is_root = user.is_root;
            let auth = AuthenticatedUser {
                user: user.clone(),
                is_root,
            };
            check_manage_mcp_servers(&state, &auth)?;
            Some(user.clone())
        }
        AuthenticatedActor::Workspace { workspace, .. } => {
            // Workspaces must pass Cedar check for list on System resource
            let decision = state.policy_engine.evaluate(
                &PolicyPrincipal::Workspace(workspace),
                actions::LIST,
                &PolicyResource::System,
                &PolicyContext::default(),
            )?;
            if decision.decision == PolicyDecisionResult::Forbid {
                return Err(ApiError::Forbidden("access denied by policy".to_string()));
            }
            None
        }
    };

    let servers = if let Some(ws_uuid) = query.workspace_id {
        let workspace_id = agent_cordon_core::domain::workspace::WorkspaceId(ws_uuid);
        state
            .store
            .list_mcp_servers_by_workspace(&workspace_id)
            .await?
    } else if let AuthenticatedActor::Workspace { workspace, .. } = &actor {
        // Workspace actors are auto-scoped to their own servers
        state
            .store
            .list_mcp_servers_by_workspace(&workspace.id)
            .await?
    } else if let Some(ref user) = calling_user {
        let is_admin =
            user.role == agent_cordon_core::domain::user::UserRole::Admin || user.is_root;
        if is_admin {
            // Admin users with no filter see all servers
            state.store.list_mcp_servers().await?
        } else {
            // Tenant scoping: non-admin users only see servers for their owned workspaces
            let owned = state.store.get_workspaces_by_owner(&user.id).await?;
            let owned_ids: std::collections::HashSet<String> =
                owned.iter().map(|w| w.id.0.to_string()).collect();
            let all = state.store.list_mcp_servers().await?;
            all.into_iter()
                .filter(|s| owned_ids.contains(&s.workspace_id.0.to_string()))
                .collect()
        }
    } else {
        state.store.list_mcp_servers().await?
    };
    let mut response: Vec<McpServerResponse> =
        servers.iter().map(McpServerResponse::from_server).collect();
    enrich_mcp_server_responses(state.store.as_ref(), &mut response).await;
    Ok(Json(ApiResponse::ok(response)))
}

pub(super) async fn get_mcp_server(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
    Path(id): Path<Uuid>,
) -> Result<Json<ApiResponse<McpServerDetailResponse>>, ApiError> {
    check_manage_mcp_servers(&state, &auth)?;

    let server_id = McpServerId(id);
    let server = state
        .store
        .get_mcp_server(&server_id)
        .await?
        .ok_or_else(|| ApiError::NotFound("MCP server not found".to_string()))?;

    let mut resp = McpServerResponse::from_server(&server);
    enrich_mcp_server_responses(state.store.as_ref(), std::slice::from_mut(&mut resp)).await;

    // Resolve installed workspace: MCP server belongs to exactly one workspace.
    let installed_workspaces = {
        match state.store.get_workspace(&server.workspace_id).await {
            Ok(Some(w))
                if w.status == agent_cordon_core::domain::workspace::WorkspaceStatus::Active =>
            {
                vec![InstalledWorkspaceInfo {
                    id: w.id.0.to_string(),
                    name: w.name.clone(),
                }]
            }
            _ => vec![],
        }
    };

    // Map allowed_tools to tool entries for the FE template
    let tools: Vec<ToolEntry> = resp
        .allowed_tools
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .map(|name| ToolEntry {
            name: name.clone(),
            description: None,
        })
        .collect();

    Ok(Json(ApiResponse::ok(McpServerDetailResponse {
        server: resp,
        installed_workspaces,
        tools,
    })))
}

pub(super) async fn update_mcp_server(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
    axum::Extension(corr): axum::Extension<CorrelationId>,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateMcpServerRequest>,
) -> Result<Json<ApiResponse<McpServerResponse>>, ApiError> {
    let policy_decision = check_manage_mcp_servers(&state, &auth)?;

    let server_id = McpServerId(id);
    let mut server = state
        .store
        .get_mcp_server(&server_id)
        .await?
        .ok_or_else(|| ApiError::NotFound("MCP server not found".to_string()))?;

    if let Some(name) = req.name {
        let trimmed = name.trim().to_string();
        if trimmed.is_empty() {
            return Err(ApiError::BadRequest("name cannot be empty".to_string()));
        }
        if trimmed.contains('.') {
            return Err(ApiError::BadRequest(
                "name must not contain '.' (dots break scope format)".to_string(),
            ));
        }
        server.name = trimmed;
    }
    server.updated_at = chrono::Utc::now();

    state.store.update_mcp_server(&server).await?;

    // Audit
    let event = AuditEvent::builder(AuditEventType::McpServerUpdated)
        .action("update")
        .user_actor(&auth.user)
        .resource("mcp_server", &server.id.0.to_string())
        .correlation_id(&corr.0)
        .decision(
            AuditDecision::Permit,
            Some(&policy_decision.reasons.join(", ")),
        )
        .details(serde_json::json!({
            "server_name": server.name,
        }))
        .build();
    if let Err(e) = state.store.append_audit_event(&event).await {
        tracing::warn!(error = %e, "Failed to write audit event");
    }

    // Emit UI event for browser auto-refresh
    state.ui_event_bus.emit(UiEvent::McpServerChanged {
        server_name: server.name.clone(),
    });

    Ok(Json(ApiResponse::ok(McpServerResponse::from_server(
        &server,
    ))))
}

pub(super) async fn delete_mcp_server(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
    axum::Extension(corr): axum::Extension<CorrelationId>,
    Path(id): Path<Uuid>,
) -> Result<Json<ApiResponse<serde_json::Value>>, ApiError> {
    let policy_decision = check_manage_mcp_servers(&state, &auth)?;

    let server_id = McpServerId(id);

    let server = state
        .store
        .get_mcp_server(&server_id)
        .await?
        .ok_or_else(|| ApiError::NotFound("MCP server not found".to_string()))?;

    // Cascade: delete all MCP grant/deny policies for this server (keyed by server ID)
    let grant_prefix = format!("grant:mcp:{}:", server.id.0);
    let deny_prefix = format!("deny:mcp:{}:", server.id.0);
    state
        .store
        .delete_policies_by_name_prefix(&grant_prefix)
        .await?;
    state
        .store
        .delete_policies_by_name_prefix(&deny_prefix)
        .await?;

    state.store.delete_mcp_server(&server_id).await?;

    // Reload policy engine so deleted grant policies take effect
    super::super::policies::reload_engine(&state).await?;

    // Audit
    let event = AuditEvent::builder(AuditEventType::McpServerDeleted)
        .action("delete")
        .user_actor(&auth.user)
        .resource("mcp_server", &server.id.0.to_string())
        .correlation_id(&corr.0)
        .decision(
            AuditDecision::Permit,
            Some(&policy_decision.reasons.join(", ")),
        )
        .details(serde_json::json!({
            "server_name": server.name,
        }))
        .build();
    if let Err(e) = state.store.append_audit_event(&event).await {
        tracing::warn!(error = %e, "Failed to write audit event");
    }

    // Emit UI event for browser auto-refresh
    state.ui_event_bus.emit(UiEvent::McpServerChanged {
        server_name: server.name.clone(),
    });

    Ok(Json(ApiResponse::ok(
        serde_json::json!({ "deleted": true }),
    )))
}
