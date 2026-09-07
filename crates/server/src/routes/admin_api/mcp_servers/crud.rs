use axum::{
    extract::{Path, State},
    Json,
};
use serde::Deserialize;
use uuid::Uuid;

use agent_cordon_core::domain::mcp::McpServerId;
use agent_cordon_core::policy::{actions, PolicyPrincipal, PolicyResource};

use crate::extractors::{AuthenticatedActor, AuthenticatedUser};
use crate::middleware::request_id::CorrelationId;
use crate::response::{ApiError, ApiResponse};
use crate::state::AppState;

use super::{
    enrich_mcp_server_responses, McpServerDetailResponse, McpServerResponse, ToolEntry,
    UpdateMcpServerRequest,
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
            state
                .authz
                .authorize(&auth, actions::MANAGE_MCP_SERVERS, &PolicyResource::System)
                .await?;
            Some(user.clone())
        }
        AuthenticatedActor::Workspace { workspace, .. } => {
            // Workspaces must pass Cedar check for list on System resource
            state
                .authz
                .request(
                    crate::authz::PolicyCaller::Principal {
                        principal: PolicyPrincipal::Workspace(workspace),
                        oauth_claims: None,
                    },
                    &uuid::Uuid::new_v4().to_string(),
                )
                .check(actions::LIST, &PolicyResource::System)
                .await?;

            None
        }
    };

    let servers = if let Some(ws_uuid) = query.workspace_id {
        let workspace_id = agent_cordon_core::domain::workspace::WorkspaceId(ws_uuid);
        state
            .store
            .list_mcp_servers_for_workspace(&workspace_id)
            .await?
    } else if let AuthenticatedActor::Workspace { workspace, .. } = &actor {
        // Workspace actors are auto-scoped to their own servers via the junction.
        state
            .store
            .list_mcp_servers_for_workspace(&workspace.id)
            .await?
    } else if let Some(ref user) = calling_user {
        let is_admin = user.is_admin();
        if is_admin {
            // Admin users with no filter see all servers
            state.store.list_mcp_servers().await?
        } else {
            // Tenant scoping: non-admin users see MCPs junction-bound to any
            // workspace they own (#37 — junction is the single source of truth).
            let owned = state.store.get_workspaces_by_owner(&user.id).await?;
            let mut by_id: std::collections::HashMap<
                String,
                agent_cordon_core::domain::mcp::McpServer,
            > = std::collections::HashMap::new();
            for ws in &owned {
                for s in state.store.list_mcp_servers_for_workspace(&ws.id).await? {
                    by_id.insert(s.id.0.to_string(), s);
                }
            }
            by_id.into_values().collect()
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
    let server_id = McpServerId(id);
    let (server, _) = state
        .services
        .mcp_servers
        .load_and_authorize(&auth, &server_id)
        .await?;

    // `enrich_mcp_server_responses` resolves the live bindings from the
    // `mcp_server_workspaces` junction, the same way the list does.
    let mut resp = McpServerResponse::from_server(&server);
    enrich_mcp_server_responses(state.store.as_ref(), std::slice::from_mut(&mut resp)).await;

    // Report what discovery found — description and input schema — rather
    // than rebuilding a list of bare names from `allowed_tools`.
    let tools: Vec<ToolEntry> = ToolEntry::list_for(&server);

    Ok(Json(ApiResponse::ok(McpServerDetailResponse {
        server: resp,
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
    let server = state
        .services
        .mcp_servers
        .update(
            &auth,
            &corr.0,
            &McpServerId(id),
            req.name,
            req.enabled,
            req.allowed_tools,
        )
        .await?;

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
    state
        .services
        .mcp_servers
        .delete(&auth, &corr.0, &McpServerId(id))
        .await?;

    Ok(Json(ApiResponse::ok(
        serde_json::json!({ "deleted": true }),
    )))
}
