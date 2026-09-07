use std::collections::HashMap;

use axum::{extract::State, Json};
use serde::Deserialize;
use uuid::Uuid;

use crate::middleware::request_id::CorrelationId;
use crate::response::{ApiError, ApiResponse};
use crate::services::mcp_servers::{ImportEntry, ImportOutcome};
use crate::state::AppState;

// --- Request/Response Types ---

#[derive(Deserialize)]
pub(super) struct ImportMcpServersRequest {
    #[serde(alias = "device_id")]
    workspace_id: Uuid,
    /// Optional workspace ID that uploaded the servers (for provenance tracking).
    #[serde(alias = "agent_id")]
    uploading_workspace_id: Option<Uuid>,
    servers: Vec<ImportMcpServerEntry>,
}

#[derive(Deserialize)]
pub(super) struct ImportMcpServerEntry {
    name: String,
    transport: Option<String>,
    #[allow(dead_code)]
    command: Option<String>,
    #[allow(dead_code)]
    args: Option<Vec<String>>,
    #[allow(dead_code)]
    env: Option<HashMap<String, String>>,
    url: Option<String>,
    tools: Option<Vec<ImportToolEntry>>,
    required_credentials: Option<Vec<String>>,
}

#[derive(Deserialize)]
pub(super) struct ImportToolEntry {
    name: String,
    #[allow(dead_code)]
    description: Option<String>,
    #[allow(dead_code)]
    input_schema: Option<serde_json::Value>,
}

/// `POST /api/v1/mcp-servers/import` -- workspace-authenticated bulk MCP import.
///
/// Workspaces forward agent MCP uploads to this endpoint. For each server entry:
/// - If (workspace_id, name) exists -> return "existing"
/// - If not -> create new McpServer with workspace_id (stored as device_id)
///
/// Cedar authorization: evaluates `create` action on `System` resource for the
/// authenticated workspace before allowing any record creation.
pub(super) async fn import_mcp_servers(
    State(state): State<AppState>,
    actor: crate::extractors::AuthenticatedActor,
    axum::Extension(corr): axum::Extension<CorrelationId>,
    Json(req): Json<ImportMcpServersRequest>,
) -> Result<Json<ApiResponse<Vec<ImportOutcome>>>, ApiError> {
    // For workspace auth: verify the workspace_id matches the authenticated workspace
    if let crate::extractors::AuthenticatedActor::Workspace { ref workspace, .. } = actor {
        if workspace.id.0 != req.workspace_id {
            return Err(ApiError::Forbidden(
                "workspace_id does not match authenticated workspace".to_string(),
            ));
        }
    }

    let entries = req
        .servers
        .into_iter()
        .map(|e| ImportEntry {
            name: e.name,
            transport: e.transport,
            url: e.url,
            tools: e
                .tools
                .map(|tools| tools.into_iter().map(|t| t.name).collect()),
            required_credentials: e.required_credentials,
        })
        .collect();
    let results = state
        .services
        .mcp_servers
        .import(
            &actor,
            &corr.0,
            agent_cordon_core::domain::workspace::WorkspaceId(req.workspace_id),
            req.uploading_workspace_id
                .map(agent_cordon_core::domain::workspace::WorkspaceId),
            entries,
        )
        .await?;
    Ok(Json(ApiResponse::ok(results)))
}
