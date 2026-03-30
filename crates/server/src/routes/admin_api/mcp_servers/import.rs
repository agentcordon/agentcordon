use std::collections::HashMap;

use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use agent_cordon_core::domain::audit::{AuditDecision, AuditEvent, AuditEventType};
use agent_cordon_core::domain::mcp::{McpServer, McpServerId};
use agent_cordon_core::domain::policy::PolicyDecisionResult;
use agent_cordon_core::policy::{
    actions, PolicyContext, PolicyEngine, PolicyPrincipal, PolicyResource,
};

use crate::events::UiEvent;
use crate::middleware::request_id::CorrelationId;
use crate::response::{ApiError, ApiResponse};
use crate::state::AppState;

// --- Request/Response Types ---

#[derive(Deserialize)]
pub(super) struct ImportMcpServersRequest {
    #[serde(alias = "device_id")]
    workspace_id: Uuid,
    /// Optional workspace ID that uploaded the servers (for auto-granting policies).
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

#[derive(Serialize)]
pub(super) struct ImportMcpServerResult {
    name: String,
    id: String,
    status: String, // "created" | "existing" | "updated"
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
    headers: axum::http::HeaderMap,
    axum::Extension(corr): axum::Extension<CorrelationId>,
    Json(req): Json<ImportMcpServersRequest>,
) -> Result<Json<ApiResponse<Vec<ImportMcpServerResult>>>, ApiError> {
    use crate::extractors::authenticated_workspace::authenticate_workspace;

    let auth_header = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| ApiError::Unauthorized("missing Authorization header".to_string()))?;

    let auth = authenticate_workspace(&state, auth_header).await?;
    let workspace = auth.workspace;

    // Verify the workspace_id in the request matches the authenticated workspace
    if workspace.id.0 != req.workspace_id {
        return Err(ApiError::Forbidden(
            "workspace_id does not match authenticated workspace".to_string(),
        ));
    }

    // Cedar policy check: workspace must be authorized to create resources.
    // MCP import is a workspace-driven "create" operation on System resources,
    // governed by default Cedar policy section 1c.
    let policy_decision = state.policy_engine.evaluate(
        &PolicyPrincipal::Workspace(&workspace),
        actions::CREATE,
        &PolicyResource::System,
        &PolicyContext::default(),
    )?;
    if policy_decision.decision == PolicyDecisionResult::Forbid {
        return Err(ApiError::Forbidden(
            "access denied by policy: workspace not authorized to import MCP servers".to_string(),
        ));
    }

    let ws_id = agent_cordon_core::domain::workspace::WorkspaceId(req.workspace_id);
    let now = chrono::Utc::now();
    let mut results = Vec::new();

    for entry in &req.servers {
        let name = entry.name.trim().to_string();
        if name.is_empty() {
            continue;
        }
        if name.contains('.') {
            continue; // dots break scope format
        }

        // Check if (device_id, name) already exists
        if let Some(existing) = state
            .store
            .get_mcp_server_by_workspace_and_name(&ws_id, &name)
            .await?
        {
            // Update tools on existing server if it has none and import provides them
            let status = if existing.allowed_tools.is_none() {
                if let Some(ref tools) = entry.tools {
                    if !tools.is_empty() {
                        let mut updated = existing.clone();
                        updated.allowed_tools =
                            Some(tools.iter().map(|t| t.name.clone()).collect());
                        state.store.update_mcp_server(&updated).await?;
                        "updated"
                    } else {
                        "existing"
                    }
                } else {
                    "existing"
                }
            } else {
                "existing"
            };
            results.push(ImportMcpServerResult {
                name,
                id: existing.id.0.to_string(),
                status: status.to_string(),
            });
            continue;
        }

        let transport = entry
            .transport
            .clone()
            .unwrap_or_else(|| "stdio".to_string());
        let upstream_url = if transport == "stdio" {
            format!("stdio://{}", name)
        } else {
            String::new()
        };

        let allowed_tools = entry
            .tools
            .as_ref()
            .map(|tools| tools.iter().map(|t| t.name.clone()).collect());

        let server = McpServer {
            id: McpServerId(Uuid::new_v4()),
            workspace_id: ws_id.clone(),
            name: name.clone(),
            upstream_url,
            transport,
            allowed_tools,
            enabled: true,
            created_by: req
                .uploading_workspace_id
                .map(agent_cordon_core::domain::workspace::WorkspaceId),
            created_at: now,
            updated_at: now,
            tags: vec![],
            required_credentials: entry.required_credentials.as_ref().map(|creds| {
                creds
                    .iter()
                    .filter_map(|s| {
                        uuid::Uuid::parse_str(s)
                            .ok()
                            .map(agent_cordon_core::domain::credential::CredentialId)
                    })
                    .collect()
            }),
        };

        state.store.create_mcp_server(&server).await?;

        // Audit event -- record the Cedar policy decision instead of a bypass marker
        let mut builder = AuditEvent::builder(AuditEventType::McpServerRegistered)
            .action("import")
            .resource("mcp_server", &server.id.0.to_string())
            .correlation_id(&corr.0)
            .decision(
                AuditDecision::Permit,
                Some(&policy_decision.reasons.join(", ")),
            )
            .details(serde_json::json!({
                "server_name": name,
                "device_id": req.workspace_id.to_string(),
                "source": "agent_upload",
            }));
        if let Some(ws_id) = req.uploading_workspace_id {
            builder = builder.actor_fields(
                Some(agent_cordon_core::domain::workspace::WorkspaceId(ws_id)),
                None,
                None,
                None,
            );
        }
        let event = builder.build();
        if let Err(e) = state.store.append_audit_event(&event).await {
            tracing::warn!(error = %e, "Failed to write audit event");
        }

        // Notify UI of new MCP server
        state.ui_event_bus.emit(UiEvent::McpServerChanged {
            server_name: name.clone(),
        });

        results.push(ImportMcpServerResult {
            name,
            id: server.id.0.to_string(),
            status: "created".to_string(),
        });
    }

    Ok(Json(ApiResponse::ok(results)))
}
