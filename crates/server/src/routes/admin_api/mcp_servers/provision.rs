//! MCP server provisioning from the template catalog.
//!
//! `POST /api/v1/mcp-servers/provision` — one-click provisioning of an MCP
//! server from a catalog template. Creates the server record, optionally
//! creates or links a credential, and emits an audit event.
//!
//! No Cedar policy is auto-generated — the default policy already permits
//! workspaces to list tools and call tools on enabled MCP servers.

use axum::{extract::State, Json};
use serde::Deserialize;
use uuid::Uuid;

use agent_cordon_core::domain::credential::CredentialId;
use agent_cordon_core::domain::workspace::WorkspaceId;

use crate::extractors::AuthenticatedUser;
use crate::middleware::request_id::CorrelationId;
use crate::response::{ApiError, ApiResponse};
use crate::services::mcp_servers::ProvisionInput;
use crate::state::AppState;

use super::McpServerResponse;

/// The provisioned server, plus why its tool-discovery probe failed if it
/// did. Discovery is best-effort and never fails the install, but a server
/// with no tools and no explanation is indistinguishable from one that
/// exposes none — so the reason travels back to the install modal, which
/// points the operator at **Rediscover tools**.
#[derive(serde::Serialize)]
pub(crate) struct ProvisionResponse {
    #[serde(flatten)]
    pub server: McpServerResponse,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_discovery_error: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProvisionRequest {
    pub template_key: String,
    pub workspace_id: Uuid,
    /// Use an existing credential by ID.
    pub credential_id: Option<Uuid>,
    /// Create a new credential with this secret value.
    pub secret_value: Option<String>,
}

/// `POST /api/v1/mcp-servers/provision`
///
/// Provision an MCP server from a catalog template for a workspace.
pub(crate) async fn provision_from_catalog(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
    axum::Extension(corr): axum::Extension<CorrelationId>,
    Json(req): Json<ProvisionRequest>,
) -> Result<Json<ApiResponse<ProvisionResponse>>, ApiError> {
    // Look up template
    let template = state
        .catalog
        .mcp_templates
        .iter()
        .find(|t| t.key == req.template_key)
        .ok_or_else(|| {
            ApiError::NotFound(format!("MCP template '{}' not found", req.template_key))
        })?
        .clone();

    let outcome = state
        .services
        .mcp_servers
        .provision(
            &auth,
            &corr.0,
            &template,
            ProvisionInput {
                workspace_id: WorkspaceId(req.workspace_id),
                credential_id: req.credential_id.map(CredentialId),
                secret_value: req.secret_value,
            },
        )
        .await?;

    let mut resp = ProvisionResponse {
        server: McpServerResponse::from_server(&outcome.server),
        tool_discovery_error: outcome.tool_discovery_error,
    };
    resp.server.workspace_name = Some(outcome.workspace.name.clone());
    resp.server.installed_workspaces = vec![super::InstalledWorkspaceInfo {
        id: outcome.workspace.id.0.to_string(),
        name: outcome.workspace.name,
    }];
    Ok(Json(ApiResponse::ok(resp)))
}
