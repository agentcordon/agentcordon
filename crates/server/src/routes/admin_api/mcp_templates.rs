//! MCP server templates endpoint.
//!
//! GET /api/v1/mcp-templates — returns templates for common MCP servers.
//!
//! Templates are loaded from embedded JSON files at compile time. Operators can
//! override or extend them at runtime by setting `AGTCRDN_MCP_TEMPLATES_DIR`
//! to a directory containing additional `.json` files (same schema). Runtime
//! templates override embedded ones by matching `key`.

use std::collections::HashSet;

use axum::extract::State;
use axum::{routing::get, Json, Router};
use serde::Serialize;

use crate::extractors::AuthenticatedUser;
use crate::response::{ApiError, ApiResponse};
use crate::state::AppState;
use crate::templates::McpServerTemplate;

pub fn routes() -> Router<AppState> {
    Router::new().route("/mcp-templates", get(list_templates))
}

/// Response wrapper that enriches an `McpServerTemplate` with vault status.
#[derive(Serialize)]
pub struct McpServerTemplateResponse {
    #[serde(flatten)]
    pub template: McpServerTemplate,
    /// For OAuth2 templates: whether an MCP OAuth App has been configured in Settings.
    /// `None` for non-OAuth templates.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oauth2_app_configured: Option<bool>,
}

/// GET /api/v1/mcp-templates — list available MCP server templates.
///
/// For OAuth2 templates, includes `oauth2_app_configured` indicating whether
/// an MCP OAuth App has been configured in Settings for that template.
async fn list_templates(
    _auth: AuthenticatedUser,
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<Vec<McpServerTemplateResponse>>>, ApiError> {
    let configured_keys: HashSet<String> = state
        .store
        .list_oauth_provider_clients()
        .await
        .unwrap_or_default()
        .iter()
        .filter(|a| a.enabled)
        .map(|a| a.label.clone())
        .collect();

    let responses: Vec<McpServerTemplateResponse> = state
        .catalog
        .mcp_templates
        .iter()
        .map(|t| {
            let oauth2_app_configured = if t.auth_method == "oauth2" {
                Some(configured_keys.contains(&t.key))
            } else {
                None
            };
            McpServerTemplateResponse {
                template: t.clone(),
                oauth2_app_configured,
            }
        })
        .collect();

    Ok(Json(ApiResponse::ok(responses)))
}
