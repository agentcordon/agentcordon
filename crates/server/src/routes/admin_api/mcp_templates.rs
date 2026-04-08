//! MCP server templates endpoint.
//!
//! GET /api/v1/mcp-templates — returns templates for common MCP servers.
//!
//! Templates are loaded from embedded JSON files at compile time. Operators can
//! override or extend them at runtime by setting `AGTCRDN_MCP_TEMPLATES_DIR`
//! to a directory containing additional `.json` files (same schema). Runtime
//! templates override embedded ones by matching `key`.

use std::collections::{HashMap, HashSet};

use axum::extract::State;
use axum::{routing::get, Json, Router};
use rust_embed::Embed;
use serde::{Deserialize, Serialize};

use crate::extractors::AuthenticatedUser;
use crate::response::{ApiError, ApiResponse};
use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new().route("/mcp-templates", get(list_templates))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct McpServerTemplate {
    pub key: String,
    pub name: String,
    pub description: String,
    pub upstream_url: String,
    pub transport: String,
    /// Authentication method: "api_key", "oauth2", or "none".
    pub auth_method: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_template_key: Option<String>,
    pub category: String,
    pub tags: Vec<String>,
    pub icon: String,
    pub sort_order: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oauth2_authorize_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oauth2_token_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oauth2_scopes: Option<String>,
    /// Deprecated: previously linked to an oauth2_app credential template.
    /// Now ignored — OAuth app config is managed via Settings > MCP OAuth Apps.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oauth2_app_credential_template_key: Option<String>,
    /// OAuth2 protected resource URL — used by discovery (RFC 9728) to find
    /// the authorization server. Required for OAuth2 templates that use
    /// dynamic discovery + DCR.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oauth2_resource_url: Option<String>,
    /// Whether to prefer Dynamic Client Registration (RFC 7591) for this
    /// template when the discovered authorization server supports it.
    /// Defaults to true.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oauth2_prefer_dcr: Option<bool>,
}

#[derive(Embed)]
#[folder = "../../data/mcp-templates/"]
struct McpTemplateAssets;

/// Check that a template has a valid `auth_method` and `transport`.
fn is_valid_template(t: &McpServerTemplate) -> bool {
    matches!(t.auth_method.as_str(), "api_key" | "oauth2" | "none")
        && matches!(t.transport.as_str(), "http" | "sse")
}

/// Load MCP server templates from embedded assets and optional runtime directory.
///
/// If `override_dir` is `Some`, `.json` files in that directory are loaded and
/// merged by `key` (runtime wins over embedded).
pub fn load_mcp_templates(override_dir: Option<&str>) -> Vec<McpServerTemplate> {
    let mut by_key: HashMap<String, McpServerTemplate> = HashMap::new();

    // 1. Load embedded templates
    for filename in McpTemplateAssets::iter() {
        if !filename.ends_with(".json") {
            continue;
        }
        if let Some(file) = McpTemplateAssets::get(&filename) {
            match serde_json::from_slice::<McpServerTemplate>(&file.data) {
                Ok(t) => {
                    if !is_valid_template(&t) {
                        tracing::warn!(file = %filename, key = %t.key, "skipping embedded MCP template with invalid auth_method or transport");
                        continue;
                    }
                    by_key.insert(t.key.clone(), t);
                }
                Err(e) => {
                    tracing::warn!(file = %filename, error = %e, "skipping invalid embedded MCP template");
                }
            }
        }
    }

    // 2. Load runtime overrides from directory.
    // SECURITY: Canonicalize the directory and verify each file resolves within it
    // to prevent symlink/path-traversal attacks. Max file size 64 KiB.
    const MAX_TEMPLATE_FILE_SIZE: u64 = 64 * 1024;
    if let Some(dir) = override_dir {
        let canonical_dir = match std::fs::canonicalize(dir) {
            Ok(d) => d,
            Err(e) => {
                tracing::warn!(dir = %dir, error = %e, "failed to canonicalize MCP templates directory");
                let mut templates: Vec<McpServerTemplate> = by_key.into_values().collect();
                templates.sort_by(|a, b| a.sort_order.cmp(&b.sort_order).then(a.name.cmp(&b.name)));
                return templates;
            }
        };
        match std::fs::read_dir(&canonical_dir) {
            Ok(entries) => {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.extension().and_then(|e| e.to_str()) != Some("json") {
                        continue;
                    }
                    // Verify the resolved path is within the canonical directory
                    let canonical_path = match std::fs::canonicalize(&path) {
                        Ok(p) => p,
                        Err(_) => continue,
                    };
                    if !canonical_path.starts_with(&canonical_dir) {
                        tracing::warn!(path = %path.display(), "skipping MCP template outside directory (symlink/traversal)");
                        continue;
                    }
                    // Enforce max file size
                    if let Ok(meta) = std::fs::metadata(&canonical_path) {
                        if meta.len() > MAX_TEMPLATE_FILE_SIZE {
                            tracing::warn!(path = %path.display(), size = meta.len(), "skipping oversized MCP template file");
                            continue;
                        }
                    }
                    match std::fs::read(&canonical_path) {
                        Ok(data) => match serde_json::from_slice::<McpServerTemplate>(&data) {
                            Ok(t) => {
                                if !is_valid_template(&t) {
                                    tracing::warn!(path = %path.display(), key = %t.key, "skipping runtime MCP template with invalid auth_method or transport");
                                    continue;
                                }
                                tracing::debug!(key = %t.key, path = %path.display(), "loaded runtime MCP template override");
                                by_key.insert(t.key.clone(), t);
                            }
                            Err(e) => {
                                tracing::warn!(path = %path.display(), error = %e, "skipping invalid runtime MCP template");
                            }
                        },
                        Err(e) => {
                            tracing::warn!(path = %path.display(), error = %e, "failed to read runtime MCP template file");
                        }
                    }
                }
            }
            Err(e) => {
                tracing::warn!(dir = %dir, error = %e, "failed to read MCP templates directory");
            }
        }
    }

    // 3. Sort by sort_order then name
    let mut templates: Vec<McpServerTemplate> = by_key.into_values().collect();
    templates.sort_by(|a, b| {
        a.sort_order
            .cmp(&b.sort_order)
            .then_with(|| a.name.cmp(&b.name))
    });
    templates
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
