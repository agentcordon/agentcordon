//! Credential templates endpoint.
//!
//! GET /api/v1/credential-templates — returns templates for common services.
//!
//! Templates are loaded from embedded JSON files at compile time. Operators can
//! override or extend them at runtime by setting `AGTCRDN_CREDENTIAL_TEMPLATES_DIR`
//! to a directory containing additional `.json` files (same schema). Runtime
//! templates override embedded ones by matching `key`.

use axum::extract::State;
use axum::{routing::get, Json, Router};
use rust_embed::Embed;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::extractors::AuthenticatedUser;
use crate::response::{ApiError, ApiResponse};
use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new().route("/credential-templates", get(list_templates))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CredentialTemplate {
    pub key: String,
    pub name: String,
    pub service: String,
    pub credential_type: String,
    pub auth_type: String,
    pub header: String,
    pub allowed_url_pattern: String,
    pub fields: Vec<String>,
    pub description: String,
    pub tags: Vec<String>,
    pub sort_order: u32,
}

#[derive(Embed)]
#[folder = "../../data/credential-templates/"]
struct TemplateAssets;

/// Load credential templates from embedded assets and optional runtime directory.
///
/// If `override_dir` is `Some`, `.json` files in that directory are loaded and
/// merged by `key` (runtime wins over embedded).
pub fn load_templates(override_dir: Option<&str>) -> Vec<CredentialTemplate> {
    let mut by_key: HashMap<String, CredentialTemplate> = HashMap::new();

    // 1. Load embedded templates
    for filename in TemplateAssets::iter() {
        if !filename.ends_with(".json") {
            continue;
        }
        if let Some(file) = TemplateAssets::get(&filename) {
            match serde_json::from_slice::<CredentialTemplate>(&file.data) {
                Ok(t) => {
                    by_key.insert(t.key.clone(), t);
                }
                Err(e) => {
                    tracing::warn!(file = %filename, error = %e, "skipping invalid embedded template");
                }
            }
        }
    }

    // 2. Load runtime overrides from directory
    if let Some(dir) = override_dir {
        match std::fs::read_dir(dir) {
            Ok(entries) => {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.extension().and_then(|e| e.to_str()) != Some("json") {
                        continue;
                    }
                    match std::fs::read(&path) {
                        Ok(data) => match serde_json::from_slice::<CredentialTemplate>(&data) {
                            Ok(t) => {
                                tracing::debug!(key = %t.key, path = %path.display(), "loaded runtime template override");
                                by_key.insert(t.key.clone(), t);
                            }
                            Err(e) => {
                                tracing::warn!(path = %path.display(), error = %e, "skipping invalid runtime template");
                            }
                        },
                        Err(e) => {
                            tracing::warn!(path = %path.display(), error = %e, "failed to read runtime template file");
                        }
                    }
                }
            }
            Err(e) => {
                tracing::warn!(dir = %dir, error = %e, "failed to read credential templates directory");
            }
        }
    }

    // 3. Sort by sort_order then name
    let mut templates: Vec<CredentialTemplate> = by_key.into_values().collect();
    templates.sort_by(|a, b| {
        a.sort_order
            .cmp(&b.sort_order)
            .then_with(|| a.name.cmp(&b.name))
    });
    templates
}

/// GET /api/v1/credential-templates — list available credential templates.
async fn list_templates(
    _auth: AuthenticatedUser,
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<Vec<CredentialTemplate>>>, ApiError> {
    Ok(Json(ApiResponse::ok(state.credential_templates.clone())))
}
