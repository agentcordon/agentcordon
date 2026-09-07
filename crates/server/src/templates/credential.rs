//! Credential template catalog: pure data structs (rendered by the
//! credential form) and the loader that merges embedded assets with the
//! operator's override directory.

use std::collections::HashMap;

use rust_embed::Embed;
use serde::{Deserialize, Serialize};

/// One input field rendered on the credential creation form.
///
/// All template-specific UI knowledge (label, validation, placeholder) lives
/// here so the page renderer can stay generic. Adding a new field to a
/// template is a JSON-only change.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FieldSpec {
    /// Backend submission key (e.g. "tenant_id", "secret_value"). Also used
    /// as the local form key in the renderer.
    pub key: String,
    /// Displayed label.
    pub label: String,
    #[serde(default)]
    pub placeholder: String,
    /// Hint text rendered under the input. Plain text (escaped).
    #[serde(default)]
    pub help: String,
    /// "text" | "password" | "textarea". Defaults to "text".
    #[serde(default = "default_input_type")]
    pub input_type: String,
    /// Whether the field must be filled before submit.
    #[serde(default)]
    pub required: bool,
    /// Render with monospace font (for GUIDs, keys, URLs).
    #[serde(default)]
    pub mono: bool,
    /// Mask value with a show/hide toggle.
    #[serde(default)]
    pub secret: bool,
    /// If true, the field is collected from the user but NOT sent to the
    /// backend (used as input to client-side substitutions, e.g. Entra's
    /// tenant_id is spliced into the oauth2_token_endpoint URL).
    #[serde(default)]
    pub client_only: bool,
}

fn default_input_type() -> String {
    "text".to_string()
}

/// Client-side string substitution applied to a template-level URL before POST.
///
/// Example (Entra): substitute the user's `tenant_id` into the
/// `{tenant_id}` placeholder of `oauth2_token_endpoint`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClientSubstitution {
    /// Template field whose string is interpolated (e.g. "oauth2_token_endpoint").
    pub target: String,
    /// Form field key whose value is spliced in (e.g. "tenant_id").
    pub source: String,
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
    pub fields: Vec<FieldSpec>,
    pub description: String,
    pub tags: Vec<String>,
    pub sort_order: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oauth2_token_endpoint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oauth2_scopes: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub client_substitutions: Vec<ClientSubstitution>,
}

#[derive(Embed)]
#[folder = "../../data/credential-templates/"]
struct TemplateAssets;

/// Load credential templates from embedded assets and optional runtime directory.
///
/// If `override_dir` is `Some`, `.json` files in that directory are loaded and
/// merged by `key` (runtime wins over embedded).
pub fn load_credential_templates(override_dir: Option<&str>) -> Vec<CredentialTemplate> {
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
