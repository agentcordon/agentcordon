//! Policy template catalog: pure data structs and the loader that merges
//! embedded assets with the operator's override directory.

use std::collections::HashMap;

use rust_embed::Embed;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PolicyTemplate {
    pub key: String,
    pub name: String,
    pub description: String,
    pub cedar_policy: String,
    pub tags: Vec<String>,
    pub sort_order: u32,
}

#[derive(Embed)]
#[folder = "../../data/policy-templates/"]
struct PolicyTemplateAssets;

/// Load policy templates from embedded assets and optional runtime directory.
///
/// If `override_dir` is `Some`, `.json` files in that directory are loaded and
/// merged by `key` (runtime wins over embedded).
pub fn load_policy_templates(override_dir: Option<&str>) -> Vec<PolicyTemplate> {
    let mut by_key: HashMap<String, PolicyTemplate> = HashMap::new();

    // 1. Load embedded templates
    for filename in PolicyTemplateAssets::iter() {
        if !filename.ends_with(".json") {
            continue;
        }
        if let Some(file) = PolicyTemplateAssets::get(&filename) {
            match serde_json::from_slice::<PolicyTemplate>(&file.data) {
                Ok(t) => {
                    by_key.insert(t.key.clone(), t);
                }
                Err(e) => {
                    tracing::warn!(file = %filename, error = %e, "skipping invalid embedded policy template");
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
                        Ok(data) => match serde_json::from_slice::<PolicyTemplate>(&data) {
                            Ok(t) => {
                                tracing::debug!(key = %t.key, path = %path.display(), "loaded runtime policy template override");
                                by_key.insert(t.key.clone(), t);
                            }
                            Err(e) => {
                                tracing::warn!(path = %path.display(), error = %e, "skipping invalid runtime policy template");
                            }
                        },
                        Err(e) => {
                            tracing::warn!(path = %path.display(), error = %e, "failed to read runtime policy template file");
                        }
                    }
                }
            }
            Err(e) => {
                tracing::warn!(dir = %dir, error = %e, "failed to read policy templates directory");
            }
        }
    }

    // 3. Sort by sort_order then name
    let mut templates: Vec<PolicyTemplate> = by_key.into_values().collect();
    templates.sort_by(|a, b| {
        a.sort_order
            .cmp(&b.sort_order)
            .then_with(|| a.name.cmp(&b.name))
    });
    templates
}
