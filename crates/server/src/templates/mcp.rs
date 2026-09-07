//! MCP server template catalog: pure data structs and the loader that
//! merges embedded assets with the operator's override directory.

use std::collections::HashMap;

use rust_embed::Embed;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct McpServerTemplate {
    pub key: String,
    pub name: String,
    /// Free text for the marketplace card. Optional; defaults to empty.
    #[serde(default)]
    pub description: String,
    pub upstream_url: String,
    /// `http` (the default) or `sse`.
    #[serde(default = "default_transport")]
    pub transport: String,
    /// Authentication method: "api_key", "oauth2", or "none".
    pub auth_method: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_template_key: Option<String>,
    /// Where the API key goes for an `auth_method: "api_key"` template.
    ///
    /// `api_key_header` names a custom request header (`X-API-Key`), and
    /// `api_key_query` a query parameter (`api_key`); at most one may be set.
    /// When both are absent, provisioning keeps the historical behaviour and
    /// sends `Authorization: Bearer <key>`, so existing templates need no
    /// change.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_key_header: Option<String>,
    /// Query-parameter placement for the API key. See `api_key_header`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_key_query: Option<String>,
    /// Marketplace filter chip. Free text; the built-ins use `productivity`,
    /// `developer-tools` and `payments`. Defaults to `DEFAULT_CATEGORY`,
    /// which is where an operator's own templates land.
    #[serde(default = "default_category")]
    pub category: String,
    /// Search keywords, and the tags the provisioned MCP record carries.
    /// Optional; defaults to none.
    #[serde(default)]
    pub tags: Vec<String>,
    /// Logo key for the marketplace card. Defaults to the template's `key`,
    /// which is the fallback the card already applies; a key with no logo
    /// draws the name's first letter.
    #[serde(default)]
    pub icon: String,
    /// Where the card sorts in the grid. Defaults to `DEFAULT_SORT_ORDER`,
    /// after every built-in.
    #[serde(default = "default_sort_order")]
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

/// The sort order an operator's own template gets. The built-ins are
/// numbered in tens up to about a hundred, so a template that names no
/// `sort_order` lands at the end of the grid.
pub const DEFAULT_SORT_ORDER: u32 = 1000;

/// Where a template that names no `category` lands.
pub const DEFAULT_CATEGORY: &str = "custom";

/// The `auth_method` values provisioning understands.
pub const LEGAL_AUTH_METHODS: [&str; 3] = ["none", "api_key", "oauth2"];

/// The `transport` values `McpTransport` understands.
pub const LEGAL_TRANSPORTS: [&str; 2] = ["http", "sse"];

fn default_transport() -> String {
    LEGAL_TRANSPORTS[0].to_string()
}

fn default_category() -> String {
    DEFAULT_CATEGORY.to_string()
}

fn default_sort_order() -> u32 {
    DEFAULT_SORT_ORDER
}

#[derive(Embed)]
#[folder = "../../data/mcp-templates/"]
struct McpTemplateAssets;

/// One template file that did not load, and every problem found in it.
///
/// The loader collects problems rather than stopping at the first, so an
/// operator fixes a file in one restart instead of one restart per field.
#[derive(Clone, Debug)]
pub struct TemplateFileProblems {
    /// The file, named the way the operator sees it (embedded name or path).
    pub file: String,
    /// Every problem found, each naming the field and what is legal there.
    pub problems: Vec<String>,
}

/// What a runtime template directory contributed to the marketplace.
///
/// "The directory is read once, at startup" was the whole of the success
/// path: an operator who mistyped the mount path or the variable got a
/// silent no-op and learned of it only by hunting the marketplace grid.
#[derive(Clone, Debug)]
pub struct TemplateDirLoad {
    /// The directory as it resolved on disk.
    pub dir: String,
    /// The keys taken from it, sorted.
    pub loaded: Vec<String>,
    /// Files in it that did not load; each is in `problems` with its reasons.
    pub skipped: usize,
}

/// The outcome of one template load: what the marketplace will show, every
/// file that did not load, and what a runtime directory contributed.
#[derive(Clone, Debug)]
pub struct McpTemplateLoad {
    /// The merged templates, in marketplace order.
    pub templates: Vec<McpServerTemplate>,
    /// Every file that did not load, with all of its problems.
    pub problems: Vec<TemplateFileProblems>,
    /// `None` when no runtime directory was configured, or when the
    /// directory itself could not be read (which is warned about by name).
    pub directory: Option<TemplateDirLoad>,
}

/// Every problem in one template file, named field by field.
///
/// Validation runs over the parsed JSON rather than over serde's first
/// error, because serde stops at the first missing field: an operator
/// fixing a template that way pays one server restart per field, which is
/// what two fresh-user walkthroughs actually did.
fn validate(obj: &serde_json::Map<String, serde_json::Value>) -> Vec<String> {
    let mut problems = Vec::new();

    for field in ["key", "name", "upstream_url"] {
        match obj.get(field) {
            None | Some(serde_json::Value::Null) => {
                problems.push(format!("`{field}` is required (a non-empty string)"))
            }
            Some(v) if v.as_str().is_some_and(|s| !s.trim().is_empty()) => {}
            Some(v) => problems.push(format!("`{field}` must be a non-empty string, not {v}")),
        }
    }

    let auth_methods = LEGAL_AUTH_METHODS.join(", ");
    match obj.get("auth_method") {
        None | Some(serde_json::Value::Null) => problems.push(format!(
            "`auth_method` is required; legal values are {auth_methods}"
        )),
        Some(v) => match v.as_str() {
            Some(m) if LEGAL_AUTH_METHODS.contains(&m) => {}
            _ => problems.push(format!(
                "`auth_method` is {v}; legal values are {auth_methods}"
            )),
        },
    }

    let transports = LEGAL_TRANSPORTS.join(", ");
    if let Some(v) = obj.get("transport").filter(|v| !v.is_null()) {
        match v.as_str() {
            Some(t) if LEGAL_TRANSPORTS.contains(&t) => {}
            _ => problems.push(format!(
                "`transport` is {v}; legal values are {transports} (optional, defaults to http)"
            )),
        }
    }

    for field in ["description", "category", "icon"] {
        if let Some(v) = obj.get(field).filter(|v| !v.is_null()) {
            if v.as_str().is_none() {
                problems.push(format!("`{field}` must be a string, not {v} (optional)"));
            }
        }
    }

    if let Some(v) = obj.get("tags").filter(|v| !v.is_null()) {
        let all_strings = v
            .as_array()
            .is_some_and(|a| a.iter().all(|t| t.is_string()));
        if !all_strings {
            problems.push(format!(
                "`tags` must be an array of strings, not {v} (optional, defaults to [])"
            ));
        }
    }

    if let Some(v) = obj.get("sort_order").filter(|v| !v.is_null()) {
        if v.as_u64().is_none_or(|n| n > u32::MAX as u64) {
            problems.push(format!(
                "`sort_order` must be a non-negative integer, not {v} (optional, defaults to \
                 {DEFAULT_SORT_ORDER})"
            ));
        }
    }

    for field in ["api_key_header", "api_key_query"] {
        if let Some(v) = obj.get(field).filter(|v| !v.is_null()) {
            if !v.as_str().is_some_and(|s| !s.trim().is_empty()) {
                problems.push(format!("`{field}` must be a non-empty string, not {v}"));
            }
        }
    }
    // A key cannot be in a header and in the query string at once; a template
    // declaring both would silently get one of them.
    if obj.get("api_key_header").is_some_and(|v| !v.is_null())
        && obj.get("api_key_query").is_some_and(|v| !v.is_null())
    {
        problems.push(
            "`api_key_header` and `api_key_query` name two different placements for one key; \
             set at most one"
                .to_string(),
        );
    }

    problems
}

/// Parse one template file, reporting every problem it has at once.
fn parse_template(data: &[u8]) -> Result<McpServerTemplate, Vec<String>> {
    let value: serde_json::Value = match serde_json::from_slice(data) {
        Ok(v) => v,
        Err(e) => return Err(vec![format!("not valid JSON: {e}")]),
    };
    let Some(obj) = value.as_object() else {
        return Err(vec![
            "the file must contain a JSON object describing one template".to_string(),
        ]);
    };

    let problems = validate(obj);
    if !problems.is_empty() {
        return Err(problems);
    }

    match serde_json::from_value::<McpServerTemplate>(value) {
        Ok(mut t) => {
            // The marketplace card already falls back to the key when a
            // template names no icon; make that the stored default so the
            // API reports what the UI will draw.
            if t.icon.trim().is_empty() {
                t.icon = t.key.clone();
            }
            Ok(t)
        }
        // Every documented field is checked above, so anything left is a
        // known field with the wrong shape in it.
        Err(e) => Err(vec![e.to_string()]),
    }
}

/// Load MCP server templates, returning the templates, every file that did
/// not load with all of its problems, and what a runtime directory
/// contributed. [`load_mcp_templates`] logs all three.
pub fn load_mcp_templates_reporting(override_dir: Option<&str>) -> McpTemplateLoad {
    let mut by_key: HashMap<String, McpServerTemplate> = HashMap::new();
    let mut problems: Vec<TemplateFileProblems> = Vec::new();
    let mut directory: Option<TemplateDirLoad> = None;

    // 1. Load embedded templates
    for filename in McpTemplateAssets::iter() {
        if !filename.ends_with(".json") {
            continue;
        }
        if let Some(file) = McpTemplateAssets::get(&filename) {
            match parse_template(&file.data) {
                Ok(t) => {
                    by_key.insert(t.key.clone(), t);
                }
                Err(found) => problems.push(TemplateFileProblems {
                    file: filename.to_string(),
                    problems: found,
                }),
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
                return McpTemplateLoad {
                    templates: sorted(by_key),
                    problems,
                    directory: None,
                };
            }
        };
        match std::fs::read_dir(&canonical_dir) {
            Ok(entries) => {
                let mut from_dir = TemplateDirLoad {
                    dir: canonical_dir.display().to_string(),
                    loaded: Vec::new(),
                    skipped: 0,
                };
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
                            from_dir.skipped += 1;
                            problems.push(TemplateFileProblems {
                                file: path.display().to_string(),
                                problems: vec![format!(
                                    "file is {} bytes; the limit is {MAX_TEMPLATE_FILE_SIZE}",
                                    meta.len()
                                )],
                            });
                            continue;
                        }
                    }
                    match std::fs::read(&canonical_path) {
                        Ok(data) => match parse_template(&data) {
                            Ok(t) => {
                                tracing::debug!(key = %t.key, path = %path.display(), "loaded runtime MCP template override");
                                from_dir.loaded.push(t.key.clone());
                                by_key.insert(t.key.clone(), t);
                            }
                            Err(found) => {
                                from_dir.skipped += 1;
                                problems.push(TemplateFileProblems {
                                    file: path.display().to_string(),
                                    problems: found,
                                });
                            }
                        },
                        Err(e) => {
                            from_dir.skipped += 1;
                            problems.push(TemplateFileProblems {
                                file: path.display().to_string(),
                                problems: vec![format!("could not be read: {e}")],
                            });
                        }
                    }
                }
                from_dir.loaded.sort();
                directory = Some(from_dir);
            }
            Err(e) => {
                tracing::warn!(dir = %dir, error = %e, "failed to read MCP templates directory");
            }
        }
    }

    McpTemplateLoad {
        templates: sorted(by_key),
        problems,
        directory,
    }
}

/// Sort by `sort_order` then name — the order the marketplace grid shows.
fn sorted(by_key: HashMap<String, McpServerTemplate>) -> Vec<McpServerTemplate> {
    let mut templates: Vec<McpServerTemplate> = by_key.into_values().collect();
    templates.sort_by(|a, b| {
        a.sort_order
            .cmp(&b.sort_order)
            .then_with(|| a.name.cmp(&b.name))
    });
    templates
}

/// Load MCP server templates from embedded assets and optional runtime directory.
///
/// If `override_dir` is `Some`, `.json` files in that directory are loaded and
/// merged by `key` (runtime wins over embedded).
///
/// A file that does not load is skipped with one log line naming the file and
/// every problem in it, so a template is fixed in one restart.
pub fn load_mcp_templates(override_dir: Option<&str>) -> Vec<McpServerTemplate> {
    let load = load_mcp_templates_reporting(override_dir);
    for p in &load.problems {
        tracing::warn!(
            file = %p.file,
            problems = %p.problems.join("; "),
            "skipping invalid MCP server template"
        );
    }
    if let Some(dir) = &load.directory {
        tracing::info!(
            dir = %dir.dir,
            loaded = dir.loaded.len(),
            keys = %dir.loaded.join(", "),
            skipped = dir.skipped,
            "loaded MCP server templates from directory"
        );
    }
    load.templates
}
