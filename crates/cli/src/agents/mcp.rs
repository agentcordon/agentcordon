//! Registering `agentcordon mcp-serve` in each selected runtime's MCP
//! configuration, so the `agentcordon_*` tools are native tools rather than a
//! shell command the model has to remember.
//!
//! The command line is fixed and identical everywhere — `agentcordon`,
//! `mcp-serve`, plus a `--expose <server>` pair per re-exported server — so
//! the only thing that varies between runtimes is the file it goes in and how
//! that file spells a stdio entry. [`super::McpShape`] is that difference, and
//! nothing else here is per-runtime.
//!
//! Three rules hold for every writer:
//!
//! 1. **Never an absolute path.** `command` is the bare binary name, so PATH
//!    resolution stays the user's and a committed file works on the next
//!    machine. `mcp_config_never_writes_an_absolute_path` pins it.
//! 2. **Never damage a file we did not write.** A file that does not parse,
//!    or that already carries an `agentcordon` entry saying something else, is
//!    left byte-identical and its snippet is printed instead.
//! 3. **Idempotent.** A second run finds its own entry and writes nothing.

use std::fs;
use std::path::Path;

use serde_json::{json, Map, Value};

use crate::error::CliError;

use super::install::{Action, Installed};
use super::{McpConfig, McpFile, McpShape, McpUser, Runtime, MCP_COMMAND, MCP_ENTRY};

/// What `init` decided about the MCP registration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Choice {
    /// Write each selected runtime's MCP config. `--no-mcp` clears it.
    pub register: bool,
    /// Servers whose tools are re-exported as typed tools, one `--expose`
    /// pair each. Empty is the default: six fixed tools, ~800 tokens.
    pub expose: Vec<String>,
}

impl Default for Choice {
    /// Yes. A runtime with no entry cannot see the tools at all, and the
    /// fixed surface costs the same whether the workspace has one upstream or
    /// twenty (issue #54's amendment).
    fn default() -> Self {
        Self {
            register: true,
            expose: Vec::new(),
        }
    }
}

/// The arguments `mcp-serve` is started with.
pub fn args(expose: &[String]) -> Vec<String> {
    let mut out = vec!["mcp-serve".to_string()];
    for server in expose {
        out.push("--expose".to_string());
        out.push(server.clone());
    }
    out
}

/// Write every selected runtime's project-level MCP config, and describe the
/// user-level ones it cannot write.
///
/// Returns one [`Installed`] per file, in the registry's order, ready for the
/// same summary the skill files are reported in.
pub fn install(
    root: &Path,
    selected: &[&'static Runtime],
    choice: &Choice,
) -> Result<Vec<Installed>, CliError> {
    if !choice.register {
        return Ok(Vec::new());
    }
    let args = args(&choice.expose);
    let mut out: Vec<Installed> = Vec::new();

    // Two runtimes could come to share a file; collect the names first so the
    // file is written once and the summary names both.
    let mut project: Vec<(McpFile, Vec<&'static str>)> = Vec::new();
    let mut user: Vec<(McpUser, Vec<&'static str>)> = Vec::new();
    fn push<K: PartialEq>(list: &mut Vec<(K, Vec<&'static str>)>, key: K, display: &'static str) {
        match list.iter_mut().find(|(k, _)| *k == key) {
            Some((_, names)) => names.push(display),
            None => list.push((key, vec![display])),
        }
    }
    for runtime in selected {
        match runtime.mcp {
            McpConfig::Project(file) => push(&mut project, file, runtime.display),
            McpConfig::ProjectAndUser(file, also) => {
                push(&mut project, file, runtime.display);
                push(&mut user, also, runtime.display);
            }
            McpConfig::User(also) => push(&mut user, also, runtime.display),
            McpConfig::None => {}
        }
    }

    for (file, serves) in project {
        out.push(write(root, &file, &args, serves)?);
    }
    for (also, serves) in user {
        out.push(describe_user(&also, &args, serves));
    }
    Ok(out)
}

/// Write one project-level config.
fn write(
    root: &Path,
    file: &McpFile,
    args: &[String],
    serves: Vec<&'static str>,
) -> Result<Installed, CliError> {
    let path = super::install::join_rel(root, file.path);
    let existing = fs::read_to_string(&path).ok();
    let outcome = match file.shape {
        McpShape::Toml => merge_toml(existing.as_deref(), args),
        _ => merge_json(existing.as_deref(), file.shape, args),
    };

    let action = match outcome {
        Merged::Write { body, action, note } => {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).map_err(|e| {
                    CliError::general(format!("failed to create {}: {e}", file.path))
                })?;
            }
            fs::write(&path, body)
                .map_err(|e| CliError::general(format!("failed to write {}: {e}", file.path)))?;
            return Ok(Installed {
                path: file.path.to_string(),
                action,
                serves,
                detail: note,
            });
        }
        Merged::Unchanged => Action::Unchanged,
        Merged::Refuse(reason) => Action::Skipped {
            reason,
            snippet: snippet(file.shape, args),
        },
    };
    Ok(Installed {
        path: file.path.to_string(),
        action,
        serves,
        detail: None,
    })
}

/// A user-level file is outside the workspace, shared by every project, and
/// often owned by the runtime's own CLI. `init` writes only inside the
/// directory it was run in, so this is a printed instruction.
fn describe_user(user: &McpUser, args: &[String], serves: Vec<&'static str>) -> Installed {
    let reason = match user.command {
        Some(command) => format!(
            "{} configures MCP servers per user, not per project — run `{command}`, or add this to {}",
            user.label, user.path
        ),
        None => format!(
            "{} configures MCP servers per user, not per project — add this to {}",
            user.label, user.path
        ),
    };
    Installed {
        path: user.path.to_string(),
        action: Action::Skipped {
            reason,
            snippet: snippet(user.shape, args),
        },
        serves,
        detail: None,
    }
}

/// The result of merging our entry into whatever was there.
enum Merged {
    Write {
        body: String,
        action: Action,
        note: Option<String>,
    },
    /// Our entry is already there and already right.
    Unchanged,
    /// Leave the file byte-identical; the reason is shown with the snippet.
    Refuse(String),
}

// ---------------------------------------------------------------------------
// JSON
// ---------------------------------------------------------------------------

fn merge_json(existing: Option<&str>, shape: McpShape, args: &[String]) -> Merged {
    let key = key(shape);
    let desired = entry(shape, args);

    let Some(text) = existing else {
        let mut servers = Map::new();
        servers.insert(MCP_ENTRY.to_string(), desired);
        let mut root = Map::new();
        root.insert(key.to_string(), Value::Object(servers));
        return Merged::Write {
            body: pretty(&Value::Object(root)),
            action: Action::Created,
            note: None,
        };
    };

    let Ok(mut root) = serde_json::from_str::<Value>(text) else {
        return Merged::Refuse(
            "not strict JSON — comments and trailing commas are not parsed, so nothing was changed"
                .to_string(),
        );
    };
    let Some(map) = root.as_object_mut() else {
        return Merged::Refuse(
            "the top level is not a JSON object; nothing was changed".to_string(),
        );
    };

    let servers = map.entry(key.to_string()).or_insert_with(|| json!({}));
    let Some(servers) = servers.as_object_mut() else {
        return Merged::Refuse(format!("`{key}` is not an object; nothing was changed"));
    };
    let write = match servers.get(MCP_ENTRY) {
        None => desired,
        Some(found) if ours(shape, found) => {
            // The entry names our own binary, so it is ours to keep current —
            // `--expose` changing is the ordinary case. Only the keys this
            // module owns are overwritten; an `env` or a `timeout` the user
            // added to it survives.
            let mut merged = found.clone();
            if let (Some(merged), Some(desired)) = (merged.as_object_mut(), desired.as_object()) {
                for (k, v) in desired {
                    merged.insert(k.clone(), v.clone());
                }
            }
            if merged == *found {
                return Merged::Unchanged;
            }
            merged
        }
        Some(_) => {
            return Merged::Refuse(format!(
                "`{key}.{MCP_ENTRY}` starts something other than the `agentcordon` binary, so it \
                 is yours, not ours; nothing was changed"
            ))
        }
    };
    servers.insert(MCP_ENTRY.to_string(), write);

    Merged::Write {
        body: pretty(&root),
        action: Action::Updated,
        note: Some(
            "the file was re-serialised with 2-space indent; key order and blank lines may differ"
                .to_string(),
        ),
    }
}

/// Whether an entry already in the file is one `init` may keep current.
///
/// The test is what the runtime would actually start. An entry naming the
/// `agentcordon` binary is ours whatever else it carries; an entry pointing at
/// a wrapper script, an absolute path or another binary is the user's, and
/// overwriting it would undo a deliberate choice.
fn ours(shape: McpShape, found: &Value) -> bool {
    let starts = match shape {
        McpShape::OpenCode => found
            .get("command")
            .and_then(|c| c.as_array())
            .and_then(|c| c.first())
            .and_then(|c| c.as_str()),
        _ => found.get("command").and_then(|c| c.as_str()),
    };
    starts == Some(MCP_COMMAND)
}

/// One server entry, in this runtime's spelling.
fn entry(shape: McpShape, args: &[String]) -> Value {
    match shape {
        McpShape::Json { stdio, .. } => {
            let mut entry = Map::new();
            if stdio {
                entry.insert("type".to_string(), json!("stdio"));
            }
            entry.insert("command".to_string(), json!(MCP_COMMAND));
            entry.insert("args".to_string(), json!(args));
            Value::Object(entry)
        }
        McpShape::OpenCode => {
            let mut command = vec![MCP_COMMAND.to_string()];
            command.extend(args.iter().cloned());
            json!({ "type": "local", "command": command, "enabled": true })
        }
        McpShape::CopilotCli => json!({
            "type": "local",
            "command": MCP_COMMAND,
            "args": args,
            "tools": ["*"],
        }),
        McpShape::Zed => json!({ "source": "custom", "command": MCP_COMMAND, "args": args }),
        // Neither is JSON; `snippet` renders them and `write` never routes
        // them here.
        McpShape::Toml | McpShape::Goose => Value::Null,
    }
}

/// The key the map of servers lives under.
fn key(shape: McpShape) -> &'static str {
    match shape {
        McpShape::Json { key, .. } => key,
        McpShape::OpenCode => "mcp",
        McpShape::CopilotCli => "mcpServers",
        McpShape::Zed => "context_servers",
        McpShape::Toml => "mcp_servers",
        McpShape::Goose => "extensions",
    }
}

fn pretty(value: &Value) -> String {
    format!(
        "{}\n",
        serde_json::to_string_pretty(value).unwrap_or_default()
    )
}

// ---------------------------------------------------------------------------
// TOML
// ---------------------------------------------------------------------------

/// Codex's `.codex/config.toml`.
///
/// Appended rather than re-serialised. A `config.toml` is hand-written and
/// full of comments, and round-tripping it through `toml::Value` would delete
/// every one of them; a new `[mcp_servers.agentcordon]` table at the end of a
/// file that already parses is always valid TOML.
fn merge_toml(existing: Option<&str>, args: &[String]) -> Merged {
    let block = toml_block(args);

    let Some(text) = existing else {
        return Merged::Write {
            body: block,
            action: Action::Created,
            note: None,
        };
    };

    let Ok(parsed) = text.parse::<toml::Table>() else {
        return Merged::Refuse("not valid TOML; nothing was changed".to_string());
    };
    if let Some(found) = parsed
        .get("mcp_servers")
        .and_then(|t| t.as_table())
        .and_then(|t| t.get(MCP_ENTRY))
    {
        let desired = toml_entry(args);
        if *found == desired {
            return Merged::Unchanged;
        }
        if found.get("command").and_then(|c| c.as_str()) != Some(MCP_COMMAND) {
            return Merged::Refuse(format!(
                "`[mcp_servers.{MCP_ENTRY}]` starts something other than the `agentcordon` \
                 binary, so it is yours, not ours; nothing was changed"
            ));
        }
        // Ours, and out of date — `--expose` changed. Replace the table we
        // wrote, in place, and leave every other line of the file alone.
        return match replace_toml_block(text, &block) {
            Some(body) => Merged::Write {
                body,
                action: Action::Updated,
                note: Some(
                    "the [mcp_servers.agentcordon] table was rewritten; the rest of the file is \
                     untouched"
                        .to_string(),
                ),
            },
            None => Merged::Refuse(format!(
                "`[mcp_servers.{MCP_ENTRY}]` carries settings this command does not write, so it \
                 was left alone; replace it with:"
            )),
        };
    }

    let separator = if text.ends_with("\n\n") || text.is_empty() {
        ""
    } else if text.ends_with('\n') {
        "\n"
    } else {
        "\n\n"
    };
    Merged::Write {
        body: format!("{text}{separator}{block}"),
        action: Action::Updated,
        note: Some("appended; the rest of the file, comments included, is untouched".to_string()),
    }
}

/// Swap the `[mcp_servers.agentcordon]` table for `block`, textually.
///
/// Only a table whose every line is one this module wrote is replaced;
/// anything else in it means the user has been in here, and `None` sends the
/// caller down the "leave it alone and print" path. Working on lines rather
/// than on a parsed document is what keeps the comments in the rest of the
/// file, which is the whole reason TOML is appended to and not re-serialised.
fn replace_toml_block(text: &str, block: &str) -> Option<String> {
    let header = format!("[mcp_servers.{MCP_ENTRY}]");
    let lines: Vec<&str> = text.lines().collect();
    let start = lines.iter().position(|l| l.trim() == header)?;
    let end = lines
        .iter()
        .enumerate()
        .skip(start + 1)
        .find(|(_, l)| l.trim_start().starts_with('['))
        .map_or(lines.len(), |(i, _)| i);

    let ours_only = lines[start + 1..end].iter().all(|l| {
        let t = l.trim();
        t.is_empty() || t.starts_with("command") || t.starts_with("args")
    });
    if !ours_only {
        return None;
    }

    // Blank lines after the table are separators, not part of it.
    let mut resume = end;
    while resume > start + 1 && lines[resume - 1].trim().is_empty() {
        resume -= 1;
    }

    let mut out = String::new();
    for line in &lines[..start] {
        out.push_str(line);
        out.push('\n');
    }
    out.push_str(block);
    for line in &lines[resume..] {
        out.push_str(line);
        out.push('\n');
    }
    Some(out)
}

fn toml_entry(args: &[String]) -> toml::Value {
    let mut table = toml::value::Table::new();
    table.insert(
        "command".to_string(),
        toml::Value::String(MCP_COMMAND.into()),
    );
    table.insert(
        "args".to_string(),
        toml::Value::Array(args.iter().cloned().map(toml::Value::String).collect()),
    );
    toml::Value::Table(table)
}

fn toml_block(args: &[String]) -> String {
    format!(
        "[mcp_servers.{MCP_ENTRY}]\ncommand = \"{MCP_COMMAND}\"\nargs = {}\n",
        json!(args)
    )
}

// ---------------------------------------------------------------------------
// Snippets
// ---------------------------------------------------------------------------

/// The block to paste by hand: for a user-level config, and for a project file
/// `init` refused to touch.
pub fn snippet(shape: McpShape, args: &[String]) -> String {
    match shape {
        McpShape::Toml => toml_block(args),
        McpShape::Goose => {
            let indented = args
                .iter()
                .map(|a| format!("      - {a}\n"))
                .collect::<String>();
            format!(
                "extensions:\n  {MCP_ENTRY}:\n    type: stdio\n    enabled: true\n    \
                 name: {MCP_ENTRY}\n    cmd: {MCP_COMMAND}\n    args:\n{indented}    timeout: 300\n"
            )
        }
        other => {
            let mut servers = Map::new();
            servers.insert(MCP_ENTRY.to_string(), entry(other, args));
            let mut root = Map::new();
            root.insert(key(other).to_string(), Value::Object(servers));
            pretty(&Value::Object(root))
        }
    }
}
