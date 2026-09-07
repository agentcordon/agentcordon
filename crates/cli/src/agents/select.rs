//! Deciding which runtimes to install for: from `--agent`, from the choice
//! remembered in `.agentcordon/agents.toml`, or from the picker.
//!
//! The resolution itself is pure — [`from_flags`] and [`Saved`] take no
//! terminal and no environment beyond a [`DetectEnv`] — so the rules are
//! testable without a TTY. Only [`prompt`] touches the terminal, and `init`
//! calls it only when stdin *and* stdout are one.

use std::io::IsTerminal;
use std::path::Path;

use crate::error::CliError;

use super::mcp::Choice;
use super::{DetectEnv, Runtime, ALL, AUTO, COMPAT_ALIASES, NONE, RUNTIMES};

/// How the selection was arrived at, for the line `init` prints.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// `--agent` on the command line.
    Flags,
    /// Remembered from a previous run.
    Saved,
    /// The user picked in the multi-select.
    Picker,
    /// No flags, nothing remembered, no TTY: every detected runtime.
    Auto,
}

#[derive(Debug)]
pub struct Selection {
    pub runtimes: Vec<&'static Runtime>,
    pub source: Source,
    /// Lines to print before the summary — compatibility notices, mostly.
    pub notices: Vec<String>,
    /// What this source decided about the MCP registration, if anything. The
    /// picker asks and `agents.toml` remembers; `--agent` says nothing about
    /// it. [`resolve_mcp`] turns it into the answer.
    pub mcp: Option<Choice>,
}

/// Resolve `--agent` values.
///
/// `auto` (the default) is every detected runtime; `all` is every known one;
/// `none` is the portable skill and nothing else. Values combine, so
/// `--agent auto --agent kiro` is "what you found, plus Kiro".
pub fn from_flags(values: &[String], env: &DetectEnv) -> Result<Selection, CliError> {
    let mut runtimes: Vec<&'static Runtime> = Vec::new();
    let mut notices: Vec<String> = Vec::new();

    let push = |r: &'static Runtime, into: &mut Vec<&'static Runtime>| {
        if !into.iter().any(|e| e.id == r.id) {
            into.push(r);
        }
    };

    for value in values {
        match value.as_str() {
            ALL => {
                for r in RUNTIMES {
                    push(r, &mut runtimes);
                }
            }
            AUTO => {
                for r in super::detect(env) {
                    push(r, &mut runtimes);
                }
            }
            NONE => {}
            other => {
                if let Some(r) = super::find(other) {
                    push(r, &mut runtimes);
                    continue;
                }
                if let Some((_, mapped, notice)) =
                    COMPAT_ALIASES.iter().find(|(alias, _, _)| *alias == other)
                {
                    notices.push((*notice).to_string());
                    if let Some(id) = mapped.and_then(super::find) {
                        push(id, &mut runtimes);
                    }
                    continue;
                }
                return Err(CliError::general(format!(
                    "unknown agent '{other}'.\nValid values: {}, {ALL}, {AUTO}, {NONE}",
                    RUNTIMES.iter().map(|r| r.id).collect::<Vec<_>>().join(", ")
                )));
            }
        }
    }

    // Keep the registry's order whatever order the flags came in.
    runtimes.sort_by_key(|r| {
        RUNTIMES
            .iter()
            .position(|x| x.id == r.id)
            .unwrap_or(usize::MAX)
    });
    Ok(Selection {
        runtimes,
        source: Source::Flags,
        notices,
        mcp: None,
    })
}

/// Every detected runtime, for the no-flags non-interactive path.
pub fn auto(env: &DetectEnv) -> Selection {
    Selection {
        runtimes: super::detect(env),
        source: Source::Auto,
        notices: Vec::new(),
        mcp: None,
    }
}

/// The MCP registration decision.
///
/// `--no-mcp` always wins, because it is the only input the user typed *this*
/// run to say no. Otherwise whatever this run's source decided — the picker
/// asked, or `agents.toml` remembered — and otherwise yes: a runtime with no
/// entry in its MCP config cannot see the `agentcordon_*` tools at all, and
/// the surface is a fixed six tools whatever the workspace holds.
///
/// `--expose` replaces the remembered list rather than adding to it, exactly
/// as `--agent` replaces the remembered runtimes.
pub fn resolve_mcp(no_mcp: bool, expose: &[String], decided: Option<&Choice>) -> Choice {
    let register = !no_mcp && decided.is_none_or(|c| c.register);
    let expose = if expose.is_empty() {
        decided.map(|c| c.expose.clone()).unwrap_or_default()
    } else {
        let mut seen: Vec<String> = Vec::new();
        for server in expose {
            if !seen.iter().any(|s| s == server) {
                seen.push(server.clone());
            }
        }
        seen
    };
    Choice { register, expose }
}

// ---------------------------------------------------------------------------
// The remembered choice
// ---------------------------------------------------------------------------

/// `.agentcordon/agents.toml`, relative to the workspace root.
pub const SAVED_PATH: &str = ".agentcordon/agents.toml";

#[derive(serde::Serialize, serde::Deserialize, Debug, Default)]
pub struct Saved {
    /// Bumped if the shape ever changes; an unknown version is ignored rather
    /// than failing `init`.
    pub version: u32,
    pub runtimes: Vec<String>,
    /// Whether `init` writes each runtime's MCP configuration. Absent in a
    /// file written before the MCP surface existed, which reads as "nothing
    /// was decided" rather than as "no".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mcp: Option<bool>,
    /// Servers re-exported as typed tools, from `--expose`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub expose: Vec<String>,
}

/// Read the remembered choice. A file that is missing, unparseable or from a
/// future version reads as "nothing remembered" — `init` must never fail
/// because of it.
pub fn load(root: &Path) -> Option<Selection> {
    let text = std::fs::read_to_string(root.join(".agentcordon").join("agents.toml")).ok()?;
    let saved: Saved = toml::from_str(&text).ok()?;
    if saved.version != 1 {
        return None;
    }
    let mcp = match (saved.mcp, saved.expose.is_empty()) {
        (None, true) => None,
        (register, _) => Some(Choice {
            register: register.unwrap_or(true),
            expose: saved.expose,
        }),
    };
    Some(Selection {
        runtimes: saved
            .runtimes
            .iter()
            .filter_map(|id| super::find(id))
            .collect(),
        source: Source::Saved,
        notices: Vec::new(),
        mcp,
    })
}

/// Remember the choice so the next `init` is non-interactive.
pub fn save(root: &Path, runtimes: &[&'static Runtime], mcp: &Choice) -> Result<(), CliError> {
    let dir = root.join(".agentcordon");
    std::fs::create_dir_all(&dir)
        .map_err(|e| CliError::general(format!("failed to create .agentcordon/: {e}")))?;
    let saved = Saved {
        version: 1,
        runtimes: runtimes.iter().map(|r| r.id.to_string()).collect(),
        mcp: Some(mcp.register),
        expose: mcp.expose.clone(),
    };
    let body = format!(
        "# Which agent runtimes `agentcordon init` installs the AgentCordon skill for.\n\
         # Written by `agentcordon init`; re-run with `--reconfigure` to choose again.\n\
         {}",
        toml::to_string(&saved).map_err(|e| CliError::general(e.to_string()))?
    );
    std::fs::write(dir.join("agents.toml"), body)
        .map_err(|e| CliError::general(format!("failed to write {SAVED_PATH}: {e}")))
}

// ---------------------------------------------------------------------------
// The picker
// ---------------------------------------------------------------------------

/// Whether `init` may prompt: both ends of the pipe have to be a terminal, or
/// the prompt is invisible, unanswerable, or both. The UAT harness and every
/// script run `init` through a pipe and so never see it.
pub fn interactive() -> bool {
    std::io::stdin().is_terminal() && std::io::stdout().is_terminal()
}

/// The two entries above the runtimes in the multi-select.
const PICK_ALL: usize = 0;
const PICK_NONE: usize = 1;
const PICK_OFFSET: usize = 2;

/// The picker's items, in order. Exposed so the label text is testable
/// without a terminal.
pub fn items(detected: &[&'static Runtime]) -> Vec<String> {
    let mut items = vec![
        "All runtimes".to_string(),
        "None — install only the portable skill (.agents/skills/)".to_string(),
    ];
    for r in RUNTIMES {
        let mark = if detected.iter().any(|d| d.id == r.id) {
            "  (detected)"
        } else {
            ""
        };
        items.push(format!("{}{mark}", r.display));
    }
    items
}

/// Turn the multi-select's chosen indices into a selection.
///
/// "All" and "None" win over individual boxes, and "None" wins over "All":
/// a user who ticked both said two contradictory things, and the safer reading
/// of the contradiction is the smaller install.
pub fn from_indices(chosen: &[usize]) -> Vec<&'static Runtime> {
    if chosen.contains(&PICK_NONE) {
        return Vec::new();
    }
    if chosen.contains(&PICK_ALL) {
        return RUNTIMES.iter().collect();
    }
    RUNTIMES
        .iter()
        .enumerate()
        .filter(|(i, _)| chosen.contains(&(i + PICK_OFFSET)))
        .map(|(_, r)| r)
        .collect()
}

/// The one yes/no asked after the runtime list. Both halves of the trade-off
/// are in the question, because a token cost the user is not told about is a
/// cost they cannot consent to.
pub const MCP_QUESTION: &str =
    "Also register the AgentCordon MCP server with these runtimes? (native tools; about 800 \
     tokens per session)";

/// Show the multi-select, pre-checked with what was detected.
pub fn prompt(detected: &[&'static Runtime]) -> Result<Selection, CliError> {
    let items = items(detected);
    let mut defaults = vec![false, false];
    defaults.extend(
        RUNTIMES
            .iter()
            .map(|r| detected.iter().any(|d| d.id == r.id)),
    );

    println!("agentcordon init installs the AgentCordon skill for:");
    let chosen = dialoguer::MultiSelect::new()
        .with_prompt("space to toggle, enter to confirm")
        .items(&items)
        .defaults(&defaults)
        .report(false)
        .interact()
        .map_err(|e| CliError::general(format!("could not read your selection: {e}")))?;

    let runtimes = from_indices(&chosen);
    // Nothing to register against when the answer was "none", so do not ask.
    let mcp = if runtimes.is_empty() {
        None
    } else {
        Some(Choice {
            register: dialoguer::Confirm::new()
                .with_prompt(MCP_QUESTION)
                .default(true)
                .interact()
                .map_err(|e| CliError::general(format!("could not read your answer: {e}")))?,
            expose: Vec::new(),
        })
    };

    Ok(Selection {
        runtimes,
        source: Source::Picker,
        notices: Vec::new(),
        mcp,
    })
}
