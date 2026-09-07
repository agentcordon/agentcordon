//! The agent-runtime registry: which coding agents this workspace is set up
//! for, how to notice that one is present, and what each one reads.
//!
//! The product decision this module encodes is that **the Agent Skill is the
//! integration**. `.agents/skills/agentcordon/SKILL.md` is the open-standard
//! path ([agentskills.io](https://agentskills.io/specification)), and thirteen
//! of the fifteen runtimes below read it without any further configuration.
//! Three runtimes read a different directory instead, so they get a byte copy
//! there. One runtime — Aider — has no skill discovery at all, so it gets the
//! one pointer file this module writes.
//!
//! Nothing here writes `AGENTS.md`, `CLAUDE.md` or `GEMINI.md`. A prose block
//! in an always-on instruction file costs context in every session, is capped
//! by several runtimes (Windsurf: 12,000 characters per rule file; Codex:
//! 32 KiB for the concatenated chain), and is shadowed outright by Zed's
//! first-match rule. A skill is loaded as ~100 tokens of metadata and its body
//! is read only when the task is about credentials or MCP.
//!
//! Sources for every path below are cited per runtime in
//! `uat/artifacts/reviews/ONBOARDING-landscape.md` § 3.

use std::path::{Path, PathBuf};

pub mod install;
pub mod mcp;
pub mod select;

/// The canonical, cross-runtime skill directory. Always written, whatever the
/// user selected: it is the open-standard location, it is what Aider's
/// `.aider.conf.yml` entry points at, and it is what a runtime nobody selected
/// will find if it is opened in this workspace later.
pub const PORTABLE_SKILL_DIR: &str = ".agents/skills";

/// The skill's directory name, and its `name:` in frontmatter. The Agent
/// Skills spec requires the two to match.
pub const SKILL_NAME: &str = "agentcordon";

/// The skill, verbatim. One file, owned by `init`, copied unchanged into every
/// skill directory a selected runtime reads.
pub const SKILL_MD: &str = include_str!("SKILL.md");

/// Something whose presence means a runtime is probably in use.
///
/// Detection is a convenience for the picker's pre-checked boxes and for
/// `--agent auto`; it is never load-bearing. A false negative costs one
/// keystroke in the picker, a false positive costs one unread file.
///
/// No marker may name a path `init` itself writes, **or a directory `init`
/// creates on the way there**. A runtime that detects on its own installed
/// skill or MCP entry can never be deselected: `--reconfigure` and
/// `--agent auto` would keep finding it, and the file would keep being
/// refreshed. `detection_ignores_everything_init_writes` pins this, and it is
/// why several runtimes below name a rules file rather than the config
/// directory that now also holds `mcp.json`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Marker {
    /// An executable of this name on `PATH`.
    Binary(&'static str),
    /// A file or directory of this name under `$HOME`.
    Home(&'static str),
    /// A file or directory of this name in the workspace.
    Project(&'static str),
}

/// A file this runtime needs that the portable skill does not already cover.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Writer {
    /// Copy the skill into another skill root, e.g. `.claude/skills`. Written
    /// as `<root>/agentcordon/SKILL.md`.
    SkillCopy(&'static str),
    /// Aider reads nothing automatically and has no skills: it needs a `read:`
    /// entry in `.aider.conf.yml` naming the portable skill.
    /// <https://aider.chat/docs/usage/conventions.html>
    AiderRead,
}

/// One coding-agent runtime.
#[derive(Debug, Clone, Copy)]
pub struct Runtime {
    /// The `--agent` value and the key stored in `.agentcordon/agents.toml`.
    pub id: &'static str,
    /// What the picker calls it.
    pub display: &'static str,
    pub markers: &'static [Marker],
    /// What this runtime needs beyond [`PORTABLE_SKILL_DIR`].
    pub writers: &'static [Writer],
    /// Where `agentcordon mcp-serve` gets registered for this runtime.
    pub mcp: McpConfig,
    /// Which skill directory this runtime actually reads, for the summary.
    pub reads: &'static str,
    /// One line printed in the summary when this runtime is selected, for
    /// anything the files cannot say for themselves.
    pub note: Option<&'static str>,
}

/// Every runtime `init` knows about.
///
/// Ordered by how widely each is used, because this is also the picker's
/// order. Each `reads` value is the runtime's own documented discovery path;
/// where a runtime lists several, the portable one is chosen so the workspace
/// carries one file instead of five.
pub const RUNTIMES: &[Runtime] = &[
    Runtime {
        id: "claude-code",
        display: "Claude Code",
        markers: &[
            Marker::Binary("claude"),
            Marker::Home(".claude"),
            Marker::Project("CLAUDE.md"),
            Marker::Project(".claude/settings.json"),
            Marker::Project(".claude/settings.local.json"),
            Marker::Project(".claude/commands"),
        ],
        // Claude Code's skill paths are `.claude/skills/`, `~/.claude/skills/`
        // and plugins. `.agents/skills` is not among them.
        // https://code.claude.com/docs/en/skills
        writers: &[Writer::SkillCopy(".claude/skills")],
        reads: ".claude/skills/agentcordon/SKILL.md",
        // Project-scoped `.mcp.json`, `mcpServers`. A stdio entry is one with
        // a `command` and no `type`.
        // https://code.claude.com/docs/en/mcp
        mcp: McpConfig::Project(McpFile {
            path: ".mcp.json",
            shape: McpShape::Json {
                key: "mcpServers",
                stdio: false,
            },
        }),
        note: None,
    },
    Runtime {
        id: "codex",
        display: "OpenAI Codex CLI",
        markers: &[Marker::Binary("codex"), Marker::Home(".codex")],
        // `.agents/skills` from cwd up to the repo root.
        // https://learn.chatgpt.com/docs/build-skills
        writers: &[],
        reads: PORTABLE_SKILL_DIR,
        // `~/.codex/config.toml`, and a project `.codex/config.toml` for a
        // project you have marked trusted.
        // https://learn.chatgpt.com/docs/extend/mcp?surface=cli
        mcp: McpConfig::Project(McpFile {
            path: ".codex/config.toml",
            shape: McpShape::Toml,
        }),
        note: None,
    },
    Runtime {
        id: "opencode",
        display: "OpenCode",
        markers: &[
            Marker::Binary("opencode"),
            Marker::Home(".config/opencode"),
            Marker::Project("opencode.jsonc"),
            Marker::Project(".opencode"),
        ],
        // Reads `.agents/skills` among several. https://opencode.ai/docs/skills/
        writers: &[],
        reads: PORTABLE_SKILL_DIR,
        // `opencode.json`, key `mcp`, `type: "local"` and one command array.
        // https://opencode.ai/docs/mcp-servers/
        mcp: McpConfig::Project(McpFile {
            path: "opencode.json",
            shape: McpShape::OpenCode,
        }),
        note: None,
    },
    Runtime {
        id: "gemini",
        display: "Gemini CLI",
        markers: &[
            Marker::Binary("gemini"),
            Marker::Home(".gemini"),
            Marker::Project(".gemini/commands"),
            Marker::Project("GEMINI.md"),
        ],
        // `.agents/skills` (workspace), on by default.
        // https://geminicli.com/docs/cli/skills/
        writers: &[],
        reads: PORTABLE_SKILL_DIR,
        // `.gemini/settings.json`, `mcpServers` at the top level.
        // https://geminicli.com/docs/tools/mcp-server/
        mcp: McpConfig::Project(McpFile {
            path: ".gemini/settings.json",
            shape: McpShape::Json {
                key: "mcpServers",
                stdio: false,
            },
        }),
        note: None,
    },
    Runtime {
        id: "copilot",
        display: "GitHub Copilot (VS Code and CLI)",
        markers: &[
            Marker::Binary("copilot"),
            Marker::Home(".copilot"),
            Marker::Project(".github/copilot-instructions.md"),
            Marker::Project(".vscode/settings.json"),
            Marker::Project(".vscode/extensions.json"),
        ],
        // `.github/skills`, `.claude/skills`, `.agents/skills`.
        // https://code.visualstudio.com/docs/copilot/customization/agent-skills
        writers: &[],
        reads: PORTABLE_SKILL_DIR,
        // Two clients under one name. VS Code reads `.vscode/mcp.json`, key
        // `servers`, and documents `"type": "stdio"` as required
        // (https://code.visualstudio.com/docs/copilot/customization/mcp-servers).
        // Copilot CLI has no project file at all: `~/.copilot/mcp-config.json`
        // only, with a `tools` allow-list
        // (https://docs.github.com/en/copilot/how-tos/copilot-cli/customize-copilot/add-mcp-servers).
        mcp: McpConfig::ProjectAndUser(
            McpFile {
                path: ".vscode/mcp.json",
                shape: McpShape::Json {
                    key: "servers",
                    stdio: true,
                },
            },
            McpUser {
                path: "~/.copilot/mcp-config.json",
                shape: McpShape::CopilotCli,
                label: "GitHub Copilot CLI",
                command: Some("copilot mcp add"),
            },
        ),
        note: None,
    },
    Runtime {
        id: "cursor",
        display: "Cursor",
        markers: &[
            Marker::Binary("cursor"),
            Marker::Home(".cursor"),
            Marker::Project(".cursor/rules"),
            Marker::Project(".cursorrules"),
        ],
        // `.agents/skills`, `.cursor/skills`. https://cursor.com/docs/context/skills
        writers: &[],
        reads: PORTABLE_SKILL_DIR,
        // `.cursor/mcp.json`, `mcpServers`; `type` is documented as required.
        // https://cursor.com/docs/context/mcp
        mcp: McpConfig::Project(McpFile {
            path: ".cursor/mcp.json",
            shape: McpShape::Json {
                key: "mcpServers",
                stdio: true,
            },
        }),
        note: None,
    },
    Runtime {
        id: "windsurf",
        display: "Windsurf",
        markers: &[
            Marker::Binary("windsurf"),
            Marker::Home(".codeium/windsurf"),
            Marker::Project(".windsurf"),
            Marker::Project(".devin"),
        ],
        // `.windsurf/skills`, `.agents/skills`.
        // https://docs.devin.ai/desktop/cascade/skills
        writers: &[],
        reads: PORTABLE_SKILL_DIR,
        // `~/.codeium/windsurf/mcp_config.json` only — no project-level file.
        // https://docs.devin.ai/desktop/cascade/mcp
        mcp: McpConfig::User(McpUser {
            path: "~/.codeium/windsurf/mcp_config.json",
            shape: McpShape::Json {
                key: "mcpServers",
                stdio: false,
            },
            label: "Windsurf",
            command: None,
        }),
        note: Some(
            "Windsurf caps a workspace *rule* file at 12,000 characters. A skill is not a \
             rule file, so the cap does not apply and nothing was added to .windsurfrules.",
        ),
    },
    Runtime {
        id: "cline",
        display: "Cline",
        markers: &[
            Marker::Home(".cline"),
            Marker::Project(".clinerules"),
            Marker::Project(".cline"),
        ],
        // `.cline/skills`, `.clinerules/skills`, `.claude/skills` — not
        // `.agents/skills`. https://docs.cline.bot/features/skills
        writers: &[Writer::SkillCopy(".claude/skills")],
        reads: ".claude/skills/agentcordon/SKILL.md",
        // `~/.cline/mcp.json` (CLI) or the extension's settings UI. No
        // project-level file. https://docs.cline.bot/mcp/configuring-mcp-servers
        mcp: McpConfig::User(McpUser {
            path: "~/.cline/mcp.json",
            shape: McpShape::Json {
                key: "mcpServers",
                stdio: false,
            },
            label: "Cline",
            command: None,
        }),
        note: None,
    },
    Runtime {
        id: "roo",
        display: "Roo Code",
        markers: &[
            Marker::Home(".roo"),
            Marker::Project(".roo/rules"),
            Marker::Project(".roorules"),
        ],
        // `.roo/skills`, `.agents/skills`. https://docs.roocode.com/features/skills
        writers: &[],
        reads: PORTABLE_SKILL_DIR,
        // `.roo/mcp.json`, `mcpServers`; `type` defaults to `stdio` when there
        // is a `command`, so it is omitted.
        // https://roocodeinc.github.io/Roo-Code/features/mcp/using-mcp-in-roo
        mcp: McpConfig::Project(McpFile {
            path: ".roo/mcp.json",
            shape: McpShape::Json {
                key: "mcpServers",
                stdio: false,
            },
        }),
        note: None,
    },
    Runtime {
        id: "aider",
        display: "Aider",
        markers: &[
            Marker::Binary("aider"),
            Marker::Home(".aider.conf.yml"),
            // `.aider.conf.yml` is deliberately *not* a marker: `init` writes
            // it for this runtime, so detecting on it would make Aider
            // impossible to deselect. These two are written by Aider itself.
            Marker::Project(".aider.input.history"),
            Marker::Project(".aider.chat.history.md"),
        ],
        // Aider auto-loads nothing and has no skill discovery: the only route
        // in is `read:` in `.aider.conf.yml`.
        // https://aider.chat/docs/usage/conventions.html
        writers: &[Writer::AiderRead],
        reads: ".agents/skills/agentcordon/SKILL.md (via .aider.conf.yml `read:`)",
        // Aider has no MCP client: neither the options reference nor HISTORY
        // mentions MCP. https://aider.chat/docs/config/options.html
        mcp: McpConfig::None,
        note: Some(
            "Aider has no skill discovery, so .aider.conf.yml names the skill explicitly. \
             Aider also asks you before running a shell command, so calls are human-approved.",
        ),
    },
    Runtime {
        id: "amp",
        display: "Amp",
        markers: &[
            // No project marker: `.amp/` holds exactly one documented file,
            // `settings.json`, and `init` writes it.
            Marker::Binary("amp"),
            Marker::Home(".config/amp"),
        ],
        // `.agents/skills` (+parents), `.claude/skills`.
        // https://ampcode.com/docs/customize/skills
        writers: &[],
        reads: PORTABLE_SKILL_DIR,
        // Workspace `.amp/settings.json`, key `"amp.mcpServers"` — one key
        // with a dot in it, not a nested path.
        // https://ampcode.com/docs/customize/mcp
        mcp: McpConfig::Project(McpFile {
            path: ".amp/settings.json",
            shape: McpShape::Json {
                key: "amp.mcpServers",
                stdio: false,
            },
        }),
        note: None,
    },
    Runtime {
        id: "goose",
        display: "Goose",
        markers: &[
            Marker::Binary("goose"),
            Marker::Home(".config/goose"),
            Marker::Project(".goosehints"),
            Marker::Project(".goose"),
        ],
        // `.agents/skills` is the recommended project path.
        // block/goose documentation/docs/guides/context-engineering/using-skills.md
        writers: &[],
        reads: PORTABLE_SKILL_DIR,
        // `~/.config/goose/config.yaml`, key `extensions`, `cmd` rather than
        // `command`. No project-level config.
        // https://block.github.io/goose/docs/guides/config-file/
        mcp: McpConfig::User(McpUser {
            path: "~/.config/goose/config.yaml",
            shape: McpShape::Goose,
            label: "Goose",
            command: Some("goose configure"),
        }),
        note: None,
    },
    Runtime {
        id: "zed",
        display: "Zed",
        markers: &[
            Marker::Binary("zed"),
            Marker::Home(".config/zed"),
            Marker::Project(".zed"),
        ],
        // `<worktree>/.agents/skills/` and `~/.agents/skills/` only.
        // https://zed.dev/docs/ai/skills
        writers: &[],
        reads: PORTABLE_SKILL_DIR,
        // `context_servers` in Zed's user settings; the docs show no
        // project-level `.zed/settings.json` entry for it.
        // https://zed.dev/docs/ai/mcp
        mcp: McpConfig::User(McpUser {
            path: "~/.config/zed/settings.json",
            shape: McpShape::Zed,
            label: "Zed",
            command: None,
        }),
        note: Some(
            "Zed loads only the first of .rules / .cursorrules / .windsurfrules / \
             .clinerules / .github/copilot-instructions.md / AGENT.md / AGENTS.md. Skills \
             are discovered separately, so that shadowing does not apply here.",
        ),
    },
    Runtime {
        id: "junie",
        display: "JetBrains Junie",
        markers: &[
            Marker::Home(".junie"),
            Marker::Project(".junie/guidelines.md"),
            Marker::Project(".junie/rules"),
            Marker::Project(".junie/AGENTS.md"),
        ],
        // `.junie/skills`, `.agents/skills` (trusted project).
        // https://junie.jetbrains.com/docs/agent-skills.html
        writers: &[],
        reads: PORTABLE_SKILL_DIR,
        // `.junie/mcp/mcp.json` (project), `~/.junie/mcp/mcp.json` (user).
        // https://junie.jetbrains.com/docs/junie-cli-mcp-configuration.html
        mcp: McpConfig::Project(McpFile {
            path: ".junie/mcp/mcp.json",
            shape: McpShape::Json {
                key: "mcpServers",
                stdio: false,
            },
        }),
        note: Some("Junie reads .agents/skills only in a project you have marked trusted."),
    },
    Runtime {
        id: "kiro",
        display: "Kiro",
        markers: &[
            Marker::Binary("kiro"),
            Marker::Home(".kiro"),
            Marker::Project(".kiro/steering"),
            Marker::Project(".kiro/specs"),
        ],
        // `.kiro/skills`, `~/.kiro/skills`. `.agents/skills` is not listed.
        // https://kiro.dev/docs/skills/
        writers: &[Writer::SkillCopy(".kiro/skills")],
        reads: ".kiro/skills/agentcordon/SKILL.md",
        // `.kiro/settings/mcp.json` (workspace), `~/.kiro/settings/mcp.json`
        // (user); workspace wins. https://kiro.dev/docs/mcp/configuration/
        mcp: McpConfig::Project(McpFile {
            path: ".kiro/settings/mcp.json",
            shape: McpShape::Json {
                key: "mcpServers",
                stdio: false,
            },
        }),
        note: None,
    },
];

/// `--agent` values that are not runtimes.
pub const ALL: &str = "all";
pub const AUTO: &str = "auto";
pub const NONE: &str = "none";

/// `--agent` values kept only so an old command line does not fail.
///
/// `openclaw` used to write `.openclaw/instructions.md`, a path OpenClaw does
/// not read: it is a self-hosted gateway whose workspace is
/// `~/.openclaw/workspace`, not a project directory
/// (<https://docs.openclaw.ai/concepts/agent>). It reads
/// `<workspace>/.agents/skills`, which is what `init` writes, so the name maps
/// to the portable skill and nothing else.
pub const COMPAT_ALIASES: &[(&str, Option<&str>, &str)] = &[(
    "openclaw",
    None,
    "`--agent openclaw` now installs only the portable skill. OpenClaw reads \
     <workspace>/.agents/skills, not a project .openclaw/ directory, so the old \
     .openclaw/instructions.md was never loaded by anything.",
)];

pub fn find(id: &str) -> Option<&'static Runtime> {
    RUNTIMES.iter().find(|r| r.id == id)
}

/// Where detection looks. Injected so the tests can stub a `$HOME` and a
/// `PATH` without touching either.
#[derive(Debug, Clone)]
pub struct DetectEnv {
    pub workspace: PathBuf,
    pub home: Option<PathBuf>,
    pub path_dirs: Vec<PathBuf>,
}

impl DetectEnv {
    /// The real environment: this workspace, `$HOME`, and `$PATH`.
    pub fn current(workspace: &Path) -> Self {
        Self {
            workspace: workspace.to_path_buf(),
            home: dirs::home_dir(),
            path_dirs: std::env::var_os("PATH")
                .map(|p| std::env::split_paths(&p).collect())
                .unwrap_or_default(),
        }
    }

    fn matches(&self, marker: &Marker) -> bool {
        match marker {
            Marker::Binary(name) => self.path_dirs.iter().any(|d| d.join(name).exists()),
            Marker::Home(rel) => self.home.as_ref().is_some_and(|h| h.join(rel).exists()),
            Marker::Project(rel) => self.workspace.join(rel).exists(),
        }
    }
}

/// Every runtime with at least one marker present.
pub fn detect(env: &DetectEnv) -> Vec<&'static Runtime> {
    RUNTIMES
        .iter()
        .filter(|r| r.markers.iter().any(|m| env.matches(m)))
        .collect()
}

// ---------------------------------------------------------------------------
// MCP server registration
// ---------------------------------------------------------------------------

/// The binary a runtime starts, and the name the entry is filed under.
///
/// Bare, never a path. PATH resolution stays the user's, and an absolute path
/// baked into a file that gets committed is wrong on every other machine.
pub const MCP_COMMAND: &str = "agentcordon";
pub const MCP_ENTRY: &str = SKILL_NAME;

/// How a runtime spells a stdio MCP server entry.
///
/// The shapes differ in four ways only: the key the map of servers lives
/// under, whether the transport has to be named, whether the command is a
/// string plus an argument list or one array, and the file format. Each use
/// in [`RUNTIMES`] cites the documentation it was read from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum McpShape {
    /// `{"<key>": {"agentcordon": {"command": …, "args": […]}}}`. `stdio` adds
    /// `"type": "stdio"`, which VS Code and Cursor document as required and
    /// which Claude Code and Roo infer from the absence of `url`.
    Json { key: &'static str, stdio: bool },
    /// OpenCode: `"type": "local"` and one `command` array.
    OpenCode,
    /// Codex: `[mcp_servers.agentcordon]` in TOML.
    Toml,
    /// Copilot CLI: `mcpServers`, `"type": "local"`, and a `tools` allow-list.
    CopilotCli,
    /// Zed: `context_servers`, with `"source": "custom"`.
    Zed,
    /// Goose: a YAML `extensions:` map, `cmd` rather than `command`.
    Goose,
}

/// A project-level MCP config file, relative to the workspace root.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct McpFile {
    /// Workspace-relative, `/`-separated.
    pub path: &'static str,
    pub shape: McpShape,
}

/// A user-level MCP config `init` never writes: it is outside the workspace,
/// shared by every project, and often maintained by the runtime's own CLI. It
/// is printed instead, path and snippet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct McpUser {
    /// As displayed, with `~`. Never expanded and never opened.
    pub path: &'static str,
    pub shape: McpShape,
    /// Which client this covers, when the runtime also has a project file.
    pub label: &'static str,
    /// The command that edits it, when the runtime ships one.
    pub command: Option<&'static str>,
}

/// Where a runtime's registration for `agentcordon mcp-serve` lives.
///
/// Every runtime names one of these four. A new entry in [`RUNTIMES`] cannot
/// be left undecided; `every_runtime_declares_what_it_does_about_mcp` fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum McpConfig {
    /// A project-level file `init` writes.
    Project(McpFile),
    /// A project-level file, plus a user-level path for a second client that
    /// ships under the same name and has no project file of its own.
    ProjectAndUser(McpFile, McpUser),
    /// User-level only: printed, not written.
    User(McpUser),
    /// Not an MCP client.
    None,
}
