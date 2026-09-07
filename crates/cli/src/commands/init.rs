//! `agentcordon init` — generate the workspace key, install the AgentCordon
//! skill for the agent runtimes this workspace is used with, and enrol the
//! workspace with the configured server.
//!
//! Enrolment moved here in v0.4.1. Install-to-use is three commands: the admin
//! starts the server, the developer runs the one-liner the server serves, and
//! `agentcordon init` does everything else. The server URL comes from the
//! config file the installer wrote, so nothing has to be copied out of a
//! terminal. `register` is unchanged and remains the standalone re-enrolment
//! command; `--no-register` is how a script or an air-gapped setup gets the
//! old `init`.
//!
//! What `init` writes changed in v0.4.1. It used to write a ~5.5 KB prose
//! block into `AGENTS.md`, a `CLAUDE.md` importing it, and two stub files
//! (`.codex/instructions.md`, `.openclaw/instructions.md`) that no runtime has
//! ever read. It now writes one Agent Skill, into the skill directory each
//! selected runtime documents. The reasoning is ADR-0013; the evidence is
//! `uat/artifacts/reviews/ONBOARDING-landscape.md` (which runtime reads what)
//! and `ONBOARDING-empirical.md` (that the instructions are what makes an
//! agent use the broker at all).

use std::fs;
use std::path::{Path, PathBuf};

use agentcordon_identity::{pk_hash_of, KeyFileError};

use crate::agents::install::Action;
use crate::agents::{self, install, mcp, select, DetectEnv};
use crate::broker::BrokerClient;
use crate::commands::register;
use crate::config::{self, ServerUrl};
use crate::error::CliError;
use crate::{broker_autostart, signing::workspace_dir};

/// The parsed `agentcordon init` command line.
#[derive(Debug, Default, Clone)]
pub struct InitArgs {
    /// `--agent`, repeatable. Empty means "decide": the remembered choice, the
    /// picker, or `auto`, in that order.
    pub agents: Vec<String>,
    /// Ignore the remembered choice and pick again.
    pub reconfigure: bool,
    /// Install the skill and stop: no broker, no device flow. For scripts and
    /// air-gapped setups.
    pub no_register: bool,
    /// `--server-url`, first in the precedence [`config::resolve_server_url`]
    /// applies.
    pub server_url: Option<String>,
    /// Workspace display name for the enrolment; the current directory's
    /// basename when omitted, exactly as for `register`.
    pub name: Option<String>,
    /// Install the skill but register no MCP server, for a user who wants the
    /// skill's zero always-on cost and not the ~800 tokens of tool schemas.
    pub no_mcp: bool,
    /// `--expose`, repeatable: brokered servers whose tools `mcp-serve`
    /// re-exports as typed tools.
    pub expose: Vec<String>,
}

/// What `init` does once the skill is installed.
#[derive(Debug, PartialEq, Eq)]
enum Enrollment {
    /// `--no-register`.
    Skipped,
    /// Enrol against this server.
    Enrol(ServerUrl),
    /// No server URL from the flag, the environment or the config file.
    Unconfigured,
}

/// The decision, with the resolved server URL supplied.
///
/// Being off a terminal is deliberately not an input. The picker needs a human
/// and is skipped without one, but the device flow prints a code and polls —
/// it never prompts — so a CI job that wants no enrolment says `--no-register`
/// rather than getting a different `init` for having no tty.
fn enrollment_plan(no_register: bool, configured: Option<ServerUrl>) -> Enrollment {
    if no_register {
        return Enrollment::Skipped;
    }
    match configured {
        Some(server) => Enrollment::Enrol(server),
        None => Enrollment::Unconfigured,
    }
}

/// The line `--no-register` prints, so the skipped step is visible rather than
/// silently absent.
const SKIPPED_NOTICE: &str =
    "--no-register: skipping enrollment. Run `agentcordon register` when you want it.";

/// The two lines that end a successful `init`.
fn registered_summary(workspace_name: &str, server: &str) -> String {
    format!("Registered as {workspace_name} at {server}.\nTry: agentcordon credentials")
}

/// The one line an already-enrolled workspace gets.
fn already_registered_line(server: &str) -> String {
    format!("Already registered with {server}. Nothing to do; `agentcordon register --force` re-enrols.")
}

/// The workspace root — the directory `init` writes into.
fn workspace_root() -> PathBuf {
    PathBuf::from(std::env::var("AGTCRDN_WORKSPACE_DIR").unwrap_or_else(|_| ".".to_string()))
}

/// Generate the Ed25519 keypair and install the skill.
///
/// The half of `init` that touches only this directory. Split from [`run`] so
/// it stays synchronous and testable without a broker.
pub fn install(args: &InitArgs) -> Result<(), CliError> {
    let key_dir = workspace_dir();
    let root = workspace_root();

    if agentcordon_identity::workspace_key_exists(&key_dir) {
        let pub_hex = agentcordon_identity::read_public_key_hex(&key_dir)
            .map_err(|e| CliError::general(e.to_string()))?;
        let pub_bytes = hex::decode(&pub_hex)
            .map_err(|e| CliError::general(format!("invalid public key format: {e}")))?;
        println!("Workspace identity: sha256:{}", pk_hash_of(&pub_bytes));
        println!("(keypair already exists)");
    } else {
        let key = agentcordon_identity::create_workspace_key(&key_dir).map_err(|e| match e {
            KeyFileError::AlreadyExists { .. } => {
                CliError::general(format!("{e} — re-run `agentcordon init`"))
            }
            other => CliError::general(other.to_string()),
        })?;
        println!("Workspace identity: sha256:{}", key.pk_hash());
        add_to_gitignore(&root)?;
    }

    let selection = resolve(args, &root)?;
    for notice in &selection.notices {
        println!("{notice}");
    }

    let choice = selection.mcp.clone().unwrap_or_default();
    let written = install::install(&root, &selection.runtimes)?;
    let registered = mcp::install(&root, &selection.runtimes, &choice)?;
    select::save(&root, &selection.runtimes, &choice)?;
    report(&selection, &written, &registered);

    Ok(())
}

/// `agentcordon init`: install the skill, then finish enrollment.
pub async fn run(args: InitArgs) -> Result<(), CliError> {
    install(&args)?;

    println!();
    match enrollment_plan(
        args.no_register,
        config::resolve_server_url(args.server_url.as_deref()),
    ) {
        Enrollment::Skipped => {
            println!("{SKIPPED_NOTICE}");
            Ok(())
        }
        Enrollment::Unconfigured => Err(CliError::general(format!(
            "{} Or run `agentcordon init --no-register` to set up this directory only.",
            config::missing_server_url_hint()
        ))),
        Enrollment::Enrol(server) => enroll(&args, &server).await,
    }
}

/// Start a broker if none is running, then run the same device flow
/// `register` runs.
async fn enroll(args: &InitArgs, server: &ServerUrl) -> Result<(), CliError> {
    println!(
        "Enrolling with {} (from {})",
        server.url,
        server.source.describe()
    );
    broker_autostart::ensure_broker_running(&server.url).await?;

    let client = match BrokerClient::connect_for_registration(false).await {
        Ok(c) => c,
        Err(e) if e.code == crate::error::ExitCode::BrokerNotRunning => {
            return Err(CliError::broker_not_running());
        }
        Err(e) => return Err(e),
    };

    if register::is_already_registered(&client).await {
        println!("{}", already_registered_line(&server.url));
        return Ok(());
    }

    let enrolled = register::device_flow(
        &client,
        Vec::new(),
        args.name.as_deref(),
        register::POLL_INTERVAL,
    )
    .await?;
    println!(
        "{}",
        registered_summary(&enrolled.workspace_name, &server.url)
    );
    Ok(())
}

/// Which runtimes to install for.
///
/// The order matters more than any single rule in it: an explicit `--agent`
/// always wins, a remembered choice makes a rerun quiet, and the picker only
/// appears when a human is there to answer it. That last clause is why the UAT
/// harness and every script that runs `init` in a pipe keep working.
fn resolve(args: &InitArgs, root: &Path) -> Result<select::Selection, CliError> {
    let env = DetectEnv::current(root);
    // Read once: the remembered MCP answer survives an explicit `--agent`,
    // which says nothing about it, but not `--reconfigure`, which is the user
    // asking to be asked again.
    let stored = select::load(root).filter(|_| !args.reconfigure);
    let remembered = stored.as_ref().and_then(|s| s.mcp.clone());

    let mut selection = if !args.agents.is_empty() {
        select::from_flags(&args.agents, &env)?
    } else if let Some(saved) = stored {
        saved
    } else if select::interactive() {
        select::prompt(&agents::detect(&env))?
    } else {
        select::auto(&env)
    };

    let decided = selection.mcp.take().or(remembered);
    selection.mcp = Some(select::resolve_mcp(
        args.no_mcp,
        &args.expose,
        decided.as_ref(),
    ));
    Ok(selection)
}

/// The closing summary: every file, what happened to it, and which of the
/// selected runtimes reads it.
fn report(
    selection: &select::Selection,
    written: &[install::Installed],
    registered: &[install::Installed],
) {
    println!();
    println!("AgentCordon skill:");
    for file in written {
        print_file(file, "read by");
    }

    if !registered.is_empty() {
        println!();
        let expose = selection
            .mcp
            .as_ref()
            .map(|c| c.expose.clone())
            .unwrap_or_default();
        let extra = if expose.is_empty() {
            String::new()
        } else {
            format!(", re-exporting {}", expose.join(", "))
        };
        println!("MCP server (`agentcordon mcp-serve`{extra}):");
        for file in registered {
            print_file(file, "used by");
        }
    }

    println!();
    if selection.runtimes.is_empty() {
        println!("No runtimes selected — only the portable skill was installed.");
    } else {
        println!(
            "Runtimes: {}",
            selection
                .runtimes
                .iter()
                .map(|r| r.display)
                .collect::<Vec<_>>()
                .join(", ")
        );
        for runtime in &selection.runtimes {
            if let Some(note) = runtime.note {
                println!("  {}: {note}", runtime.display);
            }
        }
    }
    let how = match selection.source {
        select::Source::Flags => "from --agent",
        select::Source::Saved => "remembered from a previous run",
        select::Source::Picker => "you picked them",
        select::Source::Auto => "detected in this workspace and your home directory",
    };
    println!(
        "({how}; saved to {} — rerun `agentcordon init --reconfigure` to choose again.)",
        select::SAVED_PATH
    );
}

/// One file's line in the summary: the verb, the path, who reads it, and
/// anything the verb does not say.
fn print_file(file: &install::Installed, whom: &str) {
    match &file.action {
        Action::Skipped { reason, snippet } => {
            println!("  not written {}", file.path);
            println!("              {reason}");
            for line in snippet.trim_end().lines() {
                println!("                {line}");
            }
        }
        other => {
            let verb = match other {
                Action::Created => "created",
                Action::Updated => "updated",
                _ => "unchanged",
            };
            let serves = if file.serves.is_empty() {
                "portable copy — read by any runtime that follows the Agent Skills standard"
                    .to_string()
            } else {
                format!("{whom} {}", file.serves.join(", "))
            };
            println!("  {verb:<11} {}", file.path);
            println!("              {serves}");
            if let Some(detail) = &file.detail {
                println!("              {detail}");
            }
        }
    }
}

/// Add `.agentcordon/` to `.gitignore` if not already present.
fn add_to_gitignore(root: &Path) -> Result<(), CliError> {
    let gitignore_path = root.join(".gitignore");
    let entry = ".agentcordon/";

    if gitignore_path.exists() {
        let content = fs::read_to_string(&gitignore_path)
            .map_err(|e| CliError::general(format!("failed to read .gitignore: {e}")))?;
        if content.lines().any(|line| line.trim() == entry) {
            return Ok(());
        }
        let separator = if content.ends_with('\n') { "" } else { "\n" };
        fs::write(&gitignore_path, format!("{content}{separator}{entry}\n"))
            .map_err(|e| CliError::general(format!("failed to update .gitignore: {e}")))?;
    } else {
        fs::write(&gitignore_path, format!("{entry}\n"))
            .map_err(|e| CliError::general(format!("failed to create .gitignore: {e}")))?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agents::{Marker, McpConfig, Runtime, RUNTIMES, SKILL_MD};
    use crate::config::ServerUrlSource;
    use crate::test_env::EnvGuard;
    use std::collections::BTreeSet;
    use tempfile::TempDir;

    /// Point the CLI at a scratch workspace root. Tests that touch the
    /// environment must run serially, which [`EnvGuard`] enforces
    /// process-wide.
    fn workspace_guard(dir: &Path) -> EnvGuard {
        let mut guard = EnvGuard::new();
        guard.set("AGTCRDN_WORKSPACE_DIR", dir);
        guard
    }

    fn init(agents: &[&str]) -> InitArgs {
        InitArgs {
            agents: agents.iter().map(|s| s.to_string()).collect(),
            ..InitArgs::default()
        }
    }

    // -----------------------------------------------------------------
    // The skill is the integration
    // -----------------------------------------------------------------

    /// The one file every runtime is meant to find.
    #[test]
    fn init_writes_the_portable_skill() {
        let dir = TempDir::new().unwrap();
        let _g = workspace_guard(dir.path());

        install(&init(&["claude-code"])).unwrap();

        let skill = dir.path().join(".agents/skills/agentcordon/SKILL.md");
        assert!(skill.exists(), "init must write the portable Agent Skill");
        let body = fs::read_to_string(&skill).unwrap();
        assert!(body.starts_with("---\nname: agentcordon\n"));
    }

    /// Claude Code discovers `.claude/skills/<name>/SKILL.md` with no
    /// `CLAUDE.md` and no `AGENTS.md` present — proved by a headless trial
    /// against Claude Code 2.1.263, recorded in ADR-0013 — so `init` writes
    /// the skill and no always-on prose block.
    #[test]
    fn selecting_claude_code_writes_a_skill_and_no_markdown_pointer() {
        let dir = TempDir::new().unwrap();
        let _g = workspace_guard(dir.path());

        install(&init(&["claude-code"])).unwrap();

        assert!(dir
            .path()
            .join(".claude/skills/agentcordon/SKILL.md")
            .exists());
        assert!(
            !dir.path().join("CLAUDE.md").exists(),
            "a runtime with skill discovery gets no CLAUDE.md"
        );
        assert!(
            !dir.path().join("AGENTS.md").exists(),
            "a runtime with skill discovery gets no AGENTS.md"
        );
    }

    /// `init` used to write `AGENTS.md`, `CLAUDE.md`, `.codex/instructions.md`
    /// and `.openclaw/instructions.md`. Two of those four were read by
    /// nothing; the other two put ~5.5 KB in every session of every runtime.
    #[test]
    fn init_writes_no_always_on_instruction_file_for_any_runtime() {
        let dir = TempDir::new().unwrap();
        let _g = workspace_guard(dir.path());

        install(&init(&["all"])).unwrap();

        for dead in [
            "AGENTS.md",
            "CLAUDE.md",
            "GEMINI.md",
            ".codex/instructions.md",
            ".openclaw/instructions.md",
            ".github/copilot-instructions.md",
            ".goosehints",
            ".cursor/rules/agentcordon.mdc",
        ] {
            assert!(
                !dir.path().join(dead).exists(),
                "{dead}: the skill is the integration; no always-on prose file is written"
            );
        }
    }

    /// Every runtime in the registry must end up with a skill it can actually
    /// discover — either the portable one or its own copy.
    #[test]
    fn every_runtime_gets_a_skill_it_reads() {
        for runtime in RUNTIMES {
            let dir = TempDir::new().unwrap();
            let _g = workspace_guard(dir.path());

            install(&init(&[runtime.id])).unwrap();

            let portable = dir.path().join(".agents/skills/agentcordon/SKILL.md");
            assert!(portable.exists(), "{}: portable skill", runtime.id);

            // `reads` is what the summary promises the runtime will load, so
            // it has to name a file that is on disk.
            let promised = runtime
                .reads
                .split_whitespace()
                .next()
                .expect("reads names a path");
            assert!(
                dir.path().join(promised).exists(),
                "{}: promises to be read from {promised}, which init did not write",
                runtime.id
            );
        }
    }

    /// Claude Code and Cline both read `.claude/skills`; selecting both must
    /// write one file, not two conflicting ones.
    #[test]
    fn runtimes_sharing_a_skill_root_share_one_file() {
        let dir = TempDir::new().unwrap();
        let _g = workspace_guard(dir.path());

        install(&init(&["claude-code", "cline"])).unwrap();

        let body =
            fs::read_to_string(dir.path().join(".claude/skills/agentcordon/SKILL.md")).unwrap();
        assert_eq!(body, SKILL_MD);
    }

    /// Rerunning must be a no-op, including after the user has re-selected.
    #[test]
    fn installing_twice_changes_nothing() {
        let dir = TempDir::new().unwrap();
        let _g = workspace_guard(dir.path());

        install(&init(&["all"])).unwrap();
        let before = tree(dir.path());
        install(&init(&["all"])).unwrap();
        install(&InitArgs::default()).unwrap();
        assert_eq!(before, tree(dir.path()), "init is idempotent");
    }

    /// A skill file the user (or an older `init`) left behind is brought up to
    /// date: `init` owns the whole file.
    #[test]
    fn a_stale_skill_file_is_rewritten() {
        let dir = TempDir::new().unwrap();
        let _g = workspace_guard(dir.path());
        let path = dir.path().join(".agents/skills/agentcordon/SKILL.md");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, "---\nname: agentcordon\n---\n\nold\n").unwrap();

        install(&init(&["none"])).unwrap();

        assert_eq!(fs::read_to_string(&path).unwrap(), SKILL_MD);
    }

    // -----------------------------------------------------------------
    // Aider — the one runtime with no skill discovery
    // -----------------------------------------------------------------

    #[test]
    fn aider_gets_a_read_entry_pointing_at_the_portable_skill() {
        let dir = TempDir::new().unwrap();
        let _g = workspace_guard(dir.path());

        install(&init(&["aider"])).unwrap();

        let conf = fs::read_to_string(dir.path().join(".aider.conf.yml")).unwrap();
        assert!(conf.contains("read:"));
        assert!(conf.contains(".agents/skills/agentcordon/SKILL.md"));
        assert!(dir
            .path()
            .join(".agents/skills/agentcordon/SKILL.md")
            .exists());
    }

    #[test]
    fn an_existing_aider_conf_keeps_its_own_keys() {
        let dir = TempDir::new().unwrap();
        let _g = workspace_guard(dir.path());
        fs::write(
            dir.path().join(".aider.conf.yml"),
            "model: gpt-4o\n# a comment we must not eat\nauto-commits: false\n",
        )
        .unwrap();

        install(&init(&["aider"])).unwrap();
        install(&init(&["aider"])).unwrap();

        let conf = fs::read_to_string(dir.path().join(".aider.conf.yml")).unwrap();
        assert!(conf.contains("model: gpt-4o"));
        assert!(conf.contains("# a comment we must not eat"));
        assert_eq!(conf.matches("# BEGIN AGENTCORDON").count(), 1);
        assert_eq!(conf.matches("read:").count(), 1);
    }

    /// A YAML mapping may carry only one `read:` key, so a config that already
    /// has one is left byte-identical and the line is printed instead.
    #[test]
    fn an_aider_conf_that_already_reads_something_is_left_alone() {
        let dir = TempDir::new().unwrap();
        let _g = workspace_guard(dir.path());
        let original = "read:\n  - CONVENTIONS.md\n";
        fs::write(dir.path().join(".aider.conf.yml"), original).unwrap();

        install(&init(&["aider"])).unwrap();

        assert_eq!(
            fs::read_to_string(dir.path().join(".aider.conf.yml")).unwrap(),
            original
        );
    }

    // -----------------------------------------------------------------
    // Selection
    // -----------------------------------------------------------------

    #[test]
    fn unknown_agent_is_rejected_and_the_error_lists_the_valid_ones() {
        let dir = TempDir::new().unwrap();
        let _g = workspace_guard(dir.path());

        let err = install(&init(&["emacs"])).unwrap_err();
        assert!(err.message.contains("unknown agent 'emacs'"));
        assert!(err.message.contains("claude-code"));
        assert!(err.message.contains("auto"));
    }

    /// The two names the old `--agent` accepted still parse, so a script or a
    /// docs page that predates this change does not break.
    #[test]
    fn the_old_agent_names_still_work() {
        for legacy in ["codex", "openclaw"] {
            let dir = TempDir::new().unwrap();
            let _g = workspace_guard(dir.path());
            install(&init(&[legacy])).unwrap();
            assert!(dir
                .path()
                .join(".agents/skills/agentcordon/SKILL.md")
                .exists());
            assert!(
                !dir.path().join(".openclaw").exists(),
                "{legacy}: nothing reads .openclaw/ in a project"
            );
            assert!(
                !dir.path().join(".codex/instructions.md").exists(),
                "{legacy}: Codex reads AGENTS.md and .agents/skills, never .codex/instructions.md"
            );
        }
    }

    /// The choice is remembered, so a rerun is non-interactive by default.
    #[test]
    fn the_choice_is_remembered_and_reused() {
        let dir = TempDir::new().unwrap();
        let _g = workspace_guard(dir.path());

        install(&init(&["kiro"])).unwrap();
        assert!(dir.path().join(".agentcordon/agents.toml").exists());

        // No flags: the remembered choice is used, so Kiro's copy is refreshed
        // and no other runtime's appears.
        fs::remove_dir_all(dir.path().join(".kiro")).unwrap();
        install(&InitArgs::default()).unwrap();
        assert!(dir
            .path()
            .join(".kiro/skills/agentcordon/SKILL.md")
            .exists());
        assert!(!dir.path().join(".claude/skills").exists());
    }

    /// A corrupt or future `agents.toml` must not make `init` fail; it reads
    /// as "nothing remembered".
    #[test]
    fn a_broken_agents_toml_is_ignored() {
        let dir = TempDir::new().unwrap();
        let _g = workspace_guard(dir.path());
        fs::create_dir_all(dir.path().join(".agentcordon")).unwrap();
        fs::write(dir.path().join(".agentcordon/agents.toml"), "not = [toml").unwrap();

        install(&InitArgs::default()).unwrap();

        assert!(dir
            .path()
            .join(".agents/skills/agentcordon/SKILL.md")
            .exists());
    }

    #[test]
    fn reconfigure_ignores_the_remembered_choice() {
        let dir = TempDir::new().unwrap();
        let _g = workspace_guard(dir.path());

        install(&init(&["kiro"])).unwrap();
        // Not a TTY under `cargo test`, so `--reconfigure` falls through to
        // detection rather than prompting. Kiro is not detectable from what
        // `init` wrote, so it drops out.
        install(&InitArgs {
            agents: Vec::new(),
            reconfigure: true,
            ..InitArgs::default()
        })
        .unwrap();

        let saved = fs::read_to_string(dir.path().join(".agentcordon/agents.toml")).unwrap();
        assert!(
            !saved.contains("kiro"),
            "--reconfigure replaces the remembered choice, it does not add to it"
        );
    }

    /// A runtime that detects on a file `init` wrote can never be deselected:
    /// `--reconfigure` and `--agent auto` would find it again every time, and
    /// keep refreshing a skill the user asked to be rid of.
    #[test]
    fn detection_ignores_everything_init_writes() {
        let dir = TempDir::new().unwrap();
        let _g = workspace_guard(dir.path());

        install(&init(&["all"])).unwrap();

        let env = DetectEnv {
            workspace: dir.path().to_path_buf(),
            home: None,
            path_dirs: Vec::new(),
        };
        let found: Vec<&str> = agents::detect(&env).iter().map(|r| r.id).collect();
        assert!(
            found.is_empty(),
            "init's own output must not look like a runtime: {found:?}"
        );
    }

    // -----------------------------------------------------------------
    // The registry itself
    // -----------------------------------------------------------------

    #[test]
    fn every_runtime_id_is_unique_and_flag_shaped() {
        let mut seen = BTreeSet::new();
        for r in RUNTIMES {
            assert!(seen.insert(r.id), "duplicate runtime id {}", r.id);
            assert!(
                r.id.chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'),
                "{}: an --agent value is lowercase and hyphenated",
                r.id
            );
            assert!(!r.markers.is_empty(), "{}: needs a detection marker", r.id);
        }
        for (alias, _, _) in agents::COMPAT_ALIASES {
            assert!(
                agents::find(alias).is_none(),
                "{alias} is both an alias and a runtime"
            );
        }
    }

    /// Detection is stubbed: a fake `$HOME` and a fake `PATH`, so the test
    /// says nothing about the machine it runs on.
    #[test]
    fn detection_sees_home_project_and_path_markers() {
        let home = TempDir::new().unwrap();
        let project = TempDir::new().unwrap();
        let bin = TempDir::new().unwrap();

        fs::create_dir_all(home.path().join(".kiro")).unwrap();
        // `.junie/` itself is not a marker: `init` writes `.junie/mcp/mcp.json`
        // into it. The guidelines file is Junie's own.
        fs::create_dir_all(project.path().join(".junie")).unwrap();
        fs::write(project.path().join(".junie/guidelines.md"), "# junie\n").unwrap();
        fs::write(bin.path().join("aider"), "#!/bin/sh\n").unwrap();

        let env = DetectEnv {
            workspace: project.path().to_path_buf(),
            home: Some(home.path().to_path_buf()),
            path_dirs: vec![bin.path().to_path_buf()],
        };
        let found: BTreeSet<&str> = agents::detect(&env).iter().map(|r| r.id).collect();

        assert_eq!(
            found,
            ["aider", "junie", "kiro"]
                .into_iter()
                .collect::<BTreeSet<_>>()
        );
    }

    #[test]
    fn detection_finds_nothing_in_an_empty_world() {
        let project = TempDir::new().unwrap();
        let env = DetectEnv {
            workspace: project.path().to_path_buf(),
            home: None,
            path_dirs: Vec::new(),
        };
        assert!(agents::detect(&env).is_empty());
    }

    /// `all` and `none` are the picker's two shortcuts and `--agent`'s two
    /// keywords; they have to mean the same thing on both.
    #[test]
    fn picker_shortcuts_match_the_flag_keywords() {
        let all: Vec<&str> = select::from_indices(&[0]).iter().map(|r| r.id).collect();
        assert_eq!(all.len(), RUNTIMES.len());
        assert!(select::from_indices(&[1]).is_empty());
        // "None" wins over "All" — the safer reading of a contradiction.
        assert!(select::from_indices(&[0, 1]).is_empty());

        let picked: Vec<&str> = select::from_indices(&[2]).iter().map(|r| r.id).collect();
        assert_eq!(picked, vec![RUNTIMES[0].id]);
    }

    #[test]
    fn the_picker_lists_every_runtime_and_marks_the_detected_ones() {
        let detected: Vec<&'static Runtime> = vec![agents::find("kiro").unwrap()];
        let items = select::items(&detected);

        assert_eq!(items.len(), RUNTIMES.len() + 2);
        assert!(items[0].contains("All runtimes"));
        assert!(items[1].contains("portable skill"));
        assert_eq!(items.iter().filter(|i| i.contains("(detected)")).count(), 1);
        assert!(items.iter().any(|i| i == "Kiro  (detected)"));
    }

    // -----------------------------------------------------------------
    // The skill's content
    // -----------------------------------------------------------------

    /// The skill is the only thing an agent reads, so every command it could
    /// need has to be in it. Derived from clap so a new subcommand fails here
    /// rather than being silently undocumented.
    #[test]
    fn the_skill_names_every_cli_subcommand() {
        use clap::CommandFactory;

        for sub in crate::Cli::command().get_subcommands() {
            let name = sub.get_name();
            if name == "help" {
                continue;
            }
            assert!(
                SKILL_MD.contains(&format!("agentcordon {name}")),
                "SKILL.md never mentions `agentcordon {name}`"
            );
        }
    }

    /// Agent Skills frontmatter: `name` must equal the directory name, and
    /// `description` is what a runtime loads at startup to decide whether to
    /// open the body, capped at 1024 characters by the spec.
    /// <https://agentskills.io/specification>
    #[test]
    fn the_skill_frontmatter_matches_the_agent_skills_spec() {
        let mut lines = SKILL_MD.lines();
        assert_eq!(lines.next(), Some("---"));
        assert_eq!(lines.next(), Some("name: agentcordon"));

        let description = SKILL_MD
            .lines()
            .find(|l| l.starts_with("description: "))
            .expect("frontmatter carries a description");
        assert!(
            description.len() - "description: ".len() <= 1024,
            "description is capped at 1024 characters by the spec"
        );
        assert!(
            SKILL_MD.lines().count() <= 500,
            "the spec caps a skill body at 500 lines"
        );
    }

    /// An agent pays for this file in tokens on every task that touches a
    /// credential, and it has to be able to act on it without reading to the
    /// end. The first section is the fast path: the exact command for an API
    /// call, the exact command for an MCP tool, and "look things up only when
    /// something errors". Everything else is reference below it.
    #[test]
    fn the_skill_opens_with_a_fast_path_that_can_be_acted_on() {
        let body = SKILL_MD;
        let first_section = body
            .split("\n## ")
            .nth(1)
            .expect("the skill has at least one section");

        for expected in [
            "agentcordon proxy",
            "agentcordon mcp-call",
            "agentcordon mcp-tools --schema",
            "agentcordon proxy --auto",
        ] {
            assert!(
                first_section.contains(expected),
                "the first section must carry `{expected}`: {first_section}"
            );
        }
        assert!(
            first_section.to_lowercase().contains("only if")
                || first_section.to_lowercase().contains("only when"),
            "the first section must say discovery is for after an error: {first_section}"
        );
    }

    /// The Agent Skills spec caps a body at 500 lines. That is not the
    /// constraint that matters here: an agent reads this on every credential
    /// task, so the budget is a screen. The reference sections earn their
    /// place by being commands, not prose.
    #[test]
    fn the_skill_fits_on_a_screen() {
        let lines = SKILL_MD.lines().count();
        assert!(lines <= 60, "SKILL.md is {lines} lines; the budget is 60");
    }

    /// The identity is derived from the key and changes when the key does.
    /// Baking it into a file that `init` overwrites in place is how two files
    /// came to name two different workspaces
    /// (uat/artifacts/reviews/UI-REVIEW-static.md G1); the skill tells the
    /// agent to ask the CLI instead.
    #[test]
    fn the_skill_does_not_bake_in_the_identity() {
        assert!(!SKILL_MD.contains("AC_IDENTITY"));
        assert!(!SKILL_MD.contains("sha256:"));
        assert!(SKILL_MD.contains("agentcordon status"));
    }

    /// The one rule, and the two things the empirical trials showed an agent
    /// gets wrong without being told.
    #[test]
    fn the_skill_carries_the_rules_that_earned_their_place() {
        for required in [
            "Never use a raw",
            "ALLOWED URL",
            "least privileged",
            "Never guess a credential name",
            "Never pick an unauthenticated server",
            "url_pattern_denied",
            "AGTCRDN_PROXY_ALLOW_LOOPBACK=true agentcordon-broker",
            "broker.port",
        ] {
            assert!(SKILL_MD.contains(required), "SKILL.md must say: {required}");
        }
        assert!(
            !SKILL_MD.contains("AGTCRDN_PROXY_ALLOW_LOOPBACK=true agentcordon proxy"),
            "the CLI never reads the flag; prefixing a proxy call with it does nothing"
        );
    }

    // -----------------------------------------------------------------
    // The MCP server registration
    // -----------------------------------------------------------------

    /// Claude Code's project-scoped MCP config. `command` is the bare binary
    /// name so PATH resolution stays the user's.
    /// <https://code.claude.com/docs/en/mcp>
    #[test]
    fn claude_code_gets_an_mcp_json_pointing_at_mcp_serve() {
        let dir = TempDir::new().unwrap();
        let _g = workspace_guard(dir.path());

        install(&init(&["claude-code"])).unwrap();

        let body: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(dir.path().join(".mcp.json")).unwrap())
                .unwrap();
        assert_eq!(body["mcpServers"]["agentcordon"]["command"], "agentcordon");
        assert_eq!(
            body["mcpServers"]["agentcordon"]["args"],
            serde_json::json!(["mcp-serve"])
        );
    }

    /// Codex reads a project `.codex/config.toml` in a project you have marked
    /// trusted, so `init` writes one rather than printing it.
    /// <https://learn.chatgpt.com/docs/extend/mcp?surface=cli>
    #[test]
    fn codex_gets_a_project_config_toml_table() {
        let dir = TempDir::new().unwrap();
        let _g = workspace_guard(dir.path());

        install(&init(&["codex"])).unwrap();

        let body = fs::read_to_string(dir.path().join(".codex/config.toml")).unwrap();
        let parsed: toml::Table = body.parse().unwrap();
        let entry = &parsed["mcp_servers"]["agentcordon"];
        assert_eq!(entry["command"].as_str(), Some("agentcordon"));
        assert_eq!(
            entry["args"].as_array().unwrap(),
            &vec![toml::Value::String("mcp-serve".into())]
        );
    }

    /// OpenCode is the one runtime whose command is a single array and whose
    /// transport is called `local`, not `stdio`.
    /// <https://opencode.ai/docs/mcp-servers/>
    #[test]
    fn opencode_gets_one_command_array_and_a_local_type() {
        let dir = TempDir::new().unwrap();
        let _g = workspace_guard(dir.path());

        install(&init(&["opencode"])).unwrap();

        let body: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(dir.path().join("opencode.json")).unwrap())
                .unwrap();
        assert_eq!(
            body["mcp"]["agentcordon"],
            serde_json::json!({
                "type": "local",
                "command": ["agentcordon", "mcp-serve"],
                "enabled": true,
            })
        );
    }

    /// Every runtime with a project-level file gets it, at the documented path
    /// and under the documented key. One assertion per runtime, so a wrong key
    /// names the runtime that has it wrong.
    #[test]
    fn every_project_runtime_gets_its_documented_file() {
        for runtime in RUNTIMES {
            let file = match runtime.mcp {
                McpConfig::Project(f) | McpConfig::ProjectAndUser(f, _) => f,
                _ => continue,
            };
            let dir = TempDir::new().unwrap();
            let _g = workspace_guard(dir.path());

            install(&init(&[runtime.id])).unwrap();

            let path = dir.path().join(file.path);
            let body = fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("{}: {} not written: {e}", runtime.id, file.path));
            match file.shape {
                agents::McpShape::Toml => {
                    let parsed: toml::Table = body
                        .parse()
                        .unwrap_or_else(|e| panic!("{}: not TOML: {e}", runtime.id));
                    assert!(
                        parsed["mcp_servers"].get("agentcordon").is_some(),
                        "{}: no [mcp_servers.agentcordon]",
                        runtime.id
                    );
                }
                shape => {
                    let parsed: serde_json::Value = serde_json::from_str(&body)
                        .unwrap_or_else(|e| panic!("{}: not JSON: {e}", runtime.id));
                    let key = match shape {
                        agents::McpShape::Json { key, .. } => key,
                        agents::McpShape::OpenCode => "mcp",
                        other => panic!("{}: no project writer for {other:?}", runtime.id),
                    };
                    assert!(
                        parsed[key].get("agentcordon").is_some(),
                        "{}: {} has no {key}.agentcordon: {body}",
                        runtime.id,
                        file.path
                    );
                }
            }
        }
    }

    /// A repository that already registers MCP servers keeps every one of
    /// them; ours is inserted alongside.
    #[test]
    fn an_existing_mcp_json_keeps_its_own_servers() {
        let dir = TempDir::new().unwrap();
        let _g = workspace_guard(dir.path());
        let original = r#"{"mcpServers":{"filesystem":{"command":"npx","args":["-y","@modelcontextprotocol/server-filesystem","/srv"],"env":{"FOO":"bar"}}}}"#;
        fs::write(dir.path().join(".mcp.json"), original).unwrap();

        install(&init(&["claude-code"])).unwrap();

        let body: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(dir.path().join(".mcp.json")).unwrap())
                .unwrap();
        assert_eq!(body["mcpServers"]["filesystem"]["command"], "npx");
        assert_eq!(body["mcpServers"]["filesystem"]["env"]["FOO"], "bar");
        assert_eq!(body["mcpServers"]["agentcordon"]["command"], "agentcordon");
    }

    /// TOML is appended to, not round-tripped: a `config.toml` is hand-written
    /// and re-serialising it through `toml::Value` deletes every comment.
    #[test]
    fn an_existing_codex_config_keeps_its_comments() {
        let dir = TempDir::new().unwrap();
        let _g = workspace_guard(dir.path());
        fs::create_dir_all(dir.path().join(".codex")).unwrap();
        let original =
            "# my settings\nmodel = \"gpt-5\"\n\n[mcp_servers.context7]\ncommand = \"npx\"\n";
        fs::write(dir.path().join(".codex/config.toml"), original).unwrap();

        install(&init(&["codex"])).unwrap();

        let body = fs::read_to_string(dir.path().join(".codex/config.toml")).unwrap();
        assert!(
            body.starts_with(original),
            "the original is untouched: {body}"
        );
        assert!(body.contains("# my settings"));
        let parsed: toml::Table = body.parse().unwrap();
        assert!(parsed["mcp_servers"].get("context7").is_some());
        assert!(parsed["mcp_servers"].get("agentcordon").is_some());
    }

    /// A config with comments in it is JSONC, not JSON. Guessing at an edit
    /// would corrupt it, so it is left exactly as it was and the snippet is
    /// printed instead.
    #[test]
    fn an_unparseable_mcp_config_is_left_byte_identical() {
        let dir = TempDir::new().unwrap();
        let _g = workspace_guard(dir.path());
        let original = "{\n  // the filesystem server\n  \"mcpServers\": {}\n}\n";
        fs::write(dir.path().join(".mcp.json"), original).unwrap();

        install(&init(&["claude-code"])).unwrap();

        assert_eq!(
            fs::read_to_string(dir.path().join(".mcp.json")).unwrap(),
            original
        );
    }

    /// An `agentcordon` entry that starts something other than our binary — a
    /// wrapper script, an absolute path — is a deliberate choice of the
    /// user's, and overwriting it would undo it.
    #[test]
    fn an_agentcordon_entry_that_says_something_else_is_left_alone() {
        let dir = TempDir::new().unwrap();
        let _g = workspace_guard(dir.path());
        let original =
            "{\n  \"mcpServers\": {\n    \"agentcordon\": {\n      \"command\": \"./wrapper.sh\"\n    }\n  }\n}\n";
        fs::write(dir.path().join(".mcp.json"), original).unwrap();

        install(&init(&["claude-code"])).unwrap();

        assert_eq!(
            fs::read_to_string(dir.path().join(".mcp.json")).unwrap(),
            original
        );
    }

    /// An entry naming our own binary is ours to keep current: changing
    /// `--expose` has to reach the file, or the flag silently does nothing on
    /// every workspace that has already run `init`.
    #[test]
    fn our_own_entry_is_brought_up_to_date_when_expose_changes() {
        let dir = TempDir::new().unwrap();
        let _g = workspace_guard(dir.path());

        install(&init(&["claude-code", "codex"])).unwrap();
        install(&InitArgs {
            agents: vec!["claude-code".to_string(), "codex".to_string()],
            expose: vec!["github".to_string()],
            ..InitArgs::default()
        })
        .unwrap();

        let claude: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(dir.path().join(".mcp.json")).unwrap())
                .unwrap();
        assert_eq!(
            claude["mcpServers"]["agentcordon"]["args"],
            serde_json::json!(["mcp-serve", "--expose", "github"])
        );
        let codex = fs::read_to_string(dir.path().join(".codex/config.toml")).unwrap();
        assert!(codex.contains("\"--expose\",\"github\""), "{codex}");
        assert_eq!(
            codex.matches("[mcp_servers.agentcordon]").count(),
            1,
            "the table is replaced, not duplicated: {codex}"
        );
    }

    /// Keys the user added to our own entry are theirs; only the ones this
    /// command writes are refreshed.
    #[test]
    fn keys_added_to_our_entry_by_hand_survive_a_rerun() {
        let dir = TempDir::new().unwrap();
        let _g = workspace_guard(dir.path());
        fs::write(
            dir.path().join(".mcp.json"),
            r#"{"mcpServers":{"agentcordon":{"command":"agentcordon","args":[],"env":{"AGTCRDN_LOG_LEVEL":"debug"}}}}"#,
        )
        .unwrap();

        install(&init(&["claude-code"])).unwrap();

        let body: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(dir.path().join(".mcp.json")).unwrap())
                .unwrap();
        assert_eq!(
            body["mcpServers"]["agentcordon"]["env"]["AGTCRDN_LOG_LEVEL"],
            "debug"
        );
        assert_eq!(
            body["mcpServers"]["agentcordon"]["args"],
            serde_json::json!(["mcp-serve"])
        );
    }

    /// A codex table with a setting we never write is not ours to rewrite.
    #[test]
    fn a_codex_table_with_extra_settings_is_left_alone() {
        let dir = TempDir::new().unwrap();
        let _g = workspace_guard(dir.path());
        fs::create_dir_all(dir.path().join(".codex")).unwrap();
        let original = "[mcp_servers.agentcordon]\ncommand = \"agentcordon\"\nargs = [\"mcp-serve\"]\nstartup_timeout_sec = 30\n";
        fs::write(dir.path().join(".codex/config.toml"), original).unwrap();

        install(&InitArgs {
            agents: vec!["codex".to_string()],
            expose: vec!["github".to_string()],
            ..InitArgs::default()
        })
        .unwrap();

        assert_eq!(
            fs::read_to_string(dir.path().join(".codex/config.toml")).unwrap(),
            original
        );
    }

    /// Every writer, twice, byte for byte. `installing_twice_changes_nothing`
    /// covers the same ground for the whole tree; this one fails with the
    /// runtime's name.
    #[test]
    fn writing_an_mcp_config_twice_changes_nothing() {
        for runtime in RUNTIMES {
            let file = match runtime.mcp {
                McpConfig::Project(f) | McpConfig::ProjectAndUser(f, _) => f,
                _ => continue,
            };
            let dir = TempDir::new().unwrap();
            let _g = workspace_guard(dir.path());

            install(&init(&[runtime.id])).unwrap();
            let first = fs::read_to_string(dir.path().join(file.path)).unwrap();
            install(&init(&[runtime.id])).unwrap();
            let second = fs::read_to_string(dir.path().join(file.path)).unwrap();

            assert_eq!(
                first, second,
                "{}: {} is not idempotent",
                runtime.id, file.path
            );
        }
    }

    /// `--expose` is passed through as `--expose <server>` pairs, in every
    /// config shape: the argument list is the interface `mcp-serve` reads.
    #[test]
    fn expose_becomes_expose_arguments_in_every_config() {
        let dir = TempDir::new().unwrap();
        let _g = workspace_guard(dir.path());

        install(&InitArgs {
            agents: vec!["all".to_string()],
            expose: vec!["github".to_string(), "sentry".to_string()],
            ..InitArgs::default()
        })
        .unwrap();

        let claude: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(dir.path().join(".mcp.json")).unwrap())
                .unwrap();
        assert_eq!(
            claude["mcpServers"]["agentcordon"]["args"],
            serde_json::json!(["mcp-serve", "--expose", "github", "--expose", "sentry"])
        );

        // OpenCode folds the command and the arguments into one array.
        let opencode: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(dir.path().join("opencode.json")).unwrap())
                .unwrap();
        assert_eq!(
            opencode["mcp"]["agentcordon"]["command"],
            serde_json::json!([
                "agentcordon",
                "mcp-serve",
                "--expose",
                "github",
                "--expose",
                "sentry"
            ])
        );

        let codex = fs::read_to_string(dir.path().join(".codex/config.toml")).unwrap();
        assert!(codex.contains("\"--expose\",\"sentry\""), "{codex}");
    }

    /// The skill costs nothing until it is triggered; the MCP surface costs
    /// ~800 tokens in every session. `--no-mcp` is how a user takes the first
    /// without the second, and it is remembered.
    #[test]
    fn no_mcp_writes_no_mcp_config_and_is_remembered() {
        let dir = TempDir::new().unwrap();
        let _g = workspace_guard(dir.path());

        install(&InitArgs {
            agents: vec!["all".to_string()],
            no_mcp: true,
            ..InitArgs::default()
        })
        .unwrap();

        for runtime in RUNTIMES {
            if let McpConfig::Project(f) | McpConfig::ProjectAndUser(f, _) = runtime.mcp {
                assert!(
                    !dir.path().join(f.path).exists(),
                    "{}: --no-mcp wrote {}",
                    runtime.id,
                    f.path
                );
            }
        }
        assert!(dir
            .path()
            .join(".agents/skills/agentcordon/SKILL.md")
            .exists());

        // Remembered, so a bare rerun does not quietly register after all.
        install(&init(&["all"])).unwrap();
        assert!(!dir.path().join(".mcp.json").exists());
        let saved = fs::read_to_string(dir.path().join(".agentcordon/agents.toml")).unwrap();
        assert!(saved.contains("mcp = false"), "{saved}");
    }

    #[test]
    fn the_expose_list_is_remembered_and_reused() {
        let dir = TempDir::new().unwrap();
        let _g = workspace_guard(dir.path());

        install(&InitArgs {
            agents: vec!["claude-code".to_string()],
            expose: vec!["github".to_string()],
            ..InitArgs::default()
        })
        .unwrap();
        let saved = fs::read_to_string(dir.path().join(".agentcordon/agents.toml")).unwrap();
        assert!(saved.contains("expose = [\"github\"]"), "{saved}");

        fs::remove_file(dir.path().join(".mcp.json")).unwrap();
        install(&InitArgs::default()).unwrap();
        let body: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(dir.path().join(".mcp.json")).unwrap())
                .unwrap();
        assert_eq!(
            body["mcpServers"]["agentcordon"]["args"],
            serde_json::json!(["mcp-serve", "--expose", "github"])
        );
    }

    /// A user-level config is outside the workspace and shared by every
    /// project on the machine. `init` writes only inside the directory it was
    /// run in, so those runtimes get a printed snippet and no file.
    #[test]
    fn a_user_level_runtime_gets_a_snippet_and_no_file() {
        let dir = TempDir::new().unwrap();
        let _g = workspace_guard(dir.path());

        install(&init(&["windsurf", "cline", "goose", "zed"])).unwrap();

        let before = tree(dir.path());
        install(&init(&["windsurf", "cline", "goose", "zed"])).unwrap();
        assert_eq!(before, tree(dir.path()));

        for runtime in RUNTIMES {
            let McpConfig::User(user) = runtime.mcp else {
                continue;
            };
            assert!(
                user.path.starts_with('~'),
                "{}: a user-level path is outside the workspace",
                runtime.id
            );
            let snippet = agents::mcp::snippet(user.shape, &agents::mcp::args(&[]));
            assert!(
                snippet.contains("agentcordon") && snippet.contains("mcp-serve"),
                "{}: the printed snippet must name the command: {snippet}",
                runtime.id
            );
        }
    }

    /// An absolute path in a file that gets committed is wrong on every other
    /// machine, and it takes PATH resolution away from the user.
    #[test]
    fn mcp_config_never_writes_an_absolute_path() {
        let dir = TempDir::new().unwrap();
        let _g = workspace_guard(dir.path());

        install(&init(&["all"])).unwrap();

        let root = dir.path().display().to_string();
        for (path, body) in tree(dir.path()) {
            assert!(
                !body.contains(&root),
                "{path} names the workspace's absolute path"
            );
            assert!(
                !body.contains("\"/") && !body.contains("cmd: /"),
                "{path} names an absolute command"
            );
        }
    }

    /// Every runtime says what it does about MCP: a file `init` writes, a
    /// user-level path it prints, or no MCP client at all. A new runtime
    /// cannot be added without deciding.
    #[test]
    fn every_runtime_declares_what_it_does_about_mcp() {
        for runtime in RUNTIMES {
            match runtime.mcp {
                McpConfig::Project(f) | McpConfig::ProjectAndUser(f, _) => {
                    assert!(
                        !f.path.starts_with('/') && !f.path.starts_with('~'),
                        "{}: a project file is workspace-relative",
                        runtime.id
                    );
                }
                McpConfig::User(u) => assert!(
                    u.path.starts_with('~'),
                    "{}: a user-level path is under $HOME",
                    runtime.id
                ),
                // Aider is the only one, and permanently: no MCP client is
                // documented and HISTORY has never mentioned one.
                McpConfig::None => assert_eq!(runtime.id, "aider"),
            }
        }
    }

    // -----------------------------------------------------------------
    // Deciding whether to register at all
    // -----------------------------------------------------------------

    /// Nothing said: register. A runtime with no entry cannot see the tools.
    #[test]
    fn the_default_is_to_register() {
        assert_eq!(
            select::resolve_mcp(false, &[], None),
            agents::mcp::Choice::default()
        );
    }

    /// `--no-mcp` is the only thing typed this run that says no, so it beats
    /// the picker's answer and the remembered one.
    #[test]
    fn no_mcp_beats_every_remembered_yes() {
        let remembered = agents::mcp::Choice {
            register: true,
            expose: vec!["github".to_string()],
        };
        let resolved = select::resolve_mcp(true, &[], Some(&remembered));
        assert!(!resolved.register);
        assert_eq!(resolved.expose, vec!["github".to_string()]);
    }

    /// `--expose` replaces the remembered list, exactly as `--agent` replaces
    /// the remembered runtimes, and duplicates collapse.
    #[test]
    fn expose_replaces_rather_than_adds_to_what_was_remembered() {
        let remembered = agents::mcp::Choice {
            register: true,
            expose: vec!["github".to_string()],
        };
        let flags = ["sentry".to_string(), "sentry".to_string()];
        assert_eq!(
            select::resolve_mcp(false, &flags, Some(&remembered)).expose,
            vec!["sentry".to_string()]
        );
        assert_eq!(
            select::resolve_mcp(false, &[], Some(&remembered)).expose,
            vec!["github".to_string()]
        );
    }

    /// The picker asks once, in one line that carries both halves of the
    /// trade-off.
    #[test]
    fn the_picker_asks_about_the_mcp_server_and_says_what_it_costs() {
        assert!(select::MCP_QUESTION.contains("Also register the AgentCordon MCP server"));
        assert!(select::MCP_QUESTION.contains("800 tokens"));
    }

    /// `init` writes a key the CLI's own loader accepts, and a second run
    /// reports the same identity without touching the key.
    #[test]
    fn init_creates_loadable_key_and_is_idempotent() {
        let dir = TempDir::new().unwrap();
        let _g = workspace_guard(dir.path());

        install(&init(&["claude-code"])).unwrap();
        let first = crate::signing::load_keypair().unwrap();
        assert!(agentcordon_identity::workspace_key_exists(
            &dir.path().join(".agentcordon")
        ));

        install(&init(&["claude-code"])).unwrap();
        let second = crate::signing::load_keypair().unwrap();
        assert_eq!(second.seed_hex(), first.seed_hex());

        let gitignore = fs::read_to_string(dir.path().join(".gitignore")).unwrap();
        assert_eq!(gitignore.matches(".agentcordon/").count(), 1);
    }

    /// Marker types are exercised by the detection test above; this pins that
    /// the registry actually uses all three, so none rots unused.
    #[test]
    fn the_registry_uses_every_marker_kind() {
        let all: Vec<&Marker> = RUNTIMES.iter().flat_map(|r| r.markers.iter()).collect();
        assert!(all.iter().any(|m| matches!(m, Marker::Binary(_))));
        assert!(all.iter().any(|m| matches!(m, Marker::Home(_))));
        assert!(all.iter().any(|m| matches!(m, Marker::Project(_))));
    }

    /// Every path in the tree, for the idempotence assertion.
    fn tree(root: &Path) -> BTreeSet<(String, String)> {
        let mut out = BTreeSet::new();
        let mut stack = vec![root.to_path_buf()];
        while let Some(dir) = stack.pop() {
            let Ok(entries) = fs::read_dir(&dir) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                } else {
                    let rel = path.strip_prefix(root).unwrap().display().to_string();
                    out.insert((rel, fs::read_to_string(&path).unwrap_or_default()));
                }
            }
        }
        out
    }

    // -----------------------------------------------------------------
    // Enrollment: the third of the three commands
    // -----------------------------------------------------------------

    fn server(url: &str, source: ServerUrlSource) -> ServerUrl {
        ServerUrl {
            url: url.to_string(),
            source,
        }
    }

    /// The installer wrote the server URL, so `init` has one without being
    /// told. This is the whole point of the change.
    #[test]
    fn a_remembered_server_is_enrolled_with() {
        let configured = server("https://cordon.example.com", ServerUrlSource::ConfigFile);
        assert_eq!(
            enrollment_plan(false, Some(configured.clone())),
            Enrollment::Enrol(configured)
        );
    }

    /// Scripts and air-gapped setups: the skill, and nothing that needs a
    /// network.
    #[test]
    fn no_register_skips_enrollment_even_with_a_server_configured() {
        assert_eq!(
            enrollment_plan(
                true,
                Some(server("https://cordon.example.com", ServerUrlSource::Flag))
            ),
            Enrollment::Skipped
        );
    }

    /// Silently installing the skill and stopping would leave a user with a
    /// workspace that looks set up and cannot vend anything. Say so instead.
    #[test]
    fn no_server_anywhere_is_an_error_not_a_silent_skip() {
        assert_eq!(enrollment_plan(false, None), Enrollment::Unconfigured);
    }

    /// The picker needs a human; the device flow does not — it prints a code
    /// and polls. So `init` off a terminal installs the skill without asking
    /// and still enrolls, and `--no-register` stays the way to avoid it.
    #[test]
    fn being_off_a_terminal_is_not_an_input_to_the_enrollment_decision() {
        let configured = server("https://cordon.example.com", ServerUrlSource::Env);
        assert_eq!(
            enrollment_plan(false, Some(configured.clone())),
            Enrollment::Enrol(configured)
        );
    }

    /// Two lines: what happened, and the one command that proves it worked.
    #[test]
    fn the_summary_is_two_lines_naming_the_workspace_the_server_and_what_to_try() {
        let summary = registered_summary("my-project", "https://cordon.example.com");
        let lines: Vec<&str> = summary.lines().collect();
        assert_eq!(lines.len(), 2, "exactly two lines: {summary}");
        assert_eq!(
            lines[0],
            "Registered as my-project at https://cordon.example.com."
        );
        assert_eq!(lines[1], "Try: agentcordon credentials");
    }

    /// A rerun of `init` is the common case — a new runtime, a changed mind
    /// about the skill — and it must not restart a device flow.
    #[test]
    fn an_already_registered_workspace_gets_one_line() {
        let line = already_registered_line("https://cordon.example.com");
        assert_eq!(line.lines().count(), 1, "one line: {line}");
        assert!(line.contains("Already registered"), "{line}");
        assert!(line.contains("https://cordon.example.com"), "{line}");
    }

    /// End to end, over real HTTP against a fake broker: the config file the
    /// installer writes is enough for `agentcordon init` to enroll. Nothing
    /// is passed on the command line and `AGTCRDN_SERVER_URL` is cleared.
    #[tokio::test]
    async fn init_enrolls_using_only_the_server_the_installer_recorded() {
        let workspace = TempDir::new().unwrap();
        let home = TempDir::new().unwrap();
        // One poll says "not yet", the next says approved -- the human
        // walking to a browser.
        let broker =
            crate::fake_broker::spawn(crate::fake_broker::Registration::ApprovedAfter(1)).await;

        std::fs::create_dir_all(home.path().join(".agentcordon")).unwrap();
        std::fs::write(
            home.path().join(".agentcordon/config.toml"),
            "server_url = \"https://cordon.example.com\"\n",
        )
        .unwrap();

        let mut env = EnvGuard::new();
        env.set("AGTCRDN_WORKSPACE_DIR", workspace.path());
        env.set("HOME", home.path());
        env.set("AGTCRDN_BROKER_URL", &broker.base_url);
        env.unset("AGTCRDN_SERVER_URL");
        env.unset("AGTCRDN_BROKER_SHARED_SECRET");
        env.unset("AGTCRDN_BROKER_CA");

        run(InitArgs {
            agents: vec!["none".to_string()],
            name: Some("my-project".to_string()),
            ..InitArgs::default()
        })
        .await
        .expect("init must enroll with the recorded server");

        assert_eq!(
            broker.register_calls(),
            1,
            "init must run the device flow exactly once"
        );
        assert!(
            broker.status_polls() >= 2,
            "init must poll until the approval lands, saw {}",
            broker.status_polls()
        );
        assert!(
            workspace
                .path()
                .join(".agentcordon/broker.fingerprint")
                .exists(),
            "enrolling pins the broker key, exactly as `register` does"
        );
    }

    /// A rerun must not start a second device flow.
    #[tokio::test]
    async fn init_on_an_already_registered_workspace_starts_no_device_flow() {
        let workspace = TempDir::new().unwrap();
        let home = TempDir::new().unwrap();
        let broker = crate::fake_broker::spawn(crate::fake_broker::Registration::Already).await;

        let mut env = EnvGuard::new();
        env.set("AGTCRDN_WORKSPACE_DIR", workspace.path());
        env.set("HOME", home.path());
        env.set("AGTCRDN_BROKER_URL", &broker.base_url);
        env.set("AGTCRDN_SERVER_URL", "https://cordon.example.com");
        env.unset("AGTCRDN_BROKER_SHARED_SECRET");
        env.unset("AGTCRDN_BROKER_CA");

        run(InitArgs {
            agents: vec!["none".to_string()],
            ..InitArgs::default()
        })
        .await
        .expect("a rerun is a no-op, not an error");

        assert_eq!(
            broker.register_calls(),
            0,
            "an already-registered workspace must not start a device flow"
        );
    }

    /// `--no-register` never touches the network: no broker discovery, no
    /// device flow, and no error when no server is configured anywhere.
    #[tokio::test]
    async fn no_register_installs_the_skill_and_stops() {
        let workspace = TempDir::new().unwrap();
        let home = TempDir::new().unwrap();

        let mut env = EnvGuard::new();
        env.set("AGTCRDN_WORKSPACE_DIR", workspace.path());
        env.set("HOME", home.path());
        env.unset("AGTCRDN_SERVER_URL");
        env.unset("AGTCRDN_BROKER_URL");

        run(InitArgs {
            agents: vec!["none".to_string()],
            no_register: true,
            ..InitArgs::default()
        })
        .await
        .expect("--no-register must succeed with nothing configured");

        assert!(workspace
            .path()
            .join(".agents/skills/agentcordon/SKILL.md")
            .exists());
    }

    /// With no server anywhere and no `--no-register`, `init` fails with a
    /// message that names every way out — after writing the skill, so the
    /// work is not lost.
    #[tokio::test]
    async fn init_without_a_server_says_how_to_fix_it() {
        let workspace = TempDir::new().unwrap();
        let home = TempDir::new().unwrap();

        let mut env = EnvGuard::new();
        env.set("AGTCRDN_WORKSPACE_DIR", workspace.path());
        env.set("HOME", home.path());
        env.unset("AGTCRDN_SERVER_URL");
        env.unset("AGTCRDN_BROKER_URL");

        let err = run(InitArgs {
            agents: vec!["none".to_string()],
            ..InitArgs::default()
        })
        .await
        .expect_err("no server anywhere must be an error");

        assert!(err.message.contains("--server-url"), "{}", err.message);
        assert!(
            err.message.contains("AGTCRDN_SERVER_URL"),
            "{}",
            err.message
        );
        assert!(err.message.contains("--no-register"), "{}", err.message);
        assert!(
            workspace
                .path()
                .join(".agents/skills/agentcordon/SKILL.md")
                .exists(),
            "the skill is written before enrollment is attempted"
        );
    }
}
