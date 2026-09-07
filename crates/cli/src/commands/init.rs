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
use crate::agents::{self, install, select, DetectEnv};
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

    let written = install::install(&root, &selection.runtimes)?;
    select::save(&root, &selection.runtimes)?;
    report(&selection, &written);

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

    if !args.agents.is_empty() {
        return select::from_flags(&args.agents, &env);
    }
    if !args.reconfigure {
        if let Some(saved) = select::load(root) {
            return Ok(saved);
        }
    }
    if select::interactive() {
        return select::prompt(&agents::detect(&env));
    }
    Ok(select::auto(&env))
}

/// The closing summary: every file, what happened to it, and which of the
/// selected runtimes reads it.
fn report(selection: &select::Selection, written: &[install::Installed]) {
    println!();
    println!("AgentCordon skill:");
    for file in written {
        match &file.action {
            Action::Skipped { reason, snippet } => {
                println!("  skipped   {}", file.path);
                println!("            {reason}");
                println!("            add by hand under `read:`:");
                println!("              {snippet}");
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
                    format!("read by {}", file.serves.join(", "))
                };
                println!("  {verb:<9} {}", file.path);
                println!("            {serves}");
            }
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
    use crate::agents::{Marker, Runtime, RUNTIMES, SKILL_MD};
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
        fs::create_dir_all(project.path().join(".junie")).unwrap();
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

    #[test]
    fn init_does_not_create_mcp_json() {
        let dir = TempDir::new().unwrap();
        let _g = workspace_guard(dir.path());

        install(&init(&["all"])).unwrap();

        assert!(
            !dir.path().join(".mcp.json").exists(),
            "there is no `agentcordon mcp-serve`; an .mcp.json entry would point at nothing"
        );
    }

    #[test]
    fn init_leaves_existing_mcp_json_untouched() {
        let dir = TempDir::new().unwrap();
        let _g = workspace_guard(dir.path());
        let original = r#"{"mcpServers":{"filesystem":{"command":"npx","args":["-y","@modelcontextprotocol/server-filesystem","/tmp"],"env":{"FOO":"bar"}}}}"#;
        fs::write(dir.path().join(".mcp.json"), original).unwrap();

        install(&init(&["all"])).unwrap();
        install(&init(&["all"])).unwrap();

        let after = fs::read_to_string(dir.path().join(".mcp.json")).unwrap();
        assert_eq!(after, original);
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
