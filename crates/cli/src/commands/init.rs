//! `agentcordon init` — generate the workspace key and install the AgentCordon
//! skill for the agent runtimes this workspace is used with.
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
use crate::error::CliError;
use crate::signing::workspace_dir;

/// The parsed `agentcordon init` command line.
#[derive(Debug, Default, Clone)]
pub struct InitArgs {
    /// `--agent`, repeatable. Empty means "decide": the remembered choice, the
    /// picker, or `auto`, in that order.
    pub agents: Vec<String>,
    /// Ignore the remembered choice and pick again.
    pub reconfigure: bool,
}

/// The workspace root — the directory `init` writes into.
fn workspace_root() -> PathBuf {
    PathBuf::from(std::env::var("AGTCRDN_WORKSPACE_DIR").unwrap_or_else(|_| ".".to_string()))
}

/// Generate the Ed25519 keypair and install the skill.
pub fn run(args: InitArgs) -> Result<(), CliError> {
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

    let selection = resolve(&args, &root)?;
    for notice in &selection.notices {
        println!("{notice}");
    }

    let written = install::install(&root, &selection.runtimes)?;
    select::save(&root, &selection.runtimes)?;
    report(&selection, &written);

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
    use std::collections::BTreeSet;
    use tempfile::TempDir;

    /// Set the workspace dir env var for the duration of the test. Tests that
    /// touch `AGTCRDN_WORKSPACE_DIR` must run serially because env is process-global.
    struct EnvGuard {
        _lock: std::sync::MutexGuard<'static, ()>,
    }

    impl EnvGuard {
        fn new(dir: &Path) -> Self {
            static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
            let lock = LOCK.lock().unwrap_or_else(|e| e.into_inner());
            // SAFETY: tests are serialized via the mutex above.
            unsafe {
                std::env::set_var("AGTCRDN_WORKSPACE_DIR", dir);
            }
            Self { _lock: lock }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            // SAFETY: tests are serialized via the mutex.
            unsafe {
                std::env::remove_var("AGTCRDN_WORKSPACE_DIR");
            }
        }
    }

    fn init(agents: &[&str]) -> InitArgs {
        InitArgs {
            agents: agents.iter().map(|s| s.to_string()).collect(),
            reconfigure: false,
        }
    }

    // -----------------------------------------------------------------
    // The skill is the integration
    // -----------------------------------------------------------------

    /// The one file every runtime is meant to find.
    #[test]
    fn init_writes_the_portable_skill() {
        let dir = TempDir::new().unwrap();
        let _g = EnvGuard::new(dir.path());

        run(init(&["claude-code"])).unwrap();

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
        let _g = EnvGuard::new(dir.path());

        run(init(&["claude-code"])).unwrap();

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
        let _g = EnvGuard::new(dir.path());

        run(init(&["all"])).unwrap();

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
            let _g = EnvGuard::new(dir.path());

            run(init(&[runtime.id])).unwrap();

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
        let _g = EnvGuard::new(dir.path());

        run(init(&["claude-code", "cline"])).unwrap();

        let body =
            fs::read_to_string(dir.path().join(".claude/skills/agentcordon/SKILL.md")).unwrap();
        assert_eq!(body, SKILL_MD);
    }

    /// Rerunning must be a no-op, including after the user has re-selected.
    #[test]
    fn installing_twice_changes_nothing() {
        let dir = TempDir::new().unwrap();
        let _g = EnvGuard::new(dir.path());

        run(init(&["all"])).unwrap();
        let before = tree(dir.path());
        run(init(&["all"])).unwrap();
        run(InitArgs::default()).unwrap();
        assert_eq!(before, tree(dir.path()), "init is idempotent");
    }

    /// A skill file the user (or an older `init`) left behind is brought up to
    /// date: `init` owns the whole file.
    #[test]
    fn a_stale_skill_file_is_rewritten() {
        let dir = TempDir::new().unwrap();
        let _g = EnvGuard::new(dir.path());
        let path = dir.path().join(".agents/skills/agentcordon/SKILL.md");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, "---\nname: agentcordon\n---\n\nold\n").unwrap();

        run(init(&["none"])).unwrap();

        assert_eq!(fs::read_to_string(&path).unwrap(), SKILL_MD);
    }

    // -----------------------------------------------------------------
    // Aider — the one runtime with no skill discovery
    // -----------------------------------------------------------------

    #[test]
    fn aider_gets_a_read_entry_pointing_at_the_portable_skill() {
        let dir = TempDir::new().unwrap();
        let _g = EnvGuard::new(dir.path());

        run(init(&["aider"])).unwrap();

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
        let _g = EnvGuard::new(dir.path());
        fs::write(
            dir.path().join(".aider.conf.yml"),
            "model: gpt-4o\n# a comment we must not eat\nauto-commits: false\n",
        )
        .unwrap();

        run(init(&["aider"])).unwrap();
        run(init(&["aider"])).unwrap();

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
        let _g = EnvGuard::new(dir.path());
        let original = "read:\n  - CONVENTIONS.md\n";
        fs::write(dir.path().join(".aider.conf.yml"), original).unwrap();

        run(init(&["aider"])).unwrap();

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
        let _g = EnvGuard::new(dir.path());

        let err = run(init(&["emacs"])).unwrap_err();
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
            let _g = EnvGuard::new(dir.path());
            run(init(&[legacy])).unwrap();
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
        let _g = EnvGuard::new(dir.path());

        run(init(&["kiro"])).unwrap();
        assert!(dir.path().join(".agentcordon/agents.toml").exists());

        // No flags: the remembered choice is used, so Kiro's copy is refreshed
        // and no other runtime's appears.
        fs::remove_dir_all(dir.path().join(".kiro")).unwrap();
        run(InitArgs::default()).unwrap();
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
        let _g = EnvGuard::new(dir.path());
        fs::create_dir_all(dir.path().join(".agentcordon")).unwrap();
        fs::write(dir.path().join(".agentcordon/agents.toml"), "not = [toml").unwrap();

        run(InitArgs::default()).unwrap();

        assert!(dir
            .path()
            .join(".agents/skills/agentcordon/SKILL.md")
            .exists());
    }

    #[test]
    fn reconfigure_ignores_the_remembered_choice() {
        let dir = TempDir::new().unwrap();
        let _g = EnvGuard::new(dir.path());

        run(init(&["kiro"])).unwrap();
        // Not a TTY under `cargo test`, so `--reconfigure` falls through to
        // detection rather than prompting. Kiro is not detectable from what
        // `init` wrote, so it drops out.
        run(InitArgs {
            agents: Vec::new(),
            reconfigure: true,
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
        let _g = EnvGuard::new(dir.path());

        run(init(&["all"])).unwrap();

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
        let _g = EnvGuard::new(dir.path());

        run(init(&["all"])).unwrap();

        assert!(
            !dir.path().join(".mcp.json").exists(),
            "there is no `agentcordon mcp-serve`; an .mcp.json entry would point at nothing"
        );
    }

    #[test]
    fn init_leaves_existing_mcp_json_untouched() {
        let dir = TempDir::new().unwrap();
        let _g = EnvGuard::new(dir.path());
        let original = r#"{"mcpServers":{"filesystem":{"command":"npx","args":["-y","@modelcontextprotocol/server-filesystem","/tmp"],"env":{"FOO":"bar"}}}}"#;
        fs::write(dir.path().join(".mcp.json"), original).unwrap();

        run(init(&["all"])).unwrap();
        run(init(&["all"])).unwrap();

        let after = fs::read_to_string(dir.path().join(".mcp.json")).unwrap();
        assert_eq!(after, original);
    }

    /// `init` writes a key the CLI's own loader accepts, and a second run
    /// reports the same identity without touching the key.
    #[test]
    fn init_creates_loadable_key_and_is_idempotent() {
        let dir = TempDir::new().unwrap();
        let _g = EnvGuard::new(dir.path());

        run(init(&["claude-code"])).unwrap();
        let first = crate::signing::load_keypair().unwrap();
        assert!(agentcordon_identity::workspace_key_exists(
            &dir.path().join(".agentcordon")
        ));

        run(init(&["claude-code"])).unwrap();
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
}
