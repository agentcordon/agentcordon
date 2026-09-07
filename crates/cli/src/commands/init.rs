use std::fs;
use std::path::Path;

use agentcordon_identity::{pk_hash_of, KeyFileError};

use crate::error::CliError;
use crate::signing::workspace_dir;

/// Generate Ed25519 keypair and prepare workspace for registration.
pub fn run(agent: &str) -> Result<(), CliError> {
    // Validate agent flag
    let valid_agents = ["claude-code", "codex", "openclaw", "all"];
    if !valid_agents.contains(&agent) {
        return Err(CliError::general(format!(
            "unknown agent '{}'. Valid options: {}",
            agent,
            valid_agents.join(", ")
        )));
    }

    let dir = workspace_dir();

    // Idempotent: if key already exists, just print identity
    if agentcordon_identity::workspace_key_exists(&dir) {
        let pub_hex = agentcordon_identity::read_public_key_hex(&dir)
            .map_err(|e| CliError::general(e.to_string()))?;
        let pub_bytes = hex::decode(&pub_hex)
            .map_err(|e| CliError::general(format!("invalid public key format: {e}")))?;
        let hash = pk_hash_of(&pub_bytes);
        println!("Workspace identity: sha256:{hash}");
        println!("(keypair already exists)");

        // Still generate agent-specific files even if key exists
        generate_for_agent(agent, &hash)?;
        return Ok(());
    }

    // Create .agentcordon/ (mode 0700) and write the keypair (0600 / 0644)
    // atomically; the identity crate owns the format and the policy.
    let key = agentcordon_identity::create_workspace_key(&dir).map_err(|e| match e {
        KeyFileError::AlreadyExists { .. } => {
            CliError::general(format!("{e} — re-run `agentcordon init`"))
        }
        other => CliError::general(other.to_string()),
    })?;

    let hash = key.pk_hash();
    println!("Workspace identity: sha256:{hash}");

    // Add .agentcordon/ to .gitignore
    add_to_gitignore()?;

    // Generate agent-specific instruction files
    generate_for_agent(agent, &hash)?;

    Ok(())
}

/// Generate instruction files for the specified agent (or all agents).
fn generate_for_agent(agent: &str, pk_hash: &str) -> Result<(), CliError> {
    // Always generate AGENTS.md (shared across all agents)
    generate_agents_md(pk_hash)?;

    match agent {
        "claude-code" => generate_claude_md()?,
        "codex" => generate_codex_config()?,
        "openclaw" => generate_openclaw_config()?,
        "all" => {
            generate_claude_md()?;
            generate_codex_config()?;
            generate_openclaw_config()?;
        }
        _ => unreachable!(),
    }

    Ok(())
}

/// Generate or update AGENTS.md with AgentCordon usage instructions.
///
/// This is the cross-agent instruction file (AGENTS.md open standard).
/// Claude Code imports it via `@AGENTS.md`, Codex and OpenClaw load it natively.
fn generate_agents_md(pk_hash: &str) -> Result<(), CliError> {
    let base = std::env::var("AGTCRDN_WORKSPACE_DIR").unwrap_or_else(|_| ".".to_string());
    let agents_md_path = Path::new(&base).join("AGENTS.md");

    let section = format!(
        "\n\
         <!-- BEGIN AGENTCORDON -->\n\
         ## AgentCordon\n\
         \n\
         This workspace uses AgentCordon for credential management. API credentials are \
         brokered through AgentCordon — never use raw secrets directly.\n\
         \n\
         AC_IDENTITY: sha256:{pk_hash}\n\
         \n\
         ### Workflow\n\
         \n\
         1. Run `agentcordon credentials` to list available credentials\n\
         2. Pick the credential that matches the service you need — if multiple match, \
         prefer the one with least privilege\n\
         3. Use `agentcordon proxy <credential-name> <METHOD> <url>` to make the call\n\
         \n\
         **Important**: Always discover credentials first. Never guess credential names — \
         they are assigned by the admin and vary per workspace.\n\
         \n\
         ### Commands\n\
         \n\
         - `agentcordon credentials` — list credentials available to this workspace\n\
         - `agentcordon proxy <credential-name> <METHOD> <url>` — authenticated API call\n\
         - `agentcordon proxy <credential-name> POST <url> --body '{{...}}'` — POST with JSON body\n\
         - `agentcordon mcp-servers` — list MCP servers this workspace may use\n\
         - `agentcordon mcp-tools` — list every tool, with its description\n\
         - `agentcordon mcp-tools --schema --server <server> --tool <tool>` — the tool's \
         exact argument names and types\n\
         - `agentcordon mcp-call <server> <tool> [--arg key=value]` — call an MCP tool\n\
         - `agentcordon mcp-call <server> <tool> --args-json '{{...}}'` — call with nested \
         or array arguments\n\
         - `agentcordon status` — check connection and identity\n\
         - `agentcordon help` — full command reference\n\
         \n\
         When you need to call an external API, use `agentcordon proxy` instead of direct \
         HTTP with raw tokens. Every access is policy-checked and audit-logged.\n\
         \n\
         ### Using MCP servers\n\
         \n\
         1. Run `agentcordon mcp-servers` to see which servers this workspace may use. \
         Several may be listed; they are not interchangeable.\n\
         2. Run `agentcordon mcp-tools` to see every tool and what it does.\n\
         3. **Choose the server, then the tool, by these rules, in order:**\n\
         \n\
         - **Match the service the task is about.** Pick the server that fronts the system \
         the task names (the issue tracker for an issue, the deployment platform for a \
         deploy). The server's name and its tools' descriptions are the signal; the \
         `DESCRIPTION` column of `mcp-servers` is often empty and proves nothing.\n\
         - **Prefer the server whose authenticated identity fits the question.** Several \
         servers may expose an identically named tool while speaking to different accounts \
         or tenants. Pick the one authenticated as the identity the answer should be about.\n\
         - **Never pick an unauthenticated server for a question about identity, \
         permissions, or private data.** A server the admin configured with no auth cannot \
         answer \"who am I\" or \"what may I access\" — it will return a plausible-looking \
         null or anonymous result. Least privilege applies to *credentials*, not to \
         choosing an MCP server: do not fall back to a no-auth server because it looks \
         safer.\n\
         - If two servers still fit, say which you picked and why rather than guessing \
         silently.\n\
         \n\
         4. **Before calling a tool, run \
         `agentcordon mcp-tools --schema --server <server> --tool <tool>`** to read its \
         `input_schema`. Never guess argument names. Use `--arg key=value` for flat \
         arguments and `--args-json` for nested objects or arrays.\n\
         \n\
         MCP tools are reached through the AgentCordon broker, not through a native \
         `.mcp.json` entry — there is no `.mcp.json` for these servers and you should not \
         create one.\n\
         \n\
         ### Environment\n\
         \n\
         **You do not need to configure the broker.** `agentcordon-broker` binds a port the \
         OS picks and writes the URL to `~/.agentcordon/broker.port`; the CLI reads that \
         file and connects. There is no default broker port to assume.\n\
         \n\
         | Variable | Default | Description |\n\
         |----------|---------|-------------|\n\
         | `AGTCRDN_BROKER_URL` | *(unset — discovered from `~/.agentcordon/broker.port`)* | \
         **Override only.** Set it solely when the broker is somewhere the port file cannot \
         name it, such as another host or container. Must be plain `http://` to a loopback \
         host or any `https://` URL. |\n\
         \n\
         Do not export `AGTCRDN_BROKER_URL` speculatively: a wrong value overrides working \
         discovery and breaks every command. If `agentcordon status` cannot reach the \
         broker, start one (`agentcordon-broker --server-url <server>`) rather than \
         guessing a URL.\n\
         \n\
         **Local development**: to proxy to a `localhost` URL the broker must have been \
         started with `AGTCRDN_PROXY_ALLOW_LOOPBACK=true agentcordon-broker --server-url \
         <server>`. The broker reads it once, at startup (`crates/broker/src/config.rs`); \
         the CLI never looks at it, so prefixing a `proxy` call with it does nothing.\n\
         <!-- END AGENTCORDON -->\n"
    );

    write_marked_block(
        &agents_md_path,
        "AGENTS.md",
        &section,
        "# Agent Instructions\n",
    )
}

/// Generate CLAUDE.md as a thin wrapper that imports AGENTS.md.
///
/// The identity is *not* repeated here. It used to be, and `CLAUDE.md` was
/// then skipped on every rerun (its content mentioned "AgentCordon"), so after
/// a key regeneration `AGENTS.md` and `CLAUDE.md` named different identities
/// and the agent read both (uat/artifacts/reviews/UI-REVIEW-static.md G1).
fn generate_claude_md() -> Result<(), CliError> {
    let base = std::env::var("AGTCRDN_WORKSPACE_DIR").unwrap_or_else(|_| ".".to_string());
    let claude_md_path = Path::new(&base).join("CLAUDE.md");

    let section = "\n\
                   <!-- BEGIN AGENTCORDON -->\n\
                   ## AgentCordon\n\
                   \n\
                   @AGENTS.md\n\
                   <!-- END AGENTCORDON -->\n";

    write_marked_block(
        &claude_md_path,
        "CLAUDE.md",
        section,
        "# Claude Code Instructions\n",
    )
}

/// Generate Codex-specific config referencing AGENTS.md.
fn generate_codex_config() -> Result<(), CliError> {
    let base = std::env::var("AGTCRDN_WORKSPACE_DIR").unwrap_or_else(|_| ".".to_string());
    let codex_dir = Path::new(&base).join(".codex");
    fs::create_dir_all(&codex_dir)
        .map_err(|e| CliError::general(format!("failed to create .codex/: {e}")))?;

    write_marked_block(
        &codex_dir.join("instructions.md"),
        ".codex/instructions.md",
        &agent_stub_block(),
        "# Codex Instructions\n\
         \n\
         AGENTS.md is the primary instruction file and is loaded automatically by Codex.\n",
    )
}

/// Generate OpenClaw-specific config referencing AGENTS.md.
fn generate_openclaw_config() -> Result<(), CliError> {
    let base = std::env::var("AGTCRDN_WORKSPACE_DIR").unwrap_or_else(|_| ".".to_string());
    let openclaw_dir = Path::new(&base).join(".openclaw");
    fs::create_dir_all(&openclaw_dir)
        .map_err(|e| CliError::general(format!("failed to create .openclaw/: {e}")))?;

    write_marked_block(
        &openclaw_dir.join("instructions.md"),
        ".openclaw/instructions.md",
        &agent_stub_block(),
        "# OpenClaw Instructions\n\
         \n\
         AGENTS.md is the primary instruction file and is loaded automatically by OpenClaw.\n",
    )
}

/// The block both agent stubs carry: two commands and a pointer at the one
/// file that holds the rest.
///
/// It used to name `.agents/skills/` as a "native discovery path" and promise
/// skill hot-reload. `init` writes no skill, so both sentences pointed at a
/// directory that does not exist (uat/artifacts/reviews/UI-REVIEW-static.md G4).
fn agent_stub_block() -> String {
    "\n\
     <!-- BEGIN AGENTCORDON -->\n\
     ## AgentCordon Notes\n\
     \n\
     - Use `agentcordon credentials` to discover available credentials\n\
     - Use `agentcordon proxy <credential> <METHOD> <url>` for authenticated API calls\n\
     - AGENTS.md carries the workspace identity, the full command list and the rules for \
     choosing an MCP server\n\
     <!-- END AGENTCORDON -->\n"
        .to_string()
}

const BLOCK_BEGIN: &str = "<!-- BEGIN AGENTCORDON -->";
const BLOCK_END: &str = "<!-- END AGENTCORDON -->";

/// Write `section` into `path` as the file's one delimited AgentCordon block.
///
/// Every file `init` touches is edited the same way: the block between
/// `<!-- BEGIN AGENTCORDON -->` and `<!-- END AGENTCORDON -->` is replaced in
/// place, anything else the user wrote is left alone, and a file without the
/// markers gets the block appended.
///
/// The markers are the whole point. `CLAUDE.md`, `.codex/instructions.md` and
/// `.openclaw/instructions.md` used to be skipped whenever their text merely
/// contained the word "AgentCordon", so a project whose instructions said "we
/// do not use AgentCordon here" never got the import, and one that did get it
/// never got an update (uat/artifacts/reviews/UI-REVIEW-static.md G5).
///
/// `section` carries its own leading newline and both markers; `preamble` is
/// the title written above it when the file does not exist yet.
fn write_marked_block(
    path: &Path,
    label: &str,
    section: &str,
    preamble: &str,
) -> Result<(), CliError> {
    if !path.exists() {
        fs::write(path, format!("{preamble}{section}"))
            .map_err(|e| CliError::general(format!("failed to write {label}: {e}")))?;
        println!("Created {label} with AgentCordon instructions");
        return Ok(());
    }

    let content = fs::read_to_string(path)
        .map_err(|e| CliError::general(format!("failed to read {label}: {e}")))?;

    if let (Some(start), Some(end)) = (content.find(BLOCK_BEGIN), content.find(BLOCK_END)) {
        let end = end + BLOCK_END.len();
        // Swallow the block's trailing newline so a rerun does not grow the file.
        let end = if content[end..].starts_with('\n') {
            end + 1
        } else {
            end
        };
        let mut updated = String::with_capacity(content.len() + section.len());
        updated.push_str(&content[..start]);
        updated.push_str(section.trim_start_matches('\n'));
        updated.push_str(&content[end..]);
        fs::write(path, updated)
            .map_err(|e| CliError::general(format!("failed to write {label}: {e}")))?;
        println!("Updated {label} with AgentCordon instructions");
        return Ok(());
    }

    let separator = if content.ends_with('\n') { "" } else { "\n" };
    fs::write(path, format!("{content}{separator}{section}"))
        .map_err(|e| CliError::general(format!("failed to update {label}: {e}")))?;
    println!("Appended AgentCordon instructions to {label}");
    Ok(())
}

/// Add `.agentcordon/` to `.gitignore` if not already present.
fn add_to_gitignore() -> Result<(), CliError> {
    let base = std::env::var("AGTCRDN_WORKSPACE_DIR").unwrap_or_else(|_| ".".to_string());
    let gitignore_path = Path::new(&base).join(".gitignore");

    let entry = ".agentcordon/";

    if gitignore_path.exists() {
        let content = fs::read_to_string(&gitignore_path)
            .map_err(|e| CliError::general(format!("failed to read .gitignore: {e}")))?;
        if content.lines().any(|line| line.trim() == entry) {
            return Ok(());
        }
        // Append with newline separation
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

    /// `agentcordon mcp-serve` does not exist; an `.mcp.json` entry pointing
    /// at it made every Claude Code session fail to start an MCP server.
    /// `init` leaves `.mcp.json` to the user.
    #[test]
    fn init_does_not_create_mcp_json() {
        let dir = TempDir::new().unwrap();
        let _g = EnvGuard::new(dir.path());

        run("claude-code").unwrap();

        assert!(
            !dir.path().join(".mcp.json").exists(),
            "init must not create .mcp.json"
        );
    }

    #[test]
    fn init_leaves_existing_mcp_json_untouched() {
        let dir = TempDir::new().unwrap();
        let _g = EnvGuard::new(dir.path());
        let original = r#"{"mcpServers":{"filesystem":{"command":"npx","args":["-y","@modelcontextprotocol/server-filesystem","/tmp"],"env":{"FOO":"bar"}}}}"#;
        fs::write(dir.path().join(".mcp.json"), original).unwrap();

        run("claude-code").unwrap();
        // Second run takes the "keypair already exists" path.
        run("claude-code").unwrap();

        let after = fs::read_to_string(dir.path().join(".mcp.json")).unwrap();
        assert_eq!(
            after, original,
            ".mcp.json must be byte-identical after init"
        );
    }

    /// `init` writes a key the CLI's own loader accepts, prints the
    /// identity the key derives, and a second run reports the same
    /// identity without touching the key. Atomic creation and modes are
    /// covered by the identity crate's key-file tests.
    #[test]
    fn init_creates_loadable_key_and_is_idempotent() {
        let dir = TempDir::new().unwrap();
        let _g = EnvGuard::new(dir.path());

        run("claude-code").unwrap();
        let key_dir = dir.path().join(".agentcordon");
        let first = crate::signing::load_keypair().unwrap();
        assert!(agentcordon_identity::workspace_key_exists(&key_dir));
        // The identity is written once, into AGENTS.md; CLAUDE.md imports it.
        let agents_md = fs::read_to_string(dir.path().join("AGENTS.md")).unwrap();
        assert!(
            agents_md.contains(&format!("AC_IDENTITY: {}", first.identity())),
            "AGENTS.md must carry the key's identity"
        );
        let claude_md = fs::read_to_string(dir.path().join("CLAUDE.md")).unwrap();
        assert!(
            claude_md.contains("@AGENTS.md"),
            "CLAUDE.md must import AGENTS.md rather than repeat it"
        );

        run("claude-code").unwrap();
        let second = crate::signing::load_keypair().unwrap();
        assert_eq!(second.seed_hex(), first.seed_hex());
    }

    /// `AGENTS.md` is the only documentation an agent working in this
    /// workspace ever sees, so what it says about the broker and about
    /// picking an MCP server is load-bearing.
    ///
    /// It used to give `AGTCRDN_BROKER_URL` a default of
    /// `http://localhost:3141`. The broker's default port is `0` — it
    /// auto-selects and writes the URL to `~/.agentcordon/broker.port` — so an
    /// agent that believed the table and exported the variable broke its own
    /// connection. It also offered no rule for choosing between several MCP
    /// servers, and its only selection advice ("prefer least privilege")
    /// pointed at the unauthenticated one, which cannot answer a question
    /// about identity.
    #[test]
    fn agents_md_describes_broker_discovery_and_mcp_selection() {
        let dir = TempDir::new().unwrap();
        let _g = EnvGuard::new(dir.path());

        run("claude-code").unwrap();
        let agents_md = fs::read_to_string(dir.path().join("AGENTS.md")).unwrap();

        // No invented broker default anywhere in the file.
        assert!(
            !agents_md.contains("3141"),
            "AGENTS.md must not name a default broker port; the broker auto-selects one"
        );
        assert!(
            agents_md.contains("broker.port"),
            "AGENTS.md must say the broker is discovered through the port file"
        );
        assert!(
            agents_md.contains("Override only"),
            "AGTCRDN_BROKER_URL must be presented as an override, not a default"
        );

        // A rule for choosing among MCP servers.
        assert!(
            agents_md.contains("Match the service the task is about"),
            "AGENTS.md must tell the agent to match the task's service"
        );
        assert!(
            agents_md.contains("authenticated identity fits the question"),
            "AGENTS.md must prefer the server whose auth identity fits the question"
        );
        assert!(
            agents_md.contains("Never pick an unauthenticated server"),
            "AGENTS.md must forbid an unauthenticated server for identity questions"
        );

        // Learn a tool's arguments instead of guessing them.
        assert!(
            agents_md.contains("agentcordon mcp-tools --schema"),
            "AGENTS.md must point at `mcp-tools --schema` for a tool's arguments"
        );
        assert!(
            agents_md.contains("Never guess argument names"),
            "AGENTS.md must tell the agent not to guess argument names"
        );
    }

    /// The AgentCordon block is delimited and replaced in place, so a rerun
    /// after the template changes must not leave two copies or clobber the
    /// user's own content.
    #[test]
    fn agents_md_section_is_replaced_not_duplicated() {
        let dir = TempDir::new().unwrap();
        let _g = EnvGuard::new(dir.path());

        fs::write(
            dir.path().join("AGENTS.md"),
            "# My Instructions\n\nKeep this line.\n",
        )
        .unwrap();

        run("claude-code").unwrap();
        run("claude-code").unwrap();

        let agents_md = fs::read_to_string(dir.path().join("AGENTS.md")).unwrap();
        assert_eq!(
            agents_md.matches("<!-- BEGIN AGENTCORDON -->").count(),
            1,
            "the AgentCordon section must appear exactly once"
        );
        assert!(
            agents_md.contains("Keep this line."),
            "the user's own content must survive"
        );
    }

    /// The identity belongs in exactly one generated file.
    ///
    /// `AGENTS.md`'s block is delimited and replaced on every run; `CLAUDE.md`
    /// carried a second copy and was skipped whenever it merely mentioned
    /// "AgentCordon", so after a key regeneration the two files named
    /// different identities and the agent read both
    /// (uat/artifacts/reviews/UI-REVIEW-static.md G1).
    #[test]
    fn only_agents_md_carries_the_identity() {
        let dir = TempDir::new().unwrap();
        let _g = EnvGuard::new(dir.path());

        run("all").unwrap();

        let agents_md = fs::read_to_string(dir.path().join("AGENTS.md")).unwrap();
        assert!(
            agents_md.contains("AC_IDENTITY: sha256:"),
            "AGENTS.md is where the identity lives"
        );

        for other in [
            "CLAUDE.md",
            ".codex/instructions.md",
            ".openclaw/instructions.md",
        ] {
            let content = fs::read_to_string(dir.path().join(other)).unwrap();
            assert!(
                !content.contains("AC_IDENTITY"),
                "{other} must not carry a second copy of the identity — it goes stale when \
                 the key is regenerated"
            );
        }
    }

    /// Every file `init` writes into carries the same BEGIN/END markers, so a
    /// rerun replaces its own block in place. Detection by substring left a
    /// project whose `CLAUDE.md` said "we don't use AgentCordon here"
    /// untouched forever (uat/artifacts/reviews/UI-REVIEW-static.md G5).
    #[test]
    fn every_generated_file_is_delimited_by_markers_and_replaced_in_place() {
        let dir = TempDir::new().unwrap();
        let _g = EnvGuard::new(dir.path());

        // A pre-existing file that merely mentions AgentCordon still gets the
        // block appended, because the markers are what `init` looks for.
        fs::write(
            dir.path().join("CLAUDE.md"),
            "# House rules\n\nWe do not use AgentCordon for anything else.\n",
        )
        .unwrap();

        run("all").unwrap();
        run("all").unwrap();

        for generated in [
            "AGENTS.md",
            "CLAUDE.md",
            ".codex/instructions.md",
            ".openclaw/instructions.md",
        ] {
            let content = fs::read_to_string(dir.path().join(generated)).unwrap();
            assert_eq!(
                content.matches("<!-- BEGIN AGENTCORDON -->").count(),
                1,
                "{generated}: exactly one delimited AgentCordon block"
            );
            assert_eq!(
                content.matches("<!-- END AGENTCORDON -->").count(),
                1,
                "{generated}: the block is closed exactly once"
            );
        }

        let claude_md = fs::read_to_string(dir.path().join("CLAUDE.md")).unwrap();
        assert!(
            claude_md.contains("We do not use AgentCordon for anything else."),
            "the user's own content survives"
        );
        assert!(
            claude_md.contains("@AGENTS.md"),
            "CLAUDE.md's block is the import of AGENTS.md and nothing else"
        );
    }

    /// The Codex and OpenClaw stubs promised a skills directory `init` never
    /// writes, and OpenClaw's promised hot-reload of skills that do not exist
    /// (uat/artifacts/reviews/UI-REVIEW-static.md G4).
    #[test]
    fn the_agent_stubs_do_not_promise_a_skills_directory() {
        let dir = TempDir::new().unwrap();
        let _g = EnvGuard::new(dir.path());

        run("all").unwrap();

        for stub in [".codex/instructions.md", ".openclaw/instructions.md"] {
            let content = fs::read_to_string(dir.path().join(stub)).unwrap();
            assert!(
                !content.contains(".agents/skills/"),
                "{stub}: init writes no skill, so the discovery path is a dangling promise"
            );
            assert!(
                !content.contains("hot-reload"),
                "{stub}: nothing to hot-reload"
            );
        }
        assert!(
            !dir.path().join(".agents/skills").exists(),
            "init writes no skills directory"
        );
    }

    /// One sentence about `AGTCRDN_PROXY_ALLOW_LOOPBACK`, in the one file that
    /// explains the broker.
    ///
    /// `crates/broker/src/config.rs:31` reads it as a clap `env` argument, so
    /// it is read once, when the broker process starts. Putting it in front of
    /// an `agentcordon proxy` command — which this repository's own `CLAUDE.md`
    /// told the reader to do — sets it on the CLI, which never looks at it,
    /// and the proxy is refused anyway (uat/artifacts/reviews/UI-REVIEW-static.md G2).
    #[test]
    fn one_sentence_explains_the_loopback_flag() {
        let dir = TempDir::new().unwrap();
        let _g = EnvGuard::new(dir.path());

        run("all").unwrap();

        let agents_md = fs::read_to_string(dir.path().join("AGENTS.md")).unwrap();
        assert_eq!(
            agents_md.matches("AGTCRDN_PROXY_ALLOW_LOOPBACK").count(),
            1,
            "AGENTS.md explains the loopback flag exactly once"
        );
        assert!(
            agents_md.contains("AGTCRDN_PROXY_ALLOW_LOOPBACK=true agentcordon-broker"),
            "the sentence shows the flag where it is read: in front of the broker, at start"
        );
        assert!(
            !agents_md.contains("AGTCRDN_PROXY_ALLOW_LOOPBACK=true agentcordon proxy"),
            "the CLI never reads the flag; prefixing a proxy call with it does nothing"
        );

        for other in [
            "CLAUDE.md",
            ".codex/instructions.md",
            ".openclaw/instructions.md",
        ] {
            let content = fs::read_to_string(dir.path().join(other)).unwrap();
            assert!(
                !content.contains("AGTCRDN_PROXY_ALLOW_LOOPBACK"),
                "{other} must not carry a second, divergent explanation of the flag"
            );
        }
    }
}
