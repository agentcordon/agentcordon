use std::fs::{self, OpenOptions};
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

use crate::error::CliError;
use crate::signing::workspace_dir;

/// Create a file atomically at `path` with the given body.
///
/// Uses `O_CREAT | O_EXCL` (Unix) / `CREATE_NEW` (Windows) so the file is
/// created in a single syscall that fails if anything already exists at
/// the path — closing the check-then-write TOCTOU window that a plain
/// `fs::write` leaves open. On Unix, `mode` is passed to `open(2)` so the
/// file is created with the requested permissions from the first instant
/// it exists, not widened to umask-default and then chmod'd.
///
/// `_mode` is accepted on all platforms for call-site symmetry but is
/// only honoured on Unix; Windows files inherit NTFS ACLs from the parent
/// directory.
fn create_new_file(path: &Path, _mode: u32, body: &[u8], label: &str) -> Result<(), CliError> {
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    opts.mode(_mode);

    let mut file = match opts.open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(CliError::general(format!(
                "{label} appeared concurrently — re-run `agentcordon init`"
            )));
        }
        Err(e) => {
            return Err(CliError::general(format!("failed to write {label}: {e}")));
        }
    };
    file.write_all(body)
        .map_err(|e| CliError::general(format!("failed to write {label}: {e}")))
}

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
    let key_path = dir.join("workspace.key");
    let pub_path = dir.join("workspace.pub");

    // Idempotent: if key already exists, just print identity
    if key_path.exists() {
        let pub_hex = fs::read_to_string(&pub_path)
            .map_err(|e| CliError::general(format!("failed to read public key: {e}")))?;
        let pub_bytes = hex::decode(pub_hex.trim())
            .map_err(|e| CliError::general(format!("invalid public key format: {e}")))?;
        let hash = hex::encode(Sha256::digest(&pub_bytes));
        println!("Workspace identity: sha256:{hash}");
        println!("(keypair already exists)");

        // Still generate agent-specific files even if key exists
        generate_for_agent(agent, &hash)?;
        ensure_agentcordon_mcp_entry()?;
        return Ok(());
    }

    // Create .agentcordon/ directory with mode 0700 (Unix only; Windows uses ACL defaults).
    fs::create_dir_all(&dir)
        .map_err(|e| CliError::general(format!("failed to create .agentcordon/: {e}")))?;
    #[cfg(unix)]
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))
        .map_err(|e| CliError::general(format!("failed to set directory permissions: {e}")))?;

    // Generate Ed25519 keypair
    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let verifying_key = signing_key.verifying_key();

    // Write private key (hex seed, mode 0600) atomically: create_new +
    // explicit mode close the TOCTOU window that `fs::write` +
    // follow-up `set_permissions` left open.
    let seed_hex = hex::encode(signing_key.to_bytes());
    create_new_file(&key_path, 0o600, seed_hex.as_bytes(), "private key")?;

    // Write public key (hex, mode 0644) atomically.
    let pub_hex = hex::encode(verifying_key.to_bytes());
    create_new_file(&pub_path, 0o644, pub_hex.as_bytes(), "public key")?;

    // Compute pk_hash
    let hash = hex::encode(Sha256::digest(verifying_key.to_bytes()));
    println!("Workspace identity: sha256:{hash}");

    // Add .agentcordon/ to .gitignore
    add_to_gitignore()?;

    // Generate agent-specific instruction files
    generate_for_agent(agent, &hash)?;

    // Ensure .mcp.json contains the `agentcordon` MCP server entry so that
    // Claude Code (and other MCP-aware agents) can auto-discover it.
    ensure_agentcordon_mcp_entry()?;

    Ok(())
}

/// Generate instruction files for the specified agent (or all agents).
fn generate_for_agent(agent: &str, pk_hash: &str) -> Result<(), CliError> {
    // Always generate AGENTS.md (shared across all agents)
    generate_agents_md(pk_hash)?;

    match agent {
        "claude-code" => generate_claude_md(pk_hash)?,
        "codex" => generate_codex_config()?,
        "openclaw" => generate_openclaw_config()?,
        "all" => {
            generate_claude_md(pk_hash)?;
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
         - `agentcordon mcp-servers` — list MCP servers\n\
         - `agentcordon mcp-tools` — discover available tools\n\
         - `agentcordon mcp-call <server> <tool> [--arg key=value]` — call an MCP tool\n\
         - `agentcordon status` — check connection and identity\n\
         - `agentcordon help` — full command reference\n\
         \n\
         When you need to call an external API, use `agentcordon proxy` instead of direct \
         HTTP with raw tokens. Every access is policy-checked and audit-logged.\n\
         \n\
         ### Environment\n\
         \n\
         | Variable | Default | Description |\n\
         |----------|---------|-------------|\n\
         | `AGTCRDN_BROKER_URL` | `http://localhost:3141` | Broker URL the CLI connects to |\n\
         \n\
         Set `AGTCRDN_BROKER_URL` if the broker is running on a non-default host or port.\n\
         \n\
         **Local development**: If proxying to localhost URLs, ensure the broker was \
         started with `AGTCRDN_PROXY_ALLOW_LOOPBACK=true` (this is a broker-side flag, \
         not a CLI flag).\n\
         \n\
         **MCP servers**: If the admin has configured MCP servers, `agentcordon mcp-servers` \
         lists them and `agentcordon mcp-tools` shows available tools.\n\
         \n\
         **MCP tools**: After installing MCP servers from the marketplace, use \
         `agentcordon mcp-tools` to list available tools and \
         `agentcordon mcp-call <server> <tool> [--arg key=value]` to call them. \
         MCP tools are accessed through the AgentCordon broker, not through native \
         `.mcp.json` integration.\n\
         <!-- END AGENTCORDON -->\n"
    );

    if agents_md_path.exists() {
        let content = fs::read_to_string(&agents_md_path)
            .map_err(|e| CliError::general(format!("failed to read AGENTS.md: {e}")))?;
        if content.contains("<!-- BEGIN AGENTCORDON -->") {
            // Replace existing section
            if let (Some(start), Some(end)) = (
                content.find("<!-- BEGIN AGENTCORDON -->"),
                content.find("<!-- END AGENTCORDON -->"),
            ) {
                let end = end + "<!-- END AGENTCORDON -->".len();
                // Include trailing newline if present
                let end = if content[end..].starts_with('\n') {
                    end + 1
                } else {
                    end
                };
                let mut new_content = String::new();
                new_content.push_str(&content[..start]);
                new_content.push_str(section.trim_start());
                new_content.push_str(&content[end..]);
                fs::write(&agents_md_path, new_content)
                    .map_err(|e| CliError::general(format!("failed to write AGENTS.md: {e}")))?;
                println!("Updated AGENTS.md with AgentCordon instructions");
            }
            return Ok(());
        }
        // Append to existing AGENTS.md
        let separator = if content.ends_with('\n') { "" } else { "\n" };
        fs::write(&agents_md_path, format!("{content}{separator}{section}"))
            .map_err(|e| CliError::general(format!("failed to update AGENTS.md: {e}")))?;
        println!("Appended AgentCordon instructions to AGENTS.md");
    } else {
        let content = format!("# Agent Instructions\n{section}");
        fs::write(&agents_md_path, content)
            .map_err(|e| CliError::general(format!("failed to write AGENTS.md: {e}")))?;
        println!("Created AGENTS.md with AgentCordon instructions");
    }

    Ok(())
}

/// Generate CLAUDE.md as a thin wrapper that imports AGENTS.md.
fn generate_claude_md(pk_hash: &str) -> Result<(), CliError> {
    let base = std::env::var("AGTCRDN_WORKSPACE_DIR").unwrap_or_else(|_| ".".to_string());
    let claude_md_path = Path::new(&base).join("CLAUDE.md");

    // Only create if it doesn't exist or exists but doesn't mention AgentCordon
    if claude_md_path.exists() {
        let content = fs::read_to_string(&claude_md_path)
            .map_err(|e| CliError::general(format!("failed to read CLAUDE.md: {e}")))?;
        if content.contains("AgentCordon") {
            return Ok(());
        }
        // Append AgentCordon section to existing CLAUDE.md
        let separator = if content.ends_with('\n') {
            "\n"
        } else {
            "\n\n"
        };
        let section = format!(
            "{separator}## AgentCordon\n\
             \n\
             @AGENTS.md\n\
             \n\
             AC_IDENTITY: sha256:{pk_hash}\n"
        );
        fs::write(&claude_md_path, format!("{content}{section}"))
            .map_err(|e| CliError::general(format!("failed to update CLAUDE.md: {e}")))?;
        println!("Appended AgentCordon reference to CLAUDE.md");
    } else {
        let content = format!(
            "# Claude Code Instructions\n\
             \n\
             @AGENTS.md\n\
             \n\
             AC_IDENTITY: sha256:{pk_hash}\n"
        );
        fs::write(&claude_md_path, content)
            .map_err(|e| CliError::general(format!("failed to write CLAUDE.md: {e}")))?;
        println!("Created CLAUDE.md with AgentCordon instructions");
    }

    Ok(())
}

/// Generate Codex-specific config referencing AGENTS.md.
fn generate_codex_config() -> Result<(), CliError> {
    let base = std::env::var("AGTCRDN_WORKSPACE_DIR").unwrap_or_else(|_| ".".to_string());
    let codex_dir = Path::new(&base).join(".codex");
    let instructions_path = codex_dir.join("instructions.md");

    if instructions_path.exists() {
        let content = fs::read_to_string(&instructions_path).map_err(|e| {
            CliError::general(format!("failed to read .codex/instructions.md: {e}"))
        })?;
        if content.contains("AgentCordon") {
            return Ok(());
        }
    }

    fs::create_dir_all(&codex_dir)
        .map_err(|e| CliError::general(format!("failed to create .codex/: {e}")))?;

    let content = "# Codex Instructions\n\
                   \n\
                   AGENTS.md is the primary instruction file and is loaded automatically by Codex.\n\
                   \n\
                   ## AgentCordon Notes\n\
                   \n\
                   - Use `agentcordon credentials` to discover available credentials\n\
                   - Use `agentcordon proxy <credential> <METHOD> <url>` for authenticated API calls\n\
                   - Skills are at `.agents/skills/` (native Codex discovery path)\n";

    fs::write(&instructions_path, content)
        .map_err(|e| CliError::general(format!("failed to write .codex/instructions.md: {e}")))?;

    println!("Created .codex/instructions.md");
    Ok(())
}

/// Generate OpenClaw-specific config referencing AGENTS.md.
fn generate_openclaw_config() -> Result<(), CliError> {
    let base = std::env::var("AGTCRDN_WORKSPACE_DIR").unwrap_or_else(|_| ".".to_string());
    let openclaw_dir = Path::new(&base).join(".openclaw");
    let instructions_path = openclaw_dir.join("instructions.md");

    if instructions_path.exists() {
        let content = fs::read_to_string(&instructions_path).map_err(|e| {
            CliError::general(format!("failed to read .openclaw/instructions.md: {e}"))
        })?;
        if content.contains("AgentCordon") {
            return Ok(());
        }
    }

    fs::create_dir_all(&openclaw_dir)
        .map_err(|e| CliError::general(format!("failed to create .openclaw/: {e}")))?;

    let content = "# OpenClaw Instructions\n\
                   \n\
                   AGENTS.md is the primary instruction file and is loaded automatically by OpenClaw.\n\
                   \n\
                   ## AgentCordon Notes\n\
                   \n\
                   - Use `agentcordon credentials` to discover available credentials\n\
                   - Use `agentcordon proxy <credential> <METHOD> <url>` for authenticated API calls\n\
                   - Skills are at `.agents/skills/` (native OpenClaw discovery path)\n\
                   - Skill hot-reload is supported — changes take effect without restart\n";

    fs::write(&instructions_path, content).map_err(|e| {
        CliError::general(format!("failed to write .openclaw/instructions.md: {e}"))
    })?;

    println!("Created .openclaw/instructions.md");
    Ok(())
}

/// Ensure `.mcp.json` exists and contains an `agentcordon` MCP server entry.
///
/// Claude Code reads this file to auto-discover MCP servers. We inject an
/// entry that points at `agentcordon mcp-serve` so the agent can reach the
/// AgentCordon broker as a native MCP server. Any other entries already in
/// the file are preserved untouched — we never read, back up, or persist
/// the user's existing MCP secrets.
fn ensure_agentcordon_mcp_entry() -> Result<(), CliError> {
    let base = std::env::var("AGTCRDN_WORKSPACE_DIR").unwrap_or_else(|_| ".".to_string());
    let mcp_json_path = Path::new(&base).join(".mcp.json");

    let mut json: serde_json::Value = if mcp_json_path.exists() {
        let content = fs::read_to_string(&mcp_json_path)
            .map_err(|e| CliError::general(format!("failed to read .mcp.json: {e}")))?;
        serde_json::from_str(&content)
            .map_err(|e| CliError::general(format!("invalid .mcp.json: {e}")))?
    } else {
        serde_json::json!({ "mcpServers": {} })
    };

    if !json.is_object() {
        json = serde_json::json!({ "mcpServers": {} });
    }
    let obj = json.as_object_mut().unwrap();
    let servers = obj
        .entry("mcpServers".to_string())
        .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));
    if !servers.is_object() {
        *servers = serde_json::Value::Object(serde_json::Map::new());
    }
    let servers_map = servers.as_object_mut().unwrap();
    servers_map.insert(
        "agentcordon".to_string(),
        serde_json::json!({
            "command": "agentcordon",
            "args": ["mcp-serve"],
        }),
    );

    let mut new_content = serde_json::to_string_pretty(&json)
        .map_err(|e| CliError::general(format!("failed to serialize .mcp.json: {e}")))?;
    new_content.push('\n');
    fs::write(&mcp_json_path, new_content)
        .map_err(|e| CliError::general(format!("failed to write .mcp.json: {e}")))?;

    println!("Ensured .mcp.json contains agentcordon MCP server entry");
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

    fn read_mcp(dir: &Path) -> serde_json::Value {
        let body = fs::read_to_string(dir.join(".mcp.json")).unwrap();
        serde_json::from_str(&body).unwrap()
    }

    #[test]
    fn ensure_entry_creates_file_when_missing() {
        let dir = TempDir::new().unwrap();
        let _g = EnvGuard::new(dir.path());

        ensure_agentcordon_mcp_entry().unwrap();

        let json = read_mcp(dir.path());
        let servers = json["mcpServers"].as_object().unwrap();
        assert_eq!(servers.len(), 1);
        let entry = &servers["agentcordon"];
        assert_eq!(entry["command"], "agentcordon");
        assert_eq!(entry["args"][0], "mcp-serve");
    }

    #[test]
    fn ensure_entry_preserves_existing_servers() {
        let dir = TempDir::new().unwrap();
        let _g = EnvGuard::new(dir.path());
        fs::write(
            dir.path().join(".mcp.json"),
            r#"{"mcpServers":{"filesystem":{"command":"npx","args":["-y","@modelcontextprotocol/server-filesystem","/tmp"],"env":{"FOO":"bar"}}}}"#,
        )
        .unwrap();

        ensure_agentcordon_mcp_entry().unwrap();

        let json = read_mcp(dir.path());
        let servers = json["mcpServers"].as_object().unwrap();
        assert!(servers.contains_key("agentcordon"));
        let fs_entry = &servers["filesystem"];
        assert_eq!(fs_entry["command"], "npx");
        assert_eq!(fs_entry["env"]["FOO"], "bar");
    }

    #[test]
    fn ensure_entry_is_idempotent() {
        let dir = TempDir::new().unwrap();
        let _g = EnvGuard::new(dir.path());

        ensure_agentcordon_mcp_entry().unwrap();
        let first = fs::read_to_string(dir.path().join(".mcp.json")).unwrap();
        ensure_agentcordon_mcp_entry().unwrap();
        let second = fs::read_to_string(dir.path().join(".mcp.json")).unwrap();
        assert_eq!(first, second);

        let json = read_mcp(dir.path());
        let servers = json["mcpServers"].as_object().unwrap();
        assert_eq!(servers.len(), 1);
        assert!(servers.contains_key("agentcordon"));
    }

    #[test]
    fn create_new_file_writes_exact_body() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("key");

        create_new_file(&path, 0o600, b"hello world", "private key").unwrap();

        let body = fs::read_to_string(&path).unwrap();
        assert_eq!(body, "hello world");
    }

    #[test]
    fn create_new_file_rejects_existing_path() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("key");
        fs::write(&path, b"pre-existing").unwrap();

        let err = create_new_file(&path, 0o600, b"new content", "private key").unwrap_err();

        assert_eq!(err.code, crate::error::ExitCode::GeneralError);
        assert!(
            err.message.contains("appeared concurrently"),
            "message was: {}",
            err.message
        );
        // The pre-existing content must be untouched — TOCTOU hardening
        // means we never overwrite on race.
        assert_eq!(fs::read_to_string(&path).unwrap(), "pre-existing");
    }

    #[cfg(unix)]
    #[test]
    fn create_new_file_sets_mode_atomically() {
        let dir = TempDir::new().unwrap();
        let key_path = dir.path().join("workspace.key");
        let pub_path = dir.path().join("workspace.pub");

        create_new_file(&key_path, 0o600, b"seed", "private key").unwrap();
        create_new_file(&pub_path, 0o644, b"pk", "public key").unwrap();

        let key_mode = fs::metadata(&key_path).unwrap().permissions().mode() & 0o777;
        let pub_mode = fs::metadata(&pub_path).unwrap().permissions().mode() & 0o777;
        // The active umask masks off group/world bits; just assert the
        // file never got broader perms than we asked for.
        assert!(
            key_mode & !0o600 == 0,
            "private key mode {key_mode:o} wider than 0o600"
        );
        assert!(
            pub_mode & !0o644 == 0,
            "public key mode {pub_mode:o} wider than 0o644"
        );
        // And that owner-read is set on both (sanity).
        assert_eq!(key_mode & 0o400, 0o400);
        assert_eq!(pub_mode & 0o400, 0o400);
    }
}
