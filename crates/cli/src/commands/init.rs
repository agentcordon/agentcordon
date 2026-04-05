use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

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
        return Ok(());
    }

    // Create .agentcordon/ directory with mode 0700
    fs::create_dir_all(&dir)
        .map_err(|e| CliError::general(format!("failed to create .agentcordon/: {e}")))?;
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))
        .map_err(|e| CliError::general(format!("failed to set directory permissions: {e}")))?;

    // Generate Ed25519 keypair
    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let verifying_key = signing_key.verifying_key();

    // Write private key (hex seed, mode 0600)
    let seed_hex = hex::encode(signing_key.to_bytes());
    fs::write(&key_path, &seed_hex)
        .map_err(|e| CliError::general(format!("failed to write private key: {e}")))?;
    fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600))
        .map_err(|e| CliError::general(format!("failed to set key permissions: {e}")))?;

    // Write public key (hex, mode 0644)
    let pub_hex = hex::encode(verifying_key.to_bytes());
    fs::write(&pub_path, &pub_hex)
        .map_err(|e| CliError::general(format!("failed to write public key: {e}")))?;
    fs::set_permissions(&pub_path, fs::Permissions::from_mode(0o644))
        .map_err(|e| CliError::general(format!("failed to set pubkey permissions: {e}")))?;

    // Compute pk_hash
    let hash = hex::encode(Sha256::digest(verifying_key.to_bytes()));
    println!("Workspace identity: sha256:{hash}");

    // Add .agentcordon/ to .gitignore
    add_to_gitignore()?;

    // Generate agent-specific instruction files
    generate_for_agent(agent, &hash)?;

    // Create stub .mcp.json if it doesn't already exist
    generate_mcp_json_stub()?;

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
        let separator = if content.ends_with('\n') { "\n" } else { "\n\n" };
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
        let content = fs::read_to_string(&instructions_path)
            .map_err(|e| CliError::general(format!("failed to read .codex/instructions.md: {e}")))?;
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
        let content = fs::read_to_string(&instructions_path)
            .map_err(|e| {
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

    fs::write(&instructions_path, content)
        .map_err(|e| {
            CliError::general(format!("failed to write .openclaw/instructions.md: {e}"))
        })?;

    println!("Created .openclaw/instructions.md");
    Ok(())
}

/// Create a stub `.mcp.json` if one doesn't already exist.
///
/// Claude Code uses this file to discover MCP servers. The stub is empty
/// (no servers configured) but its presence signals that MCP is available.
/// AgentCordon's HTTP MCP servers are accessed via the broker, not `.mcp.json`.
fn generate_mcp_json_stub() -> Result<(), CliError> {
    let base = std::env::var("AGTCRDN_WORKSPACE_DIR").unwrap_or_else(|_| ".".to_string());
    let mcp_json_path = Path::new(&base).join(".mcp.json");

    if mcp_json_path.exists() {
        return Ok(());
    }

    let content = "{\n  \"mcpServers\": {}\n}\n";
    fs::write(&mcp_json_path, content)
        .map_err(|e| CliError::general(format!("failed to write .mcp.json: {e}")))?;

    println!("Created .mcp.json stub");
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
