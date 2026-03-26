//! CLAUDE.md section management — generates and updates the AgentCordon
//! section in CLAUDE.md files so agents have actionable context after init.

use super::state::WorkspaceState;

/// Build the full AgentCordon CLAUDE.md section with usage instructions.
pub(super) fn agentcordon_section(pk_hash: &str) -> String {
    format!(
        "\
## AgentCordon

This workspace uses AgentCordon for credential management. \
API credentials are brokered through AgentCordon \
— never use raw secrets directly.

AC_IDENTITY: {}

### Workflow

**For API calls:**
1. Run `agentcordon credentials` to list available credentials
2. Pick the credential that matches the service you need — if multiple match, \
prefer the one with least privilege (e.g. readonly over full-access)
3. Use `agentcordon proxy <credential-name> <METHOD> <url>` to make the call

**For MCP tools:**
1. Run `agentcordon mcp-tools` to discover available tools across all MCP servers
2. Use `agentcordon mcp-call <server> <tool> --arg key=value` to call a tool

**Important**: Always discover credentials and tools first. Never guess names — \
they are assigned by the admin and vary per workspace.

### Commands

- `agentcordon credentials` — list credentials available to this workspace
- `agentcordon proxy <credential-name> <METHOD> <url>` — authenticated API call \
(credentials injected automatically)
- `agentcordon proxy <credential-name> POST <url> --body '{{\"key\": \"value\"}}'` — POST with JSON body
- `agentcordon mcp-tools` — discover all available MCP tools
- `agentcordon mcp-call <server> <tool> [--arg key=value]` — call an MCP tool
- `agentcordon mcp-servers` — list registered MCP servers
- `agentcordon status` — check connection and identity
- `agentcordon help` — full command reference

**Always prefer `agentcordon mcp-call` over native MCP tools.** When a tool is \
available through AgentCordon, use `agentcordon mcp-call` — it handles credential \
injection, policy checks, and audit logging. Only fall back to native MCP tools \
(from `.mcp.json`) if no matching AgentCordon MCP tool exists.

When you need to call an external API, use `agentcordon proxy` instead of \
direct HTTP with raw tokens. Every access is policy-checked and audit-logged.

**Local development**: If proxying to localhost URLs, prefix with:
`AGTCRDN_PROXY_ALLOW_LOOPBACK=true agentcordon proxy ...`
",
        pk_hash
    )
}

/// Update or create CLAUDE.md with the full AgentCordon section.
///
/// Before modifying an existing file, creates a one-time backup at
/// `CLAUDE.md.pre-agentcordon` (never overwrites an existing backup).
///
/// Handles three cases:
/// 1. File doesn't exist -- create it with a `# Project` header and the section.
/// 2. File exists with `## AgentCordon` or `AC_IDENTITY` -- replace the section in-place.
/// 3. File exists without either marker -- append the section at the end.
pub(super) fn update_claude_md() {
    let path = std::path::Path::new("CLAUDE.md");
    let st = WorkspaceState::load();
    let pk_hash = match &st.workspace_pk_hash {
        Some(h) => h.clone(),
        None => return,
    };

    update_claude_md_at(path, &pk_hash);
}

/// Core logic for updating/creating CLAUDE.md at a given path.
/// Extracted so tests can call it with temp-dir paths.
fn update_claude_md_at(path: &std::path::Path, pk_hash: &str) {
    let section = agentcordon_section(pk_hash);

    if !path.exists() {
        // Case 1: Create the file with a top-level heading
        let content = format!("# Project\n\n{}", section);
        let _ = std::fs::write(path, content);
        eprintln!("\u{2713} CLAUDE.md created with AgentCordon instructions");
        return;
    }

    let contents = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return,
    };

    // Backup the original before any modification (once only)
    backup_claude_md(path);

    if contents.contains("AC_IDENTITY:") || contents.contains("## AgentCordon") {
        // Case 2: Replace entire ## AgentCordon section (heading to next ## or EOF)
        let new_contents = replace_agentcordon_section(&contents, &section);
        let _ = std::fs::write(path, new_contents);
        eprintln!("\u{2713} CLAUDE.md updated with AgentCordon instructions");
    } else {
        // Case 3: Append new section
        let separator = if contents.ends_with('\n') { "" } else { "\n" };
        let _ = std::fs::write(path, format!("{}{}\n{}", contents, separator, section));
        eprintln!("\u{2713} CLAUDE.md updated with AgentCordon instructions");
    }
}

/// Create a one-time backup of CLAUDE.md before modifying it.
/// If `.pre-agentcordon` already exists, the original is preserved.
fn backup_claude_md(path: &std::path::Path) {
    let backup = path.with_extension("md.pre-agentcordon");
    if backup.exists() {
        return;
    }
    if std::fs::copy(path, &backup).is_ok() {
        eprintln!(
            "\u{2713} Backed up existing CLAUDE.md to {}",
            backup.file_name().unwrap_or_default().to_string_lossy()
        );
    }
}

/// Replace the `## AgentCordon` section in the document with new content.
/// The section spans from `## AgentCordon` to the next `## ` heading or EOF.
fn replace_agentcordon_section(contents: &str, new_section: &str) -> String {
    // Find the start of the ## AgentCordon heading
    let heading = "## AgentCordon";
    let section_start = match contents.find(heading) {
        Some(pos) => pos,
        None => {
            // No heading found but AC_IDENTITY exists — find AC_IDENTITY line
            // and replace just that line with the full section
            return replace_identity_line(contents, new_section);
        }
    };

    // Find the end: next ## heading after our section, or EOF
    let after_heading = section_start + heading.len();
    let section_end = contents[after_heading..]
        .find("\n## ")
        .map(|i| after_heading + i + 1) // +1 to keep the newline before next heading
        .unwrap_or(contents.len());

    let mut result = String::with_capacity(contents.len());
    result.push_str(&contents[..section_start]);
    result.push_str(new_section);
    if section_end < contents.len() {
        result.push_str(&contents[section_end..]);
    }
    result
}

/// Fallback: replace just the AC_IDENTITY line with the full section.
fn replace_identity_line(contents: &str, new_section: &str) -> String {
    let start = match contents.find("AC_IDENTITY:") {
        Some(pos) => pos,
        None => return contents.to_string(),
    };
    let line_end = contents[start..]
        .find('\n')
        .map(|i| start + i + 1)
        .unwrap_or(contents.len());

    let mut result = String::with_capacity(contents.len());
    result.push_str(&contents[..start]);
    result.push_str(new_section);
    result.push_str(&contents[line_end..]);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_HASH: &str = "sha256:abc123def456";

    #[test]
    fn section_contains_identity_and_usage() {
        let section = agentcordon_section(TEST_HASH);
        assert!(section.starts_with("## AgentCordon\n"));
        assert!(section.contains(&format!("AC_IDENTITY: {}", TEST_HASH)));
        assert!(section.contains("### Commands"));
        assert!(section.contains("agentcordon credentials"));
        assert!(section.contains("agentcordon proxy"));
        assert!(section.contains("agentcordon mcp-servers"));
        assert!(section.contains("agentcordon mcp-tools"));
        assert!(section.contains("agentcordon mcp-call"));
        assert!(section.contains("agentcordon status"));
        assert!(section.contains("agentcordon help"));
        assert!(section.contains("--body"));
        assert!(section.contains("Always prefer `agentcordon mcp-call` over native MCP tools"));
        assert!(section.contains("Only fall back to native MCP tools"));
        assert!(section.contains("policy-checked and audit-logged"));
        assert!(section.contains("AGTCRDN_PROXY_ALLOW_LOOPBACK=true"));
    }

    #[test]
    fn replace_section_between_headings() {
        let existing = "\
## Other stuff

Some content here.

## AgentCordon

AC_IDENTITY: sha256:old_hash

## More stuff

After.
";
        let new_section = agentcordon_section(TEST_HASH);
        let result = replace_agentcordon_section(existing, &new_section);

        assert!(result.contains("## Other stuff"));
        assert!(result.contains(&format!("AC_IDENTITY: {}", TEST_HASH)));
        assert!(!result.contains("old_hash"));
        assert!(result.contains("## More stuff"));
        assert!(result.contains("After."));
        assert!(result.contains("### Commands"));
    }

    #[test]
    fn replace_section_at_eof() {
        let existing = "\
## Intro

Hello.

## AgentCordon

AC_IDENTITY: sha256:old_hash
";
        let new_section = agentcordon_section(TEST_HASH);
        let result = replace_agentcordon_section(existing, &new_section);

        assert!(result.contains("## Intro"));
        assert!(result.contains(&format!("AC_IDENTITY: {}", TEST_HASH)));
        assert!(!result.contains("old_hash"));
        assert!(result.contains("### Commands"));
    }

    #[test]
    fn fallback_replaces_bare_identity_line() {
        let existing = "\
# My Project

AC_IDENTITY: sha256:old_hash

Other content.
";
        let new_section = agentcordon_section(TEST_HASH);
        let result = replace_identity_line(existing, &new_section);

        assert!(result.contains("# My Project"));
        assert!(result.contains(&format!("AC_IDENTITY: {}", TEST_HASH)));
        assert!(!result.contains("old_hash"));
        assert!(result.contains("Other content."));
        assert!(result.contains("### Commands"));
    }

    #[test]
    fn no_identity_returns_unchanged() {
        let existing = "# My Project\n\nSome content.\n";
        let result = replace_identity_line(existing, "replacement");
        assert_eq!(result, existing);
    }

    // --- File-level tests using update_claude_md_at ---

    #[test]
    fn creates_file_when_missing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("CLAUDE.md");

        update_claude_md_at(&path, TEST_HASH);

        let contents = std::fs::read_to_string(&path).unwrap();
        assert!(contents.starts_with("# Project\n"));
        assert!(contents.contains("## AgentCordon"));
        assert!(contents.contains(&format!("AC_IDENTITY: {}", TEST_HASH)));
        assert!(contents.contains("### Commands"));
        assert!(contents.contains("agentcordon proxy"));
    }

    #[test]
    fn replaces_existing_section() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("CLAUDE.md");
        let old =
            "# My Project\n\n## AgentCordon\n\nAC_IDENTITY: sha256:old\n\n## Other\n\nKeep.\n";
        std::fs::write(&path, old).unwrap();

        update_claude_md_at(&path, TEST_HASH);

        let contents = std::fs::read_to_string(&path).unwrap();
        assert!(contents.contains("# My Project"));
        assert!(contents.contains(&format!("AC_IDENTITY: {}", TEST_HASH)));
        assert!(!contents.contains("sha256:old"));
        assert!(contents.contains("## Other"));
        assert!(contents.contains("Keep."));
        assert!(contents.contains("### Commands"));
    }

    #[test]
    fn appends_when_no_identity() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("CLAUDE.md");
        let old = "# My Project\n\nSome existing content.\n";
        std::fs::write(&path, old).unwrap();

        update_claude_md_at(&path, TEST_HASH);

        let contents = std::fs::read_to_string(&path).unwrap();
        assert!(contents.starts_with("# My Project\n"));
        assert!(contents.contains("Some existing content."));
        assert!(contents.contains("## AgentCordon"));
        assert!(contents.contains(&format!("AC_IDENTITY: {}", TEST_HASH)));
        assert!(contents.contains("### Commands"));
    }

    // --- Backup tests ---

    #[test]
    fn backup_created_when_modifying_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("CLAUDE.md");
        let original = "# My Project\n\nImportant user content.\n";
        std::fs::write(&path, original).unwrap();

        update_claude_md_at(&path, TEST_HASH);

        let backup = dir.path().join("CLAUDE.md.pre-agentcordon");
        assert!(backup.exists(), "backup file should be created");
        let backup_contents = std::fs::read_to_string(&backup).unwrap();
        assert_eq!(backup_contents, original, "backup should match original");
    }

    #[test]
    fn backup_not_overwritten_on_second_run() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("CLAUDE.md");
        let original = "# My Project\n\nOriginal user content.\n";
        std::fs::write(&path, original).unwrap();

        // First run: creates backup
        update_claude_md_at(&path, TEST_HASH);
        let backup = dir.path().join("CLAUDE.md.pre-agentcordon");
        assert!(backup.exists());

        // Second run: should NOT overwrite backup
        update_claude_md_at(&path, "sha256:new_hash");
        let backup_contents = std::fs::read_to_string(&backup).unwrap();
        assert_eq!(
            backup_contents, original,
            "backup should preserve the original, not the first-run output"
        );
    }

    #[test]
    fn no_backup_when_creating_new_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("CLAUDE.md");

        update_claude_md_at(&path, TEST_HASH);

        let backup = dir.path().join("CLAUDE.md.pre-agentcordon");
        assert!(
            !backup.exists(),
            "no backup needed when CLAUDE.md did not exist"
        );
    }

    #[test]
    fn backup_created_when_replacing_section() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("CLAUDE.md");
        let original =
            "# My Project\n\n## AgentCordon\n\nAC_IDENTITY: sha256:old\n\n## Other\n\nKeep.\n";
        std::fs::write(&path, original).unwrap();

        update_claude_md_at(&path, TEST_HASH);

        let backup = dir.path().join("CLAUDE.md.pre-agentcordon");
        assert!(backup.exists(), "backup should be created before replacing");
        let backup_contents = std::fs::read_to_string(&backup).unwrap();
        assert_eq!(backup_contents, original);
    }

    // --- Edge case: heading exists without AC_IDENTITY ---

    #[test]
    fn replaces_heading_without_identity() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("CLAUDE.md");
        let old = "# My Project\n\n## AgentCordon\n\nSome stale content.\n\n## Other\n\nKeep.\n";
        std::fs::write(&path, old).unwrap();

        update_claude_md_at(&path, TEST_HASH);

        let contents = std::fs::read_to_string(&path).unwrap();
        assert!(contents.contains("# My Project"));
        assert!(contents.contains(&format!("AC_IDENTITY: {}", TEST_HASH)));
        assert!(!contents.contains("Some stale content."));
        assert!(contents.contains("## Other"));
        assert!(contents.contains("Keep."));
        assert!(contents.contains("### Commands"));
        // Should not duplicate the heading
        assert_eq!(
            contents.matches("## AgentCordon").count(),
            1,
            "should have exactly one AgentCordon section"
        );
    }
}
