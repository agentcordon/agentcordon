use std::path::PathBuf;

/// Result of MCP gateway installation.
pub struct McpInstallResult {
    pub editor: String,
    pub config_path: PathBuf,
    pub backup_path: Option<PathBuf>,
}

/// Install the AgentCordon MCP gateway configuration for the given editor.
/// Currently supports "claude" (Claude Code). Future: "cursor", "vscode", etc.
///
/// `migrated_servers` — server names whose credentials were migrated into AgentCordon.
/// These entries will be removed from `.mcp.json` since AgentCordon now handles them.
pub fn install_mcp_gateway(
    editor: Option<&str>,
    migrated_servers: &[String],
) -> Result<McpInstallResult, String> {
    let editor = editor.unwrap_or("claude");

    let config_path = match editor {
        "claude" => PathBuf::from(".mcp.json"),
        other => return Err(format!("unsupported editor: {}", other)),
    };

    // Determine binary path
    let binary_path = std::env::current_exe()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|_| "agentcordon".to_string());

    // Create parent directory if needed
    if let Some(parent) = config_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("failed to create {}: {}", parent.display(), e))?;
    }

    // Backup existing file (only if it exists and no backup already)
    let backup_path = if config_path.exists() {
        let backup = config_path.with_extension("json.pre-agentcordon");
        if !backup.exists() {
            std::fs::copy(&config_path, &backup)
                .map_err(|e| format!("failed to backup config: {}", e))?;
            Some(backup)
        } else {
            None
        }
    } else {
        None
    };

    // Read existing config or start fresh
    let mut config: serde_json::Value = if config_path.exists() {
        let contents = std::fs::read_to_string(&config_path)
            .map_err(|e| format!("failed to read {}: {}", config_path.display(), e))?;
        serde_json::from_str(&contents)
            .map_err(|e| format!("failed to parse {}: {}", config_path.display(), e))?
    } else {
        serde_json::json!({})
    };

    // Ensure mcpServers object exists and add agentcordon entry
    let servers = config
        .as_object_mut()
        .ok_or_else(|| "config is not a JSON object".to_string())?
        .entry("mcpServers")
        .or_insert_with(|| serde_json::json!({}));

    let servers_obj = servers
        .as_object_mut()
        .ok_or_else(|| "mcpServers is not a JSON object".to_string())?;

    servers_obj.insert(
        "agentcordon".to_string(),
        serde_json::json!({
            "command": binary_path,
            "args": ["mcp-serve"]
        }),
    );

    // Remove migrated servers from .mcp.json (their credentials are now in AgentCordon)
    for name in migrated_servers {
        if servers_obj.remove(name).is_some() {
            eprintln!(
                "  Removed {} from .mcp.json (now managed by AgentCordon)",
                name
            );
        }
    }

    // Write updated config
    let output = serde_json::to_string_pretty(&config)
        .map_err(|e| format!("failed to serialize config: {}", e))?;
    std::fs::write(&config_path, output)
        .map_err(|e| format!("failed to write {}: {}", config_path.display(), e))?;

    Ok(McpInstallResult {
        editor: editor.to_string(),
        config_path,
        backup_path,
    })
}
