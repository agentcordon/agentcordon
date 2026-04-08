//! Startup data migrations that run before the policy engine loads.

use std::collections::HashMap;

use agent_cordon_core::storage::Store;

/// Migrate MCP grant/deny policy names from server-name-based to server-ID-based.
///
/// Old format: `grant:mcp:{server_name}:{agent_id}:{action}`
/// New format: `grant:mcp:{server_id}:{agent_id}:{action}`
///
/// This is idempotent: policies already using UUIDs are skipped.
pub async fn migrate_mcp_policy_names_to_ids(store: &(dyn Store + Send + Sync)) {
    let policies = match store.list_policies().await {
        Ok(p) => p,
        Err(e) => {
            tracing::error!(error = %e, "failed to list policies for MCP name→ID migration");
            return;
        }
    };

    let servers = match store.list_mcp_servers().await {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(error = %e, "failed to list MCP servers for name→ID migration");
            return;
        }
    };

    // Build name → id map. If multiple servers share a name, mark as ambiguous.
    let mut name_to_id: HashMap<String, Option<String>> = HashMap::new();
    for server in &servers {
        let entry = name_to_id.entry(server.name.clone()).or_insert(None);
        if entry.is_none() {
            *entry = Some(server.id.0.to_string());
        } else {
            // Ambiguous — multiple servers with same name, can't auto-migrate
            *entry = None;
            tracing::warn!(
                server_name = %server.name,
                "multiple MCP servers share name '{}' — skipping policy migration for this name",
                server.name
            );
        }
    }
    // Remove ambiguous entries
    name_to_id.retain(|_, v| v.is_some());

    let mut migrated = 0u32;
    let mut skipped = 0u32;

    for policy in &policies {
        // Match grant:mcp: or deny:mcp: prefixes
        let (prefix, rest) = if let Some(rest) = policy.name.strip_prefix("grant:mcp:") {
            ("grant:mcp:", rest)
        } else if let Some(rest) = policy.name.strip_prefix("deny:mcp:") {
            ("deny:mcp:", rest)
        } else {
            continue;
        };

        // Parse: {server_identifier}:{agent_id}:{action}[:{extra}]
        let parts: Vec<&str> = rest.splitn(2, ':').collect();
        if parts.len() < 2 {
            continue;
        }
        let server_identifier = parts[0];

        // If already a UUID, skip (already migrated)
        if uuid::Uuid::parse_str(server_identifier).is_ok() {
            continue;
        }

        // Look up server ID by name
        let server_id = match name_to_id.get(server_identifier) {
            Some(Some(id)) => id.clone(),
            _ => {
                tracing::warn!(
                    policy_name = %policy.name,
                    server_name = %server_identifier,
                    "cannot migrate MCP policy — server not found or ambiguous"
                );
                skipped += 1;
                continue;
            }
        };

        // Build new policy name
        let new_name = format!(
            "{}{}{}",
            prefix,
            server_id,
            &rest[server_identifier.len()..]
        );

        // Update Cedar policy text: replace server name with server ID in resource references
        let new_cedar = policy
            .cedar_policy
            .replace(
                &format!("AgentCordon::McpServer::\"{}\"", server_identifier),
                &format!("AgentCordon::McpServer::\"{}\"", server_id),
            )
            .replace(
                &format!("resource.name == \"{}\"", server_identifier),
                &format!("resource == AgentCordon::McpServer::\"{}\"", server_id),
            );

        let mut updated_policy = policy.clone();
        updated_policy.name = new_name.clone();
        updated_policy.cedar_policy = new_cedar;

        // Delete old, store new (rename)
        if let Err(e) = store.delete_policy_by_name(&policy.name).await {
            tracing::error!(
                policy_name = %policy.name,
                error = %e,
                "failed to delete old MCP policy during migration"
            );
            skipped += 1;
            continue;
        }
        if let Err(e) = store.store_policy(&updated_policy).await {
            tracing::error!(
                policy_name = %new_name,
                error = %e,
                "failed to store migrated MCP policy"
            );
            skipped += 1;
            continue;
        }

        tracing::info!(
            old_name = %policy.name,
            new_name = %new_name,
            "migrated MCP policy name→ID"
        );
        migrated += 1;
    }

    if migrated > 0 || skipped > 0 {
        tracing::info!(
            migrated = migrated,
            skipped = skipped,
            "MCP policy name→ID migration complete"
        );
    }
}

