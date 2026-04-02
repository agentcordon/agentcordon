//! Seed data for first-run experience.
//!
//! When `config.seed_demo` is true, this module creates curated example Cedar
//! policies so new users have useful starting templates on first boot.

use std::sync::Arc;

use chrono::Utc;
use uuid::Uuid;

use agent_cordon_core::auth::jwt::JwtIssuer;
use agent_cordon_core::crypto::aes_gcm::AesGcmEncryptor;
use agent_cordon_core::domain::policy::{PolicyId, StoredPolicy};
use agent_cordon_core::storage::Store;

use crate::config::AppConfig;

/// Seed example policies if seeding is enabled.
///
/// Returns the number of entities created, or 0 if seeding was skipped.
pub async fn seed_demo_data(
    store: &Arc<dyn Store + Send + Sync>,
    _encryptor: &Arc<AesGcmEncryptor>,
    config: &AppConfig,
    _jwt_issuer: &Arc<JwtIssuer>,
) -> Result<usize, String> {
    if !config.seed_demo {
        tracing::debug!("example policy seeding disabled (AGTCRDN_SEED_DEMO=false)");
        return Ok(0);
    }

    let now = Utc::now();
    let mut entity_count = 0;

    // Create curated Cedar policies (disabled by default)
    let example_policies = vec![
        StoredPolicy {
            id: PolicyId(Uuid::new_v4()),
            name: "Tag-Based Credential Vending".to_string(),
            description: Some("Workspaces can vend and list credentials that share at least one tag. Tag both the workspace and credential with the same label (e.g., 'ci', 'deploy') for automatic access.".to_string()),
            cedar_policy: r#"// Tag-based: workspaces can vend/list credentials that share at least one tag.
permit(
    principal is AgentCordon::Workspace,
    action in [
        AgentCordon::Action::"vend_credential",
        AgentCordon::Action::"list"
    ],
    resource is AgentCordon::Credential
) when {
    principal.tags.containsAny(resource.tags)
};"#.to_string(),
            enabled: false,
            is_system: false,
            created_at: now,
            updated_at: now,
        },
        StoredPolicy {
            id: PolicyId(Uuid::new_v4()),
            name: "Read-Only Workspaces".to_string(),
            description: Some("Prevents workspaces from modifying or deleting credentials. Workspaces can still read and use credentials via vend_credential.".to_string()),
            cedar_policy: r#"// Read-only: prevent workspaces from modifying or deleting credentials.
forbid(
    principal is AgentCordon::Workspace,
    action in [
        AgentCordon::Action::"update",
        AgentCordon::Action::"delete",
        AgentCordon::Action::"create"
    ],
    resource is AgentCordon::Credential
);"#.to_string(),
            enabled: false,
            is_system: false,
            created_at: now,
            updated_at: now,
        },
        StoredPolicy {
            id: PolicyId(Uuid::new_v4()),
            name: "Workspace Environment Isolation".to_string(),
            description: Some("Production-tagged credentials can only be vended by production-tagged workspaces. Prevents dev/staging workspaces from accessing production secrets.".to_string()),
            cedar_policy: r#"// Environment isolation: production credentials require production workspaces.
forbid(
    principal is AgentCordon::Workspace,
    action == AgentCordon::Action::"vend_credential",
    resource is AgentCordon::Credential
) when {
    resource.tags.contains("production") && !principal.tags.contains("production")
};"#.to_string(),
            enabled: false,
            is_system: false,
            created_at: now,
            updated_at: now,
        },
        StoredPolicy {
            id: PolicyId(Uuid::new_v4()),
            name: "MCP Tool Restriction".to_string(),
            description: Some("Workspaces can only call tools on restricted MCP servers if they share at least one tag. Tag MCP servers as 'restricted' and matching workspaces with the same tag.".to_string()),
            cedar_policy: r#"// MCP restriction: workspaces need matching tags for restricted MCP servers.
forbid(
    principal is AgentCordon::Workspace,
    action == AgentCordon::Action::"mcp_tool_call",
    resource is AgentCordon::McpServer
) when {
    resource.tags.contains("restricted") && !principal.tags.containsAny(resource.tags)
};"#.to_string(),
            enabled: false,
            is_system: false,
            created_at: now,
            updated_at: now,
        },
        StoredPolicy {
            id: PolicyId(Uuid::new_v4()),
            name: "Owner-Only Credential Access".to_string(),
            description: Some("Workspaces can only access credentials owned by the same user. Prevents cross-user credential sharing without explicit grants.".to_string()),
            cedar_policy: r#"// Owner isolation: workspaces can only access credentials owned by the same user.
forbid(
    principal is AgentCordon::Workspace,
    action in [
        AgentCordon::Action::"access",
        AgentCordon::Action::"vend_credential"
    ],
    resource is AgentCordon::Credential
) when {
    principal has owner && resource has owner && resource.owner != principal.owner
};"#.to_string(),
            enabled: false,
            is_system: false,
            created_at: now,
            updated_at: now,
        },
    ];

    for policy in &example_policies {
        // Idempotent: check by name before inserting
        let existing = store
            .list_policies()
            .await
            .map_err(|e| format!("failed to list policies: {e}"))?;
        let already_exists = existing.iter().any(|p| p.name == policy.name);
        if !already_exists {
            store
                .store_policy(policy)
                .await
                .map_err(|e| format!("failed to create example policy '{}': {e}", policy.name))?;
            entity_count += 1;
            tracing::debug!(policy_name = %policy.name, "created example Cedar policy (disabled)");
        }
    }

    if entity_count > 0 {
        tracing::info!("example seed data created — {} policies", entity_count);
    }
    Ok(entity_count)
}
