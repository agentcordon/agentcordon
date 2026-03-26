//! Demo seed data for first-run experience.
//!
//! When the database has zero workspaces and `config.seed_demo` is true,
//! this module creates demo entities so the UI is populated on first boot.

use std::sync::Arc;

use chrono::Utc;
use uuid::Uuid;

use agent_cordon_core::auth::jwt::JwtIssuer;
use agent_cordon_core::crypto::aes_gcm::AesGcmEncryptor;
use agent_cordon_core::crypto::SecretEncryptor;
use agent_cordon_core::domain::audit::{AuditDecision, AuditEvent, AuditEventType};
use agent_cordon_core::domain::credential::{CredentialId, StoredCredential};
use agent_cordon_core::domain::policy::{PolicyId, StoredPolicy};
use agent_cordon_core::domain::workspace::{Workspace, WorkspaceId, WorkspaceStatus};
use agent_cordon_core::policy::{actions, templates};
use agent_cordon_core::storage::Store;

use crate::config::AppConfig;

/// Seed demo data if the database is empty and seeding is enabled.
///
/// Returns the number of entities created, or 0 if seeding was skipped.
pub async fn seed_demo_data(
    store: &Arc<dyn Store + Send + Sync>,
    encryptor: &Arc<AesGcmEncryptor>,
    config: &AppConfig,
    _jwt_issuer: &Arc<JwtIssuer>,
) -> Result<usize, String> {
    if !config.seed_demo {
        tracing::debug!("demo seeding disabled (AGTCRDN_SEED_DEMO=false)");
        return Ok(0);
    }

    // Check if demo workspace already exists — if so, skip seeding.
    if store
        .get_workspace_by_name("demo-workspace")
        .await
        .map_err(|e| format!("failed to check demo-workspace: {e}"))?
        .is_some()
    {
        tracing::debug!("demo-workspace already exists, skipping demo seed");
        return Ok(0);
    }

    let now = Utc::now();
    let mut entity_count = 0;

    // 1. Create demo workspace
    let workspace_id = WorkspaceId(Uuid::new_v4());
    let workspace = Workspace {
        id: workspace_id.clone(),
        name: "demo-workspace".to_string(),
        enabled: true,
        status: WorkspaceStatus::Active,
        pk_hash: None,
        encryption_public_key: None,
        tags: vec!["demo".to_string()],
        owner_id: None,
        parent_id: None,
        tool_name: None,
        created_at: now,
        updated_at: now,
    };
    store
        .create_workspace(&workspace)
        .await
        .map_err(|e| format!("failed to create demo workspace: {e}"))?;
    entity_count += 1;
    tracing::debug!(workspace_id = %workspace_id.0, "created demo workspace");

    // 2. Create demo credential (encrypted)
    let cred_id = CredentialId(Uuid::new_v4());
    let secret_value = "demo-token-not-real";
    let (encrypted_value, nonce) = encryptor
        .encrypt(secret_value.as_bytes(), cred_id.0.to_string().as_bytes())
        .map_err(|e| format!("failed to encrypt demo credential: {e}"))?;

    let credential = StoredCredential {
        id: cred_id.clone(),
        name: "demo-api-key".to_string(),
        service: "httpbin".to_string(),
        encrypted_value,
        nonce,
        scopes: vec!["read".to_string()],
        metadata: serde_json::json!({
            "demo": true,
            "description": "Demo credential for httpbin.org — not a real secret"
        }),
        created_by: None,
        created_by_user: None,
        created_at: now,
        updated_at: now,
        allowed_url_pattern: Some("https://httpbin.org/*".to_string()),
        expires_at: None,
        transform_script: None,
        transform_name: None,
        vault: "default".to_string(),
        credential_type: "generic".to_string(),
        tags: vec!["demo".to_string()],
        key_version: 1,
    };
    store
        .store_credential(&credential)
        .await
        .map_err(|e| format!("failed to create demo credential: {e}"))?;
    entity_count += 1;
    tracing::debug!(credential_id = %cred_id.0, "created demo credential");

    // 3. Grant demo workspace vend_credential + list on demo-api-key via Cedar grant policies.
    let grant_policies = vec![
        (actions::VEND_CREDENTIAL, "vend_credential"),
        (actions::LIST, "list"),
    ];
    for (cedar_action, perm_name) in &grant_policies {
        let policy_name = format!("grant:{}:{}:{}", cred_id.0, workspace_id.0, cedar_action);
        let grant_policy = StoredPolicy {
            id: PolicyId(Uuid::new_v4()),
            name: policy_name,
            description: Some(format!(
                "Grant {} on demo credential for demo-workspace",
                perm_name
            )),
            cedar_policy: templates::credential_grant_policy(
                &workspace_id.0.to_string(),
                cedar_action,
                &cred_id.0.to_string(),
            ),
            enabled: true,
            is_system: false,
            created_at: now,
            updated_at: now,
        };
        store
            .store_policy(&grant_policy)
            .await
            .map_err(|e| format!("failed to create grant policy: {e}"))?;
        entity_count += 1;
    }
    tracing::debug!("created Cedar grant policies for demo-workspace on demo-api-key");

    // 4. Create demo Cedar policy allowing credential vending
    let demo_policy = StoredPolicy {
        id: PolicyId(Uuid::new_v4()),
        name: "demo-allow-vend".to_string(),
        description: Some("Demo policy: allows demo-workspace to vend credentials".to_string()),
        cedar_policy: format!(
            r#"// Demo policy: allow demo-workspace credential vending
permit(
    principal == AgentCordon::Workspace::"{workspace_id}",
    action == AgentCordon::Action::"vend_credential",
    resource
) when {{
    resource has allowed_url_pattern
}};"#,
            workspace_id = workspace_id.0
        ),
        enabled: true,
        is_system: false,
        created_at: now,
        updated_at: now,
    };
    store
        .store_policy(&demo_policy)
        .await
        .map_err(|e| format!("failed to create demo policy: {e}"))?;
    entity_count += 1;
    tracing::debug!(policy_id = %demo_policy.id.0, "created demo Cedar policy");

    // 5. Create synthetic audit events
    let correlation_id = Uuid::new_v4().to_string();
    let audit_events = vec![
        AuditEvent {
            id: Uuid::new_v4(),
            timestamp: now - chrono::Duration::minutes(10),
            correlation_id: correlation_id.clone(),
            event_type: AuditEventType::WorkspaceCreated,
            workspace_id: Some(workspace_id.clone()),
            workspace_name: Some("demo-workspace".to_string()),
            user_id: None,
            user_name: Some("system-seed".to_string()),
            action: "create".to_string(),
            resource_type: "workspace".to_string(),
            resource_id: Some(workspace_id.0.to_string()),
            decision: AuditDecision::Permit,
            decision_reason: Some("demo seed".to_string()),
            metadata: serde_json::json!({"workspace_name": "demo-workspace", "demo": true}),
        },
        AuditEvent {
            id: Uuid::new_v4(),
            timestamp: now - chrono::Duration::minutes(7),
            correlation_id: correlation_id.clone(),
            event_type: AuditEventType::CredentialCreated,
            workspace_id: None,
            workspace_name: None,
            user_id: None,
            user_name: Some("system-seed".to_string()),
            action: "create".to_string(),
            resource_type: "credential".to_string(),
            resource_id: Some(cred_id.0.to_string()),
            decision: AuditDecision::Permit,
            decision_reason: Some("demo seed".to_string()),
            metadata: serde_json::json!({"credential_name": "demo-api-key", "service": "httpbin", "demo": true}),
        },
        AuditEvent {
            id: Uuid::new_v4(),
            timestamp: now - chrono::Duration::minutes(5),
            correlation_id: correlation_id.clone(),
            event_type: AuditEventType::CredentialAccessGranted,
            workspace_id: Some(workspace_id.clone()),
            workspace_name: Some("demo-workspace".to_string()),
            user_id: None,
            user_name: Some("system-seed".to_string()),
            action: "grant_permission".to_string(),
            resource_type: "credential".to_string(),
            resource_id: Some(cred_id.0.to_string()),
            decision: AuditDecision::Permit,
            decision_reason: Some("demo seed — delegated_use granted".to_string()),
            metadata: serde_json::json!({"credential_name": "demo-api-key", "permission": "delegated_use", "demo": true}),
        },
        AuditEvent {
            id: Uuid::new_v4(),
            timestamp: now - chrono::Duration::minutes(3),
            correlation_id: Uuid::new_v4().to_string(),
            event_type: AuditEventType::PolicyCreated,
            workspace_id: None,
            workspace_name: None,
            user_id: None,
            user_name: Some("system-seed".to_string()),
            action: "create".to_string(),
            resource_type: "policy".to_string(),
            resource_id: Some(demo_policy.id.0.to_string()),
            decision: AuditDecision::Permit,
            decision_reason: Some("demo seed".to_string()),
            metadata: serde_json::json!({"policy_name": "demo-allow-vend", "demo": true}),
        },
        AuditEvent {
            id: Uuid::new_v4(),
            timestamp: now - chrono::Duration::minutes(1),
            correlation_id: Uuid::new_v4().to_string(),
            event_type: AuditEventType::EnrollmentApproved,
            workspace_id: Some(workspace_id.clone()),
            workspace_name: Some("demo-workspace".to_string()),
            user_id: None,
            user_name: Some("system-seed".to_string()),
            action: "approve_enrollment".to_string(),
            resource_type: "enrollment".to_string(),
            resource_id: Some(workspace_id.0.to_string()),
            decision: AuditDecision::Permit,
            decision_reason: Some("demo seed — auto-approved".to_string()),
            metadata: serde_json::json!({"workspace_name": "demo-workspace", "demo": true}),
        },
    ];

    for event in &audit_events {
        store
            .append_audit_event(event)
            .await
            .map_err(|e| format!("failed to append demo audit event: {e}"))?;
    }
    entity_count += audit_events.len();

    // 6. Create curated Cedar policies (disabled by default)
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

    tracing::info!("demo seed data created — {} entities", entity_count);
    Ok(entity_count)
}
