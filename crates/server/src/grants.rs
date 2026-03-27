//! Centralized, idempotent grant policy management.
//!
//! All Cedar grant/deny policy creation flows through this module.
//! Callers should use these functions instead of constructing `StoredPolicy`
//! inline or calling `store_policy` / `list_policies` / `reload_engine` directly.

use uuid::Uuid;

use agent_cordon_core::domain::credential::CredentialId;
use agent_cordon_core::domain::mcp::McpServerId;
use agent_cordon_core::domain::policy::{PolicyId, StoredPolicy};
use agent_cordon_core::domain::workspace::WorkspaceId;
use agent_cordon_core::policy::templates;

use crate::response::ApiError;
use crate::state::AppState;

/// Low-level idempotent grant: delete any existing policy with this name,
/// create a new one. Does **not** reload the policy engine — call
/// [`reload_engine`](crate::routes::admin_api::policies::reload_engine)
/// after batching multiple grants.
async fn store_grant(
    state: &AppState,
    name: String,
    cedar_text: String,
    description: String,
) -> Result<StoredPolicy, ApiError> {
    let _ = state.store.delete_policy_by_name(&name).await;

    let now = chrono::Utc::now();
    let policy = StoredPolicy {
        id: PolicyId(Uuid::new_v4()),
        name,
        description: Some(description),
        cedar_policy: cedar_text,
        enabled: true,
        is_system: false,
        created_at: now,
        updated_at: now,
    };

    state.store.store_policy(&policy).await?;
    Ok(policy)
}

/// Idempotent grant: delete existing policy by name, create new one, reload engine.
pub async fn ensure_grant(
    state: &AppState,
    name: String,
    cedar_text: String,
    description: String,
) -> Result<StoredPolicy, ApiError> {
    let policy = store_grant(state, name, cedar_text, description).await?;
    crate::routes::admin_api::policies::reload_engine(state).await?;
    Ok(policy)
}

/// Create a single credential grant or deny policy (idempotent + reload).
pub async fn ensure_credential_grant(
    state: &AppState,
    cred_id: &CredentialId,
    workspace_id: &WorkspaceId,
    cedar_action: &str,
    perm_name: &str,
    mode: &str,
) -> Result<StoredPolicy, ApiError> {
    let is_deny = mode == "deny";
    let policy_name = format!("{}:{}:{}:{}", mode, cred_id.0, workspace_id.0, cedar_action);
    let cedar_text = if is_deny {
        templates::credential_deny_policy(
            &workspace_id.0.to_string(),
            cedar_action,
            &cred_id.0.to_string(),
        )
    } else {
        templates::credential_grant_policy(
            &workspace_id.0.to_string(),
            cedar_action,
            &cred_id.0.to_string(),
        )
    };
    let description = format!(
        "{} {} on credential for workspace",
        if is_deny { "Deny" } else { "Grant" },
        perm_name,
    );
    ensure_grant(state, policy_name, cedar_text, description).await
}

/// Create a single MCP grant or deny policy (idempotent + reload).
pub async fn ensure_mcp_grant(
    state: &AppState,
    server_id: &McpServerId,
    workspace_id: &WorkspaceId,
    permission: &str,
    mode: &str,
) -> Result<StoredPolicy, ApiError> {
    let is_deny = mode == "deny";
    let server_id_str = server_id.0.to_string();
    let workspace_id_str = workspace_id.0.to_string();

    let (policy_name, cedar_text) =
        if let Some(tool_name) = permission.strip_prefix("mcp_tool_call:") {
            let name = format!(
                "{}:mcp:{}:{}:mcp_tool_call:{}",
                mode, server_id_str, workspace_id.0, tool_name
            );
            let policy = if is_deny {
                templates::mcp_tool_deny_policy(&workspace_id_str, tool_name, &server_id_str)
            } else {
                templates::mcp_tool_grant_policy(&workspace_id_str, tool_name, &server_id_str)
            };
            (name, policy)
        } else {
            let name = format!(
                "{}:mcp:{}:{}:{}",
                mode, server_id_str, workspace_id.0, permission
            );
            let policy = if is_deny {
                templates::mcp_deny_policy(&workspace_id_str, permission, &server_id_str)
            } else {
                templates::mcp_grant_policy(&workspace_id_str, permission, &server_id_str)
            };
            (name, policy)
        };

    let description = format!(
        "{} {} on MCP server for workspace",
        if is_deny { "Deny" } else { "Grant" },
        permission,
    );

    ensure_grant(state, policy_name, cedar_text, description).await
}
