use async_trait::async_trait;

use crate::domain::mcp::{McpServer, McpServerId};
use crate::domain::user::UserId;
use crate::domain::workspace::WorkspaceId;
use crate::error::StoreError;

/// Storage trait for the `mcp_server_workspaces` junction table introduced by
/// migration 010. Encodes the M:N relationship between MCP servers and the
/// workspaces they are bound to. Methods are pure DAO: business rules
/// (last-binding guard, cross-user authz) live at the handler layer.
#[async_trait]
pub trait McpServerWorkspaceStore: Send + Sync {
    /// Insert a binding. Idempotent via PK conflict — returns `Ok(true)` if the
    /// binding was newly inserted, `Ok(false)` if the row already existed.
    async fn add_mcp_server_workspace(
        &self,
        mcp_server_id: &McpServerId,
        workspace_id: &WorkspaceId,
        created_by_user: Option<&UserId>,
    ) -> Result<bool, StoreError>;

    /// Remove a binding. Returns `Ok(true)` if a row was removed, `Ok(false)`
    /// if no matching row existed. Callers check count + last-binding rule
    /// before calling; this method is pure DAO.
    async fn remove_mcp_server_workspace(
        &self,
        mcp_server_id: &McpServerId,
        workspace_id: &WorkspaceId,
    ) -> Result<bool, StoreError>;

    /// All workspaces bound to this MCP (regardless of enable state).
    /// Returns `(workspace_id, workspace_name)` tuples ordered by workspace name.
    async fn list_workspaces_for_mcp_server(
        &self,
        mcp_server_id: &McpServerId,
    ) -> Result<Vec<(WorkspaceId, String)>, StoreError>;

    /// All MCP servers bound to this workspace. Returns only MCPs with
    /// `mcp_servers.enabled = 1` AND where the junction row exists. This is
    /// what the broker's `mcp_sync` loop calls per-workspace.
    async fn list_mcp_servers_for_workspace(
        &self,
        workspace_id: &WorkspaceId,
    ) -> Result<Vec<McpServer>, StoreError>;

    /// Count of bindings for this MCP. Used by the handler to enforce the
    /// last-binding-removal 409 rule before calling `remove`.
    async fn count_workspaces_for_mcp_server(
        &self,
        mcp_server_id: &McpServerId,
    ) -> Result<usize, StoreError>;
}
