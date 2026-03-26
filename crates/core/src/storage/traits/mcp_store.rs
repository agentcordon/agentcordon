use async_trait::async_trait;

use crate::domain::mcp::{McpServer, McpServerId};
use crate::domain::workspace::WorkspaceId;
use crate::error::StoreError;

#[async_trait]
pub trait McpStore: Send + Sync {
    async fn create_mcp_server(&self, server: &McpServer) -> Result<(), StoreError>;
    async fn get_mcp_server(&self, id: &McpServerId) -> Result<Option<McpServer>, StoreError>;
    /// Look up an MCP server by (workspace_id, name) — unique per workspace.
    async fn get_mcp_server_by_workspace_and_name(
        &self,
        workspace_id: &WorkspaceId,
        name: &str,
    ) -> Result<Option<McpServer>, StoreError>;
    async fn list_mcp_servers(&self) -> Result<Vec<McpServer>, StoreError>;
    /// List MCP servers belonging to a specific workspace.
    async fn list_mcp_servers_by_workspace(
        &self,
        workspace_id: &WorkspaceId,
    ) -> Result<Vec<McpServer>, StoreError>;
    async fn update_mcp_server(&self, server: &McpServer) -> Result<(), StoreError>;
    async fn delete_mcp_server(&self, id: &McpServerId) -> Result<bool, StoreError>;
}
