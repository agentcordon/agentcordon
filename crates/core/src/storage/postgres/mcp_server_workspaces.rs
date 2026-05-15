use async_trait::async_trait;

use super::{db_err, McpServerRow, PostgresStore};
use crate::domain::mcp::{McpServer, McpServerId};
use crate::domain::user::UserId;
use crate::domain::workspace::WorkspaceId;
use crate::error::StoreError;
use crate::storage::shared::MCP_SERVER_COLUMNS;
use crate::storage::McpServerWorkspaceStore;

#[async_trait]
impl McpServerWorkspaceStore for PostgresStore {
    async fn add_mcp_server_workspace(
        &self,
        mcp_server_id: &McpServerId,
        workspace_id: &WorkspaceId,
        created_by_user: Option<&UserId>,
    ) -> Result<bool, StoreError> {
        let created_by_user_str = created_by_user.map(|u| u.0.to_string());
        let result = sqlx::query(
            "INSERT INTO mcp_server_workspaces \
               (mcp_server_id, workspace_id, created_at, created_by_user) \
             VALUES ($1, $2, $3, $4) \
             ON CONFLICT (mcp_server_id, workspace_id) DO NOTHING",
        )
        .bind(mcp_server_id.0)
        .bind(workspace_id.0)
        .bind(chrono::Utc::now())
        .bind(&created_by_user_str)
        .execute(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(result.rows_affected() > 0)
    }

    async fn remove_mcp_server_workspace(
        &self,
        mcp_server_id: &McpServerId,
        workspace_id: &WorkspaceId,
    ) -> Result<bool, StoreError> {
        let result = sqlx::query(
            "DELETE FROM mcp_server_workspaces \
             WHERE mcp_server_id = $1 AND workspace_id = $2",
        )
        .bind(mcp_server_id.0)
        .bind(workspace_id.0)
        .execute(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(result.rows_affected() > 0)
    }

    async fn list_workspaces_for_mcp_server(
        &self,
        mcp_server_id: &McpServerId,
    ) -> Result<Vec<(WorkspaceId, String)>, StoreError> {
        let rows: Vec<(uuid::Uuid, String)> = sqlx::query_as(
            "SELECT w.id, w.name \
             FROM mcp_server_workspaces j \
             JOIN workspaces w ON w.id = j.workspace_id \
             WHERE j.mcp_server_id = $1 \
             ORDER BY w.name ASC",
        )
        .bind(mcp_server_id.0)
        .fetch_all(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(rows
            .into_iter()
            .map(|(id, name)| (WorkspaceId(id), name))
            .collect())
    }

    async fn list_mcp_servers_for_workspace(
        &self,
        workspace_id: &WorkspaceId,
    ) -> Result<Vec<McpServer>, StoreError> {
        // Prefix the column list so it resolves unambiguously against `mcp_servers m`.
        let cols = MCP_SERVER_COLUMNS
            .split(", ")
            .map(|c| format!("m.{}", c))
            .collect::<Vec<_>>()
            .join(", ");
        let sql = format!(
            "SELECT {} FROM mcp_servers m \
             JOIN mcp_server_workspaces j ON j.mcp_server_id = m.id \
             WHERE j.workspace_id = $1 AND m.enabled = TRUE \
             ORDER BY m.name ASC",
            cols
        );
        let rows = sqlx::query_as::<_, McpServerRow>(&sql)
            .bind(workspace_id.0)
            .fetch_all(&self.pool)
            .await
            .map_err(db_err)?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    async fn count_workspaces_for_mcp_server(
        &self,
        mcp_server_id: &McpServerId,
    ) -> Result<usize, StoreError> {
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM mcp_server_workspaces WHERE mcp_server_id = $1",
        )
        .bind(mcp_server_id.0)
        .fetch_one(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(count.max(0) as usize)
    }
}
