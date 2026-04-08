use async_trait::async_trait;

use super::{db_err, is_unique_violation, McpServerRow, PostgresStore};
use crate::domain::mcp::{McpServer, McpServerId};
use crate::domain::user::UserId;
use crate::domain::workspace::WorkspaceId;
use crate::error::StoreError;
use crate::storage::shared::MCP_SERVER_COLUMNS;
use crate::storage::McpStore;

#[async_trait]
impl McpStore for PostgresStore {
    async fn create_mcp_server(&self, server: &McpServer) -> Result<(), StoreError> {
        let bindings = serde_json::Value::Array(vec![]);
        let tools = server
            .allowed_tools
            .as_ref()
            .map(|t| serde_json::to_value(t).unwrap_or_default());
        let tags = serde_json::to_value(&server.tags).unwrap_or_default();
        let req_creds = server.required_credentials.as_ref().map(|r| {
            let ids: Vec<String> = r.iter().map(|c| c.0.to_string()).collect();
            serde_json::to_value(&ids).unwrap_or_default()
        });
        let created_by_str = server.created_by.as_ref().map(|w| w.0.to_string());
        let created_by_user_str = server.created_by_user.as_ref().map(|u| u.0.to_string());

        let discovered = server
            .discovered_tools
            .as_ref()
            .map(|dt| serde_json::to_value(dt).unwrap_or_default());

        let result = sqlx::query(
            &format!(
                "INSERT INTO mcp_servers ({}) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)",
                MCP_SERVER_COLUMNS
            ),
        )
        .bind(server.id.0)
        .bind(server.workspace_id.0)
        .bind(&server.name)
        .bind(&server.upstream_url)
        .bind(server.transport.to_string())
        .bind(&bindings)
        .bind(&tools)
        .bind(server.enabled)
        .bind(&created_by_str)
        .bind(server.created_at)
        .bind(server.updated_at)
        .bind(&tags)
        .bind(&req_creds)
        .bind(server.auth_method.to_string())
        .bind(&server.template_key)
        .bind(&discovered)
        .bind(&created_by_user_str)
        .execute(&self.pool)
        .await;

        match result {
            Ok(_) => Ok(()),
            Err(e) if is_unique_violation(&e) => Err(StoreError::Conflict {
                message: format!(
                    "MCP server with name '{}' already exists on this workspace",
                    server.name
                ),
                existing_id: None,
            }),
            Err(e) => Err(db_err(e)),
        }
    }

    async fn get_mcp_server(&self, id: &McpServerId) -> Result<Option<McpServer>, StoreError> {
        let row = sqlx::query_as::<_, McpServerRow>(&format!(
            "SELECT {} FROM mcp_servers WHERE id = $1",
            MCP_SERVER_COLUMNS
        ))
        .bind(id.0)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(row.map(Into::into))
    }

    async fn get_mcp_server_by_workspace_and_name(
        &self,
        workspace_id: &WorkspaceId,
        name: &str,
    ) -> Result<Option<McpServer>, StoreError> {
        let row = sqlx::query_as::<_, McpServerRow>(&format!(
            "SELECT {} FROM mcp_servers WHERE workspace_id = $1 AND name = $2",
            MCP_SERVER_COLUMNS
        ))
        .bind(workspace_id.0)
        .bind(name)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(row.map(Into::into))
    }

    async fn list_mcp_servers(&self) -> Result<Vec<McpServer>, StoreError> {
        let rows = sqlx::query_as::<_, McpServerRow>(&format!(
            "SELECT {} FROM mcp_servers ORDER BY name ASC",
            MCP_SERVER_COLUMNS
        ))
        .fetch_all(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    async fn list_mcp_servers_by_workspace(
        &self,
        workspace_id: &WorkspaceId,
    ) -> Result<Vec<McpServer>, StoreError> {
        let rows = sqlx::query_as::<_, McpServerRow>(&format!(
            "SELECT {} FROM mcp_servers WHERE workspace_id = $1 ORDER BY name ASC",
            MCP_SERVER_COLUMNS
        ))
        .bind(workspace_id.0)
        .fetch_all(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    async fn list_mcp_servers_by_user(
        &self,
        user_id: &UserId,
    ) -> Result<Vec<McpServer>, StoreError> {
        let rows = sqlx::query_as::<_, McpServerRow>(&format!(
            "SELECT {} FROM mcp_servers WHERE created_by_user = $1 ORDER BY name ASC",
            MCP_SERVER_COLUMNS
        ))
        .bind(user_id.0.to_string())
        .fetch_all(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    async fn update_mcp_server(&self, server: &McpServer) -> Result<(), StoreError> {
        let bindings = serde_json::Value::Array(vec![]);
        let tools = server
            .allowed_tools
            .as_ref()
            .map(|t| serde_json::to_value(t).unwrap_or_default());
        let tags = serde_json::to_value(&server.tags).unwrap_or_default();
        let req_creds = server.required_credentials.as_ref().map(|r| {
            let ids: Vec<String> = r.iter().map(|c| c.0.to_string()).collect();
            serde_json::to_value(&ids).unwrap_or_default()
        });

        let discovered = server
            .discovered_tools
            .as_ref()
            .map(|dt| serde_json::to_value(dt).unwrap_or_default());

        let created_by_user_str = server.created_by_user.as_ref().map(|u| u.0.to_string());
        sqlx::query(
            "UPDATE mcp_servers SET workspace_id = $1, name = $2, upstream_url = $3, transport = $4, credential_bindings = $5, \
             allowed_tools = $6, enabled = $7, updated_at = $8, tags = $9, required_credentials = $10, auth_method = $11, template_key = $12, discovered_tools = $13, created_by_user = $14 WHERE id = $15",
        )
        .bind(server.workspace_id.0)
        .bind(&server.name)
        .bind(&server.upstream_url)
        .bind(server.transport.to_string())
        .bind(&bindings)
        .bind(&tools)
        .bind(server.enabled)
        .bind(server.updated_at)
        .bind(&tags)
        .bind(&req_creds)
        .bind(server.auth_method.to_string())
        .bind(&server.template_key)
        .bind(&discovered)
        .bind(&created_by_user_str)
        .bind(server.id.0)
        .execute(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(())
    }

    async fn delete_mcp_server(&self, id: &McpServerId) -> Result<bool, StoreError> {
        let result = sqlx::query("DELETE FROM mcp_servers WHERE id = $1")
            .bind(id.0)
            .execute(&self.pool)
            .await
            .map_err(db_err)?;
        Ok(result.rows_affected() > 0)
    }
}
