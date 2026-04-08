use async_trait::async_trait;

use super::helpers::*;
use super::SqliteStore;

use crate::domain::mcp::{McpServer, McpServerId};
use crate::domain::user::UserId;
use crate::domain::workspace::WorkspaceId;
use crate::error::StoreError;
use crate::storage::McpStore;

/// Standard column list for MCP server queries (15 columns).
/// Order must match `row_to_mcp_server` in helpers.rs.
/// Uses the new `workspace_id` column added by the v2.0 migration.
const MCP_COLS: &str = "id, workspace_id, name, upstream_url, transport, credential_bindings, allowed_tools, enabled, created_by, created_at, updated_at, tags, required_credentials, auth_method, template_key, discovered_tools, created_by_user";

impl SqliteStore {
    pub(crate) async fn create_mcp_server(&self, server: &McpServer) -> Result<(), StoreError> {
        let server = server.clone();
        let tools_json = match &server.allowed_tools {
            Some(tools) => Some(serde_json::to_string(tools).map_err(|e| {
                StoreError::Database(format!("failed to serialize allowed_tools: {}", e))
            })?),
            None => None,
        };
        let tags_json = serde_json::to_string(&server.tags)
            .map_err(|e| StoreError::Database(format!("failed to serialize tags: {}", e)))?;
        let req_creds_json = server.required_credentials.as_ref().map(|r| {
            let ids: Vec<String> = r.iter().map(|c| c.0.to_string()).collect();
            serde_json::to_string(&ids).unwrap_or_default()
        });
        let discovered_tools_json = server.discovered_tools.as_ref().map(|dt| {
            serde_json::to_string(dt).unwrap_or_default()
        });
        let created_by_str = server.created_by.as_ref().map(|w| w.0.to_string());
        let created_by_user_str = server.created_by_user.as_ref().map(|u| u.0.to_string());
        let workspace_id_str = server.workspace_id.0.to_string();
        self.conn()
            .call(move |conn| {
                conn.execute(
                    "INSERT INTO mcp_servers (id, workspace_id, name, upstream_url, transport, credential_bindings, allowed_tools, enabled, created_by, created_at, updated_at, tags, required_credentials, auth_method, template_key, discovered_tools, created_by_user)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)",
                    rusqlite::params![
                        server.id.0.to_string(),
                        workspace_id_str,
                        server.name,
                        server.upstream_url,
                        server.transport.to_string(),
                        "[]", // legacy column — always write empty array
                        tools_json,
                        server.enabled as i32,
                        created_by_str,
                        server.created_at.to_rfc3339(),
                        server.updated_at.to_rfc3339(),
                        tags_json,
                        req_creds_json,
                        server.auth_method.to_string(),
                        server.template_key,
                        discovered_tools_json,
                        created_by_user_str,
                    ],
                )
                .map_err(|e| {
                    if let rusqlite::Error::SqliteFailure(ref err, _) = e {
                        if err.code == rusqlite::ErrorCode::ConstraintViolation {
                            return store_err_to_tokio(StoreError::Conflict {
                                message: format!("MCP server with name '{}' already exists on this workspace", server.name),
                                existing_id: None,
                            });
                        }
                    }
                    tokio_rusqlite::Error::Rusqlite(e)
                })?;
                Ok(())
            })
            .await
            .map_err(|e| StoreError::Database(e.to_string()))
    }

    pub(crate) async fn get_mcp_server(
        &self,
        id: &McpServerId,
    ) -> Result<Option<McpServer>, StoreError> {
        let id_str = id.0.to_string();
        let sql = format!("SELECT {} FROM mcp_servers WHERE id = ?1", MCP_COLS);
        self.conn()
            .call(move |conn| {
                let mut stmt = conn
                    .prepare(&sql)
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;
                let mut rows = stmt
                    .query_map(rusqlite::params![id_str], row_to_mcp_server)
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;
                match rows.next() {
                    Some(row) => Ok(Some(row.map_err(tokio_rusqlite::Error::Rusqlite)?)),
                    None => Ok(None),
                }
            })
            .await
            .map_err(|e| StoreError::Database(e.to_string()))
    }

    pub(crate) async fn get_mcp_server_by_workspace_and_name(
        &self,
        workspace_id: &WorkspaceId,
        name: &str,
    ) -> Result<Option<McpServer>, StoreError> {
        let workspace_id_str = workspace_id.0.to_string();
        let name = name.to_string();
        let sql = format!(
            "SELECT {} FROM mcp_servers WHERE workspace_id = ?1 AND name = ?2",
            MCP_COLS
        );
        self.conn()
            .call(move |conn| {
                let mut stmt = conn
                    .prepare(&sql)
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;
                let mut rows = stmt
                    .query_map(rusqlite::params![workspace_id_str, name], row_to_mcp_server)
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;
                match rows.next() {
                    Some(row) => Ok(Some(row.map_err(tokio_rusqlite::Error::Rusqlite)?)),
                    None => Ok(None),
                }
            })
            .await
            .map_err(|e| StoreError::Database(e.to_string()))
    }

    pub(crate) async fn list_mcp_servers(&self) -> Result<Vec<McpServer>, StoreError> {
        let sql = format!("SELECT {} FROM mcp_servers ORDER BY name ASC", MCP_COLS);
        self.conn()
            .call(move |conn| {
                let mut stmt = conn
                    .prepare(&sql)
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;
                let rows = stmt
                    .query_map([], row_to_mcp_server)
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;
                let mut servers = Vec::new();
                for row in rows {
                    servers.push(row.map_err(tokio_rusqlite::Error::Rusqlite)?);
                }
                Ok(servers)
            })
            .await
            .map_err(|e| StoreError::Database(e.to_string()))
    }

    pub(crate) async fn list_mcp_servers_by_workspace(
        &self,
        workspace_id: &WorkspaceId,
    ) -> Result<Vec<McpServer>, StoreError> {
        let workspace_id_str = workspace_id.0.to_string();
        let sql = format!(
            "SELECT {} FROM mcp_servers WHERE workspace_id = ?1 ORDER BY name ASC",
            MCP_COLS
        );
        self.conn()
            .call(move |conn| {
                let mut stmt = conn
                    .prepare(&sql)
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;
                let rows = stmt
                    .query_map(rusqlite::params![workspace_id_str], row_to_mcp_server)
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;
                let mut servers = Vec::new();
                for row in rows {
                    servers.push(row.map_err(tokio_rusqlite::Error::Rusqlite)?);
                }
                Ok(servers)
            })
            .await
            .map_err(|e| StoreError::Database(e.to_string()))
    }

    pub(crate) async fn list_mcp_servers_by_user(
        &self,
        user_id: &UserId,
    ) -> Result<Vec<McpServer>, StoreError> {
        let user_id_str = user_id.0.to_string();
        let sql = format!(
            "SELECT {} FROM mcp_servers WHERE created_by_user = ?1 ORDER BY name ASC",
            MCP_COLS
        );
        self.conn()
            .call(move |conn| {
                let mut stmt = conn
                    .prepare(&sql)
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;
                let rows = stmt
                    .query_map(rusqlite::params![user_id_str], row_to_mcp_server)
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;
                let mut servers = Vec::new();
                for row in rows {
                    servers.push(row.map_err(tokio_rusqlite::Error::Rusqlite)?);
                }
                Ok(servers)
            })
            .await
            .map_err(|e| StoreError::Database(e.to_string()))
    }

    pub(crate) async fn update_mcp_server(&self, server: &McpServer) -> Result<(), StoreError> {
        let server = server.clone();
        let tools_json = match &server.allowed_tools {
            Some(tools) => Some(serde_json::to_string(tools).map_err(|e| {
                StoreError::Database(format!("failed to serialize allowed_tools: {}", e))
            })?),
            None => None,
        };
        let tags_json = serde_json::to_string(&server.tags)
            .map_err(|e| StoreError::Database(format!("failed to serialize tags: {}", e)))?;
        let req_creds_json = server.required_credentials.as_ref().map(|r| {
            let ids: Vec<String> = r.iter().map(|c| c.0.to_string()).collect();
            serde_json::to_string(&ids).unwrap_or_default()
        });
        let discovered_tools_json = server.discovered_tools.as_ref().map(|dt| {
            serde_json::to_string(dt).unwrap_or_default()
        });
        let workspace_id_str = server.workspace_id.0.to_string();
        let created_by_user_str = server.created_by_user.as_ref().map(|u| u.0.to_string());
        self.conn()
            .call(move |conn| {
                conn.execute(
                    "UPDATE mcp_servers SET workspace_id = ?1, name = ?2, upstream_url = ?3, transport = ?4, credential_bindings = ?5, allowed_tools = ?6, enabled = ?7, updated_at = ?8, tags = ?9, required_credentials = ?10, auth_method = ?11, template_key = ?12, discovered_tools = ?13, created_by_user = ?14 WHERE id = ?15",
                    rusqlite::params![
                        workspace_id_str,
                        server.name,
                        server.upstream_url,
                        server.transport.to_string(),
                        "[]", // legacy column — always write empty array
                        tools_json,
                        server.enabled as i32,
                        server.updated_at.to_rfc3339(),
                        tags_json,
                        req_creds_json,
                        server.auth_method.to_string(),
                        server.template_key,
                        discovered_tools_json,
                        created_by_user_str,
                        server.id.0.to_string(),
                    ],
                )
                .map_err(tokio_rusqlite::Error::Rusqlite)?;
                Ok(())
            })
            .await
            .map_err(|e| StoreError::Database(e.to_string()))
    }

    pub(crate) async fn delete_mcp_server(&self, id: &McpServerId) -> Result<bool, StoreError> {
        let id_str = id.0.to_string();
        self.conn()
            .call(move |conn| {
                let count = conn
                    .execute(
                        "DELETE FROM mcp_servers WHERE id = ?1",
                        rusqlite::params![id_str],
                    )
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;
                Ok(count > 0)
            })
            .await
            .map_err(|e| StoreError::Database(e.to_string()))
    }
}

#[async_trait]
impl McpStore for SqliteStore {
    async fn create_mcp_server(&self, server: &McpServer) -> Result<(), StoreError> {
        self.create_mcp_server(server).await
    }
    async fn get_mcp_server(&self, id: &McpServerId) -> Result<Option<McpServer>, StoreError> {
        self.get_mcp_server(id).await
    }
    async fn get_mcp_server_by_workspace_and_name(
        &self,
        workspace_id: &WorkspaceId,
        name: &str,
    ) -> Result<Option<McpServer>, StoreError> {
        self.get_mcp_server_by_workspace_and_name(workspace_id, name)
            .await
    }
    async fn list_mcp_servers(&self) -> Result<Vec<McpServer>, StoreError> {
        self.list_mcp_servers().await
    }
    async fn list_mcp_servers_by_workspace(
        &self,
        workspace_id: &WorkspaceId,
    ) -> Result<Vec<McpServer>, StoreError> {
        self.list_mcp_servers_by_workspace(workspace_id).await
    }
    async fn list_mcp_servers_by_user(
        &self,
        user_id: &UserId,
    ) -> Result<Vec<McpServer>, StoreError> {
        self.list_mcp_servers_by_user(user_id).await
    }
    async fn update_mcp_server(&self, server: &McpServer) -> Result<(), StoreError> {
        self.update_mcp_server(server).await
    }
    async fn delete_mcp_server(&self, id: &McpServerId) -> Result<bool, StoreError> {
        self.delete_mcp_server(id).await
    }
}
