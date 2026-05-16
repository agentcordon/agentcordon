use async_trait::async_trait;

use super::helpers::*;
use super::SqliteStore;

use crate::domain::mcp::{McpServer, McpServerId};
use crate::domain::user::UserId;
use crate::domain::workspace::WorkspaceId;
use crate::error::StoreError;
use crate::storage::McpServerWorkspaceStore;

/// Column list shared with `sqlite::mcp`. Order must match `row_to_mcp_server`.
const MCP_COLS: &str = "m.id, m.workspace_id, m.name, m.upstream_url, m.transport, m.credential_bindings, m.allowed_tools, m.enabled, m.created_by, m.created_at, m.updated_at, m.tags, m.required_credentials, m.auth_method, m.template_key, m.discovered_tools, m.created_by_user";

#[async_trait]
impl McpServerWorkspaceStore for SqliteStore {
    async fn add_mcp_server_workspace(
        &self,
        mcp_server_id: &McpServerId,
        workspace_id: &WorkspaceId,
        created_by_user: Option<&UserId>,
    ) -> Result<bool, StoreError> {
        let mcp_id_str = mcp_server_id.0.to_string();
        let ws_id_str = workspace_id.0.to_string();
        let created_by_user_str = created_by_user.map(|u| u.0.to_string());
        let now = chrono::Utc::now().to_rfc3339();
        self.conn()
            .call(move |conn| {
                let count = conn
                    .execute(
                        "INSERT INTO mcp_server_workspaces \
                           (mcp_server_id, workspace_id, created_at, created_by_user) \
                         VALUES (?1, ?2, ?3, ?4) \
                         ON CONFLICT (mcp_server_id, workspace_id) DO NOTHING",
                        rusqlite::params![mcp_id_str, ws_id_str, now, created_by_user_str],
                    )
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;
                Ok(count > 0)
            })
            .await
            .map_err(|e| StoreError::Database(e.to_string()))
    }

    async fn remove_mcp_server_workspace(
        &self,
        mcp_server_id: &McpServerId,
        workspace_id: &WorkspaceId,
    ) -> Result<bool, StoreError> {
        let mcp_id_str = mcp_server_id.0.to_string();
        let ws_id_str = workspace_id.0.to_string();
        self.conn()
            .call(move |conn| {
                let count = conn
                    .execute(
                        "DELETE FROM mcp_server_workspaces \
                         WHERE mcp_server_id = ?1 AND workspace_id = ?2",
                        rusqlite::params![mcp_id_str, ws_id_str],
                    )
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;
                Ok(count > 0)
            })
            .await
            .map_err(|e| StoreError::Database(e.to_string()))
    }

    async fn list_workspaces_for_mcp_server(
        &self,
        mcp_server_id: &McpServerId,
    ) -> Result<Vec<(WorkspaceId, String)>, StoreError> {
        let mcp_id_str = mcp_server_id.0.to_string();
        self.conn()
            .call(move |conn| {
                let mut stmt = conn
                    .prepare(
                        "SELECT w.id, w.name \
                         FROM mcp_server_workspaces j \
                         JOIN workspaces w ON w.id = j.workspace_id \
                         WHERE j.mcp_server_id = ?1 \
                         ORDER BY w.name ASC",
                    )
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;
                let rows = stmt
                    .query_map(rusqlite::params![mcp_id_str], |row| {
                        let id_str: String = row.get(0)?;
                        let name: String = row.get(1)?;
                        Ok((id_str, name))
                    })
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;
                let mut out = Vec::new();
                for row in rows {
                    let (id_str, name) = row.map_err(tokio_rusqlite::Error::Rusqlite)?;
                    let uuid = uuid::Uuid::parse_str(&id_str).map_err(|e| {
                        tokio_rusqlite::Error::Rusqlite(rusqlite::Error::FromSqlConversionFailure(
                            0,
                            rusqlite::types::Type::Text,
                            Box::new(e),
                        ))
                    })?;
                    out.push((WorkspaceId(uuid), name));
                }
                Ok(out)
            })
            .await
            .map_err(|e| StoreError::Database(e.to_string()))
    }

    async fn list_mcp_servers_for_workspace(
        &self,
        workspace_id: &WorkspaceId,
    ) -> Result<Vec<McpServer>, StoreError> {
        let ws_id_str = workspace_id.0.to_string();
        let sql = format!(
            "SELECT {} FROM mcp_servers m \
             JOIN mcp_server_workspaces j ON j.mcp_server_id = m.id \
             WHERE j.workspace_id = ?1 AND m.enabled = 1 \
             ORDER BY m.name ASC",
            MCP_COLS
        );
        self.conn()
            .call(move |conn| {
                let mut stmt = conn
                    .prepare(&sql)
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;
                let rows = stmt
                    .query_map(rusqlite::params![ws_id_str], row_to_mcp_server)
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

    async fn count_workspaces_for_mcp_server(
        &self,
        mcp_server_id: &McpServerId,
    ) -> Result<usize, StoreError> {
        let mcp_id_str = mcp_server_id.0.to_string();
        self.conn()
            .call(move |conn| {
                let count: i64 = conn
                    .query_row(
                        "SELECT COUNT(*) FROM mcp_server_workspaces WHERE mcp_server_id = ?1",
                        rusqlite::params![mcp_id_str],
                        |row| row.get(0),
                    )
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;
                Ok(count.max(0) as usize)
            })
            .await
            .map_err(|e| StoreError::Database(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::mcp::{McpAuthMethod, McpServer, McpTransport};
    use crate::domain::workspace::{Workspace, WorkspaceStatus};
    use crate::storage::traits::WorkspaceStore;
    use crate::storage::Store;
    use chrono::Utc;
    use uuid::Uuid;

    async fn setup() -> SqliteStore {
        let store = SqliteStore::new_in_memory().await.expect("open");
        store.run_migrations().await.expect("migrate");
        store
    }

    fn make_workspace(name: &str) -> Workspace {
        let now = Utc::now();
        Workspace {
            id: WorkspaceId(Uuid::new_v4()),
            name: name.to_string(),
            tags: vec![],
            enabled: true,
            status: WorkspaceStatus::Active,
            pk_hash: None,
            encryption_public_key: None,
            owner_id: None,
            parent_id: None,
            tool_name: None,
            created_at: now,
            updated_at: now,
        }
    }

    fn make_mcp(workspace_id: WorkspaceId, name: &str, enabled: bool) -> McpServer {
        let now = Utc::now();
        McpServer {
            id: McpServerId(Uuid::new_v4()),
            workspace_id: Some(workspace_id),
            name: name.to_string(),
            upstream_url: "https://example.test".to_string(),
            transport: McpTransport::Http,
            allowed_tools: None,
            enabled,
            created_by: None,
            created_at: now,
            updated_at: now,
            tags: vec![],
            required_credentials: None,
            auth_method: McpAuthMethod::None,
            template_key: None,
            discovered_tools: None,
            created_by_user: None,
        }
    }

    #[tokio::test]
    async fn migration_backfills_junction_from_existing_mcp_servers() {
        // Reproduce the pre-010 state: a legacy row with mcp_servers.workspace_id
        // set but no junction row, then re-run the backfill SQL and assert
        // exactly one row lands. Post-#37 the regular `create_mcp_server`
        // path no longer writes the column, so we INSERT directly to mirror
        // the historical pre-010 shape.
        let store = setup().await;
        let ws = make_workspace("ws-a");
        store.create_workspace(&ws).await.expect("ws");
        let mcp_id = McpServerId(Uuid::new_v4());
        let ws_id_str = ws.id.0.to_string();
        let mcp_id_str = mcp_id.0.to_string();
        store
            .conn()
            .call(move |conn| {
                conn.execute(
                    "INSERT INTO mcp_servers \
                     (id, workspace_id, name, upstream_url, transport, credential_bindings, \
                      allowed_tools, enabled, created_at, updated_at) \
                     VALUES (?1, ?2, 'mcp-a', 'https://example.test', 'http', '[]', NULL, 1, \
                             '2026-01-01', '2026-01-01')",
                    rusqlite::params![mcp_id_str, ws_id_str],
                )
                .map_err(tokio_rusqlite::Error::Rusqlite)
            })
            .await
            .expect("seed legacy mcp row");

        // Start from a clean junction — simulates pre-010 baseline.
        store
            .conn()
            .call(|conn| {
                conn.execute("DELETE FROM mcp_server_workspaces", [])
                    .map_err(tokio_rusqlite::Error::Rusqlite)
            })
            .await
            .expect("clear junction");

        store
            .conn()
            .call(|conn| {
                conn.execute_batch(
                    "INSERT INTO mcp_server_workspaces \
                       (mcp_server_id, workspace_id, created_at, created_by_user) \
                     SELECT id, workspace_id, created_at, created_by_user \
                     FROM mcp_servers \
                     WHERE workspace_id IS NOT NULL \
                     ON CONFLICT (mcp_server_id, workspace_id) DO NOTHING;",
                )
                .map_err(tokio_rusqlite::Error::Rusqlite)
            })
            .await
            .expect("run backfill");

        let bound = store
            .list_workspaces_for_mcp_server(&mcp_id)
            .await
            .expect("list");
        assert_eq!(bound.len(), 1, "backfill inserts one row per MCP");
        assert_eq!(bound[0].0, ws.id);
        assert_eq!(bound[0].1, ws.name);
    }

    #[tokio::test]
    async fn add_is_idempotent_via_on_conflict() {
        let store = setup().await;
        let ws = make_workspace("ws-a");
        store.create_workspace(&ws).await.expect("ws");
        let ws2 = make_workspace("ws-b");
        store.create_workspace(&ws2).await.expect("ws2");
        let mcp = make_mcp(ws.id.clone(), "mcp-a", true);
        store.create_mcp_server(&mcp).await.expect("mcp");

        // Explicitly add the original binding (provision path is BE-2's territory).
        store
            .add_mcp_server_workspace(&mcp.id, &ws.id, None)
            .await
            .expect("seed original binding");

        let inserted = store
            .add_mcp_server_workspace(&mcp.id, &ws2.id, None)
            .await
            .expect("add");
        assert!(inserted);

        let re_added = store
            .add_mcp_server_workspace(&mcp.id, &ws2.id, None)
            .await
            .expect("re-add");
        assert!(!re_added, "second add returns false — row already existed");

        assert_eq!(
            store
                .count_workspaces_for_mcp_server(&mcp.id)
                .await
                .unwrap(),
            2
        );
    }

    #[tokio::test]
    async fn remove_returns_false_when_no_row() {
        let store = setup().await;
        let ws = make_workspace("ws-a");
        store.create_workspace(&ws).await.expect("ws");
        let mcp = make_mcp(ws.id.clone(), "mcp-a", true);
        store.create_mcp_server(&mcp).await.expect("mcp");

        let other_ws = WorkspaceId(Uuid::new_v4());
        let removed = store
            .remove_mcp_server_workspace(&mcp.id, &other_ws)
            .await
            .expect("remove");
        assert!(!removed);
    }

    #[tokio::test]
    async fn list_mcp_servers_for_workspace_filters_disabled_and_uses_junction() {
        let store = setup().await;
        let ws_a = make_workspace("ws-a");
        let ws_b = make_workspace("ws-b");
        store.create_workspace(&ws_a).await.unwrap();
        store.create_workspace(&ws_b).await.unwrap();

        let enabled_mcp = make_mcp(ws_a.id.clone(), "enabled", true);
        let disabled_mcp = make_mcp(ws_a.id.clone(), "disabled", false);
        store.create_mcp_server(&enabled_mcp).await.unwrap();
        store.create_mcp_server(&disabled_mcp).await.unwrap();

        // Share both into ws_b via the junction.
        store
            .add_mcp_server_workspace(&enabled_mcp.id, &ws_b.id, None)
            .await
            .unwrap();
        store
            .add_mcp_server_workspace(&disabled_mcp.id, &ws_b.id, None)
            .await
            .unwrap();

        let for_b = store
            .list_mcp_servers_for_workspace(&ws_b.id)
            .await
            .expect("list");
        assert_eq!(for_b.len(), 1, "disabled MCP is filtered out");
        assert_eq!(for_b[0].id, enabled_mcp.id);
    }

    #[tokio::test]
    async fn deleting_mcp_server_cascades_junction() {
        let store = setup().await;
        let ws = make_workspace("ws-a");
        let ws2 = make_workspace("ws-b");
        store.create_workspace(&ws).await.unwrap();
        store.create_workspace(&ws2).await.unwrap();
        let mcp = make_mcp(ws.id.clone(), "mcp-a", true);
        store.create_mcp_server(&mcp).await.unwrap();
        store
            .add_mcp_server_workspace(&mcp.id, &ws.id, None)
            .await
            .unwrap();
        store
            .add_mcp_server_workspace(&mcp.id, &ws2.id, None)
            .await
            .unwrap();

        assert_eq!(
            store
                .count_workspaces_for_mcp_server(&mcp.id)
                .await
                .unwrap(),
            2
        );

        store.delete_mcp_server(&mcp.id).await.unwrap();

        assert_eq!(
            store
                .count_workspaces_for_mcp_server(&mcp.id)
                .await
                .unwrap(),
            0,
            "FK ON DELETE CASCADE drops junction rows"
        );
    }

    #[tokio::test]
    async fn deleting_workspace_cascades_junction() {
        let store = setup().await;
        let ws = make_workspace("ws-a");
        let ws2 = make_workspace("ws-b");
        store.create_workspace(&ws).await.unwrap();
        store.create_workspace(&ws2).await.unwrap();
        let mcp = make_mcp(ws.id.clone(), "mcp-a", true);
        store.create_mcp_server(&mcp).await.unwrap();
        store
            .add_mcp_server_workspace(&mcp.id, &ws.id, None)
            .await
            .unwrap();
        store
            .add_mcp_server_workspace(&mcp.id, &ws2.id, None)
            .await
            .unwrap();

        store.delete_workspace(&ws2.id).await.unwrap();

        let bound = store.list_workspaces_for_mcp_server(&mcp.id).await.unwrap();
        assert_eq!(bound.len(), 1, "only original workspace's row remains");
        assert_eq!(bound[0].0, ws.id);
    }
}
