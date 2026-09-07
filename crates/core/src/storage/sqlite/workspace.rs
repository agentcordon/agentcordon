use async_trait::async_trait;

use super::helpers::*;
use super::SqliteStore;

use crate::domain::time::format_timestamp;
use crate::domain::user::UserId;
use crate::domain::workspace::{Workspace, WorkspaceId};
use crate::error::StoreError;
use crate::storage::shared::WORKSPACE_COLUMNS;
use crate::storage::WorkspaceStore;

impl SqliteStore {
    // ---- CRUD ----

    pub(crate) async fn create_workspace_impl(
        &self,
        workspace: &Workspace,
    ) -> Result<(), StoreError> {
        let workspace = workspace.clone();
        let tags_json = serialize_tags(&workspace.tags)?;
        let id_str = workspace.id.0.hyphenated().to_string();
        let owner_id_str = workspace
            .owner_id
            .as_ref()
            .map(|u| u.0.hyphenated().to_string());
        let parent_id_str = workspace
            .parent_id
            .as_ref()
            .map(|p| p.0.hyphenated().to_string());
        let created_at = format_timestamp(&workspace.created_at);
        let updated_at = format_timestamp(&workspace.updated_at);

        self.conn()
            .call(move |conn| {
                conn.execute(
                    "INSERT INTO workspaces (id, name, enabled, status, pk_hash, encryption_public_key, tags, owner_id, parent_id, tool_name, created_at, updated_at) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
                    rusqlite::params![
                        id_str,
                        workspace.name,
                        workspace.is_active(),
                        workspace.status.as_str(),
                        workspace.pk_hash,
                        workspace.encryption_public_key,
                        tags_json,
                        owner_id_str,
                        parent_id_str,
                        workspace.tool_name,
                        created_at,
                        updated_at,
                    ],
                )
                .map_err(tokio_rusqlite::Error::Rusqlite)?;
                Ok(())
            })
            .await
            .map_err(map_store_error)
    }

    pub(crate) async fn get_workspace_impl(
        &self,
        id: &WorkspaceId,
    ) -> Result<Option<Workspace>, StoreError> {
        let id_str = id.0.hyphenated().to_string();
        self.conn()
            .call(move |conn| {
                let mut stmt = conn
                    .prepare(&format!(
                        "SELECT {} FROM workspaces WHERE id = ?1",
                        WORKSPACE_COLUMNS
                    ))
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;
                let mut rows = stmt
                    .query_map(rusqlite::params![id_str], row_to_workspace)
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;
                match rows.next() {
                    Some(Ok(ws)) => Ok(Some(ws)),
                    Some(Err(e)) => Err(tokio_rusqlite::Error::Rusqlite(e)),
                    None => Ok(None),
                }
            })
            .await
            .map_err(map_store_error)
    }

    pub(crate) async fn get_workspace_by_name_impl(
        &self,
        name: &str,
    ) -> Result<Option<Workspace>, StoreError> {
        let name = name.to_string();
        self.conn()
            .call(move |conn| {
                let mut stmt = conn
                    .prepare(&format!(
                        "SELECT {} FROM workspaces WHERE name = ?1",
                        WORKSPACE_COLUMNS
                    ))
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;
                let mut rows = stmt
                    .query_map(rusqlite::params![name], row_to_workspace)
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;
                match rows.next() {
                    Some(Ok(ws)) => Ok(Some(ws)),
                    Some(Err(e)) => Err(tokio_rusqlite::Error::Rusqlite(e)),
                    None => Ok(None),
                }
            })
            .await
            .map_err(map_store_error)
    }

    pub(crate) async fn get_workspace_by_pk_hash_impl(
        &self,
        pk_hash: &str,
    ) -> Result<Option<Workspace>, StoreError> {
        let pk_hash = pk_hash.to_string();
        self.conn()
            .call(move |conn| {
                let mut stmt = conn
                    .prepare(&format!(
                        "SELECT {} FROM workspaces WHERE pk_hash = ?1",
                        WORKSPACE_COLUMNS
                    ))
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;
                let mut rows = stmt
                    .query_map(rusqlite::params![pk_hash], row_to_workspace)
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;
                match rows.next() {
                    Some(Ok(ws)) => Ok(Some(ws)),
                    Some(Err(e)) => Err(tokio_rusqlite::Error::Rusqlite(e)),
                    None => Ok(None),
                }
            })
            .await
            .map_err(map_store_error)
    }

    pub(crate) async fn list_workspaces_impl(&self) -> Result<Vec<Workspace>, StoreError> {
        self.conn()
            .call(move |conn| {
                let mut stmt = conn
                    .prepare(&format!(
                        "SELECT {} FROM workspaces ORDER BY name",
                        WORKSPACE_COLUMNS
                    ))
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;
                let rows = stmt
                    .query_map([], row_to_workspace)
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;
                let mut workspaces = Vec::new();
                for row in rows {
                    workspaces.push(row.map_err(tokio_rusqlite::Error::Rusqlite)?);
                }
                Ok(workspaces)
            })
            .await
            .map_err(map_store_error)
    }

    pub(crate) async fn get_workspaces_by_owner_impl(
        &self,
        owner_id: &UserId,
    ) -> Result<Vec<Workspace>, StoreError> {
        let owner_id_str = owner_id.0.hyphenated().to_string();
        self.conn()
            .call(move |conn| {
                let mut stmt = conn
                    .prepare(&format!(
                        "SELECT {} FROM workspaces WHERE owner_id = ?1 ORDER BY name",
                        WORKSPACE_COLUMNS
                    ))
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;
                let rows = stmt
                    .query_map(rusqlite::params![owner_id_str], row_to_workspace)
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;
                let mut workspaces = Vec::new();
                for row in rows {
                    workspaces.push(row.map_err(tokio_rusqlite::Error::Rusqlite)?);
                }
                Ok(workspaces)
            })
            .await
            .map_err(map_store_error)
    }

    pub(crate) async fn update_workspace_impl(
        &self,
        workspace: &Workspace,
    ) -> Result<(), StoreError> {
        let workspace = workspace.clone();
        let tags_json = serialize_tags(&workspace.tags)?;
        let id_str = workspace.id.0.hyphenated().to_string();
        let owner_id_str = workspace
            .owner_id
            .as_ref()
            .map(|u| u.0.hyphenated().to_string());
        let parent_id_str = workspace
            .parent_id
            .as_ref()
            .map(|p| p.0.hyphenated().to_string());
        let updated_at = format_timestamp(&workspace.updated_at);

        self.conn()
            .call(move |conn| {
                let changed = conn
                    .execute(
                        "UPDATE workspaces SET name = ?1, enabled = ?2, status = ?3, pk_hash = ?4, \
                         encryption_public_key = ?5, tags = ?6, owner_id = ?7, parent_id = ?8, \
                         tool_name = ?9, updated_at = ?10 \
                         WHERE id = ?11",
                        rusqlite::params![
                            workspace.name,
                            workspace.is_active(),
                            workspace.status.as_str(),
                            workspace.pk_hash,
                            workspace.encryption_public_key,
                            tags_json,
                            owner_id_str,
                            parent_id_str,
                            workspace.tool_name,
                            updated_at,
                            id_str,
                        ],
                    )
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;
                if changed == 0 {
                    return Err(store_err_to_tokio(StoreError::NotFound(format!(
                        "workspace {} not found",
                        id_str
                    ))));
                }
                Ok(())
            })
            .await
            .map_err(map_store_error)
    }

    pub(crate) async fn delete_workspace_impl(&self, id: &WorkspaceId) -> Result<bool, StoreError> {
        let id_str = id.0.hyphenated().to_string();
        self.conn()
            .call(move |conn| {
                // Check for credentials referencing this workspace
                let cred_count: i64 = conn
                    .query_row(
                        "SELECT COUNT(*) FROM credentials WHERE created_by = ?1",
                        rusqlite::params![id_str],
                        |row| row.get(0),
                    )
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;
                if cred_count > 0 {
                    return Err(store_err_to_tokio(StoreError::Conflict {
                        message: "workspace has credentials referencing it; disable instead or delete credentials first".to_string(),
                        existing_id: None,
                    }));
                }
                let changed = conn
                    .execute("DELETE FROM workspaces WHERE id = ?1", rusqlite::params![id_str])
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;
                Ok(changed > 0)
            })
            .await
            .map_err(map_store_error)
    }

    // ---- Authentication tracking ----

    pub(crate) async fn touch_workspace_authenticated_impl(
        &self,
        id: &WorkspaceId,
        now: &chrono::DateTime<chrono::Utc>,
    ) -> Result<(), StoreError> {
        let id_str = id.0.to_string();
        let now_str = format_timestamp(now);
        self.conn()
            .call(move |conn| {
                conn.execute(
                    "UPDATE workspaces SET last_authenticated_at = ?1, updated_at = ?2 WHERE id = ?3",
                    rusqlite::params![now_str, now_str, id_str],
                )
                .map_err(tokio_rusqlite::Error::Rusqlite)?;
                Ok(())
            })
            .await
            .map_err(map_store_error)
    }
}

#[async_trait]
impl WorkspaceStore for SqliteStore {
    async fn create_workspace(&self, workspace: &Workspace) -> Result<(), StoreError> {
        self.create_workspace_impl(workspace).await
    }
    async fn get_workspace(&self, id: &WorkspaceId) -> Result<Option<Workspace>, StoreError> {
        self.get_workspace_impl(id).await
    }
    async fn get_workspace_by_name(&self, name: &str) -> Result<Option<Workspace>, StoreError> {
        self.get_workspace_by_name_impl(name).await
    }
    async fn get_workspace_by_pk_hash(
        &self,
        pk_hash: &str,
    ) -> Result<Option<Workspace>, StoreError> {
        self.get_workspace_by_pk_hash_impl(pk_hash).await
    }
    async fn list_workspaces(&self) -> Result<Vec<Workspace>, StoreError> {
        self.list_workspaces_impl().await
    }
    async fn get_workspaces_by_owner(
        &self,
        owner_id: &UserId,
    ) -> Result<Vec<Workspace>, StoreError> {
        self.get_workspaces_by_owner_impl(owner_id).await
    }
    async fn update_workspace(&self, workspace: &Workspace) -> Result<(), StoreError> {
        self.update_workspace_impl(workspace).await
    }
    async fn delete_workspace(&self, id: &WorkspaceId) -> Result<bool, StoreError> {
        self.delete_workspace_impl(id).await
    }
    async fn revoke_workspace(&self, id: &WorkspaceId) -> Result<bool, StoreError> {
        let id_str = id.0.hyphenated().to_string();
        let now = format_timestamp(&chrono::Utc::now());
        self.conn()
            .call(move |conn| {
                let tx = conn
                    .transaction()
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;
                let changed = tx
                    .execute(
                        "UPDATE workspaces SET status = 'revoked', enabled = 0, updated_at = ?1 \
                         WHERE id = ?2",
                        rusqlite::params![now, id_str],
                    )
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;
                if changed == 0 {
                    return Ok(false);
                }
                // Clients bound by id, plus any older client still bound only
                // through the key hash.
                tx.execute(
                    "UPDATE oauth_clients SET revoked_at = COALESCE(revoked_at, ?1) \
                     WHERE workspace_id = ?2 \
                        OR public_key_hash IN (SELECT pk_hash FROM workspaces WHERE id = ?2 AND pk_hash IS NOT NULL)",
                    rusqlite::params![now, id_str],
                )
                .map_err(tokio_rusqlite::Error::Rusqlite)?;
                tx.execute(
                    "UPDATE oauth_access_tokens SET revoked_at = COALESCE(revoked_at, ?1) \
                     WHERE workspace_id = ?2 \
                        OR client_id IN (SELECT client_id FROM oauth_clients WHERE workspace_id = ?2)",
                    rusqlite::params![now, id_str],
                )
                .map_err(tokio_rusqlite::Error::Rusqlite)?;
                tx.execute(
                    "UPDATE oauth_refresh_tokens SET revoked_at = COALESCE(revoked_at, ?1) \
                     WHERE workspace_id = ?2 \
                        OR client_id IN (SELECT client_id FROM oauth_clients WHERE workspace_id = ?2)",
                    rusqlite::params![now, id_str],
                )
                .map_err(tokio_rusqlite::Error::Rusqlite)?;
                tx.commit().map_err(tokio_rusqlite::Error::Rusqlite)?;
                Ok(true)
            })
            .await
            .map_err(map_store_error)
    }
    async fn touch_workspace_authenticated(
        &self,
        id: &WorkspaceId,
        now: &chrono::DateTime<chrono::Utc>,
    ) -> Result<(), StoreError> {
        self.touch_workspace_authenticated_impl(id, now).await
    }
}
