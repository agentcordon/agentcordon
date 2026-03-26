use async_trait::async_trait;

use super::helpers::*;
use super::SqliteStore;

use crate::domain::user::UserId;
use crate::domain::workspace::{ProvisioningToken, Workspace, WorkspaceId, WorkspaceRegistration};
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
        let created_at = workspace.created_at.to_rfc3339();
        let updated_at = workspace.updated_at.to_rfc3339();

        self.conn()
            .call(move |conn| {
                conn.execute(
                    "INSERT INTO workspaces (id, name, enabled, status, pk_hash, encryption_public_key, tags, owner_id, parent_id, tool_name, created_at, updated_at) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
                    rusqlite::params![
                        id_str,
                        workspace.name,
                        workspace.enabled,
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
                .map_err(|e| {
                    if let rusqlite::Error::SqliteFailure(ref err, ref msg) = e {
                        if err.code == rusqlite::ErrorCode::ConstraintViolation {
                            let detail = msg.as_deref().unwrap_or("");
                            let conflict_msg = if detail.contains("PRIMARY KEY") || detail.contains("workspaces.id") {
                                format!("workspace with ID '{}' already exists", id_str)
                            } else if detail.contains("FOREIGN KEY") || detail.contains("foreign key") {
                                "referenced entity does not exist".to_string()
                            } else {
                                format!("workspace with name '{}' already exists", workspace.name)
                            };
                            return store_err_to_tokio(StoreError::Conflict { message: conflict_msg, existing_id: None });
                        }
                    }
                    tokio_rusqlite::Error::Rusqlite(e)
                })?;
                Ok(())
            })
            .await
            .map_err(|e| {
                if let tokio_rusqlite::Error::Other(ref boxed) = e {
                    if let Some(store_err) = boxed.downcast_ref::<StoreError>() {
                        return match store_err {
                            StoreError::Conflict { message, existing_id } => StoreError::Conflict { message: message.clone(), existing_id: *existing_id },
                            StoreError::NotFound(msg) => StoreError::NotFound(msg.clone()),
                            StoreError::Database(msg) => StoreError::Database(msg.clone()),
                        };
                    }
                }
                StoreError::Database(e.to_string())
            })
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
            .map_err(|e| StoreError::Database(e.to_string()))
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
            .map_err(|e| StoreError::Database(e.to_string()))
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
            .map_err(|e| StoreError::Database(e.to_string()))
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
            .map_err(|e| StoreError::Database(e.to_string()))
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
            .map_err(|e| StoreError::Database(e.to_string()))
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
        let updated_at = workspace.updated_at.to_rfc3339();

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
                            workspace.enabled,
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
            .map_err(|e| StoreError::Database(e.to_string()))
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
            .map_err(|e| {
                if let tokio_rusqlite::Error::Other(boxed) = &e {
                    if let Some(store_err) = boxed.downcast_ref::<StoreError>() {
                        return match store_err {
                            StoreError::Conflict { message, existing_id } => StoreError::Conflict { message: message.clone(), existing_id: *existing_id },
                            StoreError::NotFound(msg) => StoreError::NotFound(msg.clone()),
                            StoreError::Database(msg) => StoreError::Database(msg.clone()),
                        };
                    }
                }
                StoreError::Database(e.to_string())
            })
    }

    // ---- Enrollment ----

    pub(crate) async fn enroll_workspace_impl(
        &self,
        id: &WorkspaceId,
        encryption_public_key: &str,
    ) -> Result<bool, StoreError> {
        let id_str = id.0.to_string();
        let epk = encryption_public_key.to_string();
        let now = chrono::Utc::now().to_rfc3339();
        self.conn()
            .call(move |conn| {
                let count = conn
                    .execute(
                        "UPDATE workspaces SET status = 'active', encryption_public_key = ?1, enrollment_token_hash = NULL, updated_at = ?2 \
                         WHERE id = ?3 AND status = 'pending' AND enrollment_token_hash IS NOT NULL",
                        rusqlite::params![epk, now, id_str],
                    )
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;
                Ok(count > 0)
            })
            .await
            .map_err(|e| StoreError::Database(e.to_string()))
    }

    // ---- JTI tracking ----

    pub(crate) async fn check_workspace_jti_impl(&self, jti: &str) -> Result<bool, StoreError> {
        let jti = jti.to_string();
        self.conn()
            .call(move |conn| {
                let count: i64 = conn
                    .query_row(
                        "SELECT COUNT(*) FROM workspace_used_jtis WHERE jti = ?1",
                        rusqlite::params![jti],
                        |row| row.get(0),
                    )
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;
                Ok(count > 0)
            })
            .await
            .map_err(|e| StoreError::Database(e.to_string()))
    }

    pub(crate) async fn store_workspace_jti_impl(
        &self,
        jti: &str,
        workspace_id: &WorkspaceId,
        expires_at: &chrono::DateTime<chrono::Utc>,
    ) -> Result<bool, StoreError> {
        let jti = jti.to_string();
        let workspace_id_str = workspace_id.0.to_string();
        let expires_at_str = expires_at.to_rfc3339();
        self.conn()
            .call(move |conn| {
                // The table was renamed from device_used_jtis but columns are unchanged (jti, device_id, expires_at)
                let count = conn.execute(
                    "INSERT OR IGNORE INTO workspace_used_jtis (jti, device_id, expires_at) VALUES (?1, ?2, ?3)",
                    rusqlite::params![jti, workspace_id_str, expires_at_str],
                )
                .map_err(tokio_rusqlite::Error::Rusqlite)?;
                Ok(count > 0)
            })
            .await
            .map_err(|e| StoreError::Database(e.to_string()))
    }

    pub(crate) async fn cleanup_expired_workspace_jtis_impl(&self) -> Result<u32, StoreError> {
        self.conn()
            .call(move |conn| {
                let now = chrono::Utc::now().to_rfc3339();
                let count = conn
                    .execute(
                        "DELETE FROM workspace_used_jtis WHERE expires_at < ?1",
                        rusqlite::params![now],
                    )
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;
                Ok(count as u32)
            })
            .await
            .map_err(|e| StoreError::Database(e.to_string()))
    }

    // ---- Authentication tracking ----

    pub(crate) async fn touch_workspace_authenticated_impl(
        &self,
        id: &WorkspaceId,
        now: &chrono::DateTime<chrono::Utc>,
    ) -> Result<(), StoreError> {
        let id_str = id.0.to_string();
        let now_str = now.to_rfc3339();
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
            .map_err(|e| StoreError::Database(e.to_string()))
    }

    // ---- Registration flow ----

    pub(crate) async fn create_workspace_registration_impl(
        &self,
        reg: &WorkspaceRegistration,
    ) -> Result<(), StoreError> {
        let reg = reg.clone();
        self.conn()
            .call(move |conn| {
                conn.execute(
                    "INSERT OR REPLACE INTO workspace_registrations (pk_hash, code_challenge, code_hash, approval_code, expires_at, attempts, max_attempts, created_at, approved_by)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                    rusqlite::params![
                        reg.pk_hash,
                        reg.code_challenge,
                        reg.code_hash,
                        reg.approval_code,
                        reg.expires_at.to_rfc3339(),
                        reg.attempts as i32,
                        reg.max_attempts as i32,
                        reg.created_at.to_rfc3339(),
                        reg.approved_by,
                    ],
                )
                .map_err(tokio_rusqlite::Error::Rusqlite)?;
                Ok(())
            })
            .await
            .map_err(|e| StoreError::Database(e.to_string()))
    }

    pub(crate) async fn get_workspace_registration_impl(
        &self,
        pk_hash: &str,
    ) -> Result<Option<WorkspaceRegistration>, StoreError> {
        let pk_hash = pk_hash.to_string();
        self.conn()
            .call(move |conn| {
                let mut stmt = conn
                    .prepare("SELECT pk_hash, code_challenge, code_hash, approval_code, expires_at, attempts, max_attempts, created_at, approved_by FROM workspace_registrations WHERE pk_hash = ?1")
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;
                let mut rows = stmt
                    .query_map(rusqlite::params![pk_hash], row_to_workspace_registration)
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;
                match rows.next() {
                    Some(Ok(reg)) => Ok(Some(reg)),
                    Some(Err(e)) => Err(tokio_rusqlite::Error::Rusqlite(e)),
                    None => Ok(None),
                }
            })
            .await
            .map_err(|e| StoreError::Database(e.to_string()))
    }

    pub(crate) async fn increment_registration_attempts_impl(
        &self,
        pk_hash: &str,
    ) -> Result<(), StoreError> {
        let pk_hash = pk_hash.to_string();
        self.conn()
            .call(move |conn| {
                conn.execute(
                    "UPDATE workspace_registrations SET attempts = attempts + 1 WHERE pk_hash = ?1",
                    rusqlite::params![pk_hash],
                )
                .map_err(tokio_rusqlite::Error::Rusqlite)?;
                Ok(())
            })
            .await
            .map_err(|e| StoreError::Database(e.to_string()))
    }

    pub(crate) async fn delete_workspace_registration_impl(
        &self,
        pk_hash: &str,
    ) -> Result<bool, StoreError> {
        let pk_hash = pk_hash.to_string();
        self.conn()
            .call(move |conn| {
                let count = conn
                    .execute(
                        "DELETE FROM workspace_registrations WHERE pk_hash = ?1",
                        rusqlite::params![pk_hash],
                    )
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;
                Ok(count > 0)
            })
            .await
            .map_err(|e| StoreError::Database(e.to_string()))
    }

    pub(crate) async fn null_registration_approval_code_impl(
        &self,
        pk_hash: &str,
    ) -> Result<(), StoreError> {
        let pk_hash = pk_hash.to_string();
        self.conn()
            .call(move |conn| {
                conn.execute(
                    "UPDATE workspace_registrations SET approval_code = NULL WHERE pk_hash = ?1",
                    rusqlite::params![pk_hash],
                )
                .map_err(tokio_rusqlite::Error::Rusqlite)?;
                Ok(())
            })
            .await
            .map_err(|e| StoreError::Database(e.to_string()))
    }

    // ---- Provisioning tokens ----

    pub(crate) async fn create_provisioning_token_impl(
        &self,
        token: &ProvisioningToken,
    ) -> Result<(), StoreError> {
        let token = token.clone();
        self.conn()
            .call(move |conn| {
                conn.execute(
                    "INSERT INTO provisioning_tokens (token_hash, name, expires_at, used, created_at) \
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                    rusqlite::params![
                        token.token_hash,
                        token.name,
                        token.expires_at.to_rfc3339(),
                        token.used as i32,
                        token.created_at.to_rfc3339(),
                    ],
                )
                .map_err(|e| {
                    if let rusqlite::Error::SqliteFailure(ref err, _) = e {
                        if err.code == rusqlite::ErrorCode::ConstraintViolation {
                            return store_err_to_tokio(StoreError::Conflict {
                                message: "provisioning token already exists".to_string(),
                                existing_id: None,
                            });
                        }
                    }
                    tokio_rusqlite::Error::Rusqlite(e)
                })?;
                Ok(())
            })
            .await
            .map_err(|e| {
                if let tokio_rusqlite::Error::Other(ref boxed) = e {
                    if let Some(store_err) = boxed.downcast_ref::<StoreError>() {
                        return match store_err {
                            StoreError::Conflict { message, existing_id } => StoreError::Conflict { message: message.clone(), existing_id: *existing_id },
                            StoreError::NotFound(msg) => StoreError::NotFound(msg.clone()),
                            StoreError::Database(msg) => StoreError::Database(msg.clone()),
                        };
                    }
                }
                StoreError::Database(e.to_string())
            })
    }

    pub(crate) async fn get_provisioning_token_impl(
        &self,
        token_hash: &str,
    ) -> Result<Option<ProvisioningToken>, StoreError> {
        let token_hash = token_hash.to_string();
        self.conn()
            .call(move |conn| {
                let mut stmt = conn
                    .prepare("SELECT token_hash, name, expires_at, used, created_at FROM provisioning_tokens WHERE token_hash = ?1")
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;
                let mut rows = stmt
                    .query_map(rusqlite::params![token_hash], |row| {
                        let token_hash: String = row.get(0)?;
                        let name: String = row.get(1)?;
                        let expires_at_str: String = row.get(2)?;
                        let used: i32 = row.get(3)?;
                        let created_at_str: String = row.get(4)?;

                        let expires_at = chrono::DateTime::parse_from_rfc3339(&expires_at_str)
                            .map(|dt| dt.with_timezone(&chrono::Utc))
                            .map_err(|e| rusqlite::Error::FromSqlConversionFailure(2, rusqlite::types::Type::Text, Box::new(e)))?;
                        let created_at = chrono::DateTime::parse_from_rfc3339(&created_at_str)
                            .map(|dt| dt.with_timezone(&chrono::Utc))
                            .map_err(|e| rusqlite::Error::FromSqlConversionFailure(4, rusqlite::types::Type::Text, Box::new(e)))?;

                        Ok(ProvisioningToken {
                            token_hash,
                            name,
                            expires_at,
                            used: used != 0,
                            created_at,
                        })
                    })
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;
                match rows.next() {
                    Some(Ok(token)) => Ok(Some(token)),
                    Some(Err(e)) => Err(tokio_rusqlite::Error::Rusqlite(e)),
                    None => Ok(None),
                }
            })
            .await
            .map_err(|e| StoreError::Database(e.to_string()))
    }

    pub(crate) async fn mark_provisioning_token_used_impl(
        &self,
        token_hash: &str,
    ) -> Result<bool, StoreError> {
        let token_hash = token_hash.to_string();
        self.conn()
            .call(move |conn| {
                let count = conn
                    .execute(
                        "UPDATE provisioning_tokens SET used = 1 WHERE token_hash = ?1 AND used = 0",
                        rusqlite::params![token_hash],
                    )
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;
                Ok(count > 0)
            })
            .await
            .map_err(|e| StoreError::Database(e.to_string()))
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
    async fn enroll_workspace(
        &self,
        id: &WorkspaceId,
        encryption_public_key: &str,
    ) -> Result<bool, StoreError> {
        self.enroll_workspace_impl(id, encryption_public_key).await
    }
    async fn check_workspace_jti(&self, jti: &str) -> Result<bool, StoreError> {
        self.check_workspace_jti_impl(jti).await
    }
    async fn store_workspace_jti(
        &self,
        jti: &str,
        workspace_id: &WorkspaceId,
        expires_at: &chrono::DateTime<chrono::Utc>,
    ) -> Result<bool, StoreError> {
        self.store_workspace_jti_impl(jti, workspace_id, expires_at)
            .await
    }
    async fn cleanup_expired_workspace_jtis(&self) -> Result<u32, StoreError> {
        self.cleanup_expired_workspace_jtis_impl().await
    }
    async fn touch_workspace_authenticated(
        &self,
        id: &WorkspaceId,
        now: &chrono::DateTime<chrono::Utc>,
    ) -> Result<(), StoreError> {
        self.touch_workspace_authenticated_impl(id, now).await
    }
    async fn create_workspace_registration(
        &self,
        reg: &WorkspaceRegistration,
    ) -> Result<(), StoreError> {
        self.create_workspace_registration_impl(reg).await
    }
    async fn get_workspace_registration(
        &self,
        pk_hash: &str,
    ) -> Result<Option<WorkspaceRegistration>, StoreError> {
        self.get_workspace_registration_impl(pk_hash).await
    }
    async fn increment_registration_attempts(&self, pk_hash: &str) -> Result<(), StoreError> {
        self.increment_registration_attempts_impl(pk_hash).await
    }
    async fn delete_workspace_registration(&self, pk_hash: &str) -> Result<bool, StoreError> {
        self.delete_workspace_registration_impl(pk_hash).await
    }
    async fn null_registration_approval_code(&self, pk_hash: &str) -> Result<(), StoreError> {
        self.null_registration_approval_code_impl(pk_hash).await
    }
    async fn create_provisioning_token(&self, token: &ProvisioningToken) -> Result<(), StoreError> {
        self.create_provisioning_token_impl(token).await
    }
    async fn get_provisioning_token(
        &self,
        token_hash: &str,
    ) -> Result<Option<ProvisioningToken>, StoreError> {
        self.get_provisioning_token_impl(token_hash).await
    }
    async fn mark_provisioning_token_used(&self, token_hash: &str) -> Result<bool, StoreError> {
        self.mark_provisioning_token_used_impl(token_hash).await
    }
}
