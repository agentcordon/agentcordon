mod history;

use async_trait::async_trait;

use super::helpers::*;
use super::SqliteStore;

use crate::domain::agent::AgentId;
use crate::domain::credential::{
    CredentialId, CredentialSummary, CredentialUpdate, StoredCredential,
};
use crate::domain::user::UserId;
use crate::domain::workspace::WorkspaceId;
use crate::error::StoreError;
use crate::storage::shared::{
    build_credential_update_sql, CredentialParamValue, PlaceholderStyle, CREDENTIAL_COLUMNS,
    CREDENTIAL_SUMMARY_COLUMNS,
};
use crate::storage::CredentialStore;

impl SqliteStore {
    pub(crate) async fn store_credential(&self, cred: &StoredCredential) -> Result<(), StoreError> {
        let cred = cred.clone();

        self.conn()
            .call(move |conn| {
                let id_str = cred.id.0.hyphenated().to_string();
                let scopes_json = serialize_scopes(&cred.scopes).map_err(store_err_to_tokio)?;
                let metadata_json = serialize_metadata(&cred.metadata).map_err(store_err_to_tokio)?;
                let tags_json = serialize_tags(&cred.tags).map_err(store_err_to_tokio)?;
                let created_by_str = cred.created_by.as_ref().map(|id| id.0.hyphenated().to_string());
                let created_by_user_str = cred.created_by_user.as_ref().map(|id| id.0.hyphenated().to_string());
                let created_at = cred.created_at.to_rfc3339();
                let updated_at = cred.updated_at.to_rfc3339();
                let expires_at = cred.expires_at.map(|dt| dt.to_rfc3339());
                let cred_name = cred.name.clone();

                let sql = format!(
                    "INSERT INTO credentials ({}) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19)",
                    CREDENTIAL_COLUMNS
                );
                conn.execute(
                    &sql,
                    rusqlite::params![
                        id_str,
                        cred.name,
                        cred.service,
                        cred.encrypted_value,
                        cred.nonce,
                        scopes_json,
                        metadata_json,
                        created_by_str,
                        created_at,
                        updated_at,
                        cred.allowed_url_pattern,
                        created_by_user_str,
                        expires_at,
                        cred.transform_script,
                        cred.transform_name,
                        cred.vault,
                        cred.credential_type,
                        tags_json,
                        cred.key_version,
                    ],
                )
                .map_err(|e| {
                    if let rusqlite::Error::SqliteFailure(err, _) = &e {
                        if err.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_UNIQUE {
                            // Try to find the existing credential's ID
                            let existing_id = conn
                                .query_row(
                                    "SELECT id FROM credentials WHERE name = ?1",
                                    rusqlite::params![cred_name],
                                    |row| {
                                        let id_str: String = row.get(0)?;
                                        Ok(uuid::Uuid::parse_str(&id_str).ok())
                                    },
                                )
                                .ok()
                                .flatten();
                            return store_err_to_tokio(StoreError::Conflict {
                                message: format!("credential with name '{}' already exists", cred_name),
                                existing_id,
                            });
                        }
                    }
                    tokio_rusqlite::Error::Rusqlite(e)
                })?;
                Ok(())
            })
            .await
            .map_err(|e| {
                // Propagate StoreError::Conflict from the inner closure
                if let tokio_rusqlite::Error::Other(ref inner) = e {
                    if let Some(store_err) = inner.downcast_ref::<StoreError>() {
                        return match store_err {
                            StoreError::Conflict { message, existing_id } => StoreError::Conflict { message: message.clone(), existing_id: *existing_id },
                            _ => StoreError::Database(e.to_string()),
                        };
                    }
                }
                StoreError::Database(e.to_string())
            })
    }

    pub(crate) async fn get_credential(
        &self,
        id: &CredentialId,
    ) -> Result<Option<StoredCredential>, StoreError> {
        let id_str = id.0.hyphenated().to_string();

        self.conn()
            .call(move |conn| {
                let sql = format!(
                    "SELECT {} FROM credentials WHERE id = ?1",
                    CREDENTIAL_COLUMNS
                );
                let mut stmt = conn
                    .prepare(&sql)
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;

                let mut rows = stmt
                    .query_map(rusqlite::params![id_str], row_to_stored_credential)
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;

                match rows.next() {
                    Some(Ok(cred)) => Ok(Some(cred)),
                    Some(Err(e)) => Err(tokio_rusqlite::Error::Rusqlite(e)),
                    None => Ok(None),
                }
            })
            .await
            .map_err(|e| StoreError::Database(e.to_string()))
    }

    pub(crate) async fn get_credential_by_name(
        &self,
        name: &str,
    ) -> Result<Option<StoredCredential>, StoreError> {
        let name = name.to_string();

        self.conn()
            .call(move |conn| {
                let sql = format!(
                    "SELECT {} FROM credentials WHERE name = ?1",
                    CREDENTIAL_COLUMNS
                );
                let mut stmt = conn
                    .prepare(&sql)
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;

                let mut rows = stmt
                    .query_map(rusqlite::params![name], row_to_stored_credential)
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;

                match rows.next() {
                    Some(Ok(cred)) => Ok(Some(cred)),
                    Some(Err(e)) => Err(tokio_rusqlite::Error::Rusqlite(e)),
                    None => Ok(None),
                }
            })
            .await
            .map_err(|e| StoreError::Database(e.to_string()))
    }

    pub(crate) async fn get_credential_by_workspace_and_name(
        &self,
        workspace_id: &WorkspaceId,
        name: &str,
    ) -> Result<Option<StoredCredential>, StoreError> {
        let workspace_id_str = workspace_id.0.hyphenated().to_string();
        let name = name.to_string();

        self.conn()
            .call(move |conn| {
                let sql = format!(
                    "SELECT {} FROM credentials WHERE name = ?1 AND created_by = ?2",
                    CREDENTIAL_COLUMNS
                );
                let mut stmt = conn
                    .prepare(&sql)
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;

                let mut rows = stmt
                    .query_map(
                        rusqlite::params![name, workspace_id_str],
                        row_to_stored_credential,
                    )
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;

                match rows.next() {
                    Some(Ok(cred)) => Ok(Some(cred)),
                    Some(Err(e)) => Err(tokio_rusqlite::Error::Rusqlite(e)),
                    None => Ok(None),
                }
            })
            .await
            .map_err(|e| StoreError::Database(e.to_string()))
    }

    pub(crate) async fn list_credentials(&self) -> Result<Vec<CredentialSummary>, StoreError> {
        self.conn()
            .call(move |conn| {
                let sql = format!(
                    "SELECT {} FROM credentials ORDER BY name",
                    CREDENTIAL_SUMMARY_COLUMNS
                );
                let mut stmt = conn
                    .prepare(&sql)
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;

                let rows = stmt
                    .query_map([], row_to_credential_summary)
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;

                let mut summaries = Vec::new();
                for row in rows {
                    summaries.push(row.map_err(tokio_rusqlite::Error::Rusqlite)?);
                }
                Ok(summaries)
            })
            .await
            .map_err(|e| StoreError::Database(e.to_string()))
    }

    pub(crate) async fn delete_credential(&self, id: &CredentialId) -> Result<bool, StoreError> {
        let id_str = id.0.hyphenated().to_string();

        self.conn()
            .call(move |conn| {
                let changed = conn
                    .execute(
                        "DELETE FROM credentials WHERE id = ?1",
                        rusqlite::params![id_str],
                    )
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;
                Ok(changed > 0)
            })
            .await
            .map_err(|e| StoreError::Database(e.to_string()))
    }

    pub(crate) async fn list_vaults(&self) -> Result<Vec<String>, StoreError> {
        self.conn()
            .call(move |conn| {
                let mut stmt = conn
                    .prepare("SELECT DISTINCT vault FROM credentials ORDER BY vault")
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;

                let rows = stmt
                    .query_map([], |row| row.get::<_, String>(0))
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;

                let mut vaults = Vec::new();
                for row in rows {
                    vaults.push(row.map_err(tokio_rusqlite::Error::Rusqlite)?);
                }
                Ok(vaults)
            })
            .await
            .map_err(|e| StoreError::Database(e.to_string()))
    }

    pub(crate) async fn list_vaults_for_user(
        &self,
        user_id: &UserId,
    ) -> Result<Vec<String>, StoreError> {
        let user_id_str = user_id.0.hyphenated().to_string();

        self.conn()
            .call(move |conn| {
                // Return vaults where the user created at least one credential,
                // UNION vaults that have been shared with them.
                let mut stmt = conn
                    .prepare(
                        "SELECT DISTINCT vault FROM credentials WHERE created_by_user = ?1 \
                         UNION \
                         SELECT DISTINCT vault_name FROM vault_shares WHERE shared_with_user_id = ?1 \
                         ORDER BY 1",
                    )
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;

                let rows = stmt
                    .query_map(rusqlite::params![user_id_str], |row| row.get::<_, String>(0))
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;

                let mut vaults = Vec::new();
                for row in rows {
                    vaults.push(row.map_err(tokio_rusqlite::Error::Rusqlite)?);
                }
                Ok(vaults)
            })
            .await
            .map_err(|e| StoreError::Database(e.to_string()))
    }

    pub(crate) async fn list_credentials_by_vault(
        &self,
        vault: &str,
    ) -> Result<Vec<CredentialSummary>, StoreError> {
        let vault = vault.to_string();

        self.conn()
            .call(move |conn| {
                let sql = format!(
                    "SELECT {} FROM credentials WHERE vault = ?1 ORDER BY name",
                    CREDENTIAL_SUMMARY_COLUMNS
                );
                let mut stmt = conn
                    .prepare(&sql)
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;

                let rows = stmt
                    .query_map(rusqlite::params![vault], row_to_credential_summary)
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;

                let mut summaries = Vec::new();
                for row in rows {
                    summaries.push(row.map_err(tokio_rusqlite::Error::Rusqlite)?);
                }
                Ok(summaries)
            })
            .await
            .map_err(|e| StoreError::Database(e.to_string()))
    }

    pub(crate) async fn list_credentials_by_vault_for_user(
        &self,
        vault: &str,
        user_id: &UserId,
    ) -> Result<Vec<CredentialSummary>, StoreError> {
        let vault = vault.to_string();
        let user_id_str = user_id.0.hyphenated().to_string();

        self.conn()
            .call(move |conn| {
                // Return credentials in this vault where the user either:
                // 1. Created the credential (created_by_user matches), OR
                // 2. Has been granted a vault share via vault_shares table
                let sql = format!(
                    "SELECT c.{} FROM credentials c \
                     WHERE c.vault = ?1 \
                     AND (c.created_by_user = ?2 \
                          OR EXISTS (SELECT 1 FROM vault_shares vs \
                                     WHERE vs.vault_name = c.vault \
                                     AND vs.shared_with_user_id = ?2)) \
                     ORDER BY c.name",
                    CREDENTIAL_SUMMARY_COLUMNS.replace(", ", ", c.")
                );
                let mut stmt = conn
                    .prepare(&sql)
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;

                let rows = stmt
                    .query_map(
                        rusqlite::params![vault, user_id_str],
                        row_to_credential_summary,
                    )
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;

                let mut summaries = Vec::new();
                for row in rows {
                    summaries.push(row.map_err(tokio_rusqlite::Error::Rusqlite)?);
                }
                Ok(summaries)
            })
            .await
            .map_err(|e| StoreError::Database(e.to_string()))
    }

    pub(crate) async fn update_credential(
        &self,
        id: &CredentialId,
        updates: &CredentialUpdate,
    ) -> Result<bool, StoreError> {
        let id_str = id.0.hyphenated().to_string();
        let cq = build_credential_update_sql(
            &id_str,
            updates,
            PlaceholderStyle::QuestionMark,
            "", // no JSON cast for SQLite
        )
        .map_err(|e| StoreError::Database(e.to_string()))?;
        let update_name = updates.name.clone();

        self.conn()
            .call(move |conn| {
                if !cq.has_changes {
                    let now = chrono::Utc::now().to_rfc3339();
                    let changed = conn
                        .execute(&cq.sql, rusqlite::params![now, id_str])
                        .map_err(tokio_rusqlite::Error::Rusqlite)?;
                    return Ok(changed > 0);
                }

                let mut values: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();
                for p in &cq.params {
                    match p {
                        CredentialParamValue::String(s) => values.push(Box::new(s.clone())),
                        CredentialParamValue::Bytes(b) => values.push(Box::new(b.clone())),
                        CredentialParamValue::Int64(i) => values.push(Box::new(*i)),
                    }
                }
                values.push(Box::new(id_str.clone()));

                let param_refs: Vec<&dyn rusqlite::types::ToSql> = values
                    .iter()
                    .map(|v| v.as_ref() as &dyn rusqlite::types::ToSql)
                    .collect();

                let result = conn.execute(&cq.sql, param_refs.as_slice());
                match result {
                    Ok(changed) => Ok(changed > 0),
                    Err(e) => {
                        if let rusqlite::Error::SqliteFailure(err, _) = &e {
                            if err.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_UNIQUE {
                                let name = update_name.unwrap_or_default();
                                return Err(store_err_to_tokio(StoreError::Conflict {
                                    message: format!(
                                        "credential with name '{}' already exists",
                                        name
                                    ),
                                    existing_id: None,
                                }));
                            }
                        }
                        Err(tokio_rusqlite::Error::Rusqlite(e))
                    }
                }
            })
            .await
            .map_err(|e| {
                if let tokio_rusqlite::Error::Other(ref inner) = e {
                    if let Some(store_err) = inner.downcast_ref::<StoreError>() {
                        return match store_err {
                            StoreError::Conflict {
                                message,
                                existing_id,
                            } => StoreError::Conflict {
                                message: message.clone(),
                                existing_id: *existing_id,
                            },
                            _ => StoreError::Database(e.to_string()),
                        };
                    }
                }
                StoreError::Database(e.to_string())
            })
    }

    pub(crate) async fn list_credentials_for_agent(
        &self,
        _agent_id: &AgentId,
    ) -> Result<Vec<CredentialSummary>, StoreError> {
        // credential_permissions table has been dropped — all credential access
        // is now authorized through Cedar policies. This method is retained for
        // trait compatibility but always returns an empty list.
        Ok(Vec::new())
    }
}

#[async_trait]
impl CredentialStore for SqliteStore {
    async fn store_credential(&self, cred: &StoredCredential) -> Result<(), StoreError> {
        self.store_credential(cred).await
    }
    async fn get_credential(
        &self,
        id: &CredentialId,
    ) -> Result<Option<StoredCredential>, StoreError> {
        self.get_credential(id).await
    }
    async fn get_credential_by_name(
        &self,
        name: &str,
    ) -> Result<Option<StoredCredential>, StoreError> {
        self.get_credential_by_name(name).await
    }
    async fn get_credential_by_workspace_and_name(
        &self,
        workspace_id: &WorkspaceId,
        name: &str,
    ) -> Result<Option<StoredCredential>, StoreError> {
        self.get_credential_by_workspace_and_name(workspace_id, name)
            .await
    }
    async fn list_credentials(&self) -> Result<Vec<CredentialSummary>, StoreError> {
        self.list_credentials().await
    }
    async fn delete_credential(&self, id: &CredentialId) -> Result<bool, StoreError> {
        self.delete_credential(id).await
    }
    async fn list_vaults(&self) -> Result<Vec<String>, StoreError> {
        self.list_vaults().await
    }
    async fn list_vaults_for_user(&self, user_id: &UserId) -> Result<Vec<String>, StoreError> {
        self.list_vaults_for_user(user_id).await
    }
    async fn list_credentials_by_vault(
        &self,
        vault: &str,
    ) -> Result<Vec<CredentialSummary>, StoreError> {
        self.list_credentials_by_vault(vault).await
    }
    async fn list_credentials_by_vault_for_user(
        &self,
        vault: &str,
        user_id: &UserId,
    ) -> Result<Vec<CredentialSummary>, StoreError> {
        self.list_credentials_by_vault_for_user(vault, user_id)
            .await
    }
    async fn update_credential(
        &self,
        id: &CredentialId,
        updates: &CredentialUpdate,
    ) -> Result<bool, StoreError> {
        self.update_credential(id, updates).await
    }
    async fn list_credentials_for_agent(
        &self,
        agent_id: &AgentId,
    ) -> Result<Vec<CredentialSummary>, StoreError> {
        self.list_credentials_for_agent(agent_id).await
    }
    async fn list_all_stored_credentials(&self) -> Result<Vec<StoredCredential>, StoreError> {
        self.list_all_stored_credentials().await
    }
}
