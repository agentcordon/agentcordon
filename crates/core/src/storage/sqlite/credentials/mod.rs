mod history;

use async_trait::async_trait;

use super::helpers::*;
use super::SqliteStore;

use crate::domain::agent::AgentId;
use crate::domain::credential::{
    CredentialId, CredentialSummary, CredentialUpdate, StoredCredential,
};
use crate::domain::time::format_timestamp;
use crate::domain::user::UserId;
use crate::domain::workspace::WorkspaceId;
use crate::error::StoreError;
use crate::storage::shared::{
    build_credential_update_sql, CredentialParamValue, CredentialUpdateQuery, CREDENTIAL_COLUMNS,
    CREDENTIAL_INSERT_COLUMNS, CREDENTIAL_SOURCE, CREDENTIAL_SUMMARY_COLUMNS,
};
use crate::storage::CredentialStore;
use rusqlite::OptionalExtension;

/// Run a built credential UPDATE on `conn`. Returns the number of rows
/// changed: 0 when no credential has `id_str`.
fn apply_credential_update(
    conn: &rusqlite::Connection,
    id_str: &str,
    cq: &CredentialUpdateQuery,
) -> rusqlite::Result<usize> {
    if !cq.has_changes {
        let now = format_timestamp(&chrono::Utc::now());
        return conn.execute(&cq.sql, rusqlite::params![now, id_str]);
    }
    let mut values: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();
    for p in &cq.params {
        match p {
            CredentialParamValue::String(s) => values.push(Box::new(s.clone())),
            CredentialParamValue::Bytes(b) => values.push(Box::new(b.clone())),
            CredentialParamValue::Int64(i) => values.push(Box::new(*i)),
        }
    }
    values.push(Box::new(id_str.to_string()));
    let param_refs: Vec<&dyn rusqlite::types::ToSql> = values
        .iter()
        .map(|v| v.as_ref() as &dyn rusqlite::types::ToSql)
        .collect();
    conn.execute(&cq.sql, param_refs.as_slice())
}

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
                let created_at = format_timestamp(&cred.created_at);
                let updated_at = format_timestamp(&cred.updated_at);
                let expires_at = cred.expires_at.map(|dt| format_timestamp(&dt));

                let sql = format!(
                    "INSERT INTO credentials ({}) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21)",
                    CREDENTIAL_INSERT_COLUMNS
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
                        cred.vault_id,
                        cred.credential_type,
                        tags_json,
                        cred.key_version,
                        cred.description,
                        cred.target_identity,
                    ],
                )
                .map_err(tokio_rusqlite::Error::Rusqlite)?;
                Ok(())
            })
            .await
            .map_err(map_store_error)
    }

    pub(crate) async fn get_credential(
        &self,
        id: &CredentialId,
    ) -> Result<Option<StoredCredential>, StoreError> {
        let id_str = id.0.hyphenated().to_string();

        self.conn()
            .call(move |conn| {
                let sql =
                    format!("SELECT {CREDENTIAL_COLUMNS} FROM {CREDENTIAL_SOURCE} WHERE c.id = ?1");
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
            .map_err(map_store_error)
    }

    pub(crate) async fn get_credential_by_name(
        &self,
        name: &str,
    ) -> Result<Option<StoredCredential>, StoreError> {
        let name = name.to_string();

        self.conn()
            .call(move |conn| {
                let sql = format!(
                    "SELECT {CREDENTIAL_COLUMNS} FROM {CREDENTIAL_SOURCE} WHERE c.name = ?1"
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
            .map_err(map_store_error)
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
                    "SELECT {CREDENTIAL_COLUMNS} FROM {CREDENTIAL_SOURCE} WHERE c.name = ?1 AND c.created_by = ?2"
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
            .map_err(map_store_error)
    }

    pub(crate) async fn list_credentials(&self) -> Result<Vec<CredentialSummary>, StoreError> {
        self.conn()
            .call(move |conn| {
                let sql = format!(
                    "SELECT {CREDENTIAL_SUMMARY_COLUMNS} FROM {CREDENTIAL_SOURCE} ORDER BY c.name"
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
            .map_err(map_store_error)
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
            .map_err(map_store_error)
    }

    pub(crate) async fn list_credentials_by_vault(
        &self,
        vault_id: &str,
    ) -> Result<Vec<CredentialSummary>, StoreError> {
        let vault = vault_id.to_string();

        self.conn()
            .call(move |conn| {
                let sql = format!(
                    "SELECT {CREDENTIAL_SUMMARY_COLUMNS} FROM {CREDENTIAL_SOURCE} \
                     WHERE c.vault_id = ?1 ORDER BY c.name"
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
            .map_err(map_store_error)
    }

    pub(crate) async fn list_credentials_by_vault_for_user(
        &self,
        vault_id: &str,
        user_id: &UserId,
    ) -> Result<Vec<CredentialSummary>, StoreError> {
        let vault = vault_id.to_string();
        let user_id_str = user_id.0.hyphenated().to_string();

        self.conn()
            .call(move |conn| {
                // Return credentials in this vault where the user either:
                // 1. Created the credential (created_by_user matches), OR
                // 2. Owns the vault, OR
                // 3. Has been granted a share on the vault.
                let sql = format!(
                    "SELECT {CREDENTIAL_SUMMARY_COLUMNS} FROM {CREDENTIAL_SOURCE} \
                     WHERE c.vault_id = ?1 \
                     AND (c.created_by_user = ?2 \
                          OR v.owner_user_id = ?2 \
                          OR EXISTS (SELECT 1 FROM vault_shares vs \
                                     WHERE vs.vault_id = c.vault_id \
                                     AND vs.shared_with_user_id = ?2)) \
                     ORDER BY c.name"
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
            .map_err(map_store_error)
    }

    pub(crate) async fn update_credential(
        &self,
        id: &CredentialId,
        updates: &CredentialUpdate,
    ) -> Result<bool, StoreError> {
        let id_str = id.0.hyphenated().to_string();
        let cq = build_credential_update_sql(updates)?;

        self.conn()
            .call(move |conn| {
                let changed = apply_credential_update(conn, &id_str, &cq)?;
                Ok(changed > 0)
            })
            .await
            .map_err(map_store_error)
    }

    pub(crate) async fn rotate_credential_secret(
        &self,
        id: &CredentialId,
        updates: &CredentialUpdate,
        changed_by_user: Option<&str>,
        changed_by_agent: Option<&str>,
    ) -> Result<bool, StoreError> {
        if updates.encrypted_value.is_none() || updates.nonce.is_none() {
            return Err(StoreError::Database(
                "rotate_credential_secret needs a new encrypted_value and nonce".to_string(),
            ));
        }
        let id_str = id.0.hyphenated().to_string();
        let cq = build_credential_update_sql(updates)?;
        let history_id = uuid::Uuid::new_v4().hyphenated().to_string();
        let changed_at = format_timestamp(&chrono::Utc::now());
        let changed_by_user = changed_by_user.map(str::to_string);
        let changed_by_agent = changed_by_agent.map(str::to_string);

        self.conn()
            .call(move |conn| {
                let tx =
                    conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
                // Archive what the row holds now, not what the caller last
                // read, under the key version it was sealed with.
                let current: Option<(Vec<u8>, Vec<u8>, i64)> = tx
                    .query_row(
                        "SELECT encrypted_value, nonce, key_version FROM credentials WHERE id = ?1",
                        rusqlite::params![id_str],
                        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                    )
                    .optional()?;
                let Some((old_value, old_nonce, old_key_version)) = current else {
                    return Ok(false);
                };
                tx.execute(
                    "INSERT INTO credential_secret_history \
                       (id, credential_id, encrypted_value, nonce, changed_at, changed_by_user, changed_by_agent, key_version) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                    rusqlite::params![
                        history_id,
                        id_str,
                        old_value,
                        old_nonce,
                        changed_at,
                        changed_by_user,
                        changed_by_agent,
                        old_key_version,
                    ],
                )?;
                if apply_credential_update(&tx, &id_str, &cq)? == 0 {
                    return Ok(false);
                }
                tx.commit()?;
                Ok(true)
            })
            .await
            .map_err(map_store_error)
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
    async fn list_credentials_by_vault(
        &self,
        vault_id: &str,
    ) -> Result<Vec<CredentialSummary>, StoreError> {
        self.list_credentials_by_vault(vault_id).await
    }
    async fn list_credentials_by_vault_for_user(
        &self,
        vault_id: &str,
        user_id: &UserId,
    ) -> Result<Vec<CredentialSummary>, StoreError> {
        self.list_credentials_by_vault_for_user(vault_id, user_id)
            .await
    }
    async fn update_credential(
        &self,
        id: &CredentialId,
        updates: &CredentialUpdate,
    ) -> Result<bool, StoreError> {
        self.update_credential(id, updates).await
    }
    async fn rotate_credential_secret(
        &self,
        id: &CredentialId,
        updates: &CredentialUpdate,
        changed_by_user: Option<&str>,
        changed_by_agent: Option<&str>,
    ) -> Result<bool, StoreError> {
        self.rotate_credential_secret(id, updates, changed_by_user, changed_by_agent)
            .await
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
    async fn list_stored_credentials_by_name(
        &self,
        name: &str,
    ) -> Result<Vec<StoredCredential>, StoreError> {
        self.list_stored_credentials_by_name(name).await
    }
}
