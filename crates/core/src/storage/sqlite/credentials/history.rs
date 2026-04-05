use async_trait::async_trait;

use super::super::helpers::*;
use super::super::SqliteStore;

use crate::domain::credential::{CredentialId, SecretHistoryEntry, StoredCredential};
use crate::error::StoreError;
use crate::storage::shared::CREDENTIAL_COLUMNS;
use crate::storage::SecretHistoryStore;
use chrono::{DateTime, Utc};
use uuid::Uuid;

impl SqliteStore {
    // ---- Credential Secret History ----

    pub(crate) async fn store_secret_history(
        &self,
        credential_id: &CredentialId,
        encrypted_value: &[u8],
        nonce: &[u8],
        changed_by_user: Option<&str>,
        changed_by_agent: Option<&str>,
    ) -> Result<(), StoreError> {
        let cred_id_str = credential_id.0.hyphenated().to_string();
        let id_str = Uuid::new_v4().hyphenated().to_string();
        let changed_at = chrono::Utc::now().to_rfc3339();
        let encrypted_value = encrypted_value.to_vec();
        let nonce = nonce.to_vec();
        let changed_by_user = changed_by_user.map(|s| s.to_string());
        let changed_by_agent = changed_by_agent.map(|s| s.to_string());

        self.conn()
            .call(move |conn| {
                conn.execute(
                    "INSERT INTO credential_secret_history (id, credential_id, encrypted_value, nonce, changed_at, changed_by_user, changed_by_agent) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    rusqlite::params![
                        id_str,
                        cred_id_str,
                        encrypted_value,
                        nonce,
                        changed_at,
                        changed_by_user,
                        changed_by_agent,
                    ],
                )
                .map_err(tokio_rusqlite::Error::Rusqlite)?;
                Ok(())
            })
            .await
            .map_err(|e| StoreError::Database(e.to_string()))
    }

    pub(crate) async fn list_secret_history(
        &self,
        credential_id: &CredentialId,
    ) -> Result<Vec<SecretHistoryEntry>, StoreError> {
        let cred_id_str = credential_id.0.hyphenated().to_string();

        self.conn()
            .call(move |conn| {
                let mut stmt = conn
                    .prepare(
                        "SELECT id, credential_id, changed_at, changed_by_user, changed_by_agent \
                         FROM credential_secret_history WHERE credential_id = ?1 \
                         ORDER BY changed_at DESC",
                    )
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;

                let rows = stmt
                    .query_map(rusqlite::params![cred_id_str], |row| {
                        let id_str: String = row.get(0)?;
                        let cred_id_str: String = row.get(1)?;
                        let changed_at_str: String = row.get(2)?;
                        let changed_by_user: Option<String> = row.get(3)?;
                        let changed_by_agent: Option<String> = row.get(4)?;

                        let id = Uuid::parse_str(&id_str).map_err(|e| {
                            rusqlite::Error::FromSqlConversionFailure(
                                0,
                                rusqlite::types::Type::Text,
                                Box::new(e),
                            )
                        })?;
                        let credential_id = Uuid::parse_str(&cred_id_str).map_err(|e| {
                            rusqlite::Error::FromSqlConversionFailure(
                                1,
                                rusqlite::types::Type::Text,
                                Box::new(e),
                            )
                        })?;
                        let changed_at = DateTime::parse_from_rfc3339(&changed_at_str)
                            .map(|dt| dt.with_timezone(&Utc))
                            .map_err(|e| {
                                rusqlite::Error::FromSqlConversionFailure(
                                    2,
                                    rusqlite::types::Type::Text,
                                    Box::new(e),
                                )
                            })?;

                        Ok(SecretHistoryEntry {
                            id,
                            credential_id,
                            changed_at,
                            changed_by_user,
                            changed_by_agent,
                        })
                    })
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;

                let mut entries = Vec::new();
                for row in rows {
                    entries.push(row.map_err(tokio_rusqlite::Error::Rusqlite)?);
                }
                Ok(entries)
            })
            .await
            .map_err(|e| StoreError::Database(e.to_string()))
    }

    pub(crate) async fn get_secret_history_value(
        &self,
        history_id: &str,
    ) -> Result<Option<(Vec<u8>, Vec<u8>)>, StoreError> {
        let history_id = history_id.to_string();

        self.conn()
            .call(move |conn| {
                let mut stmt = conn
                    .prepare(
                        "SELECT encrypted_value, nonce FROM credential_secret_history WHERE id = ?1",
                    )
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;

                let mut rows = stmt
                    .query_map(rusqlite::params![history_id], |row| {
                        let encrypted_value: Vec<u8> = row.get(0)?;
                        let nonce: Vec<u8> = row.get(1)?;
                        Ok((encrypted_value, nonce))
                    })
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;

                match rows.next() {
                    Some(Ok(val)) => Ok(Some(val)),
                    Some(Err(e)) => Err(tokio_rusqlite::Error::Rusqlite(e)),
                    None => Ok(None),
                }
            })
            .await
            .map_err(|e| StoreError::Database(e.to_string()))
    }

    // ---- Batch credential loading ----

    pub(crate) async fn list_stored_credentials_by_name(
        &self,
        name: &str,
    ) -> Result<Vec<StoredCredential>, StoreError> {
        let name = name.to_string();
        self.conn()
            .call(move |conn| {
                let sql = format!(
                    "SELECT {} FROM credentials WHERE name = ?1 ORDER BY created_at",
                    CREDENTIAL_COLUMNS
                );
                let mut stmt = conn
                    .prepare(&sql)
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;

                let rows = stmt
                    .query_map([&name], row_to_stored_credential)
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;

                let mut creds = Vec::new();
                for row in rows {
                    creds.push(row.map_err(tokio_rusqlite::Error::Rusqlite)?);
                }
                Ok(creds)
            })
            .await
            .map_err(|e| StoreError::Database(e.to_string()))
    }

    pub(crate) async fn list_all_stored_credentials(
        &self,
    ) -> Result<Vec<StoredCredential>, StoreError> {
        self.conn()
            .call(move |conn| {
                let sql = format!(
                    "SELECT {} FROM credentials ORDER BY name",
                    CREDENTIAL_COLUMNS
                );
                let mut stmt = conn
                    .prepare(&sql)
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;

                let rows = stmt
                    .query_map([], row_to_stored_credential)
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;

                let mut creds = Vec::new();
                for row in rows {
                    creds.push(row.map_err(tokio_rusqlite::Error::Rusqlite)?);
                }
                Ok(creds)
            })
            .await
            .map_err(|e| StoreError::Database(e.to_string()))
    }
}

#[async_trait]
impl SecretHistoryStore for SqliteStore {
    async fn store_secret_history(
        &self,
        credential_id: &CredentialId,
        encrypted_value: &[u8],
        nonce: &[u8],
        changed_by_user: Option<&str>,
        changed_by_agent: Option<&str>,
    ) -> Result<(), StoreError> {
        self.store_secret_history(
            credential_id,
            encrypted_value,
            nonce,
            changed_by_user,
            changed_by_agent,
        )
        .await
    }
    async fn list_secret_history(
        &self,
        credential_id: &CredentialId,
    ) -> Result<Vec<SecretHistoryEntry>, StoreError> {
        self.list_secret_history(credential_id).await
    }
    async fn get_secret_history_value(
        &self,
        history_id: &str,
    ) -> Result<Option<(Vec<u8>, Vec<u8>)>, StoreError> {
        self.get_secret_history_value(history_id).await
    }
}
