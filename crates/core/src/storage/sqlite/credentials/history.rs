use async_trait::async_trait;

use super::super::helpers::*;
use super::super::SqliteStore;

use crate::domain::credential::{CredentialId, SecretHistoryEntry, StoredCredential};
use crate::domain::time::{format_timestamp, parse_timestamp};
use crate::error::StoreError;
use crate::storage::shared::{CREDENTIAL_COLUMNS, CREDENTIAL_SOURCE};
use crate::storage::{SecretHistoryCiphertext, SecretHistoryStore};
use uuid::Uuid;

fn parse_credential_id(raw: &str, column: usize) -> rusqlite::Result<CredentialId> {
    Uuid::parse_str(raw).map(CredentialId).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(column, rusqlite::types::Type::Text, Box::new(e))
    })
}

impl SqliteStore {
    // ---- Credential Secret History ----

    pub(crate) async fn store_secret_history(
        &self,
        credential_id: &CredentialId,
        encrypted_value: &[u8],
        nonce: &[u8],
        key_version: i64,
        changed_by_user: Option<&str>,
        changed_by_agent: Option<&str>,
    ) -> Result<(), StoreError> {
        let cred_id_str = credential_id.0.hyphenated().to_string();
        let id_str = Uuid::new_v4().hyphenated().to_string();
        let changed_at = format_timestamp(&chrono::Utc::now());
        let encrypted_value = encrypted_value.to_vec();
        let nonce = nonce.to_vec();
        let changed_by_user = changed_by_user.map(|s| s.to_string());
        let changed_by_agent = changed_by_agent.map(|s| s.to_string());

        self.conn()
            .call(move |conn| {
                conn.execute(
                    "INSERT INTO credential_secret_history \
                       (id, credential_id, encrypted_value, nonce, changed_at, changed_by_user, changed_by_agent, key_version) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                    rusqlite::params![
                        id_str,
                        cred_id_str,
                        encrypted_value,
                        nonce,
                        changed_at,
                        changed_by_user,
                        changed_by_agent,
                        key_version,
                    ],
                )
                .map_err(tokio_rusqlite::Error::Rusqlite)?;
                Ok(())
            })
            .await
            .map_err(map_store_error)
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
                        let credential_id = parse_credential_id(&cred_id_str, 1)?.0;
                        let changed_at = parse_timestamp(&changed_at_str).map_err(|e| {
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
            .map_err(map_store_error)
    }

    pub(crate) async fn get_secret_history_value(
        &self,
        credential_id: &CredentialId,
        history_id: &str,
    ) -> Result<Option<SecretHistoryCiphertext>, StoreError> {
        let credential_id = credential_id.0.hyphenated().to_string();
        let history_id = history_id.to_string();

        self.conn()
            .call(move |conn| {
                let mut stmt = conn
                    .prepare(
                        "SELECT id, credential_id, encrypted_value, nonce, key_version \
                         FROM credential_secret_history \
                         WHERE id = ?1 AND credential_id = ?2",
                    )
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;

                let mut rows = stmt
                    .query_map(
                        rusqlite::params![history_id, credential_id],
                        row_to_history_ciphertext,
                    )
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;

                match rows.next() {
                    Some(Ok(val)) => Ok(Some(val)),
                    Some(Err(e)) => Err(tokio_rusqlite::Error::Rusqlite(e)),
                    None => Ok(None),
                }
            })
            .await
            .map_err(map_store_error)
    }

    pub(crate) async fn list_all_secret_history_ciphertexts(
        &self,
    ) -> Result<Vec<SecretHistoryCiphertext>, StoreError> {
        self.conn()
            .call(move |conn| {
                let mut stmt = conn
                    .prepare(
                        "SELECT id, credential_id, encrypted_value, nonce, key_version \
                         FROM credential_secret_history ORDER BY changed_at, id",
                    )
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;
                let rows = stmt
                    .query_map([], row_to_history_ciphertext)
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;
                let mut out = Vec::new();
                for row in rows {
                    out.push(row.map_err(tokio_rusqlite::Error::Rusqlite)?);
                }
                Ok(out)
            })
            .await
            .map_err(map_store_error)
    }

    pub(crate) async fn update_secret_history_ciphertext(
        &self,
        history_id: &str,
        encrypted_value: &[u8],
        nonce: &[u8],
        key_version: i64,
    ) -> Result<bool, StoreError> {
        let history_id = history_id.to_string();
        let encrypted_value = encrypted_value.to_vec();
        let nonce = nonce.to_vec();
        self.conn()
            .call(move |conn| {
                let changed = conn
                    .execute(
                        "UPDATE credential_secret_history \
                         SET encrypted_value = ?1, nonce = ?2, key_version = ?3 WHERE id = ?4",
                        rusqlite::params![encrypted_value, nonce, key_version, history_id],
                    )
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;
                Ok(changed > 0)
            })
            .await
            .map_err(map_store_error)
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
                    "SELECT {CREDENTIAL_COLUMNS} FROM {CREDENTIAL_SOURCE} \
                     WHERE c.name = ?1 ORDER BY c.created_at"
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
            .map_err(map_store_error)
    }

    pub(crate) async fn list_all_stored_credentials(
        &self,
    ) -> Result<Vec<StoredCredential>, StoreError> {
        self.conn()
            .call(move |conn| {
                let sql =
                    format!("SELECT {CREDENTIAL_COLUMNS} FROM {CREDENTIAL_SOURCE} ORDER BY c.name");
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
            .map_err(map_store_error)
    }
}

/// Row shape: `id, credential_id, encrypted_value, nonce, key_version`.
fn row_to_history_ciphertext(row: &rusqlite::Row<'_>) -> rusqlite::Result<SecretHistoryCiphertext> {
    let id: String = row.get(0)?;
    let cred_id_str: String = row.get(1)?;
    Ok(SecretHistoryCiphertext {
        id,
        credential_id: parse_credential_id(&cred_id_str, 1)?,
        encrypted_value: row.get(2)?,
        nonce: row.get(3)?,
        key_version: row.get(4)?,
    })
}

#[async_trait]
impl SecretHistoryStore for SqliteStore {
    async fn store_secret_history(
        &self,
        credential_id: &CredentialId,
        encrypted_value: &[u8],
        nonce: &[u8],
        key_version: i64,
        changed_by_user: Option<&str>,
        changed_by_agent: Option<&str>,
    ) -> Result<(), StoreError> {
        self.store_secret_history(
            credential_id,
            encrypted_value,
            nonce,
            key_version,
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
        credential_id: &CredentialId,
        history_id: &str,
    ) -> Result<Option<SecretHistoryCiphertext>, StoreError> {
        self.get_secret_history_value(credential_id, history_id)
            .await
    }
    async fn list_all_secret_history_ciphertexts(
        &self,
    ) -> Result<Vec<SecretHistoryCiphertext>, StoreError> {
        self.list_all_secret_history_ciphertexts().await
    }
    async fn update_secret_history_ciphertext(
        &self,
        history_id: &str,
        encrypted_value: &[u8],
        nonce: &[u8],
        key_version: i64,
    ) -> Result<bool, StoreError> {
        self.update_secret_history_ciphertext(history_id, encrypted_value, nonce, key_version)
            .await
    }
}
