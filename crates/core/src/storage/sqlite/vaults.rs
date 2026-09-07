//! Vault rows and their share lists.

use async_trait::async_trait;
use rusqlite::OptionalExtension;

use super::helpers::*;
use super::SqliteStore;

use crate::domain::time::format_timestamp;
use crate::domain::user::UserId;
use crate::domain::vault::{Vault, VaultShare};
use crate::error::StoreError;
use crate::storage::VaultStore;

/// Columns for the `vaults` table (SELECT), in `row_to_vault` order.
const VAULT_COLUMNS: &str = "id, name, owner_user_id, created_at, updated_at";

impl SqliteStore {
    pub(crate) async fn create_vault(&self, vault: &Vault) -> Result<(), StoreError> {
        let vault = vault.clone();
        self.conn()
            .call(move |conn| {
                conn.execute(
                    "INSERT INTO vaults (id, name, owner_user_id, created_at, updated_at) \
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                    rusqlite::params![
                        vault.id,
                        vault.name,
                        vault.owner_user_id.as_ref().map(|u| u.0.to_string()),
                        format_timestamp(&vault.created_at),
                        format_timestamp(&vault.updated_at),
                    ],
                )
                .map_err(tokio_rusqlite::Error::Rusqlite)?;
                Ok(())
            })
            .await
            .map_err(map_store_error)
    }

    pub(crate) async fn get_vault(&self, id: &str) -> Result<Option<Vault>, StoreError> {
        let id = id.to_string();
        self.conn()
            .call(move |conn| {
                let sql = format!("SELECT {VAULT_COLUMNS} FROM vaults WHERE id = ?1");
                conn.query_row(&sql, rusqlite::params![id], row_to_vault)
                    .optional()
                    .map_err(tokio_rusqlite::Error::Rusqlite)
            })
            .await
            .map_err(map_store_error)
    }

    pub(crate) async fn list_vaults(&self) -> Result<Vec<Vault>, StoreError> {
        self.conn()
            .call(move |conn| {
                let sql = format!("SELECT {VAULT_COLUMNS} FROM vaults ORDER BY name, id");
                let mut stmt = conn
                    .prepare(&sql)
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;
                let rows = stmt
                    .query_map([], row_to_vault)
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;
                let mut vaults = Vec::new();
                for row in rows {
                    vaults.push(row.map_err(tokio_rusqlite::Error::Rusqlite)?);
                }
                Ok(vaults)
            })
            .await
            .map_err(map_store_error)
    }

    pub(crate) async fn list_vaults_owned_by(
        &self,
        user_id: &UserId,
    ) -> Result<Vec<Vault>, StoreError> {
        let user_id_str = user_id.0.hyphenated().to_string();
        self.conn()
            .call(move |conn| {
                let sql = format!(
                    "SELECT {VAULT_COLUMNS} FROM vaults WHERE owner_user_id = ?1 ORDER BY name, id"
                );
                let mut stmt = conn
                    .prepare(&sql)
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;
                let rows = stmt
                    .query_map(rusqlite::params![user_id_str], row_to_vault)
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;
                let mut vaults = Vec::new();
                for row in rows {
                    vaults.push(row.map_err(tokio_rusqlite::Error::Rusqlite)?);
                }
                Ok(vaults)
            })
            .await
            .map_err(map_store_error)
    }

    pub(crate) async fn rename_vault(&self, id: &str, name: &str) -> Result<bool, StoreError> {
        let id = id.to_string();
        let name = name.to_string();
        let now = format_timestamp(&chrono::Utc::now());
        self.conn()
            .call(move |conn| {
                let changed = conn
                    .execute(
                        "UPDATE vaults SET name = ?1, updated_at = ?2 WHERE id = ?3",
                        rusqlite::params![name, now, id],
                    )
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;
                Ok(changed > 0)
            })
            .await
            .map_err(map_store_error)
    }

    pub(crate) async fn delete_vault(&self, id: &str) -> Result<bool, StoreError> {
        let id = id.to_string();
        self.conn()
            .call(move |conn| {
                let changed = conn
                    .execute("DELETE FROM vaults WHERE id = ?1", rusqlite::params![id])
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;
                Ok(changed > 0)
            })
            .await
            .map_err(map_store_error)
    }

    pub(crate) async fn count_credentials_in_vault(&self, id: &str) -> Result<i64, StoreError> {
        let id = id.to_string();
        self.conn()
            .call(move |conn| {
                conn.query_row(
                    "SELECT COUNT(*) FROM credentials WHERE vault_id = ?1",
                    rusqlite::params![id],
                    |r| r.get(0),
                )
                .map_err(tokio_rusqlite::Error::Rusqlite)
            })
            .await
            .map_err(map_store_error)
    }

    pub(crate) async fn share_vault(&self, share: &VaultShare) -> Result<(), StoreError> {
        let share = share.clone();

        self.conn()
            .call(move |conn| {
                let created_at = format_timestamp(&share.created_at);

                conn.execute(
                    "INSERT INTO vault_shares (id, vault_id, shared_with_user_id, permission_level, shared_by_user_id, created_at) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    rusqlite::params![
                        share.id,
                        share.vault_id,
                        share.shared_with_user_id.0.to_string(),
                        share.permission_level,
                        share.shared_by_user_id.0.to_string(),
                        created_at,
                    ],
                )
                .map_err(tokio_rusqlite::Error::Rusqlite)?;
                Ok(())
            })
            .await
            .map_err(map_store_error)
    }

    pub(crate) async fn unshare_vault(
        &self,
        vault_id: &str,
        user_id: &UserId,
    ) -> Result<bool, StoreError> {
        let vault_id = vault_id.to_string();
        let user_id_str = user_id.0.to_string();

        self.conn()
            .call(move |conn| {
                let rows = conn
                    .execute(
                        "DELETE FROM vault_shares WHERE vault_id = ?1 AND shared_with_user_id = ?2",
                        rusqlite::params![vault_id, user_id_str],
                    )
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;
                Ok(rows > 0)
            })
            .await
            .map_err(map_store_error)
    }

    pub(crate) async fn list_vault_shares(
        &self,
        vault_id: &str,
    ) -> Result<Vec<VaultShare>, StoreError> {
        let vault_id = vault_id.to_string();

        self.conn()
            .call(move |conn| {
                let mut stmt = conn
                    .prepare(
                        "SELECT id, vault_id, shared_with_user_id, permission_level, shared_by_user_id, created_at \
                         FROM vault_shares WHERE vault_id = ?1 ORDER BY created_at",
                    )
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;

                let rows = stmt
                    .query_map(rusqlite::params![vault_id], row_to_vault_share)
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;

                let mut shares = Vec::new();
                for row in rows {
                    shares.push(row.map_err(tokio_rusqlite::Error::Rusqlite)?);
                }
                Ok(shares)
            })
            .await
            .map_err(map_store_error)
    }

    pub(crate) async fn get_vault_shares_for_user(
        &self,
        user_id: &UserId,
    ) -> Result<Vec<VaultShare>, StoreError> {
        let user_id_str = user_id.0.to_string();

        self.conn()
            .call(move |conn| {
                let mut stmt = conn
                    .prepare(
                        "SELECT id, vault_id, shared_with_user_id, permission_level, shared_by_user_id, created_at \
                         FROM vault_shares WHERE shared_with_user_id = ?1 ORDER BY vault_id",
                    )
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;

                let rows = stmt
                    .query_map(rusqlite::params![user_id_str], row_to_vault_share)
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;

                let mut shares = Vec::new();
                for row in rows {
                    shares.push(row.map_err(tokio_rusqlite::Error::Rusqlite)?);
                }
                Ok(shares)
            })
            .await
            .map_err(map_store_error)
    }
}

#[async_trait]
impl VaultStore for SqliteStore {
    async fn create_vault(&self, vault: &Vault) -> Result<(), StoreError> {
        self.create_vault(vault).await
    }
    async fn get_vault(&self, id: &str) -> Result<Option<Vault>, StoreError> {
        self.get_vault(id).await
    }
    async fn list_vaults(&self) -> Result<Vec<Vault>, StoreError> {
        self.list_vaults().await
    }
    async fn list_vaults_owned_by(&self, user_id: &UserId) -> Result<Vec<Vault>, StoreError> {
        self.list_vaults_owned_by(user_id).await
    }
    async fn rename_vault(&self, id: &str, name: &str) -> Result<bool, StoreError> {
        self.rename_vault(id, name).await
    }
    async fn delete_vault(&self, id: &str) -> Result<bool, StoreError> {
        self.delete_vault(id).await
    }
    async fn count_credentials_in_vault(&self, id: &str) -> Result<i64, StoreError> {
        self.count_credentials_in_vault(id).await
    }
    async fn share_vault(&self, share: &VaultShare) -> Result<(), StoreError> {
        self.share_vault(share).await
    }
    async fn unshare_vault(&self, vault_id: &str, user_id: &UserId) -> Result<bool, StoreError> {
        self.unshare_vault(vault_id, user_id).await
    }
    async fn list_vault_shares(&self, vault_id: &str) -> Result<Vec<VaultShare>, StoreError> {
        self.list_vault_shares(vault_id).await
    }
    async fn get_vault_shares_for_user(
        &self,
        user_id: &UserId,
    ) -> Result<Vec<VaultShare>, StoreError> {
        self.get_vault_shares_for_user(user_id).await
    }
}
