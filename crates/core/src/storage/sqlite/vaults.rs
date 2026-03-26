use async_trait::async_trait;

use super::helpers::*;
use super::SqliteStore;

use crate::domain::user::UserId;
use crate::domain::vault::VaultShare;
use crate::error::StoreError;
use crate::storage::VaultStore;

impl SqliteStore {
    pub(crate) async fn share_vault(&self, share: &VaultShare) -> Result<(), StoreError> {
        let share = share.clone();

        self.conn()
            .call(move |conn| {
                let shared_with = share.shared_with_user_id.0.hyphenated().to_string();
                let shared_by = share.shared_by_user_id.0.hyphenated().to_string();
                let created_at = share.created_at.to_rfc3339();

                conn.execute(
                    "INSERT INTO vault_shares (id, vault_name, shared_with_user_id, permission_level, shared_by_user_id, created_at) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    rusqlite::params![
                        share.id,
                        share.vault_name,
                        shared_with,
                        share.permission_level,
                        shared_by,
                        created_at,
                    ],
                )
                .map_err(tokio_rusqlite::Error::Rusqlite)?;
                Ok(())
            })
            .await
            .map_err(|e| StoreError::Database(e.to_string()))
    }

    pub(crate) async fn unshare_vault(
        &self,
        vault_name: &str,
        user_id: &UserId,
    ) -> Result<bool, StoreError> {
        let vault_name = vault_name.to_string();
        let user_id_str = user_id.0.hyphenated().to_string();

        self.conn()
            .call(move |conn| {
                let changed = conn
                    .execute(
                        "DELETE FROM vault_shares WHERE vault_name = ?1 AND shared_with_user_id = ?2",
                        rusqlite::params![vault_name, user_id_str],
                    )
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;
                Ok(changed > 0)
            })
            .await
            .map_err(|e| StoreError::Database(e.to_string()))
    }

    pub(crate) async fn list_vault_shares(
        &self,
        vault_name: &str,
    ) -> Result<Vec<VaultShare>, StoreError> {
        let vault_name = vault_name.to_string();

        self.conn()
            .call(move |conn| {
                let mut stmt = conn
                    .prepare(
                        "SELECT id, vault_name, shared_with_user_id, permission_level, shared_by_user_id, created_at \
                         FROM vault_shares WHERE vault_name = ?1 ORDER BY created_at",
                    )
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;

                let rows = stmt
                    .query_map(rusqlite::params![vault_name], row_to_vault_share)
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;

                let mut shares = Vec::new();
                for row in rows {
                    shares.push(row.map_err(tokio_rusqlite::Error::Rusqlite)?);
                }
                Ok(shares)
            })
            .await
            .map_err(|e| StoreError::Database(e.to_string()))
    }

    pub(crate) async fn get_vault_shares_for_user(
        &self,
        user_id: &UserId,
    ) -> Result<Vec<VaultShare>, StoreError> {
        let user_id_str = user_id.0.hyphenated().to_string();

        self.conn()
            .call(move |conn| {
                let mut stmt = conn
                    .prepare(
                        "SELECT id, vault_name, shared_with_user_id, permission_level, shared_by_user_id, created_at \
                         FROM vault_shares WHERE shared_with_user_id = ?1 ORDER BY vault_name",
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
            .map_err(|e| StoreError::Database(e.to_string()))
    }
}

#[async_trait]
impl VaultStore for SqliteStore {
    async fn share_vault(&self, share: &VaultShare) -> Result<(), StoreError> {
        self.share_vault(share).await
    }
    async fn unshare_vault(&self, vault_name: &str, user_id: &UserId) -> Result<bool, StoreError> {
        self.unshare_vault(vault_name, user_id).await
    }
    async fn list_vault_shares(&self, vault_name: &str) -> Result<Vec<VaultShare>, StoreError> {
        self.list_vault_shares(vault_name).await
    }
    async fn get_vault_shares_for_user(
        &self,
        user_id: &UserId,
    ) -> Result<Vec<VaultShare>, StoreError> {
        self.get_vault_shares_for_user(user_id).await
    }
}
