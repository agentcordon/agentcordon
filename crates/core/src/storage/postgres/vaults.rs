use async_trait::async_trait;

use super::{db_err, PostgresStore, VaultShareRow};
use crate::domain::user::UserId;
use crate::domain::vault::VaultShare;
use crate::error::StoreError;
use crate::storage::VaultStore;

#[async_trait]
impl VaultStore for PostgresStore {
    async fn share_vault(&self, share: &VaultShare) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO vault_shares (id, vault_name, shared_with_user_id, permission_level, shared_by_user_id, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(&share.id)
        .bind(&share.vault_name)
        .bind(share.shared_with_user_id.0)
        .bind(&share.permission_level)
        .bind(share.shared_by_user_id.0)
        .bind(share.created_at)
        .execute(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(())
    }

    async fn unshare_vault(&self, vault_name: &str, user_id: &UserId) -> Result<bool, StoreError> {
        let result = sqlx::query(
            "DELETE FROM vault_shares WHERE vault_name = $1 AND shared_with_user_id = $2",
        )
        .bind(vault_name)
        .bind(user_id.0)
        .execute(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(result.rows_affected() > 0)
    }

    async fn list_vault_shares(&self, vault_name: &str) -> Result<Vec<VaultShare>, StoreError> {
        let rows = sqlx::query_as::<_, VaultShareRow>(
            "SELECT id, vault_name, shared_with_user_id, permission_level, shared_by_user_id, created_at \
             FROM vault_shares WHERE vault_name = $1 ORDER BY created_at",
        )
        .bind(vault_name)
        .fetch_all(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    async fn get_vault_shares_for_user(
        &self,
        user_id: &UserId,
    ) -> Result<Vec<VaultShare>, StoreError> {
        let rows = sqlx::query_as::<_, VaultShareRow>(
            "SELECT id, vault_name, shared_with_user_id, permission_level, shared_by_user_id, created_at \
             FROM vault_shares WHERE shared_with_user_id = $1 ORDER BY vault_name",
        )
        .bind(user_id.0)
        .fetch_all(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(rows.into_iter().map(Into::into).collect())
    }
}
