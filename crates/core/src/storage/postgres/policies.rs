use async_trait::async_trait;

use super::{db_err, PolicyRow, PostgresStore};
use crate::domain::policy::{PolicyId, StoredPolicy};
use crate::error::StoreError;
use crate::storage::PolicyStore;

#[async_trait]
impl PolicyStore for PostgresStore {
    async fn store_policy(&self, policy: &StoredPolicy) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO policies (id, name, description, cedar_policy, enabled, is_system, created_at, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind(policy.id.0)
        .bind(&policy.name)
        .bind(&policy.description)
        .bind(&policy.cedar_policy)
        .bind(policy.enabled)
        .bind(policy.is_system)
        .bind(policy.created_at)
        .bind(policy.updated_at)
        .execute(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(())
    }

    async fn get_policy(&self, id: &PolicyId) -> Result<Option<StoredPolicy>, StoreError> {
        let row = sqlx::query_as::<_, PolicyRow>(
            "SELECT id, name, description, cedar_policy, enabled, is_system, created_at, updated_at FROM policies WHERE id = $1",
        )
        .bind(id.0)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(row.map(Into::into))
    }

    async fn list_policies(&self) -> Result<Vec<StoredPolicy>, StoreError> {
        let rows = sqlx::query_as::<_, PolicyRow>(
            "SELECT id, name, description, cedar_policy, enabled, is_system, created_at, updated_at FROM policies ORDER BY name",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    async fn update_policy(&self, policy: &StoredPolicy) -> Result<(), StoreError> {
        let result = sqlx::query(
            "UPDATE policies SET name = $1, description = $2, cedar_policy = $3, enabled = $4, is_system = $5, updated_at = $6 WHERE id = $7",
        )
        .bind(&policy.name)
        .bind(&policy.description)
        .bind(&policy.cedar_policy)
        .bind(policy.enabled)
        .bind(policy.is_system)
        .bind(policy.updated_at)
        .bind(policy.id.0)
        .execute(&self.pool)
        .await
        .map_err(db_err)?;

        if result.rows_affected() == 0 {
            return Err(StoreError::NotFound(format!(
                "policy {} not found",
                policy.id.0
            )));
        }
        Ok(())
    }

    async fn delete_policy(&self, id: &PolicyId) -> Result<bool, StoreError> {
        let result = sqlx::query("DELETE FROM policies WHERE id = $1")
            .bind(id.0)
            .execute(&self.pool)
            .await
            .map_err(db_err)?;
        Ok(result.rows_affected() > 0)
    }

    async fn get_all_enabled_policies(&self) -> Result<Vec<StoredPolicy>, StoreError> {
        let rows = sqlx::query_as::<_, PolicyRow>(
            "SELECT id, name, description, cedar_policy, enabled, is_system, created_at, updated_at \
             FROM policies WHERE enabled = true ORDER BY name",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    async fn delete_policies_by_name_prefix(&self, prefix: &str) -> Result<u64, StoreError> {
        let like_pattern = format!("{}%", prefix);
        let result = sqlx::query("DELETE FROM policies WHERE name LIKE $1")
            .bind(&like_pattern)
            .execute(&self.pool)
            .await
            .map_err(db_err)?;
        Ok(result.rows_affected())
    }

    async fn delete_policy_by_name(&self, name: &str) -> Result<bool, StoreError> {
        let result = sqlx::query("DELETE FROM policies WHERE name = $1")
            .bind(name)
            .execute(&self.pool)
            .await
            .map_err(db_err)?;
        Ok(result.rows_affected() > 0)
    }
}
