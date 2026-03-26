use async_trait::async_trait;

use super::helpers::*;
use super::SqliteStore;

use crate::domain::policy::{PolicyId, StoredPolicy};
use crate::error::StoreError;
use crate::storage::PolicyStore;

impl SqliteStore {
    pub(crate) async fn store_policy(&self, policy: &StoredPolicy) -> Result<(), StoreError> {
        let policy = policy.clone();

        self.conn()
            .call(move |conn| {
                let id_str = policy.id.0.hyphenated().to_string();
                let created_at = policy.created_at.to_rfc3339();
                let updated_at = policy.updated_at.to_rfc3339();

                conn.execute(
                    "INSERT INTO policies (id, name, description, cedar_policy, enabled, is_system, created_at, updated_at) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                    rusqlite::params![
                        id_str,
                        policy.name,
                        policy.description,
                        policy.cedar_policy,
                        policy.enabled,
                        policy.is_system,
                        created_at,
                        updated_at,
                    ],
                )
                .map_err(tokio_rusqlite::Error::Rusqlite)?;
                Ok(())
            })
            .await
            .map_err(|e| StoreError::Database(e.to_string()))
    }

    pub(crate) async fn get_policy(
        &self,
        id: &PolicyId,
    ) -> Result<Option<StoredPolicy>, StoreError> {
        let id_str = id.0.hyphenated().to_string();

        self.conn()
            .call(move |conn| {
                let mut stmt = conn
                    .prepare(
                        "SELECT id, name, description, cedar_policy, enabled, created_at, updated_at, is_system \
                         FROM policies WHERE id = ?1",
                    )
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;

                let mut rows = stmt
                    .query_map(rusqlite::params![id_str], row_to_stored_policy)
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;

                match rows.next() {
                    Some(Ok(policy)) => Ok(Some(policy)),
                    Some(Err(e)) => Err(tokio_rusqlite::Error::Rusqlite(e)),
                    None => Ok(None),
                }
            })
            .await
            .map_err(|e| StoreError::Database(e.to_string()))
    }

    pub(crate) async fn list_policies(&self) -> Result<Vec<StoredPolicy>, StoreError> {
        self.conn()
            .call(move |conn| {
                let mut stmt = conn
                    .prepare(
                        "SELECT id, name, description, cedar_policy, enabled, created_at, updated_at, is_system \
                         FROM policies ORDER BY name",
                    )
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;

                let rows = stmt
                    .query_map([], row_to_stored_policy)
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;

                let mut policies = Vec::new();
                for row in rows {
                    policies.push(row.map_err(tokio_rusqlite::Error::Rusqlite)?);
                }
                Ok(policies)
            })
            .await
            .map_err(|e| StoreError::Database(e.to_string()))
    }

    pub(crate) async fn update_policy(&self, policy: &StoredPolicy) -> Result<(), StoreError> {
        let policy = policy.clone();

        self.conn()
            .call(move |conn| {
                let id_str = policy.id.0.hyphenated().to_string();
                let updated_at = policy.updated_at.to_rfc3339();

                let changed = conn
                    .execute(
                        "UPDATE policies SET name = ?1, description = ?2, cedar_policy = ?3, enabled = ?4, is_system = ?5, updated_at = ?6 \
                         WHERE id = ?7",
                        rusqlite::params![
                            policy.name,
                            policy.description,
                            policy.cedar_policy,
                            policy.enabled,
                            policy.is_system,
                            updated_at,
                            id_str,
                        ],
                    )
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;

                if changed == 0 {
                    return Err(store_err_to_tokio(StoreError::NotFound(format!(
                        "policy {} not found",
                        id_str
                    ))));
                }
                Ok(())
            })
            .await
            .map_err(|e| StoreError::Database(e.to_string()))
    }

    pub(crate) async fn delete_policy(&self, id: &PolicyId) -> Result<bool, StoreError> {
        let id_str = id.0.hyphenated().to_string();

        self.conn()
            .call(move |conn| {
                let changed = conn
                    .execute(
                        "DELETE FROM policies WHERE id = ?1",
                        rusqlite::params![id_str],
                    )
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;
                Ok(changed > 0)
            })
            .await
            .map_err(|e| StoreError::Database(e.to_string()))
    }

    pub(crate) async fn get_all_enabled_policies(&self) -> Result<Vec<StoredPolicy>, StoreError> {
        self.conn()
            .call(move |conn| {
                let mut stmt = conn
                    .prepare(
                        "SELECT id, name, description, cedar_policy, enabled, created_at, updated_at, is_system \
                         FROM policies WHERE enabled = 1 ORDER BY name",
                    )
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;

                let rows = stmt
                    .query_map([], row_to_stored_policy)
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;

                let mut policies = Vec::new();
                for row in rows {
                    policies.push(row.map_err(tokio_rusqlite::Error::Rusqlite)?);
                }
                Ok(policies)
            })
            .await
            .map_err(|e| StoreError::Database(e.to_string()))
    }

    pub(crate) async fn delete_policies_by_name_prefix(
        &self,
        prefix: &str,
    ) -> Result<u64, StoreError> {
        let prefix = prefix.to_string();
        self.conn()
            .call(move |conn| {
                let like_pattern = format!("{}%", prefix);
                let changed = conn
                    .execute(
                        "DELETE FROM policies WHERE name LIKE ?1",
                        rusqlite::params![like_pattern],
                    )
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;
                Ok(changed as u64)
            })
            .await
            .map_err(|e| StoreError::Database(e.to_string()))
    }

    pub(crate) async fn delete_policy_by_name(&self, name: &str) -> Result<bool, StoreError> {
        let name = name.to_string();
        self.conn()
            .call(move |conn| {
                let changed = conn
                    .execute(
                        "DELETE FROM policies WHERE name = ?1",
                        rusqlite::params![name],
                    )
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;
                Ok(changed > 0)
            })
            .await
            .map_err(|e| StoreError::Database(e.to_string()))
    }
}

#[async_trait]
impl PolicyStore for SqliteStore {
    async fn store_policy(&self, policy: &StoredPolicy) -> Result<(), StoreError> {
        self.store_policy(policy).await
    }
    async fn get_policy(&self, id: &PolicyId) -> Result<Option<StoredPolicy>, StoreError> {
        self.get_policy(id).await
    }
    async fn list_policies(&self) -> Result<Vec<StoredPolicy>, StoreError> {
        self.list_policies().await
    }
    async fn update_policy(&self, policy: &StoredPolicy) -> Result<(), StoreError> {
        self.update_policy(policy).await
    }
    async fn delete_policy(&self, id: &PolicyId) -> Result<bool, StoreError> {
        self.delete_policy(id).await
    }
    async fn get_all_enabled_policies(&self) -> Result<Vec<StoredPolicy>, StoreError> {
        self.get_all_enabled_policies().await
    }
    async fn delete_policies_by_name_prefix(&self, prefix: &str) -> Result<u64, StoreError> {
        self.delete_policies_by_name_prefix(prefix).await
    }
    async fn delete_policy_by_name(&self, name: &str) -> Result<bool, StoreError> {
        self.delete_policy_by_name(name).await
    }
}
