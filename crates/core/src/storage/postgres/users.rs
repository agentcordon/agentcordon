use async_trait::async_trait;

use super::{db_err, serialize_user_role, PostgresStore, UserRow};
use crate::domain::user::{User, UserId};
use crate::error::StoreError;
use crate::storage::UserStore;

#[async_trait]
impl UserStore for PostgresStore {
    async fn create_user(&self, user: &User) -> Result<(), StoreError> {
        let role_str = serialize_user_role(&user.role);
        sqlx::query(
            "INSERT INTO users (id, username, display_name, password_hash, role, is_root, enabled, show_advanced, created_at, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
        )
        .bind(user.id.0)
        .bind(&user.username)
        .bind(&user.display_name)
        .bind(&user.password_hash)
        .bind(role_str)
        .bind(user.is_root)
        .bind(user.enabled)
        .bind(user.show_advanced)
        .bind(user.created_at)
        .bind(user.updated_at)
        .execute(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(())
    }

    async fn get_user(&self, id: &UserId) -> Result<Option<User>, StoreError> {
        let row = sqlx::query_as::<_, UserRow>(
            "SELECT id, username, display_name, password_hash, role, is_root, enabled, show_advanced, created_at, updated_at \
             FROM users WHERE id = $1",
        )
        .bind(id.0)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_err)?;
        row.map(|r| r.into_user()).transpose()
    }

    async fn get_user_by_username(&self, username: &str) -> Result<Option<User>, StoreError> {
        let row = sqlx::query_as::<_, UserRow>(
            "SELECT id, username, display_name, password_hash, role, is_root, enabled, show_advanced, created_at, updated_at \
             FROM users WHERE username = $1",
        )
        .bind(username)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_err)?;
        row.map(|r| r.into_user()).transpose()
    }

    async fn list_users(&self) -> Result<Vec<User>, StoreError> {
        let rows = sqlx::query_as::<_, UserRow>(
            "SELECT id, username, display_name, password_hash, role, is_root, enabled, show_advanced, created_at, updated_at \
             FROM users ORDER BY username",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(db_err)?;
        rows.into_iter().map(|r| r.into_user()).collect()
    }

    async fn update_user(&self, user: &User) -> Result<(), StoreError> {
        let role_str = serialize_user_role(&user.role);
        let result = sqlx::query(
            "UPDATE users SET username = $1, display_name = $2, password_hash = $3, role = $4, \
             is_root = $5, enabled = $6, show_advanced = $7, updated_at = $8 WHERE id = $9",
        )
        .bind(&user.username)
        .bind(&user.display_name)
        .bind(&user.password_hash)
        .bind(role_str)
        .bind(user.is_root)
        .bind(user.enabled)
        .bind(user.show_advanced)
        .bind(user.updated_at)
        .bind(user.id.0)
        .execute(&self.pool)
        .await
        .map_err(db_err)?;

        if result.rows_affected() == 0 {
            return Err(StoreError::NotFound(format!(
                "user {} not found",
                user.id.0
            )));
        }
        Ok(())
    }

    async fn delete_user(&self, id: &UserId) -> Result<bool, StoreError> {
        let result = sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(id.0)
            .execute(&self.pool)
            .await
            .map_err(db_err)?;
        Ok(result.rows_affected() > 0)
    }

    async fn get_root_user(&self) -> Result<Option<User>, StoreError> {
        let row = sqlx::query_as::<_, UserRow>(
            "SELECT id, username, display_name, password_hash, role, is_root, enabled, created_at, updated_at \
             FROM users WHERE is_root = true LIMIT 1",
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(db_err)?;
        row.map(|r| r.into_user()).transpose()
    }
}
