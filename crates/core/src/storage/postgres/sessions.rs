use async_trait::async_trait;
use chrono::Utc;

use super::{db_err, PostgresStore, SessionRow};
use crate::domain::session::Session;
use crate::domain::user::UserId;
use crate::error::StoreError;
use crate::storage::SessionStore;

#[async_trait]
impl SessionStore for PostgresStore {
    async fn create_session(&self, session: &Session) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO sessions (id, user_id, created_at, expires_at, last_seen_at) \
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(&session.id)
        .bind(session.user_id.0)
        .bind(session.created_at)
        .bind(session.expires_at)
        .bind(session.last_seen_at)
        .execute(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(())
    }

    async fn get_session(&self, id_hash: &str) -> Result<Option<Session>, StoreError> {
        let row = sqlx::query_as::<_, SessionRow>(
            "SELECT id, user_id, created_at, expires_at, last_seen_at FROM sessions WHERE id = $1",
        )
        .bind(id_hash)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(row.map(Into::into))
    }

    async fn delete_session(&self, id_hash: &str) -> Result<bool, StoreError> {
        let result = sqlx::query("DELETE FROM sessions WHERE id = $1")
            .bind(id_hash)
            .execute(&self.pool)
            .await
            .map_err(db_err)?;
        Ok(result.rows_affected() > 0)
    }

    async fn delete_user_sessions(&self, user_id: &UserId) -> Result<u32, StoreError> {
        let result = sqlx::query("DELETE FROM sessions WHERE user_id = $1")
            .bind(user_id.0)
            .execute(&self.pool)
            .await
            .map_err(db_err)?;
        Ok(result.rows_affected() as u32)
    }

    async fn touch_session(&self, id_hash: &str) -> Result<(), StoreError> {
        let now = Utc::now();
        let result = sqlx::query("UPDATE sessions SET last_seen_at = $1 WHERE id = $2")
            .bind(now)
            .bind(id_hash)
            .execute(&self.pool)
            .await
            .map_err(db_err)?;
        if result.rows_affected() == 0 {
            return Err(StoreError::NotFound("session not found".to_string()));
        }
        Ok(())
    }

    async fn cleanup_expired_sessions(&self) -> Result<u32, StoreError> {
        let now = Utc::now();
        let result = sqlx::query("DELETE FROM sessions WHERE expires_at < $1")
            .bind(now)
            .execute(&self.pool)
            .await
            .map_err(db_err)?;
        Ok(result.rows_affected() as u32)
    }
}
