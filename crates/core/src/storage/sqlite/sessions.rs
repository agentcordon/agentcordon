use async_trait::async_trait;

use super::helpers::*;
use super::SqliteStore;

use crate::domain::session::Session;
use crate::domain::user::UserId;
use crate::error::StoreError;
use crate::storage::SessionStore;
use chrono::Utc;

impl SqliteStore {
    pub(crate) async fn create_session(&self, session: &Session) -> Result<(), StoreError> {
        let session = session.clone();

        self.conn()
            .call(move |conn| {
                let user_id_str = session.user_id.0.hyphenated().to_string();
                let created_at = session.created_at.to_rfc3339();
                let expires_at = session.expires_at.to_rfc3339();
                let last_seen_at = session.last_seen_at.to_rfc3339();

                conn.execute(
                    "INSERT INTO sessions (id, user_id, created_at, expires_at, last_seen_at) \
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                    rusqlite::params![
                        session.id,
                        user_id_str,
                        created_at,
                        expires_at,
                        last_seen_at,
                    ],
                )
                .map_err(tokio_rusqlite::Error::Rusqlite)?;
                Ok(())
            })
            .await
            .map_err(|e| StoreError::Database(e.to_string()))
    }

    pub(crate) async fn get_session(&self, id_hash: &str) -> Result<Option<Session>, StoreError> {
        let id_hash = id_hash.to_string();

        self.conn()
            .call(move |conn| {
                let mut stmt = conn
                    .prepare(
                        "SELECT id, user_id, created_at, expires_at, last_seen_at \
                         FROM sessions WHERE id = ?1",
                    )
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;

                let mut rows = stmt
                    .query_map(rusqlite::params![id_hash], row_to_session)
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;

                match rows.next() {
                    Some(Ok(session)) => Ok(Some(session)),
                    Some(Err(e)) => Err(tokio_rusqlite::Error::Rusqlite(e)),
                    None => Ok(None),
                }
            })
            .await
            .map_err(|e| StoreError::Database(e.to_string()))
    }

    pub(crate) async fn delete_session(&self, id_hash: &str) -> Result<bool, StoreError> {
        let id_hash = id_hash.to_string();

        self.conn()
            .call(move |conn| {
                let changed = conn
                    .execute(
                        "DELETE FROM sessions WHERE id = ?1",
                        rusqlite::params![id_hash],
                    )
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;
                Ok(changed > 0)
            })
            .await
            .map_err(|e| StoreError::Database(e.to_string()))
    }

    pub(crate) async fn delete_user_sessions(&self, user_id: &UserId) -> Result<u32, StoreError> {
        let user_id_str = user_id.0.hyphenated().to_string();

        self.conn()
            .call(move |conn| {
                let changed = conn
                    .execute(
                        "DELETE FROM sessions WHERE user_id = ?1",
                        rusqlite::params![user_id_str],
                    )
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;
                Ok(changed as u32)
            })
            .await
            .map_err(|e| StoreError::Database(e.to_string()))
    }

    pub(crate) async fn touch_session(&self, id_hash: &str) -> Result<(), StoreError> {
        let id_hash = id_hash.to_string();
        let now = Utc::now().to_rfc3339();

        self.conn()
            .call(move |conn| {
                let changed = conn
                    .execute(
                        "UPDATE sessions SET last_seen_at = ?1 WHERE id = ?2",
                        rusqlite::params![now, id_hash],
                    )
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;

                if changed == 0 {
                    return Err(store_err_to_tokio(StoreError::NotFound(
                        "session not found".to_string(),
                    )));
                }
                Ok(())
            })
            .await
            .map_err(|e| StoreError::Database(e.to_string()))
    }

    pub(crate) async fn cleanup_expired_sessions(&self) -> Result<u32, StoreError> {
        let now = Utc::now().to_rfc3339();

        self.conn()
            .call(move |conn| {
                let changed = conn
                    .execute(
                        "DELETE FROM sessions WHERE expires_at < ?1",
                        rusqlite::params![now],
                    )
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;
                Ok(changed as u32)
            })
            .await
            .map_err(|e| StoreError::Database(e.to_string()))
    }
}

#[async_trait]
impl SessionStore for SqliteStore {
    async fn create_session(&self, session: &Session) -> Result<(), StoreError> {
        self.create_session(session).await
    }
    async fn get_session(&self, id_hash: &str) -> Result<Option<Session>, StoreError> {
        self.get_session(id_hash).await
    }
    async fn delete_session(&self, id_hash: &str) -> Result<bool, StoreError> {
        self.delete_session(id_hash).await
    }
    async fn delete_user_sessions(&self, user_id: &UserId) -> Result<u32, StoreError> {
        self.delete_user_sessions(user_id).await
    }
    async fn touch_session(&self, id_hash: &str) -> Result<(), StoreError> {
        self.touch_session(id_hash).await
    }
    async fn cleanup_expired_sessions(&self) -> Result<u32, StoreError> {
        self.cleanup_expired_sessions().await
    }
}
