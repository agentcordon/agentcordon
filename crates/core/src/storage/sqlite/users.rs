use async_trait::async_trait;

use super::helpers::*;
use super::SqliteStore;

use crate::domain::user::{User, UserId};
use crate::error::StoreError;
use crate::storage::shared::USER_COLUMNS;
use crate::storage::UserStore;

impl SqliteStore {
    pub(crate) async fn create_user(&self, user: &User) -> Result<(), StoreError> {
        let user = user.clone();

        self.conn()
            .call(move |conn| {
                let id_str = user.id.0.hyphenated().to_string();
                let role_str = serialize_user_role(&user.role);
                let created_at = user.created_at.to_rfc3339();
                let updated_at = user.updated_at.to_rfc3339();

                conn.execute(
                    "INSERT INTO users (id, username, display_name, password_hash, role, is_root, enabled, created_at, updated_at) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                    rusqlite::params![
                        id_str,
                        user.username,
                        user.display_name,
                        user.password_hash,
                        role_str,
                        user.is_root,
                        user.enabled,
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

    pub(crate) async fn get_user(&self, id: &UserId) -> Result<Option<User>, StoreError> {
        let id_str = id.0.hyphenated().to_string();

        self.conn()
            .call(move |conn| {
                let mut stmt = conn
                    .prepare(&format!("SELECT {} FROM users WHERE id = ?1", USER_COLUMNS))
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;

                let mut rows = stmt
                    .query_map(rusqlite::params![id_str], row_to_user)
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;

                match rows.next() {
                    Some(Ok(user)) => Ok(Some(user)),
                    Some(Err(e)) => Err(tokio_rusqlite::Error::Rusqlite(e)),
                    None => Ok(None),
                }
            })
            .await
            .map_err(|e| StoreError::Database(e.to_string()))
    }

    pub(crate) async fn get_user_by_username(
        &self,
        username: &str,
    ) -> Result<Option<User>, StoreError> {
        let username = username.to_string();

        self.conn()
            .call(move |conn| {
                let mut stmt = conn
                    .prepare(&format!(
                        "SELECT {} FROM users WHERE username = ?1",
                        USER_COLUMNS
                    ))
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;

                let mut rows = stmt
                    .query_map(rusqlite::params![username], row_to_user)
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;

                match rows.next() {
                    Some(Ok(user)) => Ok(Some(user)),
                    Some(Err(e)) => Err(tokio_rusqlite::Error::Rusqlite(e)),
                    None => Ok(None),
                }
            })
            .await
            .map_err(|e| StoreError::Database(e.to_string()))
    }

    pub(crate) async fn list_users(&self) -> Result<Vec<User>, StoreError> {
        self.conn()
            .call(move |conn| {
                let mut stmt = conn
                    .prepare(&format!(
                        "SELECT {} FROM users ORDER BY username",
                        USER_COLUMNS
                    ))
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;

                let rows = stmt
                    .query_map([], row_to_user)
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;

                let mut users = Vec::new();
                for row in rows {
                    users.push(row.map_err(tokio_rusqlite::Error::Rusqlite)?);
                }
                Ok(users)
            })
            .await
            .map_err(|e| StoreError::Database(e.to_string()))
    }

    pub(crate) async fn update_user(&self, user: &User) -> Result<(), StoreError> {
        let user = user.clone();

        self.conn()
            .call(move |conn| {
                let id_str = user.id.0.hyphenated().to_string();
                let role_str = serialize_user_role(&user.role);
                let updated_at = user.updated_at.to_rfc3339();

                let changed = conn
                    .execute(
                        "UPDATE users SET username = ?1, display_name = ?2, password_hash = ?3, role = ?4, \
                         is_root = ?5, enabled = ?6, updated_at = ?7 WHERE id = ?8",
                        rusqlite::params![
                            user.username,
                            user.display_name,
                            user.password_hash,
                            role_str,
                            user.is_root,
                            user.enabled,
                            updated_at,
                            id_str,
                        ],
                    )
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;

                if changed == 0 {
                    return Err(store_err_to_tokio(StoreError::NotFound(format!(
                        "user {} not found",
                        id_str
                    ))));
                }
                Ok(())
            })
            .await
            .map_err(|e| StoreError::Database(e.to_string()))
    }

    pub(crate) async fn delete_user(&self, id: &UserId) -> Result<bool, StoreError> {
        let id_str = id.0.hyphenated().to_string();

        self.conn()
            .call(move |conn| {
                let changed = conn
                    .execute("DELETE FROM users WHERE id = ?1", rusqlite::params![id_str])
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;
                Ok(changed > 0)
            })
            .await
            .map_err(|e| StoreError::Database(e.to_string()))
    }

    pub(crate) async fn get_root_user(&self) -> Result<Option<User>, StoreError> {
        self.conn()
            .call(move |conn| {
                let mut stmt = conn
                    .prepare(&format!(
                        "SELECT {} FROM users WHERE is_root = 1 LIMIT 1",
                        USER_COLUMNS
                    ))
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;

                let mut rows = stmt
                    .query_map([], row_to_user)
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;

                match rows.next() {
                    Some(Ok(user)) => Ok(Some(user)),
                    Some(Err(e)) => Err(tokio_rusqlite::Error::Rusqlite(e)),
                    None => Ok(None),
                }
            })
            .await
            .map_err(|e| StoreError::Database(e.to_string()))
    }
}

#[async_trait]
impl UserStore for SqliteStore {
    async fn create_user(&self, user: &User) -> Result<(), StoreError> {
        self.create_user(user).await
    }
    async fn get_user(&self, id: &UserId) -> Result<Option<User>, StoreError> {
        self.get_user(id).await
    }
    async fn get_user_by_username(&self, username: &str) -> Result<Option<User>, StoreError> {
        self.get_user_by_username(username).await
    }
    async fn list_users(&self) -> Result<Vec<User>, StoreError> {
        self.list_users().await
    }
    async fn update_user(&self, user: &User) -> Result<(), StoreError> {
        self.update_user(user).await
    }
    async fn delete_user(&self, id: &UserId) -> Result<bool, StoreError> {
        self.delete_user(id).await
    }
    async fn get_root_user(&self) -> Result<Option<User>, StoreError> {
        self.get_root_user().await
    }
}
