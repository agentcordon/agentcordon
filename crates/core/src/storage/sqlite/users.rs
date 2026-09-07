use async_trait::async_trait;

use super::helpers::*;
use super::SqliteStore;

use crate::domain::oidc::OidcProviderId;
use crate::domain::time::format_timestamp;
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
                let created_at = format_timestamp(&user.created_at);
                let updated_at = format_timestamp(&user.updated_at);

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
            .map_err(map_store_error)
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
            .map_err(map_store_error)
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
            .map_err(map_store_error)
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
            .map_err(map_store_error)
    }

    pub(crate) async fn update_user(&self, user: &User) -> Result<(), StoreError> {
        let user = user.clone();

        self.conn()
            .call(move |conn| {
                let id_str = user.id.0.hyphenated().to_string();
                let role_str = serialize_user_role(&user.role);
                let updated_at = format_timestamp(&user.updated_at);

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
            .map_err(map_store_error)
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
            .map_err(map_store_error)
    }

    pub(crate) async fn get_user_by_oidc_identity(
        &self,
        provider_id: &OidcProviderId,
        subject: &str,
    ) -> Result<Option<User>, StoreError> {
        let provider_str = provider_id.0.hyphenated().to_string();
        let subject = subject.to_string();

        self.conn()
            .call(move |conn| {
                let mut stmt = conn
                    .prepare(&format!(
                        "SELECT {} FROM users u \
                         JOIN user_oidc_identities i ON i.user_id = u.id \
                         WHERE i.provider_id = ?1 AND i.subject = ?2",
                        USER_COLUMNS
                            .split(", ")
                            .map(|c| format!("u.{c}"))
                            .collect::<Vec<_>>()
                            .join(", ")
                    ))
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;

                let mut rows = stmt
                    .query_map(rusqlite::params![provider_str, subject], row_to_user)
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;

                match rows.next() {
                    Some(Ok(user)) => Ok(Some(user)),
                    Some(Err(e)) => Err(tokio_rusqlite::Error::Rusqlite(e)),
                    None => Ok(None),
                }
            })
            .await
            .map_err(map_store_error)
    }

    pub(crate) async fn link_oidc_identity(
        &self,
        user_id: &UserId,
        provider_id: &OidcProviderId,
        subject: &str,
    ) -> Result<(), StoreError> {
        let user_str = user_id.0.hyphenated().to_string();
        let provider_str = provider_id.0.hyphenated().to_string();
        let subject = subject.to_string();
        let now = format_timestamp(&chrono::Utc::now());

        self.conn()
            .call(move |conn| {
                // Same triple again is a no-op; a different user for the
                // same (provider, subject) is a conflict, never an overwrite.
                let existing: Option<String> = conn
                    .query_row(
                        "SELECT user_id FROM user_oidc_identities \
                         WHERE provider_id = ?1 AND subject = ?2",
                        rusqlite::params![provider_str, subject],
                        |r| r.get(0),
                    )
                    .ok();
                match existing {
                    Some(u) if u == user_str => Ok(()),
                    Some(_) => Err(store_err_to_tokio(StoreError::Conflict {
                        message: "OIDC identity is already linked to another user".to_string(),
                        existing_id: None,
                    })),
                    None => {
                        conn.execute(
                            "INSERT INTO user_oidc_identities \
                             (provider_id, subject, user_id, created_at) \
                             VALUES (?1, ?2, ?3, ?4)",
                            rusqlite::params![provider_str, subject, user_str, now],
                        )
                        .map_err(tokio_rusqlite::Error::Rusqlite)?;
                        Ok(())
                    }
                }
            })
            .await
            .map_err(map_store_error)
    }
}

#[async_trait]
impl UserStore for SqliteStore {
    async fn get_user_by_oidc_identity(
        &self,
        provider_id: &OidcProviderId,
        subject: &str,
    ) -> Result<Option<User>, StoreError> {
        self.get_user_by_oidc_identity(provider_id, subject).await
    }
    async fn link_oidc_identity(
        &self,
        user_id: &UserId,
        provider_id: &OidcProviderId,
        subject: &str,
    ) -> Result<(), StoreError> {
        self.link_oidc_identity(user_id, provider_id, subject).await
    }
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
}
