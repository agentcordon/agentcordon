use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use super::SqliteStore;
use crate::domain::user::UserId;
use crate::error::StoreError;
use crate::oauth2::types::{
    OAuthAccessToken, OAuthAuthCode, OAuthClient, OAuthConsent, OAuthRefreshToken, OAuthScope,
};
use crate::storage::traits::OAuthStore;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn scopes_to_string(scopes: &[OAuthScope]) -> String {
    scopes
        .iter()
        .map(|s| s.to_string())
        .collect::<Vec<_>>()
        .join(",")
}

fn string_to_scopes(s: &str) -> Vec<OAuthScope> {
    if s.is_empty() {
        return Vec::new();
    }
    s.split(',')
        .filter_map(|part| part.parse().ok())
        .collect()
}

fn redirect_uris_to_string(uris: &[String]) -> String {
    serde_json::to_string(uris).unwrap_or_else(|_| "[]".to_string())
}

fn string_to_redirect_uris(s: &str) -> Vec<String> {
    serde_json::from_str(s).unwrap_or_default()
}

fn parse_datetime(s: &str, col: usize) -> Result<DateTime<Utc>, rusqlite::Error> {
    DateTime::parse_from_rfc3339(s)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(
                col,
                rusqlite::types::Type::Text,
                Box::new(e),
            )
        })
}

fn parse_optional_datetime(
    s: Option<String>,
    col: usize,
) -> Result<Option<DateTime<Utc>>, rusqlite::Error> {
    match s {
        Some(ref val) => parse_datetime(val, col).map(Some),
        None => Ok(None),
    }
}

const CLIENT_COLUMNS: &str =
    "id, client_id, client_secret_hash, workspace_name, public_key_hash, \
     redirect_uris, allowed_scopes, created_by_user, created_at, revoked_at";

fn row_to_oauth_client(row: &rusqlite::Row<'_>) -> Result<OAuthClient, rusqlite::Error> {
    let id_str: String = row.get(0)?;
    let client_id: String = row.get(1)?;
    let client_secret_hash: Option<String> = row.get(2)?;
    let workspace_name: String = row.get(3)?;
    let public_key_hash: String = row.get(4)?;
    let redirect_uris_json: String = row.get(5)?;
    let scopes_str: String = row.get(6)?;
    let created_by_user_str: String = row.get(7)?;
    let created_at_str: String = row.get(8)?;
    let revoked_at_str: Option<String> = row.get(9)?;

    let id = Uuid::parse_str(&id_str).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e))
    })?;
    let created_by_user_uuid = Uuid::parse_str(&created_by_user_str).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(7, rusqlite::types::Type::Text, Box::new(e))
    })?;

    Ok(OAuthClient {
        id,
        client_id,
        client_secret_hash,
        workspace_name,
        public_key_hash,
        redirect_uris: string_to_redirect_uris(&redirect_uris_json),
        allowed_scopes: string_to_scopes(&scopes_str),
        created_by_user: UserId(created_by_user_uuid),
        created_at: parse_datetime(&created_at_str, 8)?,
        revoked_at: parse_optional_datetime(revoked_at_str, 9)?,
    })
}

const AUTH_CODE_COLUMNS: &str =
    "code_hash, client_id, user_id, redirect_uri, scopes, code_challenge, \
     created_at, expires_at, consumed_at";

fn row_to_auth_code(row: &rusqlite::Row<'_>) -> Result<OAuthAuthCode, rusqlite::Error> {
    let code_hash: String = row.get(0)?;
    let client_id: String = row.get(1)?;
    let user_id_str: String = row.get(2)?;
    let redirect_uri: String = row.get(3)?;
    let scopes_str: String = row.get(4)?;
    let code_challenge: Option<String> = row.get(5)?;
    let created_at_str: String = row.get(6)?;
    let expires_at_str: String = row.get(7)?;
    let consumed_at_str: Option<String> = row.get(8)?;

    let user_id = Uuid::parse_str(&user_id_str).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(2, rusqlite::types::Type::Text, Box::new(e))
    })?;

    Ok(OAuthAuthCode {
        code_hash,
        client_id,
        user_id: UserId(user_id),
        redirect_uri,
        scopes: string_to_scopes(&scopes_str),
        code_challenge,
        created_at: parse_datetime(&created_at_str, 6)?,
        expires_at: parse_datetime(&expires_at_str, 7)?,
        consumed_at: parse_optional_datetime(consumed_at_str, 8)?,
    })
}

const ACCESS_TOKEN_COLUMNS: &str =
    "token_hash, client_id, user_id, scopes, created_at, expires_at, revoked_at";

fn row_to_access_token(row: &rusqlite::Row<'_>) -> Result<OAuthAccessToken, rusqlite::Error> {
    let token_hash: String = row.get(0)?;
    let client_id: String = row.get(1)?;
    let user_id_str: String = row.get(2)?;
    let scopes_str: String = row.get(3)?;
    let created_at_str: String = row.get(4)?;
    let expires_at_str: String = row.get(5)?;
    let revoked_at_str: Option<String> = row.get(6)?;

    let user_id = Uuid::parse_str(&user_id_str).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(2, rusqlite::types::Type::Text, Box::new(e))
    })?;

    Ok(OAuthAccessToken {
        token_hash,
        client_id,
        user_id: UserId(user_id),
        scopes: string_to_scopes(&scopes_str),
        created_at: parse_datetime(&created_at_str, 4)?,
        expires_at: parse_datetime(&expires_at_str, 5)?,
        revoked_at: parse_optional_datetime(revoked_at_str, 6)?,
    })
}

const REFRESH_TOKEN_COLUMNS: &str =
    "token_hash, client_id, user_id, scopes, access_token_hash, created_at, expires_at, revoked_at";

fn row_to_refresh_token(row: &rusqlite::Row<'_>) -> Result<OAuthRefreshToken, rusqlite::Error> {
    let token_hash: String = row.get(0)?;
    let client_id: String = row.get(1)?;
    let user_id_str: String = row.get(2)?;
    let scopes_str: String = row.get(3)?;
    let access_token_hash: String = row.get(4)?;
    let created_at_str: String = row.get(5)?;
    let expires_at_str: String = row.get(6)?;
    let revoked_at_str: Option<String> = row.get(7)?;

    let user_id = Uuid::parse_str(&user_id_str).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(2, rusqlite::types::Type::Text, Box::new(e))
    })?;

    Ok(OAuthRefreshToken {
        token_hash,
        client_id,
        user_id: UserId(user_id),
        scopes: string_to_scopes(&scopes_str),
        access_token_hash,
        created_at: parse_datetime(&created_at_str, 5)?,
        expires_at: parse_datetime(&expires_at_str, 6)?,
        revoked_at: parse_optional_datetime(revoked_at_str, 7)?,
    })
}

fn row_to_consent(row: &rusqlite::Row<'_>) -> Result<OAuthConsent, rusqlite::Error> {
    let client_id: String = row.get(0)?;
    let user_id_str: String = row.get(1)?;
    let scopes_str: String = row.get(2)?;
    let granted_at_str: String = row.get(3)?;

    let user_id = Uuid::parse_str(&user_id_str).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(1, rusqlite::types::Type::Text, Box::new(e))
    })?;

    Ok(OAuthConsent {
        client_id,
        user_id: UserId(user_id),
        scopes: string_to_scopes(&scopes_str),
        granted_at: parse_datetime(&granted_at_str, 3)?,
    })
}

// ---------------------------------------------------------------------------
// OAuthStore implementation
// ---------------------------------------------------------------------------

#[async_trait]
impl OAuthStore for SqliteStore {
    async fn create_oauth_client(&self, client: &OAuthClient) -> Result<(), StoreError> {
        let client = client.clone();
        let id_str = client.id.hyphenated().to_string();
        let redirect_uris_json = redirect_uris_to_string(&client.redirect_uris);
        let scopes_str = scopes_to_string(&client.allowed_scopes);
        let created_by_str = client.created_by_user.0.hyphenated().to_string();
        let created_at = client.created_at.to_rfc3339();
        let revoked_at = client.revoked_at.map(|dt| dt.to_rfc3339());

        self.conn()
            .call(move |conn| {
                conn.execute(
                    &format!(
                        "INSERT INTO oauth_clients ({}) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                        CLIENT_COLUMNS
                    ),
                    rusqlite::params![
                        id_str,
                        client.client_id,
                        client.client_secret_hash,
                        client.workspace_name,
                        client.public_key_hash,
                        redirect_uris_json,
                        scopes_str,
                        created_by_str,
                        created_at,
                        revoked_at,
                    ],
                )
                .map_err(tokio_rusqlite::Error::Rusqlite)?;
                Ok(())
            })
            .await
            .map_err(|e| StoreError::Database(e.to_string()))
    }

    async fn get_oauth_client_by_client_id(
        &self,
        client_id: &str,
    ) -> Result<Option<OAuthClient>, StoreError> {
        let client_id = client_id.to_string();
        self.conn()
            .call(move |conn| {
                let mut stmt = conn
                    .prepare(&format!(
                        "SELECT {} FROM oauth_clients WHERE client_id = ?1",
                        CLIENT_COLUMNS
                    ))
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;
                let mut rows = stmt
                    .query_map(rusqlite::params![client_id], row_to_oauth_client)
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;
                match rows.next() {
                    Some(Ok(c)) => Ok(Some(c)),
                    Some(Err(e)) => Err(tokio_rusqlite::Error::Rusqlite(e)),
                    None => Ok(None),
                }
            })
            .await
            .map_err(|e| StoreError::Database(e.to_string()))
    }

    async fn get_oauth_client_by_public_key_hash(
        &self,
        pk_hash: &str,
    ) -> Result<Option<OAuthClient>, StoreError> {
        let pk_hash = pk_hash.to_string();
        self.conn()
            .call(move |conn| {
                let mut stmt = conn
                    .prepare(&format!(
                        "SELECT {} FROM oauth_clients WHERE public_key_hash = ?1",
                        CLIENT_COLUMNS
                    ))
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;
                let mut rows = stmt
                    .query_map(rusqlite::params![pk_hash], row_to_oauth_client)
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;
                match rows.next() {
                    Some(Ok(c)) => Ok(Some(c)),
                    Some(Err(e)) => Err(tokio_rusqlite::Error::Rusqlite(e)),
                    None => Ok(None),
                }
            })
            .await
            .map_err(|e| StoreError::Database(e.to_string()))
    }

    async fn list_oauth_clients(&self) -> Result<Vec<OAuthClient>, StoreError> {
        self.conn()
            .call(move |conn| {
                let mut stmt = conn
                    .prepare(&format!(
                        "SELECT {} FROM oauth_clients ORDER BY created_at",
                        CLIENT_COLUMNS
                    ))
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;
                let rows = stmt
                    .query_map([], row_to_oauth_client)
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;
                let mut clients = Vec::new();
                for row in rows {
                    clients.push(row.map_err(tokio_rusqlite::Error::Rusqlite)?);
                }
                Ok(clients)
            })
            .await
            .map_err(|e| StoreError::Database(e.to_string()))
    }

    async fn revoke_oauth_client(&self, client_id: &str) -> Result<bool, StoreError> {
        let client_id = client_id.to_string();
        let now = Utc::now().to_rfc3339();
        self.conn()
            .call(move |conn| {
                let count = conn
                    .execute(
                        "UPDATE oauth_clients SET revoked_at = ?1 \
                         WHERE client_id = ?2 AND revoked_at IS NULL",
                        rusqlite::params![now, client_id],
                    )
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;
                Ok(count > 0)
            })
            .await
            .map_err(|e| StoreError::Database(e.to_string()))
    }

    async fn delete_oauth_client(&self, client_id: &str) -> Result<bool, StoreError> {
        let client_id = client_id.to_string();
        self.conn()
            .call(move |conn| {
                let tx = conn.transaction().map_err(tokio_rusqlite::Error::Rusqlite)?;
                tx.execute(
                    "DELETE FROM oauth_access_tokens WHERE client_id = ?1",
                    rusqlite::params![client_id],
                )
                .map_err(tokio_rusqlite::Error::Rusqlite)?;
                tx.execute(
                    "DELETE FROM oauth_refresh_tokens WHERE client_id = ?1",
                    rusqlite::params![client_id],
                )
                .map_err(tokio_rusqlite::Error::Rusqlite)?;
                tx.execute(
                    "DELETE FROM oauth_auth_codes WHERE client_id = ?1",
                    rusqlite::params![client_id],
                )
                .map_err(tokio_rusqlite::Error::Rusqlite)?;
                tx.execute(
                    "DELETE FROM oauth_consents WHERE client_id = ?1",
                    rusqlite::params![client_id],
                )
                .map_err(tokio_rusqlite::Error::Rusqlite)?;
                let count = tx
                    .execute(
                        "DELETE FROM oauth_clients WHERE client_id = ?1",
                        rusqlite::params![client_id],
                    )
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;
                tx.commit().map_err(tokio_rusqlite::Error::Rusqlite)?;
                Ok(count > 0)
            })
            .await
            .map_err(|e| StoreError::Database(e.to_string()))
    }

    async fn create_oauth_auth_code(&self, code: &OAuthAuthCode) -> Result<(), StoreError> {
        let code = code.clone();
        let user_id_str = code.user_id.0.hyphenated().to_string();
        let scopes_str = scopes_to_string(&code.scopes);
        let created_at = code.created_at.to_rfc3339();
        let expires_at = code.expires_at.to_rfc3339();
        let consumed_at = code.consumed_at.map(|dt| dt.to_rfc3339());

        self.conn()
            .call(move |conn| {
                conn.execute(
                    &format!(
                        "INSERT INTO oauth_auth_codes ({}) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                        AUTH_CODE_COLUMNS
                    ),
                    rusqlite::params![
                        code.code_hash,
                        code.client_id,
                        user_id_str,
                        code.redirect_uri,
                        scopes_str,
                        code.code_challenge,
                        created_at,
                        expires_at,
                        consumed_at,
                    ],
                )
                .map_err(tokio_rusqlite::Error::Rusqlite)?;
                Ok(())
            })
            .await
            .map_err(|e| StoreError::Database(e.to_string()))
    }

    async fn get_oauth_auth_code(
        &self,
        code_hash: &str,
    ) -> Result<Option<OAuthAuthCode>, StoreError> {
        let code_hash = code_hash.to_string();
        self.conn()
            .call(move |conn| {
                let mut stmt = conn
                    .prepare(&format!(
                        "SELECT {} FROM oauth_auth_codes WHERE code_hash = ?1",
                        AUTH_CODE_COLUMNS
                    ))
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;
                let mut rows = stmt
                    .query_map(rusqlite::params![code_hash], row_to_auth_code)
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;
                match rows.next() {
                    Some(Ok(c)) => Ok(Some(c)),
                    Some(Err(e)) => Err(tokio_rusqlite::Error::Rusqlite(e)),
                    None => Ok(None),
                }
            })
            .await
            .map_err(|e| StoreError::Database(e.to_string()))
    }

    async fn consume_oauth_auth_code(&self, code_hash: &str) -> Result<bool, StoreError> {
        let code_hash = code_hash.to_string();
        let now = Utc::now().to_rfc3339();
        self.conn()
            .call(move |conn| {
                let count = conn
                    .execute(
                        "UPDATE oauth_auth_codes SET consumed_at = ?1 \
                         WHERE code_hash = ?2 AND consumed_at IS NULL",
                        rusqlite::params![now, code_hash],
                    )
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;
                Ok(count > 0)
            })
            .await
            .map_err(|e| StoreError::Database(e.to_string()))
    }

    async fn create_oauth_access_token(&self, token: &OAuthAccessToken) -> Result<(), StoreError> {
        let token = token.clone();
        let user_id_str = token.user_id.0.hyphenated().to_string();
        let scopes_str = scopes_to_string(&token.scopes);
        let created_at = token.created_at.to_rfc3339();
        let expires_at = token.expires_at.to_rfc3339();
        let revoked_at = token.revoked_at.map(|dt| dt.to_rfc3339());

        self.conn()
            .call(move |conn| {
                conn.execute(
                    &format!(
                        "INSERT INTO oauth_access_tokens ({}) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                        ACCESS_TOKEN_COLUMNS
                    ),
                    rusqlite::params![
                        token.token_hash,
                        token.client_id,
                        user_id_str,
                        scopes_str,
                        created_at,
                        expires_at,
                        revoked_at,
                    ],
                )
                .map_err(tokio_rusqlite::Error::Rusqlite)?;
                Ok(())
            })
            .await
            .map_err(|e| StoreError::Database(e.to_string()))
    }

    async fn get_oauth_access_token(
        &self,
        token_hash: &str,
    ) -> Result<Option<OAuthAccessToken>, StoreError> {
        let token_hash = token_hash.to_string();
        self.conn()
            .call(move |conn| {
                let mut stmt = conn
                    .prepare(&format!(
                        "SELECT {} FROM oauth_access_tokens WHERE token_hash = ?1",
                        ACCESS_TOKEN_COLUMNS
                    ))
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;
                let mut rows = stmt
                    .query_map(rusqlite::params![token_hash], row_to_access_token)
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;
                match rows.next() {
                    Some(Ok(t)) => Ok(Some(t)),
                    Some(Err(e)) => Err(tokio_rusqlite::Error::Rusqlite(e)),
                    None => Ok(None),
                }
            })
            .await
            .map_err(|e| StoreError::Database(e.to_string()))
    }

    async fn revoke_oauth_access_token(&self, token_hash: &str) -> Result<bool, StoreError> {
        let token_hash = token_hash.to_string();
        let now = Utc::now().to_rfc3339();
        self.conn()
            .call(move |conn| {
                let count = conn
                    .execute(
                        "UPDATE oauth_access_tokens SET revoked_at = ?1 \
                         WHERE token_hash = ?2 AND revoked_at IS NULL",
                        rusqlite::params![now, token_hash],
                    )
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;
                Ok(count > 0)
            })
            .await
            .map_err(|e| StoreError::Database(e.to_string()))
    }

    async fn revoke_access_tokens_for_client(&self, client_id: &str) -> Result<u32, StoreError> {
        let client_id = client_id.to_string();
        let now = Utc::now().to_rfc3339();
        self.conn()
            .call(move |conn| {
                let count = conn
                    .execute(
                        "UPDATE oauth_access_tokens SET revoked_at = ?1 \
                         WHERE client_id = ?2 AND revoked_at IS NULL",
                        rusqlite::params![now, client_id],
                    )
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;
                Ok(count as u32)
            })
            .await
            .map_err(|e| StoreError::Database(e.to_string()))
    }

    async fn create_oauth_refresh_token(
        &self,
        token: &OAuthRefreshToken,
    ) -> Result<(), StoreError> {
        let token = token.clone();
        let user_id_str = token.user_id.0.hyphenated().to_string();
        let scopes_str = scopes_to_string(&token.scopes);
        let created_at = token.created_at.to_rfc3339();
        let expires_at = token.expires_at.to_rfc3339();
        let revoked_at = token.revoked_at.map(|dt| dt.to_rfc3339());

        self.conn()
            .call(move |conn| {
                conn.execute(
                    &format!(
                        "INSERT INTO oauth_refresh_tokens ({}) \
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                        REFRESH_TOKEN_COLUMNS
                    ),
                    rusqlite::params![
                        token.token_hash,
                        token.client_id,
                        user_id_str,
                        scopes_str,
                        token.access_token_hash,
                        created_at,
                        expires_at,
                        revoked_at,
                    ],
                )
                .map_err(tokio_rusqlite::Error::Rusqlite)?;
                Ok(())
            })
            .await
            .map_err(|e| StoreError::Database(e.to_string()))
    }

    async fn get_oauth_refresh_token(
        &self,
        token_hash: &str,
    ) -> Result<Option<OAuthRefreshToken>, StoreError> {
        let token_hash = token_hash.to_string();
        self.conn()
            .call(move |conn| {
                let mut stmt = conn
                    .prepare(&format!(
                        "SELECT {} FROM oauth_refresh_tokens WHERE token_hash = ?1",
                        REFRESH_TOKEN_COLUMNS
                    ))
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;
                let mut rows = stmt
                    .query_map(rusqlite::params![token_hash], row_to_refresh_token)
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;
                match rows.next() {
                    Some(Ok(t)) => Ok(Some(t)),
                    Some(Err(e)) => Err(tokio_rusqlite::Error::Rusqlite(e)),
                    None => Ok(None),
                }
            })
            .await
            .map_err(|e| StoreError::Database(e.to_string()))
    }

    async fn revoke_oauth_refresh_token(&self, token_hash: &str) -> Result<bool, StoreError> {
        let token_hash = token_hash.to_string();
        let now = Utc::now().to_rfc3339();
        self.conn()
            .call(move |conn| {
                let count = conn
                    .execute(
                        "UPDATE oauth_refresh_tokens SET revoked_at = ?1 \
                         WHERE token_hash = ?2 AND revoked_at IS NULL",
                        rusqlite::params![now, token_hash],
                    )
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;
                Ok(count > 0)
            })
            .await
            .map_err(|e| StoreError::Database(e.to_string()))
    }

    async fn revoke_refresh_tokens_for_client(&self, client_id: &str) -> Result<u32, StoreError> {
        let client_id = client_id.to_string();
        let now = Utc::now().to_rfc3339();
        self.conn()
            .call(move |conn| {
                let count = conn
                    .execute(
                        "UPDATE oauth_refresh_tokens SET revoked_at = ?1 \
                         WHERE client_id = ?2 AND revoked_at IS NULL",
                        rusqlite::params![now, client_id],
                    )
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;
                Ok(count as u32)
            })
            .await
            .map_err(|e| StoreError::Database(e.to_string()))
    }

    async fn revoke_access_tokens_for_refresh_token(
        &self,
        refresh_token_hash: &str,
    ) -> Result<u32, StoreError> {
        let refresh_token_hash = refresh_token_hash.to_string();
        let now = Utc::now().to_rfc3339();
        self.conn()
            .call(move |conn| {
                let access_hash: Option<String> = conn
                    .query_row(
                        "SELECT access_token_hash FROM oauth_refresh_tokens WHERE token_hash = ?1",
                        rusqlite::params![refresh_token_hash],
                        |row| row.get(0),
                    )
                    .ok();

                match access_hash {
                    Some(hash) => {
                        let count = conn
                            .execute(
                                "UPDATE oauth_access_tokens SET revoked_at = ?1 \
                                 WHERE token_hash = ?2 AND revoked_at IS NULL",
                                rusqlite::params![now, hash],
                            )
                            .map_err(tokio_rusqlite::Error::Rusqlite)?;
                        Ok(count as u32)
                    }
                    None => Ok(0),
                }
            })
            .await
            .map_err(|e| StoreError::Database(e.to_string()))
    }

    async fn get_oauth_consent(
        &self,
        client_id: &str,
        user_id: &UserId,
    ) -> Result<Option<OAuthConsent>, StoreError> {
        let client_id = client_id.to_string();
        let user_id_str = user_id.0.hyphenated().to_string();
        self.conn()
            .call(move |conn| {
                let mut stmt = conn
                    .prepare(
                        "SELECT client_id, user_id, scopes, granted_at \
                         FROM oauth_consents WHERE client_id = ?1 AND user_id = ?2",
                    )
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;
                let mut rows = stmt
                    .query_map(rusqlite::params![client_id, user_id_str], row_to_consent)
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;
                match rows.next() {
                    Some(Ok(c)) => Ok(Some(c)),
                    Some(Err(e)) => Err(tokio_rusqlite::Error::Rusqlite(e)),
                    None => Ok(None),
                }
            })
            .await
            .map_err(|e| StoreError::Database(e.to_string()))
    }

    async fn upsert_oauth_consent(&self, consent: &OAuthConsent) -> Result<(), StoreError> {
        let consent = consent.clone();
        let user_id_str = consent.user_id.0.hyphenated().to_string();
        let scopes_str = scopes_to_string(&consent.scopes);
        let granted_at = consent.granted_at.to_rfc3339();

        self.conn()
            .call(move |conn| {
                conn.execute(
                    "INSERT OR REPLACE INTO oauth_consents (client_id, user_id, scopes, granted_at) \
                     VALUES (?1, ?2, ?3, ?4)",
                    rusqlite::params![consent.client_id, user_id_str, scopes_str, granted_at],
                )
                .map_err(tokio_rusqlite::Error::Rusqlite)?;
                Ok(())
            })
            .await
            .map_err(|e| StoreError::Database(e.to_string()))
    }
}
