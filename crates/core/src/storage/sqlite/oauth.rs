use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use super::helpers::map_store_error;
use super::SqliteStore;
use crate::domain::time::{format_timestamp, parse_timestamp};
use crate::domain::user::UserId;
use crate::domain::workspace::WorkspaceId;
use crate::error::StoreError;
use crate::oauth2::types::{
    BearerResolution, OAuthAccessToken, OAuthAuthCode, OAuthClient, OAuthConsent,
    OAuthRefreshToken, OAuthScope,
};
use crate::storage::shared::WORKSPACE_COLUMNS;
use crate::storage::sqlite::helpers::row_to_workspace;
use crate::storage::traits::OAuthStore;
use rusqlite::OptionalExtension;

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
    s.split(',').filter_map(|part| part.parse().ok()).collect()
}

fn redirect_uris_to_string(uris: &[String]) -> String {
    serde_json::to_string(uris).unwrap_or_else(|_| "[]".to_string())
}

fn string_to_redirect_uris(s: &str) -> Vec<String> {
    serde_json::from_str(s).unwrap_or_default()
}

fn parse_datetime(s: &str, col: usize) -> Result<DateTime<Utc>, rusqlite::Error> {
    parse_timestamp(s).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(col, rusqlite::types::Type::Text, Box::new(e))
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

const CLIENT_COLUMNS: &str = "id, client_id, client_secret_hash, workspace_name, public_key_hash, \
     redirect_uris, allowed_scopes, created_by_user, created_at, revoked_at, workspace_id";

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
    let workspace_id_str: Option<String> = row.get(10)?;

    let id = Uuid::parse_str(&id_str).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e))
    })?;
    let created_by_user_uuid = Uuid::parse_str(&created_by_user_str).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(7, rusqlite::types::Type::Text, Box::new(e))
    })?;
    let workspace_id = workspace_id_str
        .map(|s| Uuid::parse_str(&s).map(WorkspaceId))
        .transpose()
        .map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(10, rusqlite::types::Type::Text, Box::new(e))
        })?;

    Ok(OAuthClient {
        id,
        client_id,
        client_secret_hash,
        workspace_name,
        public_key_hash,
        workspace_id,
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
    "token_hash, client_id, user_id, scopes, access_token_hash, created_at, expires_at, revoked_at, family_id";

fn row_to_refresh_token(row: &rusqlite::Row<'_>) -> Result<OAuthRefreshToken, rusqlite::Error> {
    let token_hash: String = row.get(0)?;
    let client_id: String = row.get(1)?;
    let user_id_str: String = row.get(2)?;
    let scopes_str: String = row.get(3)?;
    let access_token_hash: String = row.get(4)?;
    let created_at_str: String = row.get(5)?;
    let expires_at_str: String = row.get(6)?;
    let revoked_at_str: Option<String> = row.get(7)?;
    // Migration 015 backfills family_id = token_hash; the fallback only
    // matters for a row inserted between the ALTER and the UPDATE.
    let family_id: String = row
        .get::<_, Option<String>>(8)?
        .unwrap_or_else(|| token_hash.clone());

    let user_id = Uuid::parse_str(&user_id_str).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(2, rusqlite::types::Type::Text, Box::new(e))
    })?;

    Ok(OAuthRefreshToken {
        token_hash,
        client_id,
        user_id: UserId(user_id),
        scopes: string_to_scopes(&scopes_str),
        access_token_hash,
        family_id,
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
// Row writers shared by the single-statement methods and the transactions
// that mint or replace several rows at once. Each takes a `Connection`; a
// `Transaction` derefs to one.
// ---------------------------------------------------------------------------

fn insert_oauth_client(conn: &rusqlite::Connection, client: &OAuthClient) -> rusqlite::Result<()> {
    conn.execute(
        &format!(
            "INSERT INTO oauth_clients ({}) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            CLIENT_COLUMNS
        ),
        rusqlite::params![
            client.id.hyphenated().to_string(),
            client.client_id,
            client.client_secret_hash,
            client.workspace_name,
            client.public_key_hash,
            redirect_uris_to_string(&client.redirect_uris),
            scopes_to_string(&client.allowed_scopes),
            client.created_by_user.0.hyphenated().to_string(),
            format_timestamp(&client.created_at),
            client.revoked_at.map(|dt| format_timestamp(&dt)),
            client
                .workspace_id
                .as_ref()
                .map(|w| w.0.hyphenated().to_string()),
        ],
    )?;
    Ok(())
}

/// Delete a client and every row that refers to it. Returns whether the
/// client existed.
fn delete_oauth_client_rows(
    conn: &rusqlite::Connection,
    client_id: &str,
) -> rusqlite::Result<bool> {
    for table in [
        "oauth_access_tokens",
        "oauth_refresh_tokens",
        "oauth_auth_codes",
        "oauth_consents",
    ] {
        conn.execute(
            &format!("DELETE FROM {table} WHERE client_id = ?1"),
            rusqlite::params![client_id],
        )?;
    }
    let count = conn.execute(
        "DELETE FROM oauth_clients WHERE client_id = ?1",
        rusqlite::params![client_id],
    )?;
    Ok(count > 0)
}

/// The token inherits its client's workspace binding.
fn insert_access_token(
    conn: &rusqlite::Connection,
    token: &OAuthAccessToken,
) -> rusqlite::Result<()> {
    conn.execute(
        &format!(
            "INSERT INTO oauth_access_tokens ({}, workspace_id) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, \
                     (SELECT workspace_id FROM oauth_clients WHERE client_id = ?2))",
            ACCESS_TOKEN_COLUMNS
        ),
        rusqlite::params![
            token.token_hash,
            token.client_id,
            token.user_id.0.hyphenated().to_string(),
            scopes_to_string(&token.scopes),
            format_timestamp(&token.created_at),
            format_timestamp(&token.expires_at),
            token.revoked_at.map(|dt| format_timestamp(&dt)),
        ],
    )?;
    Ok(())
}

/// The token inherits its client's workspace binding.
fn insert_refresh_token(
    conn: &rusqlite::Connection,
    token: &OAuthRefreshToken,
) -> rusqlite::Result<()> {
    conn.execute(
        &format!(
            "INSERT INTO oauth_refresh_tokens ({}, workspace_id) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, \
                     (SELECT workspace_id FROM oauth_clients WHERE client_id = ?2))",
            REFRESH_TOKEN_COLUMNS
        ),
        rusqlite::params![
            token.token_hash,
            token.client_id,
            token.user_id.0.hyphenated().to_string(),
            scopes_to_string(&token.scopes),
            token.access_token_hash,
            format_timestamp(&token.created_at),
            format_timestamp(&token.expires_at),
            token.revoked_at.map(|dt| format_timestamp(&dt)),
            token.family_id,
        ],
    )?;
    Ok(())
}

/// Mint an access token and its refresh token, inside the transaction that
/// consumes the device code or auth code paying for them.
pub(super) fn mint_token_pair(
    conn: &rusqlite::Connection,
    access: &OAuthAccessToken,
    refresh: &OAuthRefreshToken,
) -> rusqlite::Result<()> {
    insert_access_token(conn, access)?;
    insert_refresh_token(conn, refresh)
}

// ---------------------------------------------------------------------------
// OAuthStore implementation
// ---------------------------------------------------------------------------

#[async_trait]
impl OAuthStore for SqliteStore {
    async fn create_oauth_client(&self, client: &OAuthClient) -> Result<(), StoreError> {
        let client = client.clone();
        self.conn()
            .call(move |conn| Ok(insert_oauth_client(conn, &client)?))
            .await
            .map_err(map_store_error)
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
            .map_err(map_store_error)
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
            .map_err(map_store_error)
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
            .map_err(map_store_error)
    }

    async fn revoke_oauth_client(&self, client_id: &str) -> Result<bool, StoreError> {
        let client_id = client_id.to_string();
        let now = format_timestamp(&Utc::now());
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
            .map_err(map_store_error)
    }

    async fn delete_oauth_client(&self, client_id: &str) -> Result<bool, StoreError> {
        let client_id = client_id.to_string();
        self.conn()
            .call(move |conn| {
                let tx = conn.transaction()?;
                let existed = delete_oauth_client_rows(&tx, &client_id)?;
                tx.commit()?;
                Ok(existed)
            })
            .await
            .map_err(map_store_error)
    }

    async fn replace_oauth_client(
        &self,
        client: &OAuthClient,
    ) -> Result<Option<String>, StoreError> {
        let client = client.clone();
        self.conn()
            .call(move |conn| {
                let tx =
                    conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
                let previous: Option<String> = tx
                    .query_row(
                        "SELECT client_id FROM oauth_clients WHERE public_key_hash = ?1",
                        rusqlite::params![client.public_key_hash],
                        |row| row.get(0),
                    )
                    .optional()?;
                if let Some(previous) = previous.as_deref() {
                    delete_oauth_client_rows(&tx, previous)?;
                }
                insert_oauth_client(&tx, &client)?;
                tx.commit()?;
                Ok(previous)
            })
            .await
            .map_err(map_store_error)
    }

    async fn create_oauth_auth_code(&self, code: &OAuthAuthCode) -> Result<(), StoreError> {
        let code = code.clone();
        let user_id_str = code.user_id.0.hyphenated().to_string();
        let scopes_str = scopes_to_string(&code.scopes);
        let created_at = format_timestamp(&code.created_at);
        let expires_at = format_timestamp(&code.expires_at);
        let consumed_at = code.consumed_at.map(|dt| format_timestamp(&dt));

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
            .map_err(map_store_error)
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
            .map_err(map_store_error)
    }

    async fn consume_oauth_auth_code(&self, code_hash: &str) -> Result<bool, StoreError> {
        let code_hash = code_hash.to_string();
        let now = format_timestamp(&Utc::now());
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
            .map_err(map_store_error)
    }

    async fn consume_oauth_auth_code_and_issue_tokens(
        &self,
        code_hash: &str,
        access: &OAuthAccessToken,
        refresh: &OAuthRefreshToken,
    ) -> Result<bool, StoreError> {
        let code_hash = code_hash.to_string();
        let now = format_timestamp(&Utc::now());
        let access = access.clone();
        let refresh = refresh.clone();
        self.conn()
            .call(move |conn| {
                let tx =
                    conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
                // Compare-and-swap on `consumed_at IS NULL`: a second caller
                // changes no row and the transaction ends without a mint.
                let count = tx.execute(
                    "UPDATE oauth_auth_codes SET consumed_at = ?1 \
                     WHERE code_hash = ?2 AND consumed_at IS NULL",
                    rusqlite::params![now, code_hash],
                )?;
                if count == 0 {
                    return Ok(false);
                }
                mint_token_pair(&tx, &access, &refresh)?;
                tx.commit()?;
                Ok(true)
            })
            .await
            .map_err(map_store_error)
    }

    async fn create_oauth_access_token(&self, token: &OAuthAccessToken) -> Result<(), StoreError> {
        let token = token.clone();
        self.conn()
            .call(move |conn| Ok(insert_access_token(conn, &token)?))
            .await
            .map_err(map_store_error)
    }

    async fn resolve_bearer(
        &self,
        token_hash: &str,
    ) -> Result<Option<BearerResolution>, StoreError> {
        let token_hash = token_hash.to_string();
        self.conn()
            .call(move |conn| {
                // One round trip to the store thread: token, its client, and
                // the bound workspace. The token's own binding wins; a token
                // issued before the binding existed falls back to its client's.
                let found = conn
                    .query_row(
                        &format!(
                            "SELECT {}, workspace_id FROM oauth_access_tokens WHERE token_hash = ?1",
                            ACCESS_TOKEN_COLUMNS
                        ),
                        rusqlite::params![token_hash],
                        |row| {
                            let token = row_to_access_token(row)?;
                            let workspace_id: Option<String> = row.get(7)?;
                            Ok((token, workspace_id))
                        },
                    )
                    .optional()
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;
                let Some((token, token_workspace_id)) = found else {
                    return Ok(None);
                };
                let Some(client) = conn
                    .query_row(
                        &format!(
                            "SELECT {} FROM oauth_clients WHERE client_id = ?1",
                            CLIENT_COLUMNS
                        ),
                        rusqlite::params![token.client_id],
                        row_to_oauth_client,
                    )
                    .optional()
                    .map_err(tokio_rusqlite::Error::Rusqlite)?
                else {
                    return Ok(None);
                };
                let workspace_id = token_workspace_id
                    .or_else(|| client.workspace_id.as_ref().map(|w| w.0.hyphenated().to_string()));
                let workspace = match workspace_id {
                    Some(id) => conn
                        .query_row(
                            &format!("SELECT {} FROM workspaces WHERE id = ?1", WORKSPACE_COLUMNS),
                            rusqlite::params![id],
                            row_to_workspace,
                        )
                        .optional()
                        .map_err(tokio_rusqlite::Error::Rusqlite)?,
                    None => None,
                };
                Ok(Some(BearerResolution {
                    token,
                    client,
                    workspace,
                }))
            })
            .await
            .map_err(map_store_error)
    }

    async fn bind_oauth_client_workspace(
        &self,
        client_id: &str,
        workspace_id: &WorkspaceId,
    ) -> Result<(), StoreError> {
        let client_id = client_id.to_string();
        let workspace_id = workspace_id.0.hyphenated().to_string();
        self.conn()
            .call(move |conn| {
                let tx = conn
                    .transaction()
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;
                tx.execute(
                    "UPDATE oauth_clients SET workspace_id = ?1 WHERE client_id = ?2",
                    rusqlite::params![workspace_id, client_id],
                )
                .map_err(tokio_rusqlite::Error::Rusqlite)?;
                tx.execute(
                    "UPDATE oauth_access_tokens SET workspace_id = ?1 WHERE client_id = ?2",
                    rusqlite::params![workspace_id, client_id],
                )
                .map_err(tokio_rusqlite::Error::Rusqlite)?;
                tx.execute(
                    "UPDATE oauth_refresh_tokens SET workspace_id = ?1 WHERE client_id = ?2",
                    rusqlite::params![workspace_id, client_id],
                )
                .map_err(tokio_rusqlite::Error::Rusqlite)?;
                tx.commit().map_err(tokio_rusqlite::Error::Rusqlite)?;
                Ok(())
            })
            .await
            .map_err(map_store_error)
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
            .map_err(map_store_error)
    }

    async fn revoke_oauth_access_token(&self, token_hash: &str) -> Result<bool, StoreError> {
        let token_hash = token_hash.to_string();
        let now = format_timestamp(&Utc::now());
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
            .map_err(map_store_error)
    }

    async fn revoke_access_tokens_for_client(&self, client_id: &str) -> Result<u32, StoreError> {
        let client_id = client_id.to_string();
        let now = format_timestamp(&Utc::now());
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
            .map_err(map_store_error)
    }

    async fn create_oauth_refresh_token(
        &self,
        token: &OAuthRefreshToken,
    ) -> Result<(), StoreError> {
        let token = token.clone();
        self.conn()
            .call(move |conn| Ok(insert_refresh_token(conn, &token)?))
            .await
            .map_err(map_store_error)
    }

    async fn revoke_oauth_refresh_token_family(&self, family_id: &str) -> Result<u32, StoreError> {
        let family_id = family_id.to_string();
        let now = format_timestamp(&Utc::now());
        self.conn()
            .call(move |conn| {
                let tx = conn
                    .transaction()
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;
                // Access tokens minted alongside any member of the family.
                tx.execute(
                    "UPDATE oauth_access_tokens SET revoked_at = ?1 \
                     WHERE revoked_at IS NULL AND token_hash IN \
                       (SELECT access_token_hash FROM oauth_refresh_tokens WHERE family_id = ?2)",
                    rusqlite::params![now, family_id],
                )
                .map_err(tokio_rusqlite::Error::Rusqlite)?;
                let count = tx
                    .execute(
                        "UPDATE oauth_refresh_tokens SET revoked_at = ?1 \
                         WHERE family_id = ?2 AND revoked_at IS NULL",
                        rusqlite::params![now, family_id],
                    )
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;
                tx.commit().map_err(tokio_rusqlite::Error::Rusqlite)?;
                Ok(count as u32)
            })
            .await
            .map_err(map_store_error)
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
            .map_err(map_store_error)
    }

    async fn revoke_oauth_refresh_token(&self, token_hash: &str) -> Result<bool, StoreError> {
        let token_hash = token_hash.to_string();
        let now = format_timestamp(&Utc::now());
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
            .map_err(map_store_error)
    }

    async fn revoke_refresh_tokens_for_client(&self, client_id: &str) -> Result<u32, StoreError> {
        let client_id = client_id.to_string();
        let now = format_timestamp(&Utc::now());
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
            .map_err(map_store_error)
    }

    async fn revoke_access_tokens_for_refresh_token(
        &self,
        refresh_token_hash: &str,
    ) -> Result<u32, StoreError> {
        let refresh_token_hash = refresh_token_hash.to_string();
        let now = format_timestamp(&Utc::now());
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
            .map_err(map_store_error)
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
            .map_err(map_store_error)
    }

    async fn upsert_oauth_consent(&self, consent: &OAuthConsent) -> Result<(), StoreError> {
        let consent = consent.clone();
        let user_id_str = consent.user_id.0.hyphenated().to_string();
        let scopes_str = scopes_to_string(&consent.scopes);
        let granted_at = format_timestamp(&consent.granted_at);

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
            .map_err(map_store_error)
    }

    async fn delete_consent_and_revoke_tokens(
        &self,
        client_id: &str,
        user_id: &UserId,
    ) -> Result<Option<crate::storage::traits::ConsentRevocationCounts>, StoreError> {
        let client_id = client_id.to_string();
        let user_id_str = user_id.0.hyphenated().to_string();
        let revoked_at = format_timestamp(&chrono::Utc::now());
        self.conn()
            .call(move |conn| {
                let tx = conn
                    .transaction()
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;
                let consent_deleted = tx
                    .execute(
                        "DELETE FROM oauth_consents WHERE client_id = ?1 AND user_id = ?2",
                        rusqlite::params![client_id, user_id_str],
                    )
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;
                if consent_deleted == 0 {
                    tx.commit().map_err(tokio_rusqlite::Error::Rusqlite)?;
                    return Ok(None);
                }
                let access_revoked = tx
                    .execute(
                        "UPDATE oauth_access_tokens SET revoked_at = ?3 \
                         WHERE client_id = ?1 AND user_id = ?2 AND revoked_at IS NULL",
                        rusqlite::params![client_id, user_id_str, revoked_at],
                    )
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;
                let refresh_revoked = tx
                    .execute(
                        "UPDATE oauth_refresh_tokens SET revoked_at = ?3 \
                         WHERE client_id = ?1 AND user_id = ?2 AND revoked_at IS NULL",
                        rusqlite::params![client_id, user_id_str, revoked_at],
                    )
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;
                tx.commit().map_err(tokio_rusqlite::Error::Rusqlite)?;
                Ok(Some(crate::storage::traits::ConsentRevocationCounts {
                    access_tokens: access_revoked as u32,
                    refresh_tokens: refresh_revoked as u32,
                }))
            })
            .await
            .map_err(map_store_error)
    }

    async fn list_oauth_consents_for_client(
        &self,
        client_id: &str,
    ) -> Result<Vec<OAuthConsent>, StoreError> {
        let client_id = client_id.to_string();
        self.conn()
            .call(move |conn| {
                let mut stmt = conn
                    .prepare(
                        "SELECT client_id, user_id, scopes, granted_at \
                         FROM oauth_consents WHERE client_id = ?1",
                    )
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;
                let rows = stmt
                    .query_map(rusqlite::params![client_id], row_to_consent)
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;
                let mut out = Vec::new();
                for r in rows {
                    out.push(r.map_err(tokio_rusqlite::Error::Rusqlite)?);
                }
                Ok(out)
            })
            .await
            .map_err(map_store_error)
    }
}
