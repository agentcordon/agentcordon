use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use super::SqliteStore;
use crate::domain::mcp_oauth::McpOAuthState;
use crate::domain::user::UserId;
use crate::domain::workspace::WorkspaceId;
use crate::error::StoreError;
use crate::storage::McpOAuthStore;

impl SqliteStore {
    pub(crate) async fn create_mcp_oauth_state(
        &self,
        state: &McpOAuthState,
    ) -> Result<(), StoreError> {
        let state = state.clone();
        self.conn()
            .call(move |conn| {
                conn.execute(
                    "INSERT INTO mcp_oauth_states (state, template_key, workspace_id, user_id, \
                     redirect_uri, code_verifier, created_at, expires_at, authorization_server_url) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                    rusqlite::params![
                        state.state,
                        state.template_key,
                        state.workspace_id.0.to_string(),
                        state.user_id.0.to_string(),
                        state.redirect_uri,
                        state.code_verifier,
                        state.created_at.to_rfc3339(),
                        state.expires_at.to_rfc3339(),
                        state.authorization_server_url,
                    ],
                )
                .map_err(tokio_rusqlite::Error::Rusqlite)?;
                Ok(())
            })
            .await
            .map_err(|e| StoreError::Database(e.to_string()))
    }

    pub(crate) async fn consume_mcp_oauth_state(
        &self,
        state_param: &str,
    ) -> Result<Option<McpOAuthState>, StoreError> {
        let state_param = state_param.to_string();
        self.conn()
            .call(move |conn| {
                // SELECT then DELETE in a single transaction for atomicity.
                let tx = conn
                    .transaction()
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;
                let result = {
                    let mut stmt = tx
                        .prepare(
                            "SELECT state, template_key, workspace_id, user_id, \
                             redirect_uri, code_verifier, created_at, expires_at, \
                             authorization_server_url \
                             FROM mcp_oauth_states WHERE state = ?1",
                        )
                        .map_err(tokio_rusqlite::Error::Rusqlite)?;
                    let mut rows = stmt
                        .query_map(rusqlite::params![state_param], row_to_mcp_oauth_state)
                        .map_err(tokio_rusqlite::Error::Rusqlite)?;
                    match rows.next() {
                        Some(Ok(s)) => Some(s),
                        Some(Err(e)) => return Err(tokio_rusqlite::Error::Rusqlite(e)),
                        None => None,
                    }
                };

                if result.is_some() {
                    tx.execute(
                        "DELETE FROM mcp_oauth_states WHERE state = ?1",
                        rusqlite::params![state_param],
                    )
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;
                }

                tx.commit().map_err(tokio_rusqlite::Error::Rusqlite)?;
                Ok(result)
            })
            .await
            .map_err(|e| StoreError::Database(e.to_string()))
    }

    pub(crate) async fn cleanup_expired_mcp_oauth_states(&self) -> Result<u32, StoreError> {
        let now = chrono::Utc::now().to_rfc3339();
        self.conn()
            .call(move |conn| {
                let count = conn
                    .execute(
                        "DELETE FROM mcp_oauth_states WHERE expires_at < ?1",
                        rusqlite::params![now],
                    )
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;
                Ok(count as u32)
            })
            .await
            .map_err(|e| StoreError::Database(e.to_string()))
    }
}

#[async_trait]
impl McpOAuthStore for SqliteStore {
    async fn create_mcp_oauth_state(&self, state: &McpOAuthState) -> Result<(), StoreError> {
        self.create_mcp_oauth_state(state).await
    }
    async fn consume_mcp_oauth_state(
        &self,
        state: &str,
    ) -> Result<Option<McpOAuthState>, StoreError> {
        self.consume_mcp_oauth_state(state).await
    }
    async fn cleanup_expired_mcp_oauth_states(&self) -> Result<u32, StoreError> {
        self.cleanup_expired_mcp_oauth_states().await
    }
}

/// Convert a SQLite row to an `McpOAuthState`.
fn row_to_mcp_oauth_state(row: &rusqlite::Row<'_>) -> Result<McpOAuthState, rusqlite::Error> {
    let state: String = row.get(0)?;
    let template_key: String = row.get(1)?;
    let workspace_id_str: String = row.get(2)?;
    let user_id_str: String = row.get(3)?;
    let redirect_uri: String = row.get(4)?;
    let code_verifier: Option<String> = row.get(5)?;
    let created_at_str: String = row.get(6)?;
    let expires_at_str: String = row.get(7)?;
    let authorization_server_url: Option<String> = row.get(8)?;

    let workspace_id = Uuid::parse_str(&workspace_id_str).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(2, rusqlite::types::Type::Text, Box::new(e))
    })?;
    let user_id = Uuid::parse_str(&user_id_str).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(3, rusqlite::types::Type::Text, Box::new(e))
    })?;
    let created_at = DateTime::parse_from_rfc3339(&created_at_str)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(6, rusqlite::types::Type::Text, Box::new(e))
        })?;
    let expires_at = DateTime::parse_from_rfc3339(&expires_at_str)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(7, rusqlite::types::Type::Text, Box::new(e))
        })?;

    Ok(McpOAuthState {
        state,
        template_key,
        workspace_id: WorkspaceId(workspace_id),
        user_id: UserId(user_id),
        redirect_uri,
        code_verifier,
        authorization_server_url,
        created_at,
        expires_at,
    })
}
