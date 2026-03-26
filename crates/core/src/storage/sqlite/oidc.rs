use async_trait::async_trait;

use super::helpers::*;
use super::SqliteStore;

use crate::domain::oidc::{OidcAuthState, OidcProvider, OidcProviderId, OidcProviderSummary};
use crate::error::StoreError;
use crate::storage::OidcStore;

impl SqliteStore {
    pub(crate) async fn create_oidc_provider(
        &self,
        provider: &OidcProvider,
    ) -> Result<(), StoreError> {
        let provider = provider.clone();
        let scopes_json = serialize_scopes(&provider.scopes)?;
        let role_mapping_json = serialize_metadata(&provider.role_mapping)?;
        self.conn()
            .call(move |conn| {
                conn.execute(
                    "INSERT INTO oidc_providers (id, name, issuer_url, client_id, encrypted_client_secret, nonce, scopes, role_mapping, auto_provision, enabled, username_claim, created_at, updated_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
                    rusqlite::params![
                        provider.id.0.to_string(),
                        provider.name,
                        provider.issuer_url,
                        provider.client_id,
                        provider.encrypted_client_secret,
                        provider.nonce,
                        scopes_json,
                        role_mapping_json,
                        provider.auto_provision as i32,
                        provider.enabled as i32,
                        provider.username_claim,
                        provider.created_at.to_rfc3339(),
                        provider.updated_at.to_rfc3339(),
                    ],
                )
                .map_err(tokio_rusqlite::Error::Rusqlite)?;
                Ok(())
            })
            .await
            .map_err(|e| StoreError::Database(e.to_string()))
    }

    pub(crate) async fn get_oidc_provider(
        &self,
        id: &OidcProviderId,
    ) -> Result<Option<OidcProvider>, StoreError> {
        let id_str = id.0.to_string();
        self.conn()
            .call(move |conn| {
                let mut stmt = conn
                    .prepare("SELECT id, name, issuer_url, client_id, encrypted_client_secret, nonce, scopes, role_mapping, auto_provision, enabled, username_claim, created_at, updated_at FROM oidc_providers WHERE id = ?1")
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;
                let mut rows = stmt
                    .query_map(rusqlite::params![id_str], row_to_oidc_provider)
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;
                match rows.next() {
                    Some(Ok(provider)) => Ok(Some(provider)),
                    Some(Err(e)) => Err(tokio_rusqlite::Error::Rusqlite(e)),
                    None => Ok(None),
                }
            })
            .await
            .map_err(|e| StoreError::Database(e.to_string()))
    }

    pub(crate) async fn list_oidc_providers(&self) -> Result<Vec<OidcProviderSummary>, StoreError> {
        self.conn()
            .call(move |conn| {
                let mut stmt = conn
                    .prepare("SELECT id, name, issuer_url, client_id, scopes, role_mapping, auto_provision, enabled, username_claim, created_at, updated_at FROM oidc_providers ORDER BY name ASC")
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;
                let rows = stmt
                    .query_map([], row_to_oidc_provider_summary)
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;
                let mut providers = Vec::new();
                for row in rows {
                    providers.push(row.map_err(tokio_rusqlite::Error::Rusqlite)?);
                }
                Ok(providers)
            })
            .await
            .map_err(|e| StoreError::Database(e.to_string()))
    }

    pub(crate) async fn update_oidc_provider(
        &self,
        provider: &OidcProvider,
    ) -> Result<(), StoreError> {
        let provider = provider.clone();
        let scopes_json = serialize_scopes(&provider.scopes)?;
        let role_mapping_json = serialize_metadata(&provider.role_mapping)?;
        self.conn()
            .call(move |conn| {
                conn.execute(
                    "UPDATE oidc_providers SET name = ?1, issuer_url = ?2, client_id = ?3, encrypted_client_secret = ?4, nonce = ?5, scopes = ?6, role_mapping = ?7, auto_provision = ?8, enabled = ?9, username_claim = ?10, updated_at = ?11 WHERE id = ?12",
                    rusqlite::params![
                        provider.name,
                        provider.issuer_url,
                        provider.client_id,
                        provider.encrypted_client_secret,
                        provider.nonce,
                        scopes_json,
                        role_mapping_json,
                        provider.auto_provision as i32,
                        provider.enabled as i32,
                        provider.username_claim,
                        provider.updated_at.to_rfc3339(),
                        provider.id.0.to_string(),
                    ],
                )
                .map_err(tokio_rusqlite::Error::Rusqlite)?;
                Ok(())
            })
            .await
            .map_err(|e| StoreError::Database(e.to_string()))
    }

    pub(crate) async fn delete_oidc_provider(
        &self,
        id: &OidcProviderId,
    ) -> Result<bool, StoreError> {
        let id_str = id.0.to_string();
        self.conn()
            .call(move |conn| {
                let count = conn
                    .execute(
                        "DELETE FROM oidc_providers WHERE id = ?1",
                        rusqlite::params![id_str],
                    )
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;
                Ok(count > 0)
            })
            .await
            .map_err(|e| StoreError::Database(e.to_string()))
    }

    pub(crate) async fn get_enabled_oidc_providers(
        &self,
    ) -> Result<Vec<OidcProviderSummary>, StoreError> {
        self.conn()
            .call(move |conn| {
                let mut stmt = conn
                    .prepare("SELECT id, name, issuer_url, client_id, scopes, role_mapping, auto_provision, enabled, username_claim, created_at, updated_at FROM oidc_providers WHERE enabled = 1 ORDER BY name ASC")
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;
                let rows = stmt
                    .query_map([], row_to_oidc_provider_summary)
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;
                let mut providers = Vec::new();
                for row in rows {
                    providers.push(row.map_err(tokio_rusqlite::Error::Rusqlite)?);
                }
                Ok(providers)
            })
            .await
            .map_err(|e| StoreError::Database(e.to_string()))
    }

    // ---- OIDC Auth States ----

    pub(crate) async fn create_oidc_auth_state(
        &self,
        auth_state: &OidcAuthState,
    ) -> Result<(), StoreError> {
        let auth_state = auth_state.clone();
        self.conn()
            .call(move |conn| {
                conn.execute(
                    "INSERT INTO oidc_auth_states (state, nonce, provider_id, redirect_uri, created_at, expires_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    rusqlite::params![
                        auth_state.state,
                        auth_state.nonce,
                        auth_state.provider_id.0.to_string(),
                        auth_state.redirect_uri,
                        auth_state.created_at.to_rfc3339(),
                        auth_state.expires_at.to_rfc3339(),
                    ],
                )
                .map_err(tokio_rusqlite::Error::Rusqlite)?;
                Ok(())
            })
            .await
            .map_err(|e| StoreError::Database(e.to_string()))
    }

    pub(crate) async fn get_oidc_auth_state(
        &self,
        state: &str,
    ) -> Result<Option<OidcAuthState>, StoreError> {
        let state = state.to_string();
        self.conn()
            .call(move |conn| {
                let mut stmt = conn
                    .prepare("SELECT state, nonce, provider_id, redirect_uri, created_at, expires_at FROM oidc_auth_states WHERE state = ?1")
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;
                let mut rows = stmt
                    .query_map(rusqlite::params![state], row_to_oidc_auth_state)
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;
                match rows.next() {
                    Some(Ok(auth_state)) => Ok(Some(auth_state)),
                    Some(Err(e)) => Err(tokio_rusqlite::Error::Rusqlite(e)),
                    None => Ok(None),
                }
            })
            .await
            .map_err(|e| StoreError::Database(e.to_string()))
    }

    pub(crate) async fn delete_oidc_auth_state(&self, state: &str) -> Result<bool, StoreError> {
        let state = state.to_string();
        self.conn()
            .call(move |conn| {
                let count = conn
                    .execute(
                        "DELETE FROM oidc_auth_states WHERE state = ?1",
                        rusqlite::params![state],
                    )
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;
                Ok(count > 0)
            })
            .await
            .map_err(|e| StoreError::Database(e.to_string()))
    }

    pub(crate) async fn cleanup_expired_oidc_states(&self) -> Result<u32, StoreError> {
        let now = chrono::Utc::now().to_rfc3339();
        self.conn()
            .call(move |conn| {
                let count = conn
                    .execute(
                        "DELETE FROM oidc_auth_states WHERE expires_at < ?1",
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
impl OidcStore for SqliteStore {
    async fn create_oidc_provider(&self, provider: &OidcProvider) -> Result<(), StoreError> {
        self.create_oidc_provider(provider).await
    }
    async fn get_oidc_provider(
        &self,
        id: &OidcProviderId,
    ) -> Result<Option<OidcProvider>, StoreError> {
        self.get_oidc_provider(id).await
    }
    async fn list_oidc_providers(&self) -> Result<Vec<OidcProviderSummary>, StoreError> {
        self.list_oidc_providers().await
    }
    async fn update_oidc_provider(&self, provider: &OidcProvider) -> Result<(), StoreError> {
        self.update_oidc_provider(provider).await
    }
    async fn delete_oidc_provider(&self, id: &OidcProviderId) -> Result<bool, StoreError> {
        self.delete_oidc_provider(id).await
    }
    async fn get_enabled_oidc_providers(&self) -> Result<Vec<OidcProviderSummary>, StoreError> {
        self.get_enabled_oidc_providers().await
    }
    async fn create_oidc_auth_state(&self, auth_state: &OidcAuthState) -> Result<(), StoreError> {
        self.create_oidc_auth_state(auth_state).await
    }
    async fn get_oidc_auth_state(&self, state: &str) -> Result<Option<OidcAuthState>, StoreError> {
        self.get_oidc_auth_state(state).await
    }
    async fn delete_oidc_auth_state(&self, state: &str) -> Result<bool, StoreError> {
        self.delete_oidc_auth_state(state).await
    }
    async fn cleanup_expired_oidc_states(&self) -> Result<u32, StoreError> {
        self.cleanup_expired_oidc_states().await
    }
}
