use async_trait::async_trait;
use chrono::Utc;

use super::{db_err, OidcAuthStateRow, OidcProviderRow, OidcProviderSummaryRow, PostgresStore};
use crate::domain::oidc::{OidcAuthState, OidcProvider, OidcProviderId, OidcProviderSummary};
use crate::error::StoreError;
use crate::storage::OidcStore;

#[async_trait]
impl OidcStore for PostgresStore {
    async fn create_oidc_provider(&self, provider: &OidcProvider) -> Result<(), StoreError> {
        let scopes = serde_json::to_value(&provider.scopes).unwrap_or_default();

        sqlx::query(
            "INSERT INTO oidc_providers (id, name, issuer_url, client_id, encrypted_client_secret, nonce, scopes, \
             role_mapping, auto_provision, enabled, username_claim, created_at, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)",
        )
        .bind(provider.id.0)
        .bind(&provider.name)
        .bind(&provider.issuer_url)
        .bind(&provider.client_id)
        .bind(&provider.encrypted_client_secret)
        .bind(&provider.nonce)
        .bind(&scopes)
        .bind(&provider.role_mapping)
        .bind(provider.auto_provision)
        .bind(provider.enabled)
        .bind(&provider.username_claim)
        .bind(provider.created_at)
        .bind(provider.updated_at)
        .execute(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(())
    }

    async fn get_oidc_provider(
        &self,
        id: &OidcProviderId,
    ) -> Result<Option<OidcProvider>, StoreError> {
        let row = sqlx::query_as::<_, OidcProviderRow>(
            "SELECT id, name, issuer_url, client_id, encrypted_client_secret, nonce, scopes, role_mapping, \
             auto_provision, enabled, username_claim, created_at, updated_at FROM oidc_providers WHERE id = $1",
        )
        .bind(id.0)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(row.map(Into::into))
    }

    async fn list_oidc_providers(&self) -> Result<Vec<OidcProviderSummary>, StoreError> {
        let rows = sqlx::query_as::<_, OidcProviderSummaryRow>(
            "SELECT id, name, issuer_url, client_id, scopes, role_mapping, auto_provision, enabled, \
             username_claim, created_at, updated_at FROM oidc_providers ORDER BY name ASC",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    async fn update_oidc_provider(&self, provider: &OidcProvider) -> Result<(), StoreError> {
        let scopes = serde_json::to_value(&provider.scopes).unwrap_or_default();

        sqlx::query(
            "UPDATE oidc_providers SET name = $1, issuer_url = $2, client_id = $3, encrypted_client_secret = $4, \
             nonce = $5, scopes = $6, role_mapping = $7, auto_provision = $8, enabled = $9, username_claim = $10, \
             updated_at = $11 WHERE id = $12",
        )
        .bind(&provider.name)
        .bind(&provider.issuer_url)
        .bind(&provider.client_id)
        .bind(&provider.encrypted_client_secret)
        .bind(&provider.nonce)
        .bind(&scopes)
        .bind(&provider.role_mapping)
        .bind(provider.auto_provision)
        .bind(provider.enabled)
        .bind(&provider.username_claim)
        .bind(provider.updated_at)
        .bind(provider.id.0)
        .execute(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(())
    }

    async fn delete_oidc_provider(&self, id: &OidcProviderId) -> Result<bool, StoreError> {
        let result = sqlx::query("DELETE FROM oidc_providers WHERE id = $1")
            .bind(id.0)
            .execute(&self.pool)
            .await
            .map_err(db_err)?;
        Ok(result.rows_affected() > 0)
    }

    async fn get_enabled_oidc_providers(&self) -> Result<Vec<OidcProviderSummary>, StoreError> {
        let rows = sqlx::query_as::<_, OidcProviderSummaryRow>(
            "SELECT id, name, issuer_url, client_id, scopes, role_mapping, auto_provision, enabled, \
             username_claim, created_at, updated_at FROM oidc_providers WHERE enabled = true ORDER BY name ASC",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    async fn create_oidc_auth_state(&self, auth_state: &OidcAuthState) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO oidc_auth_states (state, nonce, provider_id, redirect_uri, created_at, expires_at) \
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(&auth_state.state)
        .bind(&auth_state.nonce)
        .bind(auth_state.provider_id.0)
        .bind(&auth_state.redirect_uri)
        .bind(auth_state.created_at)
        .bind(auth_state.expires_at)
        .execute(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(())
    }

    async fn get_oidc_auth_state(&self, state: &str) -> Result<Option<OidcAuthState>, StoreError> {
        let row = sqlx::query_as::<_, OidcAuthStateRow>(
            "SELECT state, nonce, provider_id, redirect_uri, created_at, expires_at FROM oidc_auth_states WHERE state = $1",
        )
        .bind(state)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(row.map(Into::into))
    }

    async fn delete_oidc_auth_state(&self, state: &str) -> Result<bool, StoreError> {
        let result = sqlx::query("DELETE FROM oidc_auth_states WHERE state = $1")
            .bind(state)
            .execute(&self.pool)
            .await
            .map_err(db_err)?;
        Ok(result.rows_affected() > 0)
    }

    async fn cleanup_expired_oidc_states(&self) -> Result<u32, StoreError> {
        let now = Utc::now();
        let result = sqlx::query("DELETE FROM oidc_auth_states WHERE expires_at < $1")
            .bind(now)
            .execute(&self.pool)
            .await
            .map_err(db_err)?;
        Ok(result.rows_affected() as u32)
    }
}
