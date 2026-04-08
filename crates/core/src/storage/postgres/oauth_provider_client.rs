use async_trait::async_trait;

use super::PostgresStore;
use crate::domain::oauth_provider_client::{
    OAuthProviderClient, OAuthProviderClientId, OAuthProviderClientSummary,
};
use crate::error::StoreError;
use crate::storage::OAuthProviderClientStore;

/// Postgres OAuthProviderClientStore implementation stub.
/// Returns `StoreError::Database("not yet implemented")` until the Postgres
/// migration for `mcp_oauth_apps` is added.
#[async_trait]
impl OAuthProviderClientStore for PostgresStore {
    async fn create_oauth_provider_client(
        &self,
        _app: &OAuthProviderClient,
    ) -> Result<(), StoreError> {
        Err(StoreError::Database(
            "oauth_provider_client: postgres not yet implemented".into(),
        ))
    }
    async fn get_oauth_provider_client(
        &self,
        _id: &OAuthProviderClientId,
    ) -> Result<Option<OAuthProviderClient>, StoreError> {
        Err(StoreError::Database(
            "oauth_provider_client: postgres not yet implemented".into(),
        ))
    }
    async fn get_oauth_provider_client_by_authorization_server_url(
        &self,
        _authorization_server_url: &str,
    ) -> Result<Option<OAuthProviderClient>, StoreError> {
        Err(StoreError::Database(
            "oauth_provider_client: postgres not yet implemented".into(),
        ))
    }
    async fn list_oauth_provider_clients(
        &self,
    ) -> Result<Vec<OAuthProviderClientSummary>, StoreError> {
        Err(StoreError::Database(
            "oauth_provider_client: postgres not yet implemented".into(),
        ))
    }
    async fn update_oauth_provider_client(
        &self,
        _app: &OAuthProviderClient,
    ) -> Result<(), StoreError> {
        Err(StoreError::Database(
            "oauth_provider_client: postgres not yet implemented".into(),
        ))
    }
    async fn delete_oauth_provider_client(
        &self,
        _id: &OAuthProviderClientId,
    ) -> Result<bool, StoreError> {
        Err(StoreError::Database(
            "oauth_provider_client: postgres not yet implemented".into(),
        ))
    }
}
