use async_trait::async_trait;

use crate::domain::oauth_provider_client::{
    OAuthProviderClient, OAuthProviderClientId, OAuthProviderClientSummary,
};
use crate::error::StoreError;

/// Storage operations for OAuth provider client configurations.
#[async_trait]
pub trait OAuthProviderClientStore: Send + Sync {
    /// Insert a new OAuth provider client.
    async fn create_oauth_provider_client(
        &self,
        app: &OAuthProviderClient,
    ) -> Result<(), StoreError>;

    /// Get an OAuth provider client by ID.
    async fn get_oauth_provider_client(
        &self,
        id: &OAuthProviderClientId,
    ) -> Result<Option<OAuthProviderClient>, StoreError>;

    /// Get an OAuth provider client by its authorization server URL.
    async fn get_oauth_provider_client_by_authorization_server_url(
        &self,
        authorization_server_url: &str,
    ) -> Result<Option<OAuthProviderClient>, StoreError>;

    /// List all OAuth provider clients (summaries without secrets).
    async fn list_oauth_provider_clients(
        &self,
    ) -> Result<Vec<OAuthProviderClientSummary>, StoreError>;

    /// Update an existing OAuth provider client.
    async fn update_oauth_provider_client(
        &self,
        app: &OAuthProviderClient,
    ) -> Result<(), StoreError>;

    /// Delete an OAuth provider client by ID. Returns true if a row was deleted.
    async fn delete_oauth_provider_client(
        &self,
        id: &OAuthProviderClientId,
    ) -> Result<bool, StoreError>;
}
