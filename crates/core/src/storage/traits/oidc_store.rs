use async_trait::async_trait;

use crate::domain::oidc::{OidcAuthState, OidcProvider, OidcProviderId, OidcProviderSummary};
use crate::error::StoreError;

#[async_trait]
pub trait OidcStore: Send + Sync {
    async fn create_oidc_provider(&self, provider: &OidcProvider) -> Result<(), StoreError>;
    async fn get_oidc_provider(
        &self,
        id: &OidcProviderId,
    ) -> Result<Option<OidcProvider>, StoreError>;
    async fn list_oidc_providers(&self) -> Result<Vec<OidcProviderSummary>, StoreError>;
    async fn update_oidc_provider(&self, provider: &OidcProvider) -> Result<(), StoreError>;
    async fn delete_oidc_provider(&self, id: &OidcProviderId) -> Result<bool, StoreError>;
    async fn get_enabled_oidc_providers(&self) -> Result<Vec<OidcProviderSummary>, StoreError>;
    async fn create_oidc_auth_state(&self, auth_state: &OidcAuthState) -> Result<(), StoreError>;
    async fn get_oidc_auth_state(&self, state: &str) -> Result<Option<OidcAuthState>, StoreError>;
    async fn delete_oidc_auth_state(&self, state: &str) -> Result<bool, StoreError>;
    async fn cleanup_expired_oidc_states(&self) -> Result<u32, StoreError>;
}
