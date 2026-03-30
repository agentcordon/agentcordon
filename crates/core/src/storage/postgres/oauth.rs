use async_trait::async_trait;

use super::PostgresStore;
use crate::domain::user::UserId;
use crate::error::StoreError;
use crate::oauth2::types::{
    OAuthAccessToken, OAuthAuthCode, OAuthClient, OAuthConsent, OAuthRefreshToken,
};
use crate::storage::OAuthStore;

/// Postgres OAuthStore implementation — TODO: full implementation.
/// Stubbed to satisfy the Store composite trait bound. All methods return
/// `StoreError::Database("not implemented")` until the Postgres migration is added.
#[async_trait]
impl OAuthStore for PostgresStore {
    async fn create_oauth_client(&self, _client: &OAuthClient) -> Result<(), StoreError> {
        Err(StoreError::Database("oauth: postgres not yet implemented".into()))
    }
    async fn get_oauth_client_by_client_id(&self, _client_id: &str) -> Result<Option<OAuthClient>, StoreError> {
        Err(StoreError::Database("oauth: postgres not yet implemented".into()))
    }
    async fn get_oauth_client_by_public_key_hash(&self, _pk_hash: &str) -> Result<Option<OAuthClient>, StoreError> {
        Err(StoreError::Database("oauth: postgres not yet implemented".into()))
    }
    async fn list_oauth_clients(&self) -> Result<Vec<OAuthClient>, StoreError> {
        Err(StoreError::Database("oauth: postgres not yet implemented".into()))
    }
    async fn revoke_oauth_client(&self, _client_id: &str) -> Result<bool, StoreError> {
        Err(StoreError::Database("oauth: postgres not yet implemented".into()))
    }
    async fn create_oauth_auth_code(&self, _code: &OAuthAuthCode) -> Result<(), StoreError> {
        Err(StoreError::Database("oauth: postgres not yet implemented".into()))
    }
    async fn get_oauth_auth_code(&self, _code_hash: &str) -> Result<Option<OAuthAuthCode>, StoreError> {
        Err(StoreError::Database("oauth: postgres not yet implemented".into()))
    }
    async fn consume_oauth_auth_code(&self, _code_hash: &str) -> Result<bool, StoreError> {
        Err(StoreError::Database("oauth: postgres not yet implemented".into()))
    }
    async fn create_oauth_access_token(&self, _token: &OAuthAccessToken) -> Result<(), StoreError> {
        Err(StoreError::Database("oauth: postgres not yet implemented".into()))
    }
    async fn get_oauth_access_token(&self, _token_hash: &str) -> Result<Option<OAuthAccessToken>, StoreError> {
        Err(StoreError::Database("oauth: postgres not yet implemented".into()))
    }
    async fn revoke_oauth_access_token(&self, _token_hash: &str) -> Result<bool, StoreError> {
        Err(StoreError::Database("oauth: postgres not yet implemented".into()))
    }
    async fn revoke_access_tokens_for_client(&self, _client_id: &str) -> Result<u32, StoreError> {
        Err(StoreError::Database("oauth: postgres not yet implemented".into()))
    }
    async fn create_oauth_refresh_token(&self, _token: &OAuthRefreshToken) -> Result<(), StoreError> {
        Err(StoreError::Database("oauth: postgres not yet implemented".into()))
    }
    async fn get_oauth_refresh_token(&self, _token_hash: &str) -> Result<Option<OAuthRefreshToken>, StoreError> {
        Err(StoreError::Database("oauth: postgres not yet implemented".into()))
    }
    async fn revoke_oauth_refresh_token(&self, _token_hash: &str) -> Result<bool, StoreError> {
        Err(StoreError::Database("oauth: postgres not yet implemented".into()))
    }
    async fn revoke_refresh_tokens_for_client(&self, _client_id: &str) -> Result<u32, StoreError> {
        Err(StoreError::Database("oauth: postgres not yet implemented".into()))
    }
    async fn revoke_access_tokens_for_refresh_token(&self, _refresh_token_hash: &str) -> Result<u32, StoreError> {
        Err(StoreError::Database("oauth: postgres not yet implemented".into()))
    }
    async fn get_oauth_consent(&self, _client_id: &str, _user_id: &UserId) -> Result<Option<OAuthConsent>, StoreError> {
        Err(StoreError::Database("oauth: postgres not yet implemented".into()))
    }
    async fn upsert_oauth_consent(&self, _consent: &OAuthConsent) -> Result<(), StoreError> {
        Err(StoreError::Database("oauth: postgres not yet implemented".into()))
    }
}
