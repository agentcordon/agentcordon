use async_trait::async_trait;

use crate::domain::user::UserId;
use crate::error::StoreError;
use crate::oauth2::types::{
    OAuthAccessToken, OAuthAuthCode, OAuthClient, OAuthConsent, OAuthRefreshToken,
};

/// Storage trait for OAuth 2.0 Authorization Server data.
#[async_trait]
pub trait OAuthStore: Send + Sync {
    // --- Clients ---
    async fn create_oauth_client(&self, client: &OAuthClient) -> Result<(), StoreError>;
    async fn get_oauth_client_by_client_id(
        &self,
        client_id: &str,
    ) -> Result<Option<OAuthClient>, StoreError>;
    async fn get_oauth_client_by_public_key_hash(
        &self,
        pk_hash: &str,
    ) -> Result<Option<OAuthClient>, StoreError>;
    async fn list_oauth_clients(&self) -> Result<Vec<OAuthClient>, StoreError>;
    async fn revoke_oauth_client(&self, client_id: &str) -> Result<bool, StoreError>;
    /// Hard-delete an OAuth client and all associated tokens, auth codes, and consents.
    async fn delete_oauth_client(&self, client_id: &str) -> Result<bool, StoreError>;

    // --- Auth Codes ---
    async fn create_oauth_auth_code(&self, code: &OAuthAuthCode) -> Result<(), StoreError>;
    async fn get_oauth_auth_code(
        &self,
        code_hash: &str,
    ) -> Result<Option<OAuthAuthCode>, StoreError>;
    async fn consume_oauth_auth_code(&self, code_hash: &str) -> Result<bool, StoreError>;

    // --- Access Tokens ---
    async fn create_oauth_access_token(&self, token: &OAuthAccessToken) -> Result<(), StoreError>;
    async fn get_oauth_access_token(
        &self,
        token_hash: &str,
    ) -> Result<Option<OAuthAccessToken>, StoreError>;
    async fn revoke_oauth_access_token(&self, token_hash: &str) -> Result<bool, StoreError>;
    async fn revoke_access_tokens_for_client(&self, client_id: &str) -> Result<u32, StoreError>;

    // --- Refresh Tokens ---
    async fn create_oauth_refresh_token(&self, token: &OAuthRefreshToken)
        -> Result<(), StoreError>;
    async fn get_oauth_refresh_token(
        &self,
        token_hash: &str,
    ) -> Result<Option<OAuthRefreshToken>, StoreError>;
    async fn revoke_oauth_refresh_token(&self, token_hash: &str) -> Result<bool, StoreError>;
    async fn revoke_refresh_tokens_for_client(&self, client_id: &str) -> Result<u32, StoreError>;
    /// Revoke all access tokens associated with a given refresh token.
    async fn revoke_access_tokens_for_refresh_token(
        &self,
        refresh_token_hash: &str,
    ) -> Result<u32, StoreError>;

    // --- Consent ---
    async fn get_oauth_consent(
        &self,
        client_id: &str,
        user_id: &UserId,
    ) -> Result<Option<OAuthConsent>, StoreError>;
    async fn upsert_oauth_consent(&self, consent: &OAuthConsent) -> Result<(), StoreError>;
}
