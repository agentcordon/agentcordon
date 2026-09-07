use async_trait::async_trait;

use crate::domain::user::UserId;
use crate::domain::workspace::WorkspaceId;
use crate::error::StoreError;
use crate::oauth2::types::{
    BearerResolution, OAuthAccessToken, OAuthAuthCode, OAuthClient, OAuthConsent, OAuthRefreshToken,
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
    /// Insert `client`, deleting whichever client already holds its
    /// `public_key_hash` (together with that client's tokens, auth codes,
    /// and consents) in the same immediate transaction, so a failed insert
    /// leaves the previous client in place. Returns the replaced client's
    /// `client_id`.
    async fn replace_oauth_client(
        &self,
        client: &OAuthClient,
    ) -> Result<Option<String>, StoreError>;

    // --- Auth Codes ---
    async fn create_oauth_auth_code(&self, code: &OAuthAuthCode) -> Result<(), StoreError>;
    async fn get_oauth_auth_code(
        &self,
        code_hash: &str,
    ) -> Result<Option<OAuthAuthCode>, StoreError>;
    async fn consume_oauth_auth_code(&self, code_hash: &str) -> Result<bool, StoreError>;
    /// Consume an unused code and mint the tokens it earns in one immediate
    /// transaction. `Ok(false)` when the code was already consumed, in which
    /// case nothing is minted; when a token insert fails the code stays
    /// unconsumed.
    async fn consume_oauth_auth_code_and_issue_tokens(
        &self,
        code_hash: &str,
        access: &OAuthAccessToken,
        refresh: &OAuthRefreshToken,
    ) -> Result<bool, StoreError>;

    // --- Access Tokens ---
    async fn create_oauth_access_token(&self, token: &OAuthAccessToken) -> Result<(), StoreError>;
    async fn get_oauth_access_token(
        &self,
        token_hash: &str,
    ) -> Result<Option<OAuthAccessToken>, StoreError>;
    /// Resolve a bearer token to its client state and workspace in one call.
    /// `None` when no such token exists.
    async fn resolve_bearer(
        &self,
        token_hash: &str,
    ) -> Result<Option<BearerResolution>, StoreError>;
    /// Point a client (and the tokens it has issued) at a workspace. Used
    /// when a client that predates the binding is reused on re-registration.
    async fn bind_oauth_client_workspace(
        &self,
        client_id: &str,
        workspace_id: &WorkspaceId,
    ) -> Result<(), StoreError>;
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
    /// Revoke every refresh token in a family and the access tokens minted
    /// with them. Used when a retired refresh token is presented again.
    /// Returns the number of refresh tokens revoked.
    async fn revoke_oauth_refresh_token_family(&self, family_id: &str) -> Result<u32, StoreError>;
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

    /// List every consent granted to the given OAuth client. Issue #10.
    ///
    /// Returned in any order; callers that need a stable order should sort
    /// at the boundary (UI / API).
    async fn list_oauth_consents_for_client(
        &self,
        client_id: &str,
    ) -> Result<Vec<OAuthConsent>, StoreError>;

    /// Delete the consent row and revoke every access and refresh token issued
    /// to the given `(client_id, user_id)` pair, atomically. Issue #10.
    ///
    /// Returns `None` if no consent existed (handlers map this to HTTP 404);
    /// otherwise `Some(counts)` with the number of access and refresh tokens
    /// revoked, which the audit event payload records.
    async fn delete_consent_and_revoke_tokens(
        &self,
        client_id: &str,
        user_id: &UserId,
    ) -> Result<Option<ConsentRevocationCounts>, StoreError>;
}

/// Counts of tokens revoked by [`OAuthStore::delete_consent_and_revoke_tokens`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ConsentRevocationCounts {
    pub access_tokens: u32,
    pub refresh_tokens: u32,
}
