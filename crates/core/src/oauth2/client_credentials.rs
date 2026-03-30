//! OAuth2 Client Credentials token manager.
//!
//! Acquires and caches access tokens using the OAuth2 client_credentials grant.
//! Tokens are cached per-credential with automatic expiry (30s buffer).

use std::collections::HashMap;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use tokio::sync::Mutex;

use crate::domain::credential::{CredentialId, StoredCredential};

/// Errors from the OAuth2 token acquisition flow.
#[derive(Debug, thiserror::Error)]
pub enum OAuth2Error {
    #[error("missing oauth2_client_id in credential metadata")]
    MissingClientId,

    #[error("missing oauth2_token_endpoint in credential metadata")]
    MissingTokenEndpoint,

    #[error("token endpoint request failed: {0}")]
    RequestFailed(String),

    #[error("token endpoint returned HTTP {status}: {body}")]
    TokenEndpointError { status: u16, body: String },

    #[error("invalid token response: {0}")]
    InvalidResponse(String),

    #[error("token endpoint timeout")]
    Timeout,
}

/// A cached OAuth2 access token with its expiry time.
struct CachedToken {
    access_token: String,
    expires_at: DateTime<Utc>,
}

/// Manages OAuth2 client_credentials token acquisition and caching.
///
/// Thread-safe: uses `Arc<Mutex<...>>` for the cache so it can be shared
/// across request handlers.
#[derive(Clone)]
pub struct OAuth2TokenManager {
    client: reqwest::Client,
    cache: Arc<Mutex<HashMap<CredentialId, CachedToken>>>,
}

/// Result of a token acquisition, indicating whether it was from cache or fresh.
pub struct TokenResult {
    /// The access token string.
    pub access_token: String,
    /// `true` if this token was freshly acquired (not from cache).
    pub was_refreshed: bool,
}

/// Internal result from token acquisition, includes expiry for cache storage.
struct AcquireResult {
    access_token: String,
    expires_at: DateTime<Utc>,
}

impl OAuth2TokenManager {
    /// Create a new token manager with a default HTTP client (10s timeout).
    pub fn new() -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .user_agent("AgentCordon/0.1")
            .build()
            .expect("failed to build reqwest client for OAuth2");

        Self {
            client,
            cache: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Create a new token manager with a custom reqwest client (for testing).
    #[allow(dead_code)]
    pub fn with_client(client: reqwest::Client) -> Self {
        Self {
            client,
            cache: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Evict a credential's cached token, e.g. after deletion or rotation.
    pub async fn evict(&self, credential_id: &CredentialId) {
        self.cache.lock().await.remove(credential_id);
    }

    /// Get a valid access token for the given OAuth2 credential.
    ///
    /// Returns a cached token if still valid (with 30s buffer), otherwise
    /// acquires a fresh token from the token endpoint.
    ///
    /// # Arguments
    /// * `credential` - The stored credential (must be type `oauth2_client_credentials`)
    /// * `client_secret` - The decrypted client secret (secret_value from the credential)
    ///
    /// This method holds the cache lock for the entire check-and-acquire sequence
    /// to prevent TOCTOU races (thundering herd on expired tokens). Since the
    /// credential count is small and the HTTP call has a 10s timeout, serializing
    /// all credential token acquisitions is acceptable for v1.0.
    pub async fn get_token(
        &self,
        credential: &StoredCredential,
        client_secret: &str,
    ) -> Result<TokenResult, OAuth2Error> {
        let now = Utc::now();

        // Hold the lock for the entire check-and-acquire sequence to prevent
        // multiple concurrent requests from racing to acquire tokens for the
        // same expired credential.
        let mut cache = self.cache.lock().await;

        // Check cache under lock
        if let Some(cached) = cache.get(&credential.id) {
            if cached.expires_at > now {
                return Ok(TokenResult {
                    access_token: cached.access_token.clone(),
                    was_refreshed: false,
                });
            }
        }

        // Cache miss or expired — acquire new token (still holding lock)
        let token_result = self.acquire_token_inner(credential, client_secret).await?;

        // Update cache under the same lock
        cache.insert(
            credential.id.clone(),
            CachedToken {
                access_token: token_result.access_token.clone(),
                expires_at: token_result.expires_at,
            },
        );

        Ok(TokenResult {
            access_token: token_result.access_token,
            was_refreshed: true,
        })
    }

    /// Acquire a fresh token from the OAuth2 token endpoint.
    /// Does NOT update the cache -- the caller is responsible for that.
    async fn acquire_token_inner(
        &self,
        credential: &StoredCredential,
        client_secret: &str,
    ) -> Result<AcquireResult, OAuth2Error> {
        let client_id = credential
            .metadata
            .get("oauth2_client_id")
            .and_then(|v| v.as_str())
            .ok_or(OAuth2Error::MissingClientId)?;

        let token_endpoint = credential
            .metadata
            .get("oauth2_token_endpoint")
            .and_then(|v| v.as_str())
            .ok_or(OAuth2Error::MissingTokenEndpoint)?;

        let scopes = credential
            .metadata
            .get("oauth2_scopes")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        // Build form body per RFC 6749 Section 4.4.2
        let mut form = vec![
            ("grant_type", "client_credentials"),
            ("client_id", client_id),
            ("client_secret", client_secret),
        ];
        if !scopes.is_empty() {
            form.push(("scope", scopes));
        }

        let response = self
            .client
            .post(token_endpoint)
            .form(&form)
            .send()
            .await
            .map_err(|e| {
                if e.is_timeout() {
                    OAuth2Error::Timeout
                } else {
                    OAuth2Error::RequestFailed(e.to_string())
                }
            })?;

        let status = response.status().as_u16();
        if !response.status().is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(OAuth2Error::TokenEndpointError { status, body });
        }

        // Parse standard OAuth2 token response
        let body: serde_json::Value = response
            .json()
            .await
            .map_err(|e| OAuth2Error::InvalidResponse(format!("failed to parse JSON: {}", e)))?;

        let access_token = body
            .get("access_token")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                OAuth2Error::InvalidResponse("missing 'access_token' field".to_string())
            })?
            .to_string();

        let expires_in = body
            .get("expires_in")
            .and_then(|v| v.as_i64())
            .unwrap_or(3600); // Default 1 hour if not provided

        // Cache with 30s buffer to avoid using near-expired tokens
        let buffer_secs = 30;
        let effective_ttl = (expires_in - buffer_secs).max(0);
        let expires_at = Utc::now() + chrono::Duration::seconds(effective_ttl);

        Ok(AcquireResult {
            access_token,
            expires_at,
        })
    }
}

impl Default for OAuth2TokenManager {
    fn default() -> Self {
        Self::new()
    }
}
