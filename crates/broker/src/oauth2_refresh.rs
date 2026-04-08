//! OAuth2 Authorization Code refresh token manager.
//!
//! Acquires and caches access tokens using the OAuth2 refresh_token grant.
//! Tokens are cached per-credential with automatic expiry (30s buffer).
//! Follows the same pattern as `agent_cordon_core::oauth2::client_credentials::OAuth2TokenManager`.

use std::collections::HashMap;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use tokio::sync::Mutex;

/// Errors from the OAuth2 refresh token exchange flow.
#[derive(Debug, thiserror::Error)]
pub enum OAuth2RefreshError {
    #[error("token endpoint request failed: {0}")]
    RequestFailed(String),

    #[error("token endpoint returned HTTP {status}")]
    TokenEndpointError { status: u16, body: String },

    #[error("invalid token response: {0}")]
    InvalidResponse(String),

    #[error("token endpoint timeout")]
    Timeout,
}

/// A cached OAuth2 access token with its expiry time.
struct CachedAccessToken {
    access_token: String,
    expires_at: DateTime<Utc>,
}

/// Manages OAuth2 refresh_token exchange and caching for authorization code credentials.
///
/// Thread-safe: uses `Arc<Mutex<...>>` for the cache so it can be shared
/// across request handlers.
///
/// SECURITY: Manual Debug impl to prevent token leakage via `{:?}`.
#[derive(Clone)]
pub struct OAuth2RefreshManager {
    client: reqwest::Client,
    /// Keyed by credential name.
    cache: Arc<Mutex<HashMap<String, CachedAccessToken>>>,
}

impl std::fmt::Debug for OAuth2RefreshManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OAuth2RefreshManager")
            .field("cache_entries", &"[REDACTED]")
            .finish()
    }
}

impl OAuth2RefreshManager {
    /// Create a new refresh manager with a default HTTP client (10s timeout).
    pub fn new() -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .user_agent("AgentCordon-Broker/0.1")
            .build()
            .expect("failed to build reqwest client for OAuth2 refresh");

        Self {
            client,
            cache: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Get a valid access token, using cache if available.
    ///
    /// If cached token is expired or missing, exchanges the refresh_token
    /// for a new access token via the token endpoint.
    ///
    /// Holds the cache lock for the entire check-and-acquire sequence
    /// to prevent TOCTOU races (thundering herd on expired tokens).
    pub async fn get_access_token(
        &self,
        credential_name: &str,
        refresh_token: &str,
        token_url: &str,
        client_id: &str,
        client_secret: &str,
    ) -> Result<String, OAuth2RefreshError> {
        // TODO: Replace single mutex with per-credential locking (e.g., DashMap
        // with per-entry lock) when credential count grows. Currently this
        // serializes all token refreshes — acceptable for small credential counts.
        let mut cache = self.cache.lock().await;

        // Check cache under lock
        if let Some(cached) = cache.get(credential_name) {
            if cached.expires_at > Utc::now() {
                return Ok(cached.access_token.clone());
            }
        }

        // Cache miss or expired -- acquire new token (still holding lock)
        let resp = self
            .client
            .post(token_url)
            .form(&[
                ("grant_type", "refresh_token"),
                ("refresh_token", refresh_token),
                ("client_id", client_id),
                ("client_secret", client_secret),
            ])
            .send()
            .await
            .map_err(|e| {
                if e.is_timeout() {
                    OAuth2RefreshError::Timeout
                } else {
                    OAuth2RefreshError::RequestFailed(e.to_string())
                }
            })?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(OAuth2RefreshError::TokenEndpointError {
                status: status.as_u16(),
                body,
            });
        }

        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| OAuth2RefreshError::InvalidResponse(e.to_string()))?;

        let access_token = body
            .get("access_token")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                OAuth2RefreshError::InvalidResponse("missing 'access_token' field".to_string())
            })?
            .to_string();

        let expires_in = body
            .get("expires_in")
            .and_then(|v| v.as_i64())
            .unwrap_or(3600);

        // Cache with 30s buffer to avoid using near-expired tokens
        let buffer_secs = 30;
        let effective_ttl = (expires_in - buffer_secs).max(0);
        let expires_at = Utc::now() + chrono::Duration::seconds(effective_ttl);

        // Warn if refresh token was rotated (v1: we don't persist back)
        if body.get("refresh_token").and_then(|v| v.as_str()).is_some() {
            tracing::warn!(
                credential = %credential_name,
                "OAuth2 provider rotated refresh token -- new token NOT persisted (v1 limitation)"
            );
        }

        // Update cache under same lock
        cache.insert(
            credential_name.to_string(),
            CachedAccessToken {
                access_token: access_token.clone(),
                expires_at,
            },
        );

        Ok(access_token)
    }

    /// Invalidate a cached access token (e.g., on 401 from upstream).
    #[allow(dead_code)] // Public API for future 401-retry logic
    pub async fn invalidate(&self, credential_name: &str) {
        let mut cache = self.cache.lock().await;
        cache.remove(credential_name);
    }
}

impl Default for OAuth2RefreshManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_cache_miss_and_invalidation() {
        let mgr = OAuth2RefreshManager::new();
        // Nothing cached initially
        {
            let cache = mgr.cache.lock().await;
            assert!(cache.is_empty());
        }
        // Invalidation on empty cache is a no-op
        mgr.invalidate("nonexistent").await;
    }

    #[tokio::test]
    async fn test_cached_token_returned_when_valid() {
        let mgr = OAuth2RefreshManager::new();
        // Pre-populate cache
        {
            let mut cache = mgr.cache.lock().await;
            cache.insert(
                "test-cred".to_string(),
                CachedAccessToken {
                    access_token: "cached-token".to_string(),
                    expires_at: Utc::now() + chrono::Duration::seconds(300),
                },
            );
        }
        // Should return cached token without hitting the network
        let token = mgr
            .get_access_token(
                "test-cred",
                "unused-refresh",
                "http://unreachable.invalid/token",
                "client-id",
                "client-secret",
            )
            .await
            .unwrap();
        assert_eq!(token, "cached-token");
    }

    #[tokio::test]
    async fn test_invalidate_removes_cached_token() {
        let mgr = OAuth2RefreshManager::new();
        // Pre-populate
        {
            let mut cache = mgr.cache.lock().await;
            cache.insert(
                "test-cred".to_string(),
                CachedAccessToken {
                    access_token: "old-token".to_string(),
                    expires_at: Utc::now() + chrono::Duration::seconds(300),
                },
            );
        }
        mgr.invalidate("test-cred").await;
        let cache = mgr.cache.lock().await;
        assert!(cache.get("test-cred").is_none());
    }

    #[tokio::test]
    async fn test_expired_token_not_returned() {
        let mgr = OAuth2RefreshManager::new();
        // Pre-populate with expired token
        {
            let mut cache = mgr.cache.lock().await;
            cache.insert(
                "test-cred".to_string(),
                CachedAccessToken {
                    access_token: "expired-token".to_string(),
                    expires_at: Utc::now() - chrono::Duration::seconds(10),
                },
            );
        }
        // Should try to hit network (and fail since URL is invalid)
        let result = mgr
            .get_access_token(
                "test-cred",
                "refresh-tok",
                "http://unreachable.invalid/token",
                "client-id",
                "client-secret",
            )
            .await;
        assert!(result.is_err());
    }
}
