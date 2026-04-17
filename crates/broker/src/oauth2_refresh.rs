//! OAuth2 Authorization Code refresh token manager.
//!
//! Acquires and caches access tokens using the OAuth2 refresh_token grant.
//! Tokens are cached per-credential with automatic expiry (30s buffer).
//! Follows the same pattern as `agent_cordon_core::oauth2::client_credentials::OAuth2TokenManager`.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use tokio::sync::Mutex;

/// Async callback invoked when the token endpoint returns a rotated refresh
/// token. The broker MUST NOT cache the new access token unless this callback
/// succeeds — otherwise the new refresh token is lost on process restart.
///
/// The `String` argument is the new refresh token value. The callback is
/// expected to (a) persist the rotation server-side and (b) update the
/// broker's in-memory credential cache atomically before returning `Ok`.
pub type RotationFuture = Pin<Box<dyn Future<Output = Result<(), RotationError>> + Send>>;
pub type RotationCallback = Arc<dyn Fn(String) -> RotationFuture + Send + Sync>;

/// Error returned by a `RotationCallback`.
#[derive(Debug, thiserror::Error)]
#[error("refresh token rotation persistence failed: {0}")]
pub struct RotationError(pub String);

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

    #[error("rotated refresh token persistence failed: {0}")]
    RotationPersistFailed(String),
}

/// A cached OAuth2 access token with its expiry time.
struct CachedAccessToken {
    access_token: String,
    expires_at: DateTime<Utc>,
}

/// Per-credential slot: a `tokio::sync::Mutex` guards the check-and-acquire
/// sequence for one credential. Held across the HTTP refresh to preserve
/// single-flight semantics per credential, but never across credentials —
/// different keys use different `Arc<Mutex>` slots.
type TokenSlot = Arc<Mutex<Option<CachedAccessToken>>>;

/// Manages OAuth2 refresh_token exchange and caching for authorization code credentials.
///
/// Thread-safe: uses a `DashMap` keyed by credential name, with a
/// per-credential `tokio::sync::Mutex` guarding each entry. Refreshes for
/// different credentials proceed concurrently; refreshes for the same
/// credential are single-flighted so we never issue a thundering herd of
/// upstream requests.
///
/// SECURITY: Manual Debug impl to prevent token leakage via `{:?}`.
#[derive(Clone)]
pub struct OAuth2RefreshManager {
    client: reqwest::Client,
    /// Keyed by credential name. `DashMap` is `Clone` via an internal `Arc`,
    /// so cloning the manager shares the same cache across handlers.
    cache: DashMap<String, TokenSlot>,
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
            cache: DashMap::new(),
        }
    }

    /// Get a valid access token, using cache if available.
    ///
    /// If cached token is expired or missing, exchanges the refresh_token
    /// for a new access token via the token endpoint.
    ///
    /// Holds only the per-credential slot mutex across the upstream refresh,
    /// so refreshes for different credentials run in parallel while refreshes
    /// for the same credential remain single-flight (thundering-herd-safe).
    pub async fn get_access_token(
        &self,
        credential_name: &str,
        refresh_token: &str,
        token_url: &str,
        client_id: &str,
        client_secret: &str,
        rotation_callback: Option<RotationCallback>,
    ) -> Result<String, OAuth2RefreshError> {
        // Brief DashMap write to get-or-create this credential's slot. The
        // entry guard is dropped at the end of this statement; we only hold
        // the per-credential mutex across the `.await` below.
        let slot: TokenSlot = self
            .cache
            .entry(credential_name.to_string())
            .or_insert_with(|| Arc::new(Mutex::new(None)))
            .clone();

        let mut slot_guard = slot.lock().await;

        // Check cache under the per-credential lock.
        if let Some(cached) = slot_guard.as_ref() {
            if cached.expires_at > Utc::now() {
                return Ok(cached.access_token.clone());
            }
        }

        // Cache miss or expired -- acquire new token (still holding the
        // per-credential lock so concurrent callers for the same credential
        // wait and reuse the fresh token).
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

        // If the provider rotated the refresh token, persist the new value
        // BEFORE caching the access token. If persistence fails we abort the
        // whole refresh: no access token is cached, no in-memory state is
        // mutated, and the caller sees an error. On the next attempt the old
        // (possibly already-consumed) refresh token will be used; if that
        // also fails, re-consent is the only path — but either way the
        // broker's state stays consistent.
        if let Some(new_refresh) = body
            .get("refresh_token")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
        {
            match rotation_callback.as_ref() {
                Some(cb) => {
                    tracing::info!(
                        credential = %credential_name,
                        "OAuth2 provider rotated refresh token -- persisting new value"
                    );
                    if let Err(e) = cb(new_refresh).await {
                        tracing::error!(
                            credential = %credential_name,
                            error = %e,
                            "failed to persist rotated refresh token; aborting refresh"
                        );
                        return Err(OAuth2RefreshError::RotationPersistFailed(e.0));
                    }
                }
                None => {
                    tracing::warn!(
                        credential = %credential_name,
                        "OAuth2 provider rotated refresh token but no rotation callback was provided"
                    );
                }
            }
        }

        // Update cache under the same per-credential lock.
        *slot_guard = Some(CachedAccessToken {
            access_token: access_token.clone(),
            expires_at,
        });

        Ok(access_token)
    }

    /// Invalidate a cached access token (e.g., on 401 from upstream).
    ///
    /// Removes the entry from the DashMap. Any concurrent caller that has
    /// already cloned the old `Arc<Mutex<...>>` slot will finish its work
    /// against that detached slot; its writes are harmless because the slot
    /// is no longer reachable from the map and drops when the last `Arc`
    /// does. The next caller for this credential inserts a fresh slot.
    #[allow(dead_code)] // Public API for future 401-retry logic
    pub async fn invalidate(&self, credential_name: &str) {
        self.cache.remove(credential_name);
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
        assert!(mgr.cache.is_empty());
        // Invalidation on empty cache is a no-op
        mgr.invalidate("nonexistent").await;
    }

    #[tokio::test]
    async fn test_cached_token_returned_when_valid() {
        let mgr = OAuth2RefreshManager::new();
        // Pre-populate cache
        mgr.cache.insert(
            "test-cred".to_string(),
            Arc::new(Mutex::new(Some(CachedAccessToken {
                access_token: "cached-token".to_string(),
                expires_at: Utc::now() + chrono::Duration::seconds(300),
            }))),
        );
        // Should return cached token without hitting the network
        let token = mgr
            .get_access_token(
                "test-cred",
                "unused-refresh",
                "http://unreachable.invalid/token",
                "client-id",
                "client-secret",
                None,
            )
            .await
            .unwrap();
        assert_eq!(token, "cached-token");
    }

    #[tokio::test]
    async fn test_invalidate_removes_cached_token() {
        let mgr = OAuth2RefreshManager::new();
        // Pre-populate
        mgr.cache.insert(
            "test-cred".to_string(),
            Arc::new(Mutex::new(Some(CachedAccessToken {
                access_token: "old-token".to_string(),
                expires_at: Utc::now() + chrono::Duration::seconds(300),
            }))),
        );
        mgr.invalidate("test-cred").await;
        assert!(mgr.cache.get("test-cred").is_none());
    }

    /// Start a one-shot mock token endpoint that returns the given JSON body
    /// once. Returns `(base_url, join_handle)`.
    async fn mock_token_endpoint(body: serde_json::Value) -> (String, tokio::task::JoinHandle<()>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let url = format!("http://{}/token", addr);

        let handle = tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                let mut buf = [0u8; 4096];
                let _ = sock.read(&mut buf).await;
                let body_str = body.to_string();
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                     Content-Length: {}\r\n\r\n{}",
                    body_str.len(),
                    body_str
                );
                let _ = sock.write_all(resp.as_bytes()).await;
                let _ = sock.shutdown().await;
            }
        });

        (url, handle)
    }

    #[tokio::test]
    async fn test_rotated_refresh_token_invokes_callback() {
        let mgr = OAuth2RefreshManager::new();

        let (token_url, _h) = mock_token_endpoint(serde_json::json!({
            "access_token": "new-access",
            "expires_in": 3600,
            "refresh_token": "ROTATED-REFRESH",
            "token_type": "Bearer",
        }))
        .await;

        let captured: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
        let captured_clone = captured.clone();

        let callback: RotationCallback = Arc::new(move |new_token: String| {
            let captured = captured_clone.clone();
            Box::pin(async move {
                *captured.lock().await = Some(new_token);
                Ok::<(), RotationError>(())
            })
        });

        let token = mgr
            .get_access_token(
                "notion-cred",
                "OLD-REFRESH",
                &token_url,
                "client-id",
                "client-secret",
                Some(callback),
            )
            .await
            .expect("refresh should succeed");

        assert_eq!(token, "new-access");
        assert_eq!(
            captured.lock().await.as_deref(),
            Some("ROTATED-REFRESH"),
            "callback must receive the rotated refresh token"
        );
    }

    #[tokio::test]
    async fn test_rotation_callback_failure_aborts_refresh() {
        let mgr = OAuth2RefreshManager::new();

        let (token_url, _h) = mock_token_endpoint(serde_json::json!({
            "access_token": "new-access",
            "expires_in": 3600,
            "refresh_token": "ROTATED",
        }))
        .await;

        let callback: RotationCallback = Arc::new(|_new_token: String| {
            Box::pin(async move {
                Err::<(), RotationError>(RotationError("server unreachable".to_string()))
            })
        });

        let result = mgr
            .get_access_token(
                "cred",
                "OLD",
                &token_url,
                "client-id",
                "client-secret",
                Some(callback),
            )
            .await;

        assert!(matches!(
            result,
            Err(OAuth2RefreshError::RotationPersistFailed(_))
        ));

        // Atomicity: on rotation-callback failure the per-credential slot
        // stays empty. The DashMap entry exists (created by `or_insert_with`
        // before the refresh ran) but its inner `Option` must be `None`.
        // Clone the slot `Arc` out of the `Ref` so the DashMap shard guard
        // is released before we `.await` on the inner mutex.
        let slot_opt: Option<TokenSlot> = mgr.cache.get("cred").map(|r| r.clone());
        if let Some(slot) = slot_opt {
            assert!(
                slot.lock().await.is_none(),
                "inner token slot must be empty after rotation-callback failure"
            );
        }
    }

    #[tokio::test]
    async fn test_expired_token_not_returned() {
        let mgr = OAuth2RefreshManager::new();
        // Pre-populate with expired token
        mgr.cache.insert(
            "test-cred".to_string(),
            Arc::new(Mutex::new(Some(CachedAccessToken {
                access_token: "expired-token".to_string(),
                expires_at: Utc::now() - chrono::Duration::seconds(10),
            }))),
        );
        // Should try to hit network (and fail since URL is invalid)
        let result = mgr
            .get_access_token(
                "test-cred",
                "refresh-tok",
                "http://unreachable.invalid/token",
                "client-id",
                "client-secret",
                None,
            )
            .await;
        assert!(result.is_err());
    }
}
