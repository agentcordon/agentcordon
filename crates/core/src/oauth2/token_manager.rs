//! Upstream OAuth2 token manager.
//!
//! Acquires and caches access tokens from a provider's token endpoint using
//! either the `client_credentials` grant or the `refresh_token` grant.
//! Tokens are cached per credential with a 30s expiry buffer, and
//! acquisitions for the same credential are single-flighted.
//!
//! This runs on the server only: the secrets that drive an exchange (a
//! client secret, a refresh token) never leave it, and what the broker
//! receives is the resulting short-lived access token with its expiry.

use std::sync::Arc;

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use tokio::sync::Mutex;

use crate::domain::credential::{CredentialId, StoredCredential};

/// Errors from an upstream token acquisition.
#[derive(Debug, thiserror::Error)]
pub enum OAuth2Error {
    #[error("missing oauth2_client_id in credential metadata")]
    MissingClientId,

    #[error("missing oauth2_token_endpoint in credential metadata")]
    MissingTokenEndpoint,

    #[error("token endpoint request failed: {0}")]
    RequestFailed(String),

    /// The endpoint's response body is kept for logs but deliberately left
    /// out of `Display`: a provider may echo request parameters into it.
    #[error("token endpoint returned HTTP {status}")]
    TokenEndpointError { status: u16, body: String },

    #[error("invalid token response: {0}")]
    InvalidResponse(String),

    #[error("token endpoint timeout")]
    Timeout,
}

/// Which grant to run at the token endpoint.
pub enum OAuth2Grant<'a> {
    /// RFC 6749 §4.4. `scopes` is the space-separated `scope` parameter;
    /// empty means none is sent.
    ClientCredentials { scopes: &'a str },
    /// RFC 6749 §6.
    RefreshToken { refresh_token: &'a str },
}

/// One token-endpoint exchange.
pub struct OAuth2TokenRequest<'a> {
    pub token_endpoint: &'a str,
    pub client_id: &'a str,
    /// Absent for public clients.
    pub client_secret: Option<&'a str>,
    pub grant: OAuth2Grant<'a>,
}

/// A cached access token with its expiry time.
struct CachedToken {
    access_token: String,
    expires_at: DateTime<Utc>,
}

/// Per-credential slot: a `tokio::sync::Mutex` guards the check-and-acquire
/// sequence for one credential. Held across the HTTP exchange to keep
/// single-flight semantics per credential, but never across credentials —
/// different keys use different `Arc<Mutex>` slots.
type TokenSlot = Arc<Mutex<Option<CachedToken>>>;

/// A token is treated as expired this long before its real expiry so a
/// caller never receives one about to lapse.
const EXPIRY_BUFFER_SECS: i64 = 30;

/// Manages upstream OAuth2 token acquisition and caching.
///
/// Thread-safe: uses a `DashMap` keyed by `CredentialId` with a per-credential
/// `tokio::sync::Mutex` guarding each entry. Acquisitions for different
/// credentials run concurrently; acquisitions for the same credential are
/// single-flighted so we never issue a thundering herd of upstream requests.
#[derive(Clone)]
pub struct OAuth2TokenManager {
    client: reqwest::Client,
    /// Behind an `Arc` so cloning the manager shares one cache. `DashMap`'s
    /// own `Clone` deep-copies every shard, so a bare `DashMap` here gave
    /// each clone — and `AppState` is cloned per request — a private cache
    /// that was written once and dropped, making every vend and every MCP
    /// sync re-run the upstream exchange.
    cache: Arc<DashMap<CredentialId, TokenSlot>>,
}

/// Result of a token acquisition.
pub struct TokenResult {
    /// The access token string.
    pub access_token: String,
    /// When the provider says the token expires (no buffer applied).
    pub expires_at: DateTime<Utc>,
    /// `true` if this token was freshly acquired (not from cache).
    pub was_refreshed: bool,
    /// A replacement refresh token the provider issued with a fresh
    /// acquisition. The caller owns persisting it; the old one may already
    /// be invalid.
    pub rotated_refresh_token: Option<String>,
}

impl OAuth2TokenManager {
    /// Create a new token manager with a default HTTP client (10s timeout).
    pub fn new() -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .user_agent(crate::USER_AGENT)
            .build()
            .expect("failed to build reqwest client for OAuth2");

        Self {
            client,
            cache: Arc::new(DashMap::new()),
        }
    }

    /// Create a new token manager with a custom reqwest client (for testing).
    pub fn with_client(client: reqwest::Client) -> Self {
        Self {
            client,
            cache: Arc::new(DashMap::new()),
        }
    }

    /// Evict a credential's cached token, e.g. after deletion or rotation.
    ///
    /// Removes the entry from the DashMap. Any concurrent caller that has
    /// already cloned the old `Arc<Mutex<...>>` slot will finish its work
    /// against that detached slot; its writes are harmless because the slot
    /// is no longer reachable from the map and drops when the last `Arc`
    /// does. The next caller for this credential inserts a fresh slot.
    pub async fn evict(&self, credential_id: &CredentialId) {
        self.cache.remove(credential_id);
    }

    /// Get a valid access token for an `oauth2_client_credentials`
    /// credential, reading `oauth2_client_id`, `oauth2_token_endpoint`, and
    /// `oauth2_scopes` from its metadata.
    ///
    /// `client_secret` is the credential's decrypted secret value.
    pub async fn get_token(
        &self,
        credential: &StoredCredential,
        client_secret: &str,
    ) -> Result<TokenResult, OAuth2Error> {
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

        self.get_token_with(
            &credential.id,
            OAuth2TokenRequest {
                token_endpoint,
                client_id,
                client_secret: Some(client_secret),
                grant: OAuth2Grant::ClientCredentials { scopes },
            },
        )
        .await
    }

    /// Get a valid access token for `credential_id`, running `request` at
    /// the token endpoint on a cache miss.
    ///
    /// Returns a cached token if still valid (with a 30s buffer). Holds only
    /// the per-credential slot mutex across the upstream exchange, so
    /// requests for different credentials run in parallel while requests for
    /// the same credential remain single-flight.
    pub async fn get_token_with(
        &self,
        credential_id: &CredentialId,
        request: OAuth2TokenRequest<'_>,
    ) -> Result<TokenResult, OAuth2Error> {
        let now = Utc::now();

        // Brief DashMap write to get-or-create this credential's slot. The
        // entry guard is dropped at the end of this statement; we only hold
        // the per-credential mutex across the `.await` below.
        let slot: TokenSlot = self
            .cache
            .entry(credential_id.clone())
            .or_insert_with(|| Arc::new(Mutex::new(None)))
            .clone();

        let mut slot_guard = slot.lock().await;

        if let Some(cached) = slot_guard.as_ref() {
            if cached.expires_at - chrono::Duration::seconds(EXPIRY_BUFFER_SECS) > now {
                return Ok(TokenResult {
                    access_token: cached.access_token.clone(),
                    expires_at: cached.expires_at,
                    was_refreshed: false,
                    rotated_refresh_token: None,
                });
            }
        }

        // Cache miss or expired — acquire a new token (still holding the
        // per-credential lock so concurrent callers for the same credential
        // wait and reuse the fresh token).
        let fresh = self.exchange(request).await?;

        *slot_guard = Some(CachedToken {
            access_token: fresh.access_token.clone(),
            expires_at: fresh.expires_at,
        });

        Ok(fresh)
    }

    /// Run one exchange at the token endpoint. Does not touch the cache.
    async fn exchange(&self, request: OAuth2TokenRequest<'_>) -> Result<TokenResult, OAuth2Error> {
        let mut form: Vec<(&str, &str)> = vec![("client_id", request.client_id)];
        if let Some(secret) = request.client_secret {
            form.push(("client_secret", secret));
        }
        match request.grant {
            OAuth2Grant::ClientCredentials { scopes } => {
                form.push(("grant_type", "client_credentials"));
                if !scopes.is_empty() {
                    form.push(("scope", scopes));
                }
            }
            OAuth2Grant::RefreshToken { refresh_token } => {
                form.push(("grant_type", "refresh_token"));
                form.push(("refresh_token", refresh_token));
            }
        }

        let response = self
            .client
            .post(request.token_endpoint)
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

        let rotated_refresh_token = body
            .get("refresh_token")
            .and_then(|v| v.as_str())
            .map(str::to_string);

        Ok(TokenResult {
            access_token,
            expires_at: Utc::now() + chrono::Duration::seconds(expires_in.max(0)),
            was_refreshed: true,
            rotated_refresh_token,
        })
    }
}

impl Default for OAuth2TokenManager {
    fn default() -> Self {
        Self::new()
    }
}
