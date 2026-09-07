use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::config::BrokerConfig;

/// Minimal workspace state for the plaintext recovery store (`workspaces.json`).
///
/// Contains only what is needed to re-obtain an access token via refresh.
/// No access tokens or expiry times — just the refresh token + client_id.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryEntry {
    pub client_id: String,
    pub refresh_token: String,
    pub workspace_name: String,
    pub scopes: Vec<String>,
    pub registered_at: DateTime<Utc>,
}

/// Token lifecycle status.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TokenStatus {
    #[default]
    Valid,
    Expired,
    Revoked,
}

/// Per-workspace OAuth state held in memory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkspaceState {
    pub client_id: String,
    pub access_token: String,
    pub refresh_token: String,
    pub scopes: Vec<String>,
    pub token_expires_at: DateTime<Utc>,
    pub workspace_name: String,
    #[serde(default)]
    pub token_status: TokenStatus,
}

impl WorkspaceState {
    /// Convert to a `RecoveryEntry` for the plaintext recovery store.
    pub fn to_recovery_entry(&self) -> RecoveryEntry {
        RecoveryEntry {
            client_id: self.client_id.clone(),
            refresh_token: self.refresh_token.clone(),
            workspace_name: self.workspace_name.clone(),
            scopes: self.scopes.clone(),
            registered_at: Utc::now(),
        }
    }
}

/// Pending RFC 8628 device authorization registration (in-flight approval).
///
/// Keyed by `pk_hash` in [`BrokerState::pending`]. The broker polls the
/// server's token endpoint in a background task; on success the workspace is
/// inserted into [`BrokerState::workspaces`] and this entry is removed. On
/// failure (expired, denied) the error is surfaced via
/// [`BrokerState::registration_errors`].
///
/// SECURITY: `device_code` is an opaque secret — it must NEVER be logged or
/// returned to the CLI. Only `user_code` / `verification_uri` are surfaced.
#[derive(Debug, Clone)]
pub struct PendingDeviceRegistration {
    pub workspace_name: String,
    /// Opaque device code from the server — secret, do not log.
    pub device_code: String,
    /// When this pending entry was created; used for TTL cleanup.
    pub created_at: Instant,
    /// Device code TTL (from server `expires_in`).
    pub expires_in: std::time::Duration,
}

/// Cached MCP server with optional decrypted credential.
#[derive(Debug, Clone)]
pub struct CachedMcpServer {
    pub id: String,
    pub name: String,
    pub url: String,
    #[allow(dead_code)] // Retained for cache diagnostics
    pub transport: String,
    pub auth_method: String,
    #[allow(dead_code)] // Populated from sync, used in future tool-level auth
    pub tools: Vec<String>,
    #[allow(dead_code)] // Populated from sync, checked in future filtering
    pub enabled: bool,
    pub credential: Option<CachedCredential>,
    #[allow(dead_code)] // Retained for cache-expiry logic
    pub last_synced: chrono::DateTime<chrono::Utc>,
}

/// A cached token is treated as stale this long before its expiry, so a
/// call never goes upstream with a token about to lapse.
pub const CREDENTIAL_EXPIRY_MARGIN: chrono::Duration = chrono::Duration::seconds(60);

/// Decrypted credential material cached alongside an MCP server.
///
/// For OAuth-backed servers the `value` is the short-lived upstream access
/// token the server obtained; `expires_at` says when a new sync is due.
/// The broker never holds the refresh token or client secret behind it.
///
/// SECURITY: Manual Debug impl redacts the `value` field to prevent
/// plaintext secrets from leaking to logs via `{:?}` formatting.
#[derive(Clone)]
pub struct CachedCredential {
    pub credential_type: String,
    pub value: String,
    pub transform_name: Option<String>,
    pub metadata: HashMap<String, String>,
    /// When the value stops being usable, if the server said.
    pub expires_at: Option<DateTime<Utc>>,
}

impl CachedCredential {
    /// True when the value has expired or is within
    /// [`CREDENTIAL_EXPIRY_MARGIN`] of expiring.
    pub fn is_stale(&self, now: DateTime<Utc>) -> bool {
        self.expires_at
            .is_some_and(|expires_at| expires_at - CREDENTIAL_EXPIRY_MARGIN <= now)
    }
}

impl std::fmt::Debug for CachedCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CachedCredential")
            .field("credential_type", &self.credential_type)
            .field("value", &"[REDACTED]")
            .field("transform_name", &self.transform_name)
            .field("metadata", &format!("[{} keys]", self.metadata.len()))
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// Shared broker state accessible from all route handlers.
pub struct BrokerState {
    /// Workspace states keyed by SHA-256 hex hash of Ed25519 public key.
    pub workspaces: RwLock<HashMap<String, WorkspaceState>>,
    /// Pending device-flow registrations keyed by `pk_hash`.
    pub pending: RwLock<HashMap<String, PendingDeviceRegistration>>,
    /// Recent registration errors keyed by `pk_hash`. Set by the background
    /// device-code poll task when the server returns `access_denied`,
    /// `expired_token`, or a transport failure so the polling `/status`
    /// endpoint can surface the failure to the CLI instead of hanging.
    pub registration_errors: RwLock<HashMap<String, String>>,
    /// Cached MCP server configs per workspace (keyed by pk_hash).
    pub mcp_configs: RwLock<HashMap<String, Vec<CachedMcpServer>>>,
    /// AgentCordon server URL.
    pub server_url: String,
    /// HTTP client for the AgentCordon server.
    pub http_client: reqwest::Client,
    /// HTTP client for proxied and MCP upstreams; see [`crate::upstream`].
    pub upstream_client: reqwest::Client,
    /// Broker's P-256 keypair for ECIES operations.
    pub encryption_key: p256::SecretKey,
    /// Broker configuration.
    pub config: BrokerConfig,
    /// Nonces accepted within the clock-skew window, for replay refusal.
    pub nonces: crate::auth::NonceCache,
    /// Per-workspace refresh locks so concurrent 401s refresh once.
    pub refresh_locks: crate::token_refresh::RefreshLocks,
}

/// Type alias used in route handlers.
pub type SharedState = Arc<BrokerState>;
