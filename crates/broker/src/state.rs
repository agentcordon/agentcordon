use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::config::BrokerConfig;
use crate::oauth2_refresh::OAuth2RefreshManager;

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

/// Pending OAuth registration (in-flight consent flow).
#[derive(Debug, Clone)]
pub struct PendingRegistration {
    pub workspace_name: String,
    pub client_id: String,
    pub code_verifier: String,
    pub redirect_uri: String,
    pub pk_hash: String,
    /// When this registration was created; used for TTL cleanup.
    pub created_at: Instant,
}

/// Cached MCP server with optional decrypted credential.
#[derive(Debug, Clone)]
pub struct CachedMcpServer {
    #[allow(dead_code)] // Used during sync/diagnostics
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

/// Decrypted credential material cached alongside an MCP server.
///
/// SECURITY: Manual Debug impl redacts the `value` field to prevent
/// plaintext secrets from leaking to logs via `{:?}` formatting.
#[derive(Clone)]
pub struct CachedCredential {
    pub credential_type: String,
    pub value: String,
    pub transform_name: Option<String>,
    pub metadata: HashMap<String, String>,
}

impl std::fmt::Debug for CachedCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CachedCredential")
            .field("credential_type", &self.credential_type)
            .field("value", &"[REDACTED]")
            .field("transform_name", &self.transform_name)
            .field("metadata", &format!("[{} keys]", self.metadata.len()))
            .finish()
    }
}

/// Shared broker state accessible from all route handlers.
pub struct BrokerState {
    /// Workspace states keyed by SHA-256 hex hash of Ed25519 public key.
    pub workspaces: RwLock<HashMap<String, WorkspaceState>>,
    /// Pending OAuth registrations keyed by the `state` parameter.
    pub pending: RwLock<HashMap<String, PendingRegistration>>,
    /// Recent OAuth errors keyed by `pk_hash`. Set by the `/callback` route
    /// when the IdP returns `error=...` so the polling `/status` endpoint can
    /// surface the failure to the CLI instead of hanging until timeout.
    pub registration_errors: RwLock<HashMap<String, String>>,
    /// Cached MCP server configs per workspace (keyed by pk_hash).
    pub mcp_configs: RwLock<HashMap<String, Vec<CachedMcpServer>>>,
    /// AgentCordon server URL.
    pub server_url: String,
    /// Shared HTTP client.
    pub http_client: reqwest::Client,
    /// Broker's P-256 keypair for ECIES operations.
    pub encryption_key: p256::SecretKey,
    /// Broker configuration.
    pub config: BrokerConfig,
    /// OAuth2 refresh token manager for authorization code credentials.
    pub oauth2_refresh: OAuth2RefreshManager,
    /// Actual port the broker is bound to (resolves port-0 auto-select).
    pub bound_port: u16,
}

/// Type alias used in route handlers.
pub type SharedState = Arc<BrokerState>;
