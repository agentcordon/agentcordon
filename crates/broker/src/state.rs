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

/// Pending OAuth registration (in-flight consent flow).
#[derive(Debug, Clone)]
pub struct PendingRegistration {
    pub workspace_name: String,
    pub client_id: String,
    pub code_verifier: String,
    pub redirect_uri: String,
    #[allow(dead_code)]
    pub state: String,
    pub pk_hash: String,
    /// When this registration was created; used for TTL cleanup.
    pub created_at: Instant,
}

/// Shared broker state accessible from all route handlers.
pub struct BrokerState {
    /// Workspace states keyed by SHA-256 hex hash of Ed25519 public key.
    pub workspaces: RwLock<HashMap<String, WorkspaceState>>,
    /// Pending OAuth registrations keyed by the `state` parameter.
    pub pending: RwLock<HashMap<String, PendingRegistration>>,
    /// AgentCordon server URL.
    pub server_url: String,
    /// Shared HTTP client.
    pub http_client: reqwest::Client,
    /// Broker's P-256 keypair for ECIES operations.
    pub encryption_key: p256::SecretKey,
    /// Broker configuration.
    pub config: BrokerConfig,
    /// Actual port the broker is bound to (resolves port-0 auto-select).
    pub bound_port: u16,
}

/// Type alias used in route handlers.
pub type SharedState = Arc<BrokerState>;
