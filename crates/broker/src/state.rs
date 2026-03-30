use std::collections::HashMap;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::config::BrokerConfig;

/// Per-workspace OAuth state held in memory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkspaceState {
    pub client_id: String,
    pub access_token: String,
    pub refresh_token: String,
    pub scopes: Vec<String>,
    pub token_expires_at: DateTime<Utc>,
    pub workspace_name: String,
    /// `valid`, `expired`, or `revoked`.
    #[serde(default = "default_token_status")]
    pub token_status: String,
}

fn default_token_status() -> String {
    "valid".to_string()
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
}

/// Type alias used in route handlers.
pub type SharedState = Arc<BrokerState>;
