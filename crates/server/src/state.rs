use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use agent_cordon_core::auth::jwt::JwtIssuer;
use agent_cordon_core::crypto::aes_gcm::AesGcmEncryptor;
use agent_cordon_core::domain::workspace::IdentityChallenge;
use agent_cordon_core::oauth2::OAuth2TokenManager;
use agent_cordon_core::policy::cedar::CedarPolicyEngine;
use agent_cordon_core::storage::Store;
use metrics_exporter_prometheus::PrometheusHandle;

use crate::config::AppConfig;
use crate::events::{EventBus, SseConnectionTracker, UiEventBus};
use crate::rate_limit::LoginRateLimiter;
use crate::routes::admin_api::credential_templates::CredentialTemplate;
use crate::routes::admin_api::policy_templates::PolicyTemplate;

pub type SharedStore = Arc<dyn Store + Send + Sync>;

#[derive(Clone)]
pub struct AppState {
    pub store: SharedStore,
    pub jwt_issuer: Arc<JwtIssuer>,
    pub policy_engine: Arc<CedarPolicyEngine>,
    pub encryptor: Arc<AesGcmEncryptor>,
    pub config: AppConfig,
    pub login_rate_limiter: Arc<LoginRateLimiter>,
    pub metrics_handle: PrometheusHandle,
    /// HMAC key for session token hashing (domain-separated from encryption/signing keys).
    pub session_hash_key: [u8; 32],
    pub oauth2_token_manager: OAuth2TokenManager,
    /// Shared HTTP client for proxy routes (avoids per-request client creation).
    pub http_client: reqwest::Client,
    /// In-process event bus for server-to-device push notifications (SSE).
    pub event_bus: EventBus,
    /// In-process event bus for UI (browser) push notifications (SSE).
    pub ui_event_bus: UiEventBus,
    /// Per-user SSE connection limiter to prevent connection leaks.
    pub sse_tracker: SseConnectionTracker,
    /// In-memory challenge store for workspace identity authentication.
    /// Keyed by pk_hash, values are challenges with TTL.
    pub workspace_challenges: Arc<RwLock<HashMap<String, IdentityChallenge>>>,
    /// Pre-loaded credential templates (embedded + runtime overrides).
    pub credential_templates: Vec<CredentialTemplate>,
    /// Pre-loaded policy templates (embedded + runtime overrides).
    pub policy_templates: Vec<PolicyTemplate>,
}
