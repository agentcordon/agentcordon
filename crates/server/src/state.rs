use std::sync::Arc;

use agent_cordon_core::auth::jwt::JwtIssuer;
use agent_cordon_core::crypto::aes_gcm::AesGcmEncryptor;
use agent_cordon_core::oauth2::OAuth2TokenManager;
use agent_cordon_core::storage::Store;
use metrics_exporter_prometheus::PrometheusHandle;

use crate::auditing_policy_engine::AuditingPolicyEngine;
use crate::config::AppConfig;
use crate::events::{EventBus, SseConnectionTracker, UiEventBus};
use crate::middleware::rate_limit_device_approve::DeviceApproveRateLimiter;
use crate::rate_limit::LoginRateLimiter;
use crate::routes::admin_api::credential_templates::CredentialTemplate;
use crate::routes::admin_api::mcp_templates::McpServerTemplate;
use crate::routes::admin_api::policy_templates::PolicyTemplate;

pub type SharedStore = Arc<dyn Store + Send + Sync>;

#[derive(Clone)]
pub struct AppState {
    pub store: SharedStore,
    pub jwt_issuer: Arc<JwtIssuer>,
    pub policy_engine: Arc<AuditingPolicyEngine>,
    pub encryptor: Arc<AesGcmEncryptor>,
    pub config: AppConfig,
    pub login_rate_limiter: Arc<LoginRateLimiter>,
    /// Per-(IP,user) rate limiter for `/oauth/device/approve` and `/oauth/device/deny`.
    pub device_approve_limiter: Arc<DeviceApproveRateLimiter>,
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
    /// Pre-loaded credential templates (embedded + runtime overrides).
    pub credential_templates: Vec<CredentialTemplate>,
    /// Pre-loaded MCP server templates (embedded + runtime overrides).
    pub mcp_templates: Vec<McpServerTemplate>,
    /// Pre-loaded policy templates (embedded + runtime overrides).
    pub policy_templates: Vec<PolicyTemplate>,
}
