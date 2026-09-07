//! Application state: everything a handler can reach through `State<AppState>`.
//!
//! The state is built once by [`AppState::new`], from the server binary and
//! from the integration-test harness alike, so the two construction sites
//! cannot drift. Fields are grouped into sub-states ([`CryptoState`],
//! [`LimitsState`], [`RealtimeState`], [`CatalogState`], [`Services`]) that
//! implement `FromRef<AppState>`, so a handler that needs one thing can
//! extract `State<CryptoState>` instead of the whole state.

use std::sync::Arc;

use axum::extract::FromRef;
use metrics_exporter_prometheus::PrometheusHandle;

use agent_cordon_core::crypto::key_derivation::derive_session_hash_key;
use agent_cordon_core::crypto::key_ring::{KeyRing, MasterSecret};
use agent_cordon_core::error::CryptoError;
use agent_cordon_core::oauth2::OAuth2TokenManager;
use agent_cordon_core::policy::cedar::CedarPolicyEngine;
use agent_cordon_core::storage::Store;

use crate::authz::Authz;
use crate::config::AppConfig;
use crate::events::{SseConnectionTracker, UiEventBus};
use crate::middleware::rate_limit_device_approve::DeviceApproveRateLimiter;
use crate::middleware::sliding_window::SlidingWindowLimiter;
use crate::rate_limit::LoginRateLimiter;
use crate::services::Services;
use crate::templates::{
    load_credential_templates, load_mcp_templates, load_policy_templates, CredentialTemplate,
    McpServerTemplate, PolicyTemplate,
};

pub type SharedStore = Arc<dyn Store + Send + Sync>;

/// Capacity of the in-process UI event channel. A browser that falls this
/// far behind sees a lag error and resyncs; events are not persisted.
const UI_EVENT_BUS_CAPACITY: usize = 256;

/// Concurrent SSE connections one user may hold.
const SSE_MAX_PER_USER: usize = 5;

/// Key material derived from the master secret.
#[derive(Clone)]
pub struct CryptoState {
    /// Versioned master-key ring: seals under the current version, opens
    /// rows by their stored `key_version` (or current-then-previous when a
    /// row has no version).
    pub key_ring: Arc<KeyRing>,
    /// HMAC key for session token hashing (domain-separated from encryption/signing keys).
    pub session_hash_key: [u8; 32],
}

impl CryptoState {
    /// Derive the key ring and session hash key from the configured master
    /// secret(s), as the server does at startup.
    pub fn from_config(config: &AppConfig) -> Result<Self, CryptoError> {
        // One AES-GCM key per master-secret version. The previous secret, when
        // configured, lets rows sealed before a rotation open until rotate-key
        // has re-sealed them under the current version.
        let previous = config
            .previous_master_secret
            .as_deref()
            .zip(config.previous_kdf_salt.as_deref())
            .map(|(secret, salt)| MasterSecret {
                secret,
                kdf_salt: salt.as_bytes(),
            });
        let key_ring = KeyRing::from_secrets(
            MasterSecret {
                secret: &config.master_secret,
                kdf_salt: config.kdf_salt.as_bytes(),
            },
            config.master_key_version,
            previous,
        )?;
        let session_hash_key =
            derive_session_hash_key(&config.master_secret, config.kdf_salt.as_bytes())?;
        Ok(Self {
            key_ring: Arc::new(key_ring),
            session_hash_key: *session_hash_key,
        })
    }
}

/// Rate limiters and connection caps.
#[derive(Clone)]
pub struct LimitsState {
    /// Per-(address, username) login lockout.
    pub login: Arc<LoginRateLimiter>,
    /// Per-(IP,user) rate limiter for `/oauth/device/approve` and `/oauth/device/deny`.
    pub device_approve: Arc<DeviceApproveRateLimiter>,
    /// Per-(IP, client_id) limit on `POST /oauth/device/code`, which is
    /// unauthenticated and writes a row per call.
    pub device_code_issue: Arc<SlidingWindowLimiter>,
    /// Per-user SSE connection limiter to prevent connection leaks.
    pub sse: SseConnectionTracker,
}

impl LimitsState {
    fn from_config(config: &AppConfig) -> Self {
        Self {
            login: Arc::new(LoginRateLimiter::new(
                config.login_max_attempts,
                config.login_lockout_seconds,
            )),
            device_approve: DeviceApproveRateLimiter::new(),
            device_code_issue: Arc::new(SlidingWindowLimiter::new(
                crate::routes::oauth::DEVICE_CODE_ISSUE_MAX_PER_MINUTE,
                std::time::Duration::from_secs(60),
            )),
            sse: SseConnectionTracker::new(SSE_MAX_PER_USER),
        }
    }
}

/// Push channels to connected browsers.
#[derive(Clone)]
pub struct RealtimeState {
    /// In-process event bus for UI (browser) push notifications (SSE).
    pub ui_event_bus: UiEventBus,
}

/// Pre-loaded template catalogs (embedded + runtime overrides).
#[derive(Clone)]
pub struct CatalogState {
    pub credential_templates: Arc<Vec<CredentialTemplate>>,
    pub mcp_templates: Arc<Vec<McpServerTemplate>>,
    pub policy_templates: Arc<Vec<PolicyTemplate>>,
}

impl CatalogState {
    /// Load every catalog from the embedded assets plus the override
    /// directories named in `config`.
    pub fn load(config: &AppConfig) -> Self {
        Self {
            credential_templates: Arc::new(load_credential_templates(
                config.credential_templates_dir.as_deref(),
            )),
            mcp_templates: Arc::new(load_mcp_templates(config.mcp_templates_dir.as_deref())),
            policy_templates: Arc::new(load_policy_templates(
                config.policy_templates_dir.as_deref(),
            )),
        }
    }

    /// Append MCP templates to the loaded catalog (test harness: templates
    /// pointing at a mock authorization server).
    pub fn with_extra_mcp_templates(mut self, extra: Vec<McpServerTemplate>) -> Self {
        if !extra.is_empty() {
            let mut templates = (*self.mcp_templates).clone();
            templates.extend(extra);
            self.mcp_templates = Arc::new(templates);
        }
        self
    }
}

#[derive(Clone)]
pub struct AppState {
    pub store: SharedStore,
    pub authz: Arc<Authz>,
    pub config: AppConfig,
    pub metrics_handle: PrometheusHandle,
    /// Cache of upstream OAuth2 access tokens for OAuth-backed credentials.
    pub oauth2_token_manager: OAuth2TokenManager,
    /// Shared HTTP client for proxy routes (avoids per-request client creation).
    pub http_client: reqwest::Client,
    pub crypto: CryptoState,
    pub limits: LimitsState,
    pub realtime: RealtimeState,
    pub catalog: CatalogState,
    /// Application services, one per aggregate. Handlers call these for
    /// every state change.
    pub services: Services,
}

impl AppState {
    /// Build the state. Both `main` and the test harness call this; nothing
    /// else constructs an `AppState`.
    ///
    /// The policy engine is loaded by [`policy_engine_from_store`] before
    /// this is called so the caller decides how a load failure is reported.
    pub fn new(
        config: AppConfig,
        store: SharedStore,
        crypto: CryptoState,
        policy_engine: Arc<CedarPolicyEngine>,
        metrics_handle: PrometheusHandle,
        catalog: CatalogState,
    ) -> Self {
        let authz = Arc::new(Authz::new(policy_engine, store.clone()));
        let http_client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(config.proxy_timeout_seconds))
            .user_agent(agent_cordon_core::USER_AGENT)
            .build()
            .expect("failed to build shared HTTP client");
        let oauth2_token_manager = OAuth2TokenManager::new();
        let limits = LimitsState::from_config(&config);
        let realtime = RealtimeState {
            ui_event_bus: UiEventBus::new(UI_EVENT_BUS_CAPACITY),
        };
        let services = Services::new(
            store.clone(),
            authz.clone(),
            crypto.clone(),
            realtime.ui_event_bus.clone(),
            oauth2_token_manager.clone(),
            limits.login.clone(),
            config.clone(),
        );
        Self {
            store,
            authz,
            config,
            metrics_handle,
            oauth2_token_manager,
            http_client,
            crypto,
            limits,
            realtime,
            catalog,
            services,
        }
    }
}

macro_rules! from_ref_field {
    ($ty:ty, $field:ident) => {
        impl FromRef<AppState> for $ty {
            fn from_ref(state: &AppState) -> Self {
                state.$field.clone()
            }
        }
    };
}

from_ref_field!(CryptoState, crypto);
from_ref_field!(LimitsState, limits);
from_ref_field!(RealtimeState, realtime);
from_ref_field!(CatalogState, catalog);
from_ref_field!(Services, services);
from_ref_field!(SharedStore, store);
from_ref_field!(Arc<Authz>, authz);
from_ref_field!(AppConfig, config);

/// Why the policy engine could not be built from the database.
#[derive(Debug, thiserror::Error)]
pub enum PolicyEngineLoadError {
    #[error("failed to load policies from database: {0}")]
    Store(#[from] agent_cordon_core::error::StoreError),
    #[error("failed to initialize policy engine: {0}")]
    Engine(#[from] agent_cordon_core::error::PolicyError),
}

/// Load every enabled policy from the store into a fresh Cedar engine. The
/// database is the single source of truth: an empty set means deny-all.
pub async fn policy_engine_from_store(
    store: &(dyn Store + Send + Sync),
) -> Result<Arc<CedarPolicyEngine>, PolicyEngineLoadError> {
    let db_policies = store.get_all_enabled_policies().await?;
    if db_policies.is_empty() {
        tracing::warn!("no enabled policies in database — deny-all is in effect");
    }
    let policy_sources: Vec<(String, String)> = db_policies
        .into_iter()
        .map(|p| (p.id.0.to_string(), p.cedar_policy))
        .collect();
    Ok(Arc::new(CedarPolicyEngine::new(policy_sources)?))
}
