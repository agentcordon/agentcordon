//! Test infrastructure for integration tests.
//!
//! Provides [`TestAppBuilder`] — the single source of truth for constructing
//! a complete test environment.  Every integration test MUST use this builder
//! instead of constructing `AppState` manually.
//!
//! # Example
//! ```text
//! let ctx = TestAppBuilder::new()
//!     .with_admin()
//!     .build()
//!     .await;
//! // ctx.app      -- the Router
//! // ctx.admin_key -- raw API key for the admin agent
//! // ctx.store    -- Arc<dyn Store>
//! ```

use std::collections::HashMap;
use std::sync::Arc;

use axum::Router;
use uuid::Uuid;

use agent_cordon_core::auth::jwt::JwtIssuer;
use agent_cordon_core::crypto::aes_gcm::AesGcmEncryptor;
use agent_cordon_core::crypto::key_derivation::{
    derive_jwt_signing_keypair, derive_master_key, derive_session_hash_key,
};
use agent_cordon_core::domain::workspace::{Workspace, WorkspaceId, WorkspaceStatus};
// Re-export Agent as alias for tests that reference it
pub type Agent = Workspace;
pub type AgentId = WorkspaceId;
use agent_cordon_core::policy::cedar::CedarPolicyEngine;
#[cfg(feature = "sqlite")]
use agent_cordon_core::storage::sqlite::SqliteStore;
use agent_cordon_core::storage::Store;

use crate::build_router;
use crate::config::AppConfig;
use crate::rate_limit::LoginRateLimiter;
use crate::state::AppState;

// ---------------------------------------------------------------------------
// Constants (internal)
// ---------------------------------------------------------------------------

const TEST_MASTER_SECRET: &str = "integration-test-secret-at-least-16";
const TEST_KDF_SALT: &str = "test-salt-value!";

// ---------------------------------------------------------------------------
// TestContext — the output of TestAppBuilder::build()
// ---------------------------------------------------------------------------

/// Device context for an agent created by the test builder.
pub struct TestDeviceContext {
    /// Device UUID as a string.
    pub device_id: String,
    /// P-256 signing key for the device.
    pub signing_key: p256::ecdsa::SigningKey,
}

/// Everything a test needs to exercise the application.
pub struct TestContext {
    /// The fully-configured Axum router.
    pub app: Router,
    /// Raw API key for the admin agent (empty string if `.with_admin()` was not called).
    pub admin_key: String,
    /// The backing store (in-memory SQLite).
    pub store: Arc<dyn Store + Send + Sync>,
    /// The full application state — useful when tests need inner components.
    pub state: AppState,
    /// Encryptor instance shared by the app state (convenience accessor).
    pub encryptor: Arc<AesGcmEncryptor>,
    /// JWT issuer shared by the app state (convenience accessor).
    pub jwt_issuer: Arc<JwtIssuer>,
    /// Raw API keys for agents created via `.with_agent()`, keyed by agent name.
    pub agent_keys: HashMap<String, String>,
    /// Agent records created via `.with_agent()`, keyed by agent name.
    pub agents: HashMap<String, Agent>,
    /// The admin agent record (if `.with_admin()` was called).
    pub admin_agent: Option<Agent>,
    /// Device contexts for agents created by the builder, keyed by agent name.
    pub device_contexts: HashMap<String, TestDeviceContext>,
    /// Device context for the admin agent (if `.with_admin()` was called).
    pub admin_device: Option<TestDeviceContext>,
}

impl TestContext {
    /// Get a device-bound JWT for the admin agent.
    pub fn admin_device_id(&self) -> &str {
        &self
            .admin_device
            .as_ref()
            .expect("admin device must exist")
            .device_id
    }

    /// Get the admin device signing key.
    pub fn admin_signing_key(&self) -> &p256::ecdsa::SigningKey {
        &self
            .admin_device
            .as_ref()
            .expect("admin device must exist")
            .signing_key
    }

    /// Get the device context for a named agent.
    pub fn device_for(&self, name: &str) -> &TestDeviceContext {
        self.device_contexts.get(name).unwrap_or_else(|| {
            panic!("no device context for agent '{}'", name);
        })
    }
}

// ---------------------------------------------------------------------------
// TestAppBuilder
// ---------------------------------------------------------------------------

/// Pending agent to create during `build()`.
struct PendingAgent {
    name: String,
    tags: Vec<String>,
    enabled: bool,
}

/// Builder for test environments.
///
/// Constructs an in-memory `AppState` with sensible defaults, optionally
/// pre-creating agents and loading custom Cedar policies.
pub struct TestAppBuilder {
    create_admin: bool,
    pending_agents: Vec<PendingAgent>,
    custom_policy: Option<String>,
    #[allow(clippy::type_complexity)]
    config_modifiers: Vec<Box<dyn FnOnce(&mut AppConfig)>>,
}

impl TestAppBuilder {
    /// Create a new builder with sensible defaults.
    pub fn new() -> Self {
        Self {
            create_admin: false,
            pending_agents: Vec::new(),
            custom_policy: None,
            config_modifiers: Vec::new(),
        }
    }

    /// Pre-create an admin agent (tags = `["admin"]`).
    ///
    /// The raw API key will be available as `ctx.admin_key` after build.
    pub fn with_admin(mut self) -> Self {
        self.create_admin = true;
        self
    }

    /// Supply a custom Cedar policy (replaces the default policy).
    pub fn with_policy(mut self, policy: &str) -> Self {
        self.custom_policy = Some(policy.to_string());
        self
    }

    /// Pre-create an additional agent with the given name and roles/tags.
    ///
    /// The raw API key will be available in `ctx.agent_keys[name]` after build.
    pub fn with_agent(mut self, name: &str, roles: &[&str]) -> Self {
        self.pending_agents.push(PendingAgent {
            name: name.to_string(),
            tags: roles.iter().map(|r| r.to_string()).collect(),
            enabled: true,
        });
        self
    }

    /// Apply a config modifier (called before `AppState` construction).
    ///
    /// Multiple modifiers are applied in order.
    pub fn with_config(mut self, f: impl FnOnce(&mut AppConfig) + 'static) -> Self {
        self.config_modifiers.push(Box::new(f));
        self
    }

    /// Shorthand: enable enrollment in the config.
    pub fn with_enrollment(self) -> Self {
        self.with_config(|c| {
            c.enrollment_enabled = true;
        })
    }

    /// Build the test environment.
    #[cfg(feature = "sqlite")]
    pub async fn build(self) -> TestContext {
        // ---- Crypto keys ----
        let master_key = derive_master_key(TEST_MASTER_SECRET, TEST_KDF_SALT.as_bytes())
            .expect("derive master key");
        let session_hash_key =
            derive_session_hash_key(TEST_MASTER_SECRET, TEST_KDF_SALT.as_bytes())
                .expect("derive session hash key");
        let session_hash_key = *session_hash_key;

        let encryptor = Arc::new(AesGcmEncryptor::new(&master_key));

        // Derive ES256 key pair for JWT signing
        let (jwt_sk, jwt_vk) =
            derive_jwt_signing_keypair(TEST_MASTER_SECRET, TEST_KDF_SALT.as_bytes())
                .expect("derive jwt es256 keypair");
        let jwt_issuer = Arc::new(JwtIssuer::new(
            &jwt_sk,
            &jwt_vk,
            agent_cordon_core::auth::jwt::ISSUER.to_string(),
            900,
        ));

        // ---- Store ----
        let sqlite_store = SqliteStore::new_in_memory()
            .await
            .expect("create in-memory store");
        sqlite_store.run_migrations().await.expect("run migrations");
        let store: Arc<dyn Store + Send + Sync> = Arc::new(sqlite_store);

        // ---- Policy engine (DB is single source of truth) ----
        // Seed policy into DB first, then load from DB — mirrors production startup.
        {
            use agent_cordon_core::domain::policy::{PolicyId, StoredPolicy};

            let policy_text = self
                .custom_policy
                .unwrap_or_else(|| {
                    // Start with the shipped default policy, then append the auto-enroll
                    // rule that is commented out in default.cedar for new installations
                    // but needed by most tests.
                    let mut policy = include_str!("../../../policies/default.cedar").to_string();
                    policy.push_str("\n// Auto-enroll rule (added by test harness)\npermit(\n  principal is AgentCordon::Workspace,\n  action == AgentCordon::Action::\"enroll_agent\",\n  resource is AgentCordon::System\n) when {\n  principal.enabled\n};\n");
                    policy
                });

            let now = chrono::Utc::now();
            let seed_policy = StoredPolicy {
                id: PolicyId(Uuid::new_v4()),
                name: "default".to_string(),
                description: Some("Test default policy".to_string()),
                cedar_policy: policy_text,
                enabled: true,
                is_system: false,
                created_at: now,
                updated_at: now,
            };
            store
                .store_policy(&seed_policy)
                .await
                .expect("seed test policy into DB");
        }

        let db_policies = store
            .get_all_enabled_policies()
            .await
            .expect("load policies from DB");
        let policy_sources: Vec<(String, String)> = db_policies
            .into_iter()
            .map(|p| (p.id.0.to_string(), p.cedar_policy))
            .collect();
        let policy_engine =
            CedarPolicyEngine::new(policy_sources).expect("init policy engine from DB");
        let policy_engine = Arc::new(policy_engine);

        // ---- Config ----
        let mut config = AppConfig::test_default();
        for modifier in self.config_modifiers {
            modifier(&mut config);
        }

        // ---- Rate limiter ----
        let login_rate_limiter = Arc::new(LoginRateLimiter::new(
            config.login_max_attempts,
            config.login_lockout_seconds,
        ));

        // ---- Metrics ----
        let metrics_handle = crate::metrics::test_handle();

        // ---- Shared HTTP client ----
        let http_client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(config.proxy_timeout_seconds))
            .user_agent("AgentCordon/0.1")
            .build()
            .expect("build test HTTP client");

        // ---- AppState ----
        let app_state = AppState {
            store: store.clone(),
            jwt_issuer: jwt_issuer.clone(),
            policy_engine,
            encryptor: encryptor.clone(),
            config,
            login_rate_limiter,
            metrics_handle,
            session_hash_key,
            oauth2_token_manager: agent_cordon_core::oauth2::OAuth2TokenManager::new(),
            http_client,
            event_bus: crate::events::EventBus::new(256),
            ui_event_bus: crate::events::UiEventBus::new(16),
            sse_tracker: crate::events::SseConnectionTracker::new(5),
            workspace_challenges: std::sync::Arc::new(tokio::sync::RwLock::new(
                std::collections::HashMap::new(),
            )),
            credential_templates: crate::routes::admin_api::credential_templates::load_templates(
                None,
            ),
            policy_templates: crate::routes::admin_api::policy_templates::load_templates(None),
        };

        // ---- Create agents ----
        let mut admin_key = String::new();
        let mut admin_agent: Option<Agent> = None;
        let mut admin_device: Option<TestDeviceContext> = None;
        let mut agent_keys: HashMap<String, String> = HashMap::new();
        let mut agents: HashMap<String, Agent> = HashMap::new();
        let mut device_contexts: HashMap<String, TestDeviceContext> = HashMap::new();

        if self.create_admin {
            let (agent, raw_key, dev_ctx) =
                create_agent_in_store(&*store, "test-admin", &["admin"], true).await;
            admin_key = raw_key;
            admin_agent = Some(agent);
            admin_device = Some(dev_ctx);
        }

        for pending in self.pending_agents {
            let tag_refs: Vec<&str> = pending.tags.iter().map(|s| s.as_str()).collect();
            let (agent, raw_key, dev_ctx) =
                create_agent_in_store(&*store, &pending.name, &tag_refs, pending.enabled).await;
            agent_keys.insert(pending.name.clone(), raw_key);
            agents.insert(pending.name.clone(), agent);
            device_contexts.insert(pending.name, dev_ctx);
        }

        // ---- Router ----
        let app = build_router(app_state.clone());

        TestContext {
            app,
            admin_key,
            store,
            state: app_state,
            encryptor,
            jwt_issuer,
            agent_keys,
            agents,
            admin_agent,
            device_contexts,
            admin_device,
        }
    }
}

impl Default for TestAppBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Create a workspace in the store and return (Workspace, raw_api_key, TestDeviceContext).
///
/// Each workspace is created with a P-256 signing key for auth in tests.
async fn create_agent_in_store(
    store: &(dyn Store + Send + Sync),
    name: &str,
    tags: &[&str],
    enabled: bool,
) -> (Workspace, String, TestDeviceContext) {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;

    let now = chrono::Utc::now();

    let workspace_id = WorkspaceId(Uuid::new_v4());
    let signing_key = p256::ecdsa::SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
    let verifying_key = signing_key.verifying_key();
    let point = verifying_key.to_encoded_point(false);
    let _x = URL_SAFE_NO_PAD.encode(AsRef::<[u8]>::as_ref(point.x().unwrap()));
    let _y = URL_SAFE_NO_PAD.encode(AsRef::<[u8]>::as_ref(point.y().unwrap()));

    // Compute pk_hash for the workspace
    let pk_bytes = verifying_key.to_encoded_point(true);
    let pk_hash = {
        use sha2::Digest;
        let hash = sha2::Sha256::digest(pk_bytes.as_bytes());
        hex::encode(hash)
    };

    let enc_signing_key =
        p256::ecdsa::SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
    let enc_verifying_key = enc_signing_key.verifying_key();
    let enc_point = enc_verifying_key.to_encoded_point(false);
    let enc_x = URL_SAFE_NO_PAD.encode(AsRef::<[u8]>::as_ref(enc_point.x().unwrap()));
    let enc_y = URL_SAFE_NO_PAD.encode(AsRef::<[u8]>::as_ref(enc_point.y().unwrap()));
    let enc_jwk = serde_json::json!({
        "kty": "EC",
        "crv": "P-256",
        "x": enc_x,
        "y": enc_y,
        "use": "enc"
    });
    let enc_pub_key = serde_json::to_string(&enc_jwk).unwrap();

    let workspace = Workspace {
        id: workspace_id,
        name: name.to_string(),
        enabled,
        status: WorkspaceStatus::Active,
        pk_hash: Some(pk_hash),
        encryption_public_key: Some(enc_pub_key),
        tags: tags.iter().map(|t| t.to_string()).collect(),
        owner_id: None,
        parent_id: None,
        tool_name: None,
        created_at: now,
        updated_at: now,
    };
    store
        .create_workspace(&workspace)
        .await
        .expect("create workspace");

    let dev_ctx = TestDeviceContext {
        device_id: workspace.id.0.to_string(),
        signing_key,
    };

    (workspace, String::new(), dev_ctx)
}
