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

use agent_cordon_core::crypto::aes_gcm::AesGcmEncryptor;
use agent_cordon_core::crypto::key_derivation::{derive_master_key, derive_session_hash_key};
use agent_cordon_core::crypto::key_ring::KeyRing;
use agent_cordon_core::domain::workspace::{Workspace, WorkspaceId, WorkspaceStatus};
// Re-export Agent as alias for tests that reference it
pub type Agent = Workspace;
pub type AgentId = WorkspaceId;
use agent_cordon_core::storage::sqlite::SqliteStore;
use agent_cordon_core::storage::Store;

use crate::build_router;
use crate::config::AppConfig;
use crate::state::{policy_engine_from_store, AppState, CatalogState, CryptoState};

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
    /// The backing store (in-memory SQLite, or the one given to `with_store`).
    pub store: Arc<dyn Store + Send + Sync>,
    /// The full application state — useful when tests need inner components.
    pub state: AppState,
    /// An encryptor holding the app's current master key. Anything it seals
    /// opens with the app's key ring (`state.crypto.key_ring`) and vice versa.
    pub encryptor: Arc<AesGcmEncryptor>,
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
    /// The operator warning the master-secret resolution produced, set only
    /// when [`TestAppBuilder::with_sqlite_file`] named a database whose weak
    /// secret had to keep its legacy derivation.
    pub master_secret_warning: Option<String>,
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
    extra_mcp_templates: Vec<crate::templates::McpServerTemplate>,
    master_secret: String,
    master_key_version: i64,
    previous_master_secret: Option<String>,
    store: Option<Arc<dyn Store + Send + Sync>>,
    db_file: Option<String>,
}

impl TestAppBuilder {
    /// Create a new builder with sensible defaults.
    ///
    /// Installs the cheap Argon2id parameters process-wide (the runtime
    /// replacement for the old `test-crypto` cargo feature) so a test that
    /// hashes a password before building the app is fast too.
    pub fn new() -> Self {
        agent_cordon_core::crypto::install_argon2_params(
            agent_cordon_core::crypto::Argon2Params::FAST,
        );
        Self {
            create_admin: false,
            pending_agents: Vec::new(),
            custom_policy: None,
            config_modifiers: Vec::new(),
            extra_mcp_templates: Vec::new(),
            master_secret: TEST_MASTER_SECRET.to_string(),
            master_key_version: 1,
            previous_master_secret: None,
            store: None,
            db_file: None,
        }
    }

    /// Use `secret` as the current master secret, at key `version`
    /// (`AGTCRDN_MASTER_SECRET` + `AGTCRDN_MASTER_KEY_VERSION`).
    pub fn with_master_secret(mut self, secret: &str, version: i64) -> Self {
        self.master_secret = secret.to_string();
        self.master_key_version = version;
        self
    }

    /// Load `secret` as the key for `version - 1`
    /// (`AGTCRDN_PREVIOUS_MASTER_SECRET`), for rotation-window tests.
    pub fn with_previous_master_secret(mut self, secret: &str) -> Self {
        self.previous_master_secret = Some(secret.to_string());
        self
    }

    /// Build over an existing store instead of a fresh in-memory one.
    ///
    /// Migrations and the default-policy seed are skipped (the store already
    /// has them). This is how a test simulates a server restart: a second
    /// app, possibly with different master secrets, over the same data.
    pub fn with_store(mut self, store: Arc<dyn Store + Send + Sync>) -> Self {
        self.store = Some(store);
        self
    }

    /// Build over a file-backed SQLite database, the way the server boots
    /// over an install that already exists on disk.
    ///
    /// Unlike [`TestAppBuilder::with_store`], the migrations in `migrations/`
    /// are run against the file, so a test can point at a database written by
    /// an older release and assert what the upgrade does to it. Two further
    /// things follow the real startup path rather than the test defaults:
    /// the KDF salt is derived from the master secret the way
    /// `AppConfig::from_env` derives it, and the secret then passes through
    /// `AppConfig::finalize_master_secret` with the store's actual state, so a
    /// weak secret protecting an existing install keeps its legacy derivation
    /// instead of being stretched out from under its own ciphertext. The
    /// warning that branch produces lands in
    /// [`TestContext::master_secret_warning`].
    ///
    /// The file is opened in place and migrated in place: copy the fixture
    /// into a `tempfile::TempDir` first.
    pub fn with_sqlite_file(mut self, db_path: impl Into<String>) -> Self {
        self.db_file = Some(db_path.into());
        self
    }

    /// Inject an additional MCP template into the in-memory catalog.
    ///
    /// Used by OAuth/DCR tests that need a template pointing at a mock
    /// authorization server.
    pub fn with_mcp_template(mut self, template: crate::templates::McpServerTemplate) -> Self {
        self.extra_mcp_templates.push(template);
        self
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

    /// Build the test environment.
    pub async fn build(self) -> TestContext {
        // ---- A file-backed database, if one was named ----
        // Open it, migrate it, and resolve the master secret against what it
        // already holds, exactly as startup does before deriving any key.
        let (file_backed_store, resolved_secret, resolved_salt, master_secret_warning) =
            self.open_db_file().await;

        // ---- Crypto keys ----
        // For an in-memory store the salt is fixed for every secret, as with
        // an explicit AGTCRDN_KDF_SALT; a file-backed one derives it.
        let master_secret = resolved_secret.as_str();
        let kdf_salt = resolved_salt.as_str();
        let master_key =
            derive_master_key(master_secret, kdf_salt.as_bytes()).expect("derive master key");
        let session_hash_key = derive_session_hash_key(master_secret, kdf_salt.as_bytes())
            .expect("derive session hash key");
        let session_hash_key = *session_hash_key;

        let encryptor = Arc::new(AesGcmEncryptor::new(&master_key));
        // The ring shares `encryptor` as its current key, so a test can read
        // the nonce counter the app is incrementing.
        let mut key_ring = KeyRing::new(self.master_key_version, encryptor.clone());
        if let Some(previous) = self.previous_master_secret.as_deref() {
            assert_ne!(
                previous, master_secret,
                "previous master secret must differ from the current one"
            );
            let previous_key = derive_master_key(previous, TEST_KDF_SALT.as_bytes())
                .expect("derive previous master key");
            key_ring = key_ring.with_previous(Arc::new(AesGcmEncryptor::new(&previous_key)));
        }
        let key_ring = Arc::new(key_ring);

        // ---- Store ----
        let reused_store = self.store.is_some() || file_backed_store.is_some();
        let store: Arc<dyn Store + Send + Sync> = match file_backed_store.or(self.store) {
            Some(store) => store,
            None => {
                let sqlite_store = SqliteStore::new_in_memory()
                    .await
                    .expect("create in-memory store");
                sqlite_store.run_migrations().await.expect("run migrations");
                Arc::new(sqlite_store)
            }
        };

        // ---- Policy engine (DB is single source of truth) ----
        // Seed policy into DB first, then load from DB — mirrors production startup.
        // A reused store was seeded by the app that created it.
        if !reused_store {
            use agent_cordon_core::domain::policy::{PolicyId, StoredPolicy};

            let policy_text = self.custom_policy.unwrap_or_else(|| {
                // Start with the shipped default policy, then append the auto-enroll
                // rule that is commented out in default.cedar for new installations
                // but needed by most tests.
                include_str!("../../../policies/default.cedar").to_string()
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

        let policy_engine = policy_engine_from_store(&*store)
            .await
            .expect("init policy engine from DB");

        // ---- Config ----
        let mut config = AppConfig::test_default();
        config.master_secret = master_secret.to_string();
        config.kdf_salt = kdf_salt.to_string();
        config.master_key_version = self.master_key_version;
        if let Some(db_file) = self.db_file.as_ref() {
            config.db_path = db_file.clone();
        }
        config.previous_master_secret = self.previous_master_secret.clone();
        config.previous_kdf_salt = self
            .previous_master_secret
            .as_ref()
            .map(|_| TEST_KDF_SALT.to_string());
        for modifier in self.config_modifiers {
            modifier(&mut config);
        }

        // ---- AppState (same constructor as `main`) ----
        let catalog =
            CatalogState::load(&config).with_extra_mcp_templates(self.extra_mcp_templates);
        let app_state = AppState::new(
            config,
            store.clone(),
            CryptoState {
                key_ring,
                session_hash_key,
            },
            policy_engine,
            crate::metrics::test_handle(),
            catalog,
        );

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
            agent_keys,
            agents,
            admin_agent,
            device_contexts,
            admin_device,
            master_secret_warning,
        }
    }

    /// Open, migrate, and key a file-backed database named by
    /// [`TestAppBuilder::with_sqlite_file`].
    ///
    /// Returns the store, the secret to feed HKDF, the KDF salt, and the
    /// operator warning the master-secret resolution produced. With no file
    /// named, returns the in-memory defaults: the configured secret and the
    /// fixed test salt.
    async fn open_db_file(
        &self,
    ) -> (
        Option<Arc<dyn Store + Send + Sync>>,
        String,
        String,
        Option<String>,
    ) {
        use agent_cordon_core::crypto::master_secret::StoreState;

        let Some(db_path) = self.db_file.as_deref() else {
            return (
                None,
                self.master_secret.clone(),
                TEST_KDF_SALT.to_string(),
                None,
            );
        };

        let sqlite_store = SqliteStore::new(db_path).await.expect("open sqlite file");
        sqlite_store.run_migrations().await.expect("run migrations");
        let store: Arc<dyn Store + Send + Sync> = Arc::new(sqlite_store);

        // The salt is derived from the configured secret, before any
        // stretching, as `AppConfig::from_env` derives it.
        let kdf_salt = agent_cordon_core::crypto::kdf::derive_kdf_salt(&self.master_secret);

        // "Nothing sealed yet" is no credentials and no users, the same
        // signal `main` uses to decide whether a weak secret may be stretched.
        let no_credentials = store
            .list_credentials()
            .await
            .map(|c| c.is_empty())
            .unwrap_or(false);
        let no_users = store
            .list_users()
            .await
            .map(|u| u.is_empty())
            .unwrap_or(false);
        let store_state = if no_credentials && no_users {
            StoreState::Fresh
        } else {
            StoreState::Populated
        };

        let mut config = AppConfig::test_default();
        config.db_path = db_path.to_string();
        config.master_secret = self.master_secret.clone();
        let warning = config
            .finalize_master_secret(store_state)
            .expect("resolve the master secret");

        (Some(store), config.master_secret, kdf_salt, warning)
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
        status: if enabled {
            WorkspaceStatus::Active
        } else {
            WorkspaceStatus::Disabled
        },
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
