// AgentCordon — credential brokering and policy enforcement for AI agents.
// Copyright (C) 2026 The AgentCordon Authors
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, version 3.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Affero
// General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

use std::sync::Arc;

use clap::Parser;
use tracing_subscriber::{fmt, EnvFilter};

use agent_cordon_core::crypto::install_argon2_params;
use agent_cordon_core::crypto::master_secret::StoreState;
use agent_cordon_core::crypto::password::hash_password_async;
use agent_cordon_core::domain::user::{User, UserId, UserRole};
use agent_cordon_core::storage::Store;

use agent_cordon_server::build_router;
use agent_cordon_server::config::AppConfig;
use agent_cordon_server::metrics::setup_metrics;
use agent_cordon_server::state::{policy_engine_from_store, AppState, CatalogState, CryptoState};

/// The environment is the server's configuration surface, so `--help` is the
/// only place the binary itself can say what it reads. Kept in step with
/// docs/configuration.md.
const ENV_HELP: &str = "\
The server takes no configuration flags: everything is read from the
environment (or a `.env` file your process manager loads for it).

Core:
  AGTCRDN_LISTEN_ADDR    Address and port to bind        [default: 0.0.0.0:3140]
  AGTCRDN_BASE_URL       The URL users reach this server on. Device-flow
                         activation links, the OAuth2 MCP callback redirect
                         URI and GET /install.sh are built from it. Unset, it
                         falls back to http://$AGTCRDN_LISTEN_ADDR, which is
                         unusable in a container. Set it.
  AGTCRDN_DB_PATH        SQLite database file      [default: ./data/agent-cordon.db]
  AGTCRDN_REPLICA_MODE   `single` (default) or `unsafe-shared` to disable the
                         single-instance database guard

Secrets and bootstrap:
  AGTCRDN_MASTER_SECRET            Master encryption key. Auto-generated into
                                   <db dir>/.secret when unset — set it in
                                   production and persist it.
  AGTCRDN_MASTER_KEY_VERSION       Version of the current master secret  [default: 1]
  AGTCRDN_PREVIOUS_MASTER_SECRET   The secret for version N-1, during a rotation
  AGTCRDN_ROOT_USERNAME            Bootstrap admin username    [default: root]
  AGTCRDN_ROOT_PASSWORD            Bootstrap admin password    [default: generated
                                   and printed once on first boot]

Key derivation (see docs/master-key.md):
  AGTCRDN_KDF_SALT             HKDF salt override, applied to the current and
                               the previous master secret alike. Unset, each
                               secret derives its own salt — the safe default.
                               Set it and you must keep setting it, including
                               through a rotation.
  AGTCRDN_ARGON2_M_COST_KIB    Argon2id memory cost, KiB       [default: 65536]
  AGTCRDN_ARGON2_T_COST        Argon2id iterations             [default: 3]
  AGTCRDN_ARGON2_P_COST        Argon2id lanes                  [default: 4]
                               The three costs apply to master-secret
                               stretching, password hashing and secret hashing
                               alike; lowering them weakens all three.

Logging:
  AGTCRDN_LOG_LEVEL      trace|debug|info|warn|error    [default: info]
  AGTCRDN_LOG_FORMAT     json|pretty                    [default: json]

Sessions and limits:
  AGTCRDN_SESSION_TTL                     Session lifetime, seconds   [default: 28800]
  AGTCRDN_AUTH_CODE_TTL                   OAuth authorization code TTL, seconds [default: 600]
  AGTCRDN_DEVICE_CODE_TTL_SECS            Device code TTL, seconds    [default: 600]
  AGTCRDN_DEVICE_CODE_POLL_INTERVAL_SECS  Device flow poll interval   [default: 5]
  AGTCRDN_LOGIN_MAX_ATTEMPTS              Failed logins before lockout [default: 5]
  AGTCRDN_LOGIN_LOCKOUT_SECONDS           Lockout duration, seconds    [default: 30]
  AGTCRDN_TRUST_FORWARDED_HEADERS         Trust X-Forwarded-For. Only behind a
                                          proxy that overwrites it.  [default: false]

Templates (read once at startup — restart after editing one):
  AGTCRDN_MCP_TEMPLATES_DIR          Extra MCP marketplace templates
  AGTCRDN_CREDENTIAL_TEMPLATES_DIR   Extra credential templates
  AGTCRDN_POLICY_TEMPLATES_DIR       Extra policy templates
  AGTCRDN_INSTANCE_LABEL             client_name sent in OAuth Dynamic Client
                                     Registration            [default: AgentCordon]

Development only:
  AGTCRDN_PROXY_ALLOW_LOOPBACK   Turns the SSRF guard OFF, not just the loopback
                                 rule: every private and reserved range becomes a
                                 reachable proxy target.     [default: false]

See docs/configuration.md for the full table.";

/// `agent-cordon-server` takes no flags. It still needs a parser: without one
/// `--help` fell through to the server boot, which bound 0.0.0.0:3140 and
/// wrote a database and a master key into the operator's working directory.
#[derive(Parser, Debug)]
#[command(
    name = "agent-cordon-server",
    version,
    about = "AgentCordon control plane — admin API and UI, OAuth authorization server, and vault",
    after_help = ENV_HELP,
    after_long_help = ENV_HELP
)]
struct Cli {}

#[tokio::main]
async fn main() {
    // Before anything binds, opens, or writes: an unknown argument exits 2
    // and `--help` / `--version` exit 0, having started nothing.
    Cli::parse();

    let mut config = match AppConfig::from_env() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Configuration error: {e}");
            std::process::exit(1);
        }
    };

    init_tracing(&config);
    install_argon2_params(config.argon2);

    // Held for the life of the process, and taken before migrations: two
    // servers must not migrate or enforce policy over one database.
    let _instance_lock = match config.acquire_instance_lock() {
        Ok(lock) => {
            if let Some(lock) = &lock {
                tracing::info!(lock_file = %lock.path().display(), "single-instance lock acquired");
            }
            lock
        }
        Err(e) => {
            tracing::error!(error = %e, "refusing to start");
            eprintln!("Startup error: {e}");
            std::process::exit(1);
        }
    };

    let store = init_store(&config).await;
    finalize_master_secret(&mut config, &*store).await;
    let crypto = init_crypto(&config);
    seed_default_policy(&*store).await;
    agent_cordon_server::migrations::migrate_mcp_policy_names_to_ids(&*store).await;
    agent_cordon_server::migrations::migrate_generated_mcp_policy_names(&*store).await;
    let policy_engine = match policy_engine_from_store(&*store).await {
        Ok(engine) => engine,
        Err(e) => {
            tracing::error!(error = %e, "failed to load policy engine");
            std::process::exit(1);
        }
    };
    bootstrap_root_user(&*store, &config).await;

    let app_state = AppState::new(
        config.clone(),
        store,
        crypto,
        policy_engine,
        setup_metrics(),
        CatalogState::load(&config),
    );

    spawn_cleanup_task(&app_state, &config);

    let app = build_router(app_state);

    tracing::info!(listen_addr = %config.listen_addr, "starting agent-cordon server");

    let listener = tokio::net::TcpListener::bind(&config.listen_addr)
        .await
        .expect("failed to bind listener");
    // Record each connection's peer address so per-address limits (login
    // lockout, device-code approval) key on something a caller cannot forge.
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
    .unwrap();

    tracing::info!("Server shut down cleanly");
}

fn init_tracing(config: &AppConfig) {
    let env_filter = EnvFilter::from_default_env()
        .add_directive(config.log_level.parse().unwrap_or("info".parse().unwrap()));

    if config.log_format == "pretty" {
        fmt().pretty().with_env_filter(env_filter).init();
    } else {
        fmt().json().with_env_filter(env_filter).init();
    }
}

/// Decide, now that the store is open, whether a weak master secret may be
/// stretched. Stretching changes the derived key, so it is only safe when
/// nothing is sealed under the old derivation yet (or the salt file shows
/// this install was already stretched).
///
/// "Nothing sealed" means no credentials *and* no users: OAuth provider
/// client secrets, OIDC client secrets and MCP upstream tokens are sealed
/// with the master key too, and none of them can exist before the root user
/// is bootstrapped. This runs before that bootstrap, so an empty user table
/// is a reliable first-boot signal.
async fn finalize_master_secret(config: &mut AppConfig, store: &(dyn Store + Send + Sync)) {
    // Conservative on error: assume there is something to lose.
    let no_credentials = match store.list_credentials().await {
        Ok(credentials) => credentials.is_empty(),
        Err(e) => {
            tracing::warn!(error = %e, "could not list credentials; assuming the store is populated");
            false
        }
    };
    let no_users = match store.list_users().await {
        Ok(users) => users.is_empty(),
        Err(e) => {
            tracing::warn!(error = %e, "could not list users; assuming the store is populated");
            false
        }
    };
    let store_state = if no_credentials && no_users {
        StoreState::Fresh
    } else {
        StoreState::Populated
    };

    match config.finalize_master_secret(store_state) {
        Ok(Some(warning)) => tracing::warn!("{warning}"),
        Ok(None) => {}
        Err(e) => {
            tracing::error!(error = %e, "failed to resolve the master secret");
            eprintln!("Configuration error: {e}");
            std::process::exit(1);
        }
    }
}

fn init_crypto(config: &AppConfig) -> CryptoState {
    if config.is_default_salt() {
        tracing::warn!("KDF salt is the legacy hardcoded default — consider setting AGTCRDN_KDF_SALT or removing it to use the auto-derived salt");
    }

    let crypto = CryptoState::from_config(config).expect("failed to derive master key ring");
    tracing::info!(
        master_key_version = crypto.key_ring.current_version(),
        previous_master_key_loaded = crypto.key_ring.previous_version().is_some(),
        "master key ring ready"
    );
    crypto
}

async fn init_store(config: &AppConfig) -> Arc<dyn Store + Send + Sync> {
    use agent_cordon_core::storage::sqlite::SqliteStore;

    if let Some(parent) = std::path::Path::new(&config.db_path).parent() {
        std::fs::create_dir_all(parent).ok();
    }
    let sqlite_store = SqliteStore::new(&config.db_path)
        .await
        .expect("failed to open SQLite database");
    sqlite_store
        .run_migrations()
        .await
        .expect("failed to run SQLite migrations");
    Arc::new(sqlite_store)
}

async fn seed_default_policy(store: &(dyn Store + Send + Sync)) {
    use agent_cordon_core::domain::policy::{PolicyId, StoredPolicy};

    match store.get_all_enabled_policies().await {
        Ok(policies) if policies.is_empty() => {
            let default_cedar = include_str!("../../../policies/default.cedar");
            let now = chrono::Utc::now();
            let seed_policy = StoredPolicy {
                id: PolicyId(uuid::Uuid::new_v4()),
                name: "default".to_string(),
                description: Some("Built-in default policy, seeded on first boot".to_string()),
                cedar_policy: default_cedar.to_string(),
                enabled: true,
                is_system: false,
                created_at: now,
                updated_at: now,
            };
            store
                .store_policy(&seed_policy)
                .await
                .expect("failed to seed default policy into database");
            tracing::info!(policy_id = %seed_policy.id.0, "seeded default Cedar policy into database (first boot)");
        }
        Ok(_) => {
            tracing::debug!("policies exist in database, skipping default policy seed");
        }
        Err(e) => {
            tracing::error!(error = %e, "failed to check for existing policies");
            std::process::exit(1);
        }
    }
}

async fn bootstrap_root_user(store: &(dyn Store + Send + Sync), config: &AppConfig) {
    match store.list_users().await {
        Ok(users) if users.is_empty() => {
            let root_username = config
                .root_username
                .clone()
                .unwrap_or_else(|| "root".to_string());

            let root_password = config.root_password.clone().unwrap_or_else(|| {
                use base64::Engine;
                let mut bytes = [0u8; 32];
                rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut bytes);
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
            });

            if root_password.len() < 12 {
                eprintln!("Error: AGTCRDN_ROOT_PASSWORD must be at least 12 characters");
                std::process::exit(1);
            }

            let password_hash = hash_password_async(&root_password)
                .await
                .expect("failed to hash root password");

            let now = chrono::Utc::now();
            let root_user = User {
                id: UserId(uuid::Uuid::new_v4()),
                username: root_username.clone(),
                display_name: Some("Root Administrator".to_string()),
                password_hash,
                role: UserRole::Admin,
                is_root: true,
                enabled: true,
                created_at: now,
                updated_at: now,
            };

            store
                .create_user(&root_user)
                .await
                .expect("failed to create root user");

            // Print root credentials to stderr (one-time bootstrap only).
            // These MUST go to stderr, not structured logs, to avoid persisting
            // secrets in log aggregation systems.
            eprintln!("========================================");
            eprintln!("  Bootstrap root user created");
            eprintln!("  Username: {root_username}");
            eprintln!("  Password: {root_password}");
            eprintln!("  Save these credentials — they will not be shown again.");
            eprintln!("========================================");

            tracing::info!(user_id = %root_user.id.0, username = %root_username, "bootstrap root user created");
        }
        Ok(_) => {
            tracing::debug!("users exist, skipping root user bootstrap");
        }
        Err(e) => {
            tracing::error!(error = %e, "failed to check for existing users");
        }
    }
}

fn spawn_cleanup_task(app_state: &AppState, config: &AppConfig) {
    let store = app_state.store.clone();
    let rate_limiter = app_state.limits.login.clone();
    let interval_secs = config.session_cleanup_interval_seconds;
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(interval_secs));
        interval.tick().await;
        loop {
            interval.tick().await;
            match store.cleanup_expired_sessions().await {
                Ok(count) => {
                    tracing::info!(
                        expired_sessions_cleaned = count,
                        "session cleanup completed"
                    );
                }
                Err(e) => {
                    tracing::error!(error = %e, "session cleanup failed");
                }
            }
            match store.cleanup_expired_oidc_states().await {
                Ok(count) => {
                    if count > 0 {
                        tracing::info!(
                            expired_oidc_states_cleaned = count,
                            "OIDC state cleanup completed"
                        );
                    }
                }
                Err(e) => {
                    tracing::error!(error = %e, "OIDC state cleanup failed");
                }
            }
            match store.cleanup_expired_mcp_oauth_states().await {
                Ok(count) => {
                    if count > 0 {
                        tracing::info!(
                            expired_mcp_oauth_states_cleaned = count,
                            "MCP OAuth state cleanup completed"
                        );
                    }
                }
                Err(e) => {
                    tracing::error!(error = %e, "MCP OAuth state cleanup failed");
                }
            }
            rate_limiter.cleanup_stale_entries();
            tracing::debug!("rate limiter stale entries cleaned");
        }
    });
    tracing::info!(
        interval_seconds = config.session_cleanup_interval_seconds,
        "session/rate-limiter cleanup background task started"
    );
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install SIGINT handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    tracing::info!("Received shutdown signal, draining connections...");
}
