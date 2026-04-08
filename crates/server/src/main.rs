use std::sync::Arc;

use tracing_subscriber::{fmt, EnvFilter};

use agent_cordon_core::auth::jwt::JwtIssuer;
use agent_cordon_core::crypto::aes_gcm::AesGcmEncryptor;
use agent_cordon_core::crypto::key_derivation::{
    derive_jwt_signing_keypair, derive_master_key, derive_session_hash_key,
};
use agent_cordon_core::crypto::password::hash_password_async;
use agent_cordon_core::domain::user::{User, UserId, UserRole};
use agent_cordon_core::policy::cedar::CedarPolicyEngine;
use agent_cordon_core::storage::Store;

use agent_cordon_server::auditing_policy_engine::AuditingPolicyEngine;

use agent_cordon_server::build_router;
use agent_cordon_server::config::AppConfig;
use agent_cordon_server::metrics::setup_metrics;
use agent_cordon_server::rate_limit::LoginRateLimiter;
use agent_cordon_server::state::AppState;

/// Crypto material derived from the master secret during startup.
struct CryptoKeys {
    encryptor: Arc<AesGcmEncryptor>,
    jwt_issuer: Arc<JwtIssuer>,
    session_hash_key: [u8; 32],
}

#[tokio::main]
async fn main() {
    let config = match AppConfig::from_env() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Configuration error: {e}");
            std::process::exit(1);
        }
    };

    init_tracing(&config);

    let crypto = init_crypto(&config);
    let store = init_store(&config).await;
    seed_default_policy(&*store).await;
    agent_cordon_server::migrations::migrate_mcp_policy_names_to_ids(&*store).await;
    let cedar_engine = load_policy_engine(&*store).await;
    let policy_engine = Arc::new(AuditingPolicyEngine::new(cedar_engine, store.clone()));
    bootstrap_root_user(&*store, &config).await;

    let login_rate_limiter = Arc::new(LoginRateLimiter::new(
        config.login_max_attempts,
        config.login_lockout_seconds,
    ));

    let metrics_handle = setup_metrics();

    let http_client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(config.proxy_timeout_seconds))
        .user_agent("AgentCordon/0.1")
        .build()
        .expect("failed to build shared HTTP client");

    let credential_templates =
        agent_cordon_server::routes::admin_api::credential_templates::load_templates(
            config.credential_templates_dir.as_deref(),
        );

    let mcp_templates = agent_cordon_server::routes::admin_api::mcp_templates::load_mcp_templates(
        config.mcp_templates_dir.as_deref(),
    );

    let policy_templates = agent_cordon_server::routes::admin_api::policy_templates::load_templates(
        config.policy_templates_dir.as_deref(),
    );

    let app_state = AppState {
        store,
        jwt_issuer: crypto.jwt_issuer,
        policy_engine,
        encryptor: crypto.encryptor,
        config: config.clone(),
        login_rate_limiter,
        metrics_handle,
        session_hash_key: crypto.session_hash_key,
        oauth2_token_manager: agent_cordon_core::oauth2::OAuth2TokenManager::new(),
        http_client,
        event_bus: agent_cordon_server::events::EventBus::new(256),
        ui_event_bus: agent_cordon_server::events::UiEventBus::new(256),
        sse_tracker: agent_cordon_server::events::SseConnectionTracker::new(5),
        credential_templates,
        mcp_templates,
        policy_templates,
    };

    spawn_cleanup_task(&app_state, &config);

    let app = build_router(app_state);

    tracing::info!(listen_addr = %config.listen_addr, "starting agent-cordon server");

    let listener = tokio::net::TcpListener::bind(&config.listen_addr)
        .await
        .expect("failed to bind listener");
    axum::serve(listener, app)
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

fn init_crypto(config: &AppConfig) -> CryptoKeys {
    if config.is_default_salt() {
        tracing::warn!("KDF salt is the legacy hardcoded default — consider setting AGTCRDN_KDF_SALT or removing it to use the auto-derived salt");
    }

    let master_key = derive_master_key(&config.master_secret, config.kdf_salt.as_bytes())
        .expect("failed to derive master key");
    let encryptor = Arc::new(AesGcmEncryptor::new(&master_key));

    let (jwt_signing_key_ec, jwt_verifying_key_ec) =
        derive_jwt_signing_keypair(&config.master_secret, config.kdf_salt.as_bytes())
            .expect("failed to derive ES256 JWT signing key pair");

    let jwt_issuer = Arc::new(JwtIssuer::new(
        &jwt_signing_key_ec,
        &jwt_verifying_key_ec,
        agent_cordon_core::auth::jwt::ISSUER.to_string(),
        config.jwt_ttl_seconds,
    ));

    let session_hash_key =
        derive_session_hash_key(&config.master_secret, config.kdf_salt.as_bytes())
            .expect("failed to derive session hash key");
    let session_hash_key = *session_hash_key;

    CryptoKeys {
        encryptor,
        jwt_issuer,
        session_hash_key,
    }
}

async fn init_store(config: &AppConfig) -> Arc<dyn Store + Send + Sync> {
    match config.db_type.as_str() {
        #[cfg(feature = "sqlite")]
        "sqlite" => {
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
        #[cfg(feature = "postgres")]
        "postgres" => {
            use agent_cordon_core::storage::postgres::PostgresStore;
            let db_url = config.db_url.as_deref().unwrap_or_else(|| {
                eprintln!("Error: AGTCRDN_DB_URL is required when AGTCRDN_DB_TYPE=postgres");
                std::process::exit(1);
            });
            let pg_store = PostgresStore::new(db_url)
                .await
                .expect("failed to connect to PostgreSQL");
            pg_store
                .run_migrations()
                .await
                .expect("failed to run PostgreSQL migrations");
            Arc::new(pg_store)
        }
        other => {
            eprintln!(
                "Error: unknown AGTCRDN_DB_TYPE '{}' (expected 'sqlite' or 'postgres')",
                other
            );
            std::process::exit(1);
        }
    }
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

async fn load_policy_engine(store: &(dyn Store + Send + Sync)) -> Arc<CedarPolicyEngine> {
    let policy_sources: Vec<(String, String)> = match store.get_all_enabled_policies().await {
        Ok(db_policies) => {
            if db_policies.is_empty() {
                tracing::warn!("no enabled policies in database — deny-all is in effect");
            }
            db_policies
                .into_iter()
                .map(|p| (p.id.0.to_string(), p.cedar_policy))
                .collect()
        }
        Err(e) => {
            tracing::error!(error = %e, "failed to load policies from database");
            std::process::exit(1);
        }
    };

    let policy_engine =
        CedarPolicyEngine::new(policy_sources).expect("failed to initialize policy engine");
    Arc::new(policy_engine)
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
    let rate_limiter = app_state.login_rate_limiter.clone();
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
