//! Daemon lifecycle: startup, signal handling, graceful shutdown.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use p256::elliptic_curve::rand_core::OsRng;
use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey};
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tracing::{error, info, warn};

use crate::config::BrokerConfig;
use crate::routes;
use crate::state::{BrokerState, SharedState};
use crate::token_refresh;
use crate::token_store;

/// Run the broker daemon. Blocks until shutdown signal is received.
pub async fn run(config: BrokerConfig) -> Result<(), String> {
    let data_dir = config.data_dir();
    std::fs::create_dir_all(&data_dir)
        .map_err(|e| format!("failed to create data dir {}: {}", data_dir.display(), e))?;

    // 1. Read or create P-256 keypair
    let encryption_key = load_or_create_keypair(&config.key_path())?;

    // 2. Load encrypted token store
    let workspaces =
        token_store::load(&config.token_store_path(), &encryption_key).unwrap_or_else(|e| {
            warn!(error = %e, "failed to load token store, starting fresh");
            HashMap::new()
        });
    info!(count = workspaces.len(), "loaded workspace tokens");

    // 3. Build shared state
    let http_client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .user_agent("agentcordon-broker/3.0.0")
        .build()
        .map_err(|e| format!("failed to create HTTP client: {}", e))?;

    let state: SharedState = Arc::new(BrokerState {
        workspaces: RwLock::new(workspaces),
        pending: RwLock::new(HashMap::new()),
        server_url: config.server_url.clone(),
        http_client,
        encryption_key,
        config: config.clone(),
    });

    // 4. Bind to localhost
    let addr = SocketAddr::from(([127, 0, 0, 1], config.port));
    let listener = TcpListener::bind(addr)
        .await
        .map_err(|e| format!("failed to bind to {}: {}", addr, e))?;
    let bound_addr = listener
        .local_addr()
        .map_err(|e| format!("failed to get bound address: {}", e))?;
    let bound_port = bound_addr.port();

    info!(port = bound_port, "broker listening on {}", bound_addr);

    // 5. Write port and PID files
    // Update the config port for register redirect_uri
    // We need to update the shared state's config with the actual bound port
    // Since config is inside Arc, we stored it already — but the register route
    // reads config.port. We handle this by writing a mutable port into config
    // before building state. For now, write the port file and PID file.
    let port_file = config.data_dir().join("broker.port");
    let pid_file = config.data_dir().join("broker.pid");
    std::fs::write(&port_file, bound_port.to_string())
        .map_err(|e| format!("failed to write port file: {}", e))?;
    std::fs::write(&pid_file, std::process::id().to_string())
        .map_err(|e| format!("failed to write pid file: {}", e))?;

    // 6. Start background token refresh
    let refresh_handle = token_refresh::spawn_refresh_task(state.clone());

    // 7. Build router and serve
    let router = routes::build_router(state.clone());

    let shutdown_signal = async {
        let ctrl_c = tokio::signal::ctrl_c();
        #[cfg(unix)]
        {
            let mut sigterm =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                    .expect("failed to register SIGTERM handler");
            tokio::select! {
                _ = ctrl_c => {},
                _ = sigterm.recv() => {},
            }
        }
        #[cfg(not(unix))]
        {
            ctrl_c.await.ok();
        }
        info!("shutdown signal received");
    };

    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown_signal)
        .await
        .map_err(|e| format!("server error: {}", e))?;

    // 8. Graceful shutdown: flush tokens, clean up files
    info!("shutting down...");
    refresh_handle.abort();

    // Flush token store
    {
        let workspaces = state.workspaces.read().await;
        if let Err(e) = token_store::save(
            &state.config.token_store_path(),
            &workspaces,
            &state.encryption_key,
        ) {
            error!(error = %e, "failed to flush token store on shutdown");
        }
    }

    // Remove port and PID files
    let _ = std::fs::remove_file(&port_file);
    let _ = std::fs::remove_file(&pid_file);

    info!("broker shut down cleanly");
    Ok(())
}

/// Load an existing P-256 keypair from disk, or create a new one.
fn load_or_create_keypair(path: &Path) -> Result<p256::SecretKey, String> {
    if path.exists() {
        let pem =
            std::fs::read_to_string(path).map_err(|e| format!("failed to read key file: {}", e))?;
        let key = p256::SecretKey::from_pkcs8_pem(&pem)
            .map_err(|e| format!("failed to parse key file: {}", e))?;
        info!("loaded existing P-256 keypair");
        return Ok(key);
    }

    // Generate new keypair
    let key = p256::SecretKey::random(&mut OsRng);
    let pem = key
        .to_pkcs8_pem(p256::pkcs8::LineEnding::LF)
        .map_err(|e| format!("failed to encode key: {}", e))?;

    // Ensure parent directory exists
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("failed to create key directory: {}", e))?;
    }

    std::fs::write(path, pem.as_bytes()).map_err(|e| format!("failed to write key file: {}", e))?;

    // Set file permissions to 0600 (owner read/write only)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(path, perms)
            .map_err(|e| format!("failed to set key file permissions: {}", e))?;
    }

    info!("generated new P-256 keypair");
    Ok(key)
}
