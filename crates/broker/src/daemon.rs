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
use crate::server_client::ServerClient;
use crate::state::{BrokerState, SharedState, TokenStatus, WorkspaceState};
use crate::token_refresh;
use crate::token_store;

/// Run the broker daemon. Blocks until shutdown signal is received.
pub async fn run(config: BrokerConfig) -> Result<(), String> {
    let data_dir = config.data_dir();
    std::fs::create_dir_all(&data_dir)
        .map_err(|e| format!("failed to create data dir {}: {}", data_dir.display(), e))?;

    // 1. Read or create P-256 keypair
    let encryption_key = load_or_create_keypair(&config.key_path())?;

    // 2. Build HTTP client (needed for recovery before state construction)
    let http_client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .user_agent("agentcordon-broker/3.0.0")
        .build()
        .map_err(|e| format!("failed to create HTTP client: {}", e))?;

    // 3. Load encrypted token store, falling back to recovery store
    let workspaces = load_with_recovery(&config, &encryption_key, &http_client).await;
    info!(count = workspaces.len(), "loaded workspace tokens");

    // 4. Bind (before building state so we know the actual port)
    let bind_ip: std::net::IpAddr = config
        .bind
        .parse()
        .map_err(|e| format!("invalid bind address '{}': {}", config.bind, e))?;
    let addr = SocketAddr::from((bind_ip, config.port));
    let listener = TcpListener::bind(addr)
        .await
        .map_err(|e| format!("failed to bind to {}: {}", addr, e))?;
    let bound_addr = listener
        .local_addr()
        .map_err(|e| format!("failed to get bound address: {}", e))?;
    let bound_port = bound_addr.port();

    info!(port = bound_port, "broker listening on {}", bound_addr);

    // 5. Build shared state (with actual bound port for redirect URIs)
    let state: SharedState = Arc::new(BrokerState {
        workspaces: RwLock::new(workspaces),
        pending: RwLock::new(HashMap::new()),
        server_url: config.server_url.clone(),
        http_client,
        encryption_key,
        config: config.clone(),
        bound_port,
    });

    // 6. Write port and PID files
    let port_file = config.data_dir().join("broker.port");
    let pid_file = config.data_dir().join("broker.pid");
    std::fs::write(&port_file, bound_port.to_string())
        .map_err(|e| format!("failed to write port file: {}", e))?;
    std::fs::write(&pid_file, std::process::id().to_string())
        .map_err(|e| format!("failed to write pid file: {}", e))?;

    // 7. Start background token refresh
    let refresh_handle = token_refresh::spawn_refresh_task(state.clone());

    // 8. Build router and serve
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

    // 9. Graceful shutdown: flush tokens, clean up files
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

    // Flush recovery store
    token_store::save_recovery_store(&state).await;

    // Remove port and PID files
    let _ = std::fs::remove_file(&port_file);
    let _ = std::fs::remove_file(&pid_file);

    info!("broker shut down cleanly");
    Ok(())
}

/// Load an existing P-256 keypair from disk, or create a new one.
fn load_or_create_keypair(path: &Path) -> Result<p256::SecretKey, String> {
    if path.exists() {
        // Verify file permissions before reading sensitive key material
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let metadata =
                std::fs::metadata(path).map_err(|e| format!("failed to stat key file: {}", e))?;
            let mode = metadata.permissions().mode() & 0o777;
            if mode != 0o600 {
                return Err(format!(
                    "broker key file has too-open permissions (expected 0600, got {mode:o})"
                ));
            }
        }

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

    // Write atomically: temp file → set permissions → rename into place
    let tmp_path = path.with_extension("tmp");
    std::fs::write(&tmp_path, pem.as_bytes())
        .map_err(|e| format!("failed to write temp key file: {}", e))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(&tmp_path, perms)
            .map_err(|e| format!("failed to set key file permissions: {}", e))?;
    }

    std::fs::rename(&tmp_path, path)
        .map_err(|e| format!("failed to rename key file into place: {}", e))?;

    info!("generated new P-256 keypair");
    Ok(key)
}

/// Load workspace tokens with recovery fallback.
///
/// 1. Try the encrypted token store (`tokens.enc`) — this is the fast path.
/// 2. If it fails, fall back to the plaintext recovery store (`workspaces.json`).
/// 3. For each recovery entry, attempt a refresh token exchange.
/// 4. Successfully recovered workspaces are returned (and will be saved to
///    `tokens.enc` once the full state is available).
async fn load_with_recovery(
    config: &BrokerConfig,
    encryption_key: &p256::SecretKey,
    http_client: &reqwest::Client,
) -> HashMap<String, WorkspaceState> {
    // Try encrypted store first
    match token_store::load(&config.token_store_path(), encryption_key) {
        Ok(workspaces) => {
            // Update recovery store from the loaded data so it stays in sync
            let entries: HashMap<String, _> = workspaces
                .iter()
                .map(|(k, ws)| (k.clone(), ws.to_recovery_entry()))
                .collect();
            if let Err(e) = token_store::save_recovery(&config.recovery_store_path(), &entries) {
                warn!(error = %e, "failed to sync recovery store on startup");
            }
            return workspaces;
        }
        Err(e) => {
            warn!(
                error = %e,
                "encrypted token store failed, attempting recovery from workspaces.json"
            );
        }
    }

    // Fall back to recovery store
    let entries = token_store::load_recovery(&config.recovery_store_path());
    if entries.is_empty() {
        info!("no recovery entries found, starting fresh");
        return HashMap::new();
    }

    info!(
        count = entries.len(),
        "found recovery entries, attempting token refresh"
    );

    recover_from_entries(entries, config, encryption_key, http_client).await
}

/// Attempt to recover workspace tokens from recovery entries by refreshing
/// each one against the server.
async fn recover_from_entries(
    entries: HashMap<String, crate::state::RecoveryEntry>,
    config: &BrokerConfig,
    encryption_key: &p256::SecretKey,
    http_client: &reqwest::Client,
) -> HashMap<String, WorkspaceState> {
    let server_client = ServerClient::new(http_client.clone(), config.server_url.clone());
    let mut recovered = HashMap::new();

    for (pk_hash, entry) in &entries {
        match server_client
            .refresh_token(&entry.refresh_token, &entry.client_id)
            .await
        {
            Ok(token_resp) => {
                let ws = WorkspaceState {
                    client_id: entry.client_id.clone(),
                    access_token: token_resp.access_token,
                    refresh_token: token_resp
                        .refresh_token
                        .unwrap_or_else(|| entry.refresh_token.clone()),
                    scopes: entry.scopes.clone(),
                    token_expires_at: chrono::Utc::now()
                        + chrono::Duration::seconds(token_resp.expires_in as i64),
                    workspace_name: entry.workspace_name.clone(),
                    token_status: TokenStatus::Valid,
                };
                info!(
                    workspace = entry.workspace_name,
                    "recovered workspace via refresh token"
                );
                recovered.insert(pk_hash.clone(), ws);
            }
            Err(e) => {
                warn!(
                    workspace = entry.workspace_name,
                    error = %e,
                    "recovery refresh failed, workspace will need re-registration"
                );
            }
        }
    }

    // Save successfully recovered workspaces to encrypted store
    if !recovered.is_empty() {
        if let Err(e) = token_store::save(&config.token_store_path(), &recovered, encryption_key) {
            warn!(error = %e, "failed to save recovered tokens to encrypted store");
        }

        // Update recovery store with only successfully recovered entries
        let recovery_entries: HashMap<String, _> = recovered
            .iter()
            .map(|(k, ws)| (k.clone(), ws.to_recovery_entry()))
            .collect();
        if let Err(e) = token_store::save_recovery(&config.recovery_store_path(), &recovery_entries)
        {
            warn!(error = %e, "failed to update recovery store after recovery");
        }
    }

    info!(
        recovered = recovered.len(),
        total = entries.len(),
        "startup recovery complete"
    );

    recovered
}
