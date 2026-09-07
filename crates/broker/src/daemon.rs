//! Daemon lifecycle: startup, single-instance lock, signal handling,
//! graceful shutdown.
//!
//! Every artifact the broker creates under its data directory (key, token
//! store, recovery store, port, pid, lock) is owner-only: `0700` for the
//! directory, `0600` for files, set at creation rather than after.

use std::collections::HashMap;
use std::fs::File;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use p256::elliptic_curve::rand_core::OsRng;
use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey};
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tracing::{error, info, warn};

use crate::config::BrokerConfig;
use crate::mcp_sync;
use crate::routes;
use crate::server_client::ServerClient;
use crate::state::{BrokerState, SharedState, TokenStatus, WorkspaceState};
use crate::token_refresh;
use crate::token_store;

/// Run the broker daemon. Blocks until shutdown signal is received.
pub async fn run(config: BrokerConfig) -> Result<(), String> {
    // 0. Refuse bad configuration before touching disk or network. A
    //    non-loopback bind needs TLS or a shared secret (config::validate).
    config.validate()?;

    // Read the TLS material now, while a bad certificate is still only a
    // startup error: a broker that gets as far as listening must be able to
    // complete a handshake.
    let tls_config = match (&config.tls_cert, &config.tls_key) {
        (Some(cert), Some(key)) => Some(crate::tls::load_server_config(cert, key)?),
        _ => None,
    };

    let data_dir = config.data_dir();
    prepare_data_dir(&data_dir)?;

    // One broker per data directory: the lock is held for the life of the
    // process and released by the OS if it dies.
    let instance_lock = InstanceLock::acquire(&config.lock_file_path())?;

    // 1. Read or create P-256 keypair
    let encryption_key = load_or_create_keypair(&config.key_path())?;

    // 2. Build HTTP client (needed for recovery before state construction)
    let http_client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .user_agent(concat!("agentcordon-broker/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|e| format!("failed to create HTTP client: {}", e))?;
    let upstream_client = crate::upstream::build_client()
        .map_err(|e| format!("failed to create upstream HTTP client: {}", e))?;

    // 3. Load encrypted token store, falling back to recovery store
    let workspaces = load_with_recovery(&config, &encryption_key, &http_client).await;
    info!(count = workspaces.len(), "loaded workspace tokens");

    // 4. Bind (before building state so we know the actual port)
    let bind_ip = config.bind_ip()?;
    let addr = SocketAddr::from((bind_ip, config.port));
    let listener = TcpListener::bind(addr)
        .await
        .map_err(|e| format!("failed to bind to {}: {}", addr, e))?;
    let bound_addr = listener
        .local_addr()
        .map_err(|e| format!("failed to get bound address: {}", e))?;
    let bound_port = bound_addr.port();

    let scheme = if tls_config.is_some() {
        "https"
    } else {
        "http"
    };
    info!(
        port = bound_port,
        scheme, "broker listening on {}://{}", scheme, bound_addr
    );

    // 5. Build shared state (with actual bound port for redirect URIs)
    let state: SharedState = Arc::new(BrokerState {
        workspaces: RwLock::new(workspaces),
        pending: RwLock::new(HashMap::new()),
        registration_errors: RwLock::new(HashMap::new()),
        mcp_configs: RwLock::new(HashMap::new()),
        server_url: config.server_url.clone(),
        http_client,
        upstream_client,
        encryption_key,
        config: config.clone(),
        nonces: crate::auth::NonceCache::default(),
        refresh_locks: token_refresh::RefreshLocks::default(),
    });

    // 6. Write port and PID files (owner-only)
    let port_file = config.port_file_path();
    let pid_file = config.pid_file_path();
    token_store::write_private_file(
        &port_file,
        port_file_contents(bind_ip, bound_port, config.tls_configured()).as_bytes(),
    )
    .map_err(|e| format!("failed to write port file: {}", e))?;
    token_store::write_private_file(&pid_file, std::process::id().to_string().as_bytes())
        .map_err(|e| format!("failed to write pid file: {}", e))?;

    // 7. Start background token refresh
    let refresh_handle = token_refresh::spawn_refresh_task(state.clone());

    // 7b. Start background MCP config sync
    let mcp_sync_handle = mcp_sync::spawn_mcp_sync_task(state.clone());

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

    match tls_config {
        Some(tls) => crate::tls::serve(listener, router, tls, shutdown_signal).await?,
        None => axum::serve(listener, router)
            .with_graceful_shutdown(shutdown_signal)
            .await
            .map_err(|e| format!("server error: {}", e))?,
    }

    // 9. Graceful shutdown: flush tokens, clean up files
    info!("shutting down...");
    refresh_handle.abort();
    mcp_sync_handle.abort();

    flush_state(&state).await;

    // Remove port and PID files, then release the instance lock last so a
    // successor cannot start against a half-cleaned directory.
    let _ = std::fs::remove_file(&port_file);
    let _ = std::fs::remove_file(&pid_file);
    drop(instance_lock);

    info!("broker shut down cleanly");
    Ok(())
}

/// Write the workspace tokens out: the encrypted store first, then the
/// plaintext recovery store beside it.
///
/// What a clean shutdown does, and the only thing that makes a token
/// survive a restart. Named so the restart itself is testable.
pub async fn flush_state(state: &SharedState) {
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

    token_store::save_recovery_store(state).await;
}

/// Create the data directory if needed and make it owner-only.
pub fn prepare_data_dir(data_dir: &Path) -> Result<(), String> {
    std::fs::create_dir_all(data_dir)
        .map_err(|e| format!("failed to create data dir {}: {}", data_dir.display(), e))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(data_dir, std::fs::Permissions::from_mode(0o700)).map_err(
            |e| {
                format!(
                    "failed to set permissions on data dir {}: {}",
                    data_dir.display(),
                    e
                )
            },
        )?;
    }
    Ok(())
}

/// Single-instance lock on the data directory.
///
/// An advisory `flock(LOCK_EX | LOCK_NB)` on `broker.lock`, held open for
/// the life of the process. The kernel drops it when the process exits,
/// however it exits, so there is no stale-lock cleanup. On non-Unix
/// targets the file is created but not locked.
#[derive(Debug)]
pub struct InstanceLock {
    _file: File,
    path: PathBuf,
}

impl InstanceLock {
    pub fn acquire(path: &Path) -> Result<Self, String> {
        let mut opts = std::fs::OpenOptions::new();
        opts.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let file = opts
            .open(path)
            .map_err(|e| format!("failed to open lock file {}: {}", path.display(), e))?;

        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            // SAFETY: `flock` on a file descriptor we own and keep open for
            // the lifetime of `Self`.
            let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
            if rc != 0 {
                let err = std::io::Error::last_os_error();
                return Err(if err.raw_os_error() == Some(libc::EWOULDBLOCK) {
                    format!(
                        "another agentcordon-broker is already running on this data directory \
                         ({} is locked). Stop it first, or point this one at a different \
                         --data-dir",
                        path.display()
                    )
                } else {
                    format!("failed to lock {}: {}", path.display(), err)
                });
            }
        }

        Ok(Self {
            _file: file,
            path: path.to_path_buf(),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
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

    // Write atomically: owner-only temp file → rename into place. The mode
    // is set at open(2), so the key never exists readable by others.
    let tmp_path = path.with_extension("tmp");
    token_store::write_private_file(&tmp_path, pem.as_bytes())
        .map_err(|e| format!("failed to write temp key file: {}", e))?;

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
pub async fn load_with_recovery(
    config: &BrokerConfig,
    encryption_key: &p256::SecretKey,
    http_client: &reqwest::Client,
) -> HashMap<String, WorkspaceState> {
    // Try encrypted store first. An absent store is the first run; only a
    // store that exists and will not open is a failure worth a warning.
    let never_written = match token_store::load(&config.token_store_path(), encryption_key) {
        Ok(Some(workspaces)) => {
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
        // No `tokens.enc` yet. An older broker may still have left a
        // recovery store behind, so keep looking, quietly.
        Ok(None) => true,
        Err(e) => {
            warn!(
                error = %e,
                "encrypted token store failed, attempting recovery from workspaces.json"
            );
            false
        }
    };

    // Fall back to recovery store
    let entries = token_store::load_recovery(&config.recovery_store_path());
    if entries.is_empty() {
        if never_written {
            info!("no token store yet, starting fresh");
        } else {
            info!("no recovery entries found, starting fresh");
        }
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
                        + chrono::Duration::seconds(token_resp.expires_in),
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

/// What the port file says: the URL a local CLI should dial. A TLS broker
/// is `https`, and a broker bound to every interface is reached on loopback.
pub(crate) fn port_file_contents(bind_ip: std::net::IpAddr, port: u16, tls: bool) -> String {
    let scheme = if tls { "https" } else { "http" };
    let host = match bind_ip {
        std::net::IpAddr::V4(ip) if ip.is_unspecified() => "127.0.0.1".to_string(),
        std::net::IpAddr::V6(ip) if ip.is_unspecified() => "[::1]".to_string(),
        std::net::IpAddr::V4(ip) => ip.to_string(),
        std::net::IpAddr::V6(ip) => format!("[{ip}]"),
    };
    format!("{scheme}://{host}:{port}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn second_lock_on_same_data_dir_conflicts_until_first_is_dropped() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("broker.lock");

        let first = InstanceLock::acquire(&path).expect("first lock");
        let err = InstanceLock::acquire(&path).expect_err("second lock must conflict");
        assert!(err.contains("already running"), "{err}");

        drop(first);
        InstanceLock::acquire(&path).expect("lock is free after the holder exits");
    }

    #[cfg(unix)]
    #[test]
    fn lock_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("broker.lock");
        let lock = InstanceLock::acquire(&path).unwrap();
        let mode = std::fs::metadata(lock.path()).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn data_dir_is_created_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let data_dir = dir.path().join("data");
        prepare_data_dir(&data_dir).unwrap();
        let mode = std::fs::metadata(&data_dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
    }

    #[cfg(unix)]
    /// The port file names how to reach the broker, not just where: a TLS
    /// broker must be dialled as https, and a broker bound to every
    /// interface is reached locally on loopback.
    #[test]
    fn port_file_names_scheme_and_loopback_host() {
        use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
        assert_eq!(
            port_file_contents(IpAddr::V4(Ipv4Addr::LOCALHOST), 9876, false),
            "http://127.0.0.1:9876"
        );
        assert_eq!(
            port_file_contents(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 9876, true),
            "https://127.0.0.1:9876"
        );
        assert_eq!(
            port_file_contents(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 9876, true),
            "https://[::1]:9876"
        );
        assert_eq!(
            port_file_contents(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)), 443, true),
            "https://10.0.0.5:443"
        );
    }

    #[test]
    fn port_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("broker.port");
        token_store::write_private_file(&path, b"9876").unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "9876");
    }

    #[cfg(unix)]
    #[test]
    fn generated_key_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("broker.key");
        load_or_create_keypair(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert!(!dir.path().join("broker.tmp").exists());
    }
}
