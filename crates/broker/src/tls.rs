//! TLS termination for the broker's own listener.
//!
//! `--tls-cert`/`--tls-key` make the broker serve HTTPS on its bind address
//! instead of plaintext HTTP. That is what lets a non-loopback bind (a
//! container publishing the broker to other containers, say) carry signed
//! requests and vended credentials without a reverse proxy in front; the
//! `--shared-secret` alternative is unchanged and still available.
//!
//! There is no `axum::serve` equivalent for a TLS listener, so this module
//! owns the accept loop: each accepted `TcpStream` is wrapped by
//! `tokio_rustls::TlsAcceptor` and handed to the same axum router through
//! hyper-util's auto (HTTP/1 + HTTP/2) connection builder. A failed
//! handshake kills that one connection and nothing else.

use std::future::Future;
use std::path::Path;
use std::sync::Arc;

use axum::Router;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder;
use hyper_util::server::graceful::GracefulShutdown;
use hyper_util::service::TowerToHyperService;
use rustls::ServerConfig;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info, warn};

/// Read the PEM certificate chain and private key and build a rustls server
/// config from them.
///
/// Every failure names the flag that owns the file, and all of them happen
/// here — at startup, before anything is served — rather than at the first
/// handshake, so a broker that comes up is a broker that can complete one.
pub fn load_server_config(cert: &Path, key: &Path) -> Result<Arc<ServerConfig>, String> {
    let chain: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(cert)
        .map_err(|e| format!("--tls-cert {}: {e}", cert.display()))?
        .collect::<Result<_, _>>()
        .map_err(|e| format!("--tls-cert {}: {e}", cert.display()))?;
    if chain.is_empty() {
        return Err(format!(
            "--tls-cert {} contains no CERTIFICATE block",
            cert.display()
        ));
    }

    let private_key = PrivateKeyDer::from_pem_file(key)
        .map_err(|e| format!("--tls-key {}: {e}", key.display()))?;

    // Name the provider rather than relying on a process-wide default: the
    // dependency graph enables both ring and aws-lc-rs, and rustls refuses
    // to guess between them.
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("failed to configure TLS protocol versions: {e}"))?
        .with_no_client_auth()
        .with_single_cert(chain, private_key)
        .map_err(|e| {
            format!(
                "--tls-cert {} and --tls-key {} do not form a usable pair: {e}",
                cert.display(),
                key.display()
            )
        })?;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

/// Serve `router` over TLS on `listener` until `shutdown` resolves.
///
/// The counterpart of `axum::serve(..).with_graceful_shutdown(..)`: the
/// signal stops the accept loop, in-flight connections are given a chance
/// to finish, and only then does this return.
pub async fn serve(
    listener: TcpListener,
    router: Router,
    config: Arc<ServerConfig>,
    shutdown: impl Future<Output = ()> + Send,
) -> Result<(), String> {
    let acceptor = TlsAcceptor::from(config);
    let graceful = GracefulShutdown::new();
    let mut shutdown = std::pin::pin!(shutdown);

    loop {
        let stream = tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok((stream, _peer)) => stream,
                Err(e) => {
                    // Per-connection accept errors (a client that hung up,
                    // a momentary fd shortage) must not take the broker
                    // down; the listener is still good.
                    warn!(error = %e, "failed to accept connection");
                    continue;
                }
            },
            _ = &mut shutdown => break,
        };

        let acceptor = acceptor.clone();
        let service = TowerToHyperService::new(router.clone());
        let watcher = graceful.watcher();
        tokio::spawn(async move {
            let tls_stream = match acceptor.accept(stream).await {
                Ok(s) => s,
                Err(e) => {
                    // A plaintext request, a wrong SNI, a client that does
                    // not trust us: one connection's problem.
                    debug!(error = %e, "TLS handshake failed");
                    return;
                }
            };
            let builder = Builder::new(TokioExecutor::new());
            let conn = builder.serve_connection_with_upgrades(TokioIo::new(tls_stream), service);
            if let Err(e) = watcher.watch(conn.into_owned()).await {
                debug!(error = %e, "connection closed with error");
            }
        });
    }

    // Stop listening first, then let live connections drain.
    drop(listener);
    info!("waiting for in-flight TLS connections to finish");
    graceful.shutdown().await;
    Ok(())
}
