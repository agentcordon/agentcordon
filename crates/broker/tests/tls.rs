//! TLS termination on the broker's own listener.
//!
//! Every other test in this binary drives the router in-process. TLS only
//! exists on the wire, so these tests bind `127.0.0.1:0` for real and speak
//! HTTPS to it with the committed fixture certificate
//! (`tests/fixtures/README.md` — test-only material, key included).

use std::net::SocketAddr;
use std::time::Duration;

use axum::Router;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

use agentcordon_broker::config::BrokerConfig;
use agentcordon_broker::routes::health::published_key;
use agentcordon_broker::tls;

use crate::common::{tls_cert_path, tls_key_path, TestBroker};

/// Serve `app` over TLS on an ephemeral loopback port. Returns the bound
/// address, the shutdown trigger, and the serving task.
async fn serve_tls(
    app: Router,
) -> (
    SocketAddr,
    oneshot::Sender<()>,
    JoinHandle<Result<(), String>>,
) {
    let config = tls::load_server_config(&tls_cert_path(), &tls_key_path()).expect("fixture TLS");
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local addr");
    let (tx, rx) = oneshot::channel();
    let handle = tokio::spawn(async move {
        tls::serve(listener, app, config, async {
            rx.await.ok();
        })
        .await
    });
    (addr, tx, handle)
}

/// A client that trusts only the fixture certificate and refuses to speak
/// plaintext, so a passing assertion cannot be an accidental HTTP call.
fn https_client() -> reqwest::Client {
    let pem = std::fs::read(tls_cert_path()).expect("read fixture cert");
    reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(&pem).expect("parse fixture cert"))
        .https_only(true)
        .timeout(Duration::from_secs(5))
        .build()
        .expect("https client")
}

/// The broker serves its real router over TLS: `/health` answers 200 and
/// publishes the same key fingerprint the CLI pins.
#[tokio::test]
async fn https_health_answers_with_the_published_key_fingerprint() {
    let broker = TestBroker::new().await;
    let expected = published_key(&broker.state.encryption_key).1;
    let (addr, shutdown, handle) = serve_tls(broker.app.clone()).await;

    let resp = https_client()
        .get(format!("https://127.0.0.1:{}/health", addr.port()))
        .send()
        .await
        .expect("https request");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = resp.json().await.expect("json body");
    assert_eq!(body["status"], "ok");
    assert_eq!(body["key_fingerprint"], expected);

    shutdown.send(()).ok();
    handle.await.expect("join").expect("serve");
}

/// A plaintext request to the TLS port never reaches the router: the
/// handshake fails, so there is no "accidentally serving HTTP" mode.
#[tokio::test]
async fn plain_http_to_the_tls_port_is_refused() {
    let broker = TestBroker::new().await;
    let (addr, shutdown, handle) = serve_tls(broker.app.clone()).await;

    let err = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("plain client")
        .get(format!("http://127.0.0.1:{}/health", addr.port()))
        .send()
        .await
        .expect_err("plaintext must not be served on the TLS port");
    assert!(
        !err.is_timeout(),
        "expected a transport failure, not a hang"
    );

    shutdown.send(()).ok();
    handle.await.expect("join").expect("serve");
}

/// A client that does not know the broker's certificate is refused, and the
/// refusal says so: the CLI keys its `AGTCRDN_BROKER_CA` hint on the word
/// "certificate" appearing in this error chain
/// (`crates/cli/src/broker.rs::is_certificate_failure`), so this test is
/// what keeps that hint pointing at the real failure.
#[tokio::test]
async fn https_without_the_broker_certificate_fails_with_a_certificate_error() {
    let broker = TestBroker::new().await;
    let (addr, shutdown, handle) = serve_tls(broker.app.clone()).await;

    let err = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("default-roots client")
        .get(format!("https://127.0.0.1:{}/health", addr.port()))
        .send()
        .await
        .expect_err("an untrusted certificate must be refused");

    let mut chain = err.to_string();
    let mut source = std::error::Error::source(&err);
    while let Some(e) = source {
        chain.push_str(&format!(": {e}"));
        source = e.source();
    }
    assert!(
        chain.to_ascii_lowercase().contains("certificate"),
        "expected a certificate failure, got: {chain}"
    );

    shutdown.send(()).ok();
    handle.await.expect("join").expect("serve");
}

/// A certificate and key that do not belong together are refused when the
/// config is loaded, not at the first handshake.
#[tokio::test]
async fn mismatched_tls_material_is_refused_at_load() {
    let dir = tempfile::tempdir().unwrap();
    let bad_key = dir.path().join("key.pem");
    std::fs::write(&bad_key, "-----BEGIN PRIVATE KEY-----\nnot-a-key\n").unwrap();
    let err = tls::load_server_config(&tls_cert_path(), &bad_key).expect_err("must refuse");
    assert!(err.contains("--tls-key"), "{err}");
}

/// A non-loopback bind is allowed when TLS is configured, and the daemon
/// really starts and serves HTTPS on it.
///
/// The config is parsed the way a container deployment writes it
/// (`--bind 0.0.0.0`) and validated as such; the bind is then rewritten to
/// loopback so the test never opens a port to the network.
#[tokio::test]
async fn non_loopback_bind_with_tls_passes_validation_and_starts() {
    let server = wiremock::MockServer::start().await;
    let dir = tempfile::tempdir().unwrap();
    let mut config = <BrokerConfig as clap::Parser>::parse_from([
        "agentcordon-broker",
        "--bind",
        "0.0.0.0",
        "--port",
        "0",
        "--tls-cert",
        tls_cert_path().to_str().unwrap(),
        "--tls-key",
        tls_key_path().to_str().unwrap(),
        "--data-dir",
        dir.path().to_str().unwrap(),
        "--server-url",
        &server.uri(),
    ]);
    config.validate().expect("0.0.0.0 with TLS is allowed");
    config.bind = "127.0.0.1".to_string();

    let port_file = config.port_file_path();
    let daemon = tokio::spawn(async move { agentcordon_broker::daemon::run(config).await });

    let port = wait_for_port(&port_file).await;
    let resp = https_client()
        .get(format!("https://127.0.0.1:{port}/health"))
        .send()
        .await
        .expect("https request to the running daemon");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);

    daemon.abort();
}

/// Poll the broker's port file until the daemon has bound and written it.
async fn wait_for_port(path: &std::path::Path) -> u16 {
    for _ in 0..200 {
        if let Ok(text) = std::fs::read_to_string(path) {
            // The file names the URL to dial (`https://127.0.0.1:<port>`).
            if let Some(port) = text
                .trim()
                .rsplit(':')
                .next()
                .and_then(|p| p.parse::<u16>().ok())
            {
                return port;
            }
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("broker never wrote {}", path.display());
}
