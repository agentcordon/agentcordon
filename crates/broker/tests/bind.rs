//! The guards on a non-loopback bind, seen from the wire.
//!
//! Binding the broker to anything but loopback publishes the signed API —
//! and the credentials it vends — to whoever can reach the port. The broker
//! refuses to come up that way unless the traffic is protected: TLS
//! (`tests/tls.rs` serves it), or `--shared-secret`, which every route but
//! `/health` must then present. A refusal happens at startup, before the
//! data directory exists; the shared secret is enforced on every request.

use std::time::Duration;

use agentcordon_broker::auth::SHARED_SECRET_HEADER;
use agentcordon_broker::config::BrokerConfig;

const SECRET: &str = "s3cret-for-the-network";

/// Poll the broker's port file until the daemon has bound and written it,
/// then return the URL it names.
async fn wait_for_url(path: &std::path::Path) -> String {
    for _ in 0..200 {
        if let Ok(text) = std::fs::read_to_string(path) {
            let text = text.trim().to_string();
            if !text.is_empty() {
                return text;
            }
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("broker never wrote {}", path.display());
}

/// A broker started the way a container deployment writes it — bound to
/// every interface — with the transport protection those flags require.
/// The bind is rewritten to loopback after validation so the test never
/// opens a port to the network.
async fn open_bind_config(
    dir: &std::path::Path,
    extra: &[&str],
) -> (BrokerConfig, wiremock::MockServer) {
    let server = wiremock::MockServer::start().await;
    let mut args: Vec<String> = [
        "agentcordon-broker",
        "--bind",
        "0.0.0.0",
        "--port",
        "0",
        "--data-dir",
        dir.to_str().unwrap(),
        "--server-url",
        &server.uri(),
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    args.extend(extra.iter().map(|s| s.to_string()));
    (<BrokerConfig as clap::Parser>::parse_from(args), server)
}

/// Without TLS or a shared secret the daemon refuses before it binds, and
/// before it has created anything under the data directory.
#[tokio::test(flavor = "multi_thread")]
async fn non_loopback_bind_without_transport_protection_never_binds() {
    let dir = tempfile::tempdir().unwrap();
    let data_dir = dir.path().join("data");
    let (config, _server) = open_bind_config(&data_dir, &[]).await;

    let err = agentcordon_broker::daemon::run(config)
        .await
        .expect_err("must refuse");

    assert!(err.contains("non-loopback"), "{err}");
    assert!(err.contains("--shared-secret"), "{err}");
    assert!(err.contains("--tls-cert"), "{err}");
    assert!(!data_dir.exists(), "refused before touching the data dir");
}

/// TLS material that cannot be loaded is the same kind of refusal: at
/// startup, naming the flag at fault, before the data directory exists. A
/// broker that gets as far as listening can complete a handshake.
#[tokio::test(flavor = "multi_thread")]
async fn non_loopback_bind_with_unusable_tls_material_never_binds() {
    let dir = tempfile::tempdir().unwrap();
    let data_dir = dir.path().join("data");
    let cert = dir.path().join("cert.pem");
    let key = dir.path().join("key.pem");
    std::fs::write(&cert, "not a certificate").unwrap();
    std::fs::write(&key, "not a key").unwrap();
    let (config, _server) = open_bind_config(
        &data_dir,
        &[
            "--tls-cert",
            cert.to_str().unwrap(),
            "--tls-key",
            key.to_str().unwrap(),
        ],
    )
    .await;

    let err = agentcordon_broker::daemon::run(config)
        .await
        .expect_err("must refuse");

    assert!(err.contains("--tls-cert"), "{err}");
    assert!(!data_dir.exists(), "refused before touching the data dir");
}

/// A shared secret is the other way to satisfy the guard. The broker comes
/// up, and on the wire every route but `/health` demands the header:
/// missing, wrong, and right are three different outcomes, and only the
/// right one gets as far as signature verification.
#[tokio::test(flavor = "multi_thread")]
async fn non_loopback_bind_with_a_shared_secret_demands_it_on_every_route_but_health() {
    let dir = tempfile::tempdir().unwrap();
    let (mut config, _server) = open_bind_config(dir.path(), &["--shared-secret", SECRET]).await;
    config.validate().expect("0.0.0.0 with a secret is allowed");
    config.bind = "127.0.0.1".to_string();
    let port_file = config.port_file_path();

    let daemon = tokio::spawn(async move { agentcordon_broker::daemon::run(config).await });
    let base = wait_for_url(&port_file).await;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();

    // Discovery and key pinning happen before any secret is known.
    let health = client
        .get(format!("{base}/health"))
        .send()
        .await
        .expect("health");
    assert_eq!(health.status(), reqwest::StatusCode::OK);

    // No secret: refused, and the refusal names the variable to set.
    let none = client.get(format!("{base}/status")).send().await.unwrap();
    assert_eq!(none.status(), reqwest::StatusCode::UNAUTHORIZED);
    let body: serde_json::Value = none.json().await.unwrap();
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("AGTCRDN_BROKER_SHARED_SECRET"),
        "{body}"
    );

    // Wrong secret: the same refusal, no hint that it was close.
    let wrong = client
        .get(format!("{base}/status"))
        .header(SHARED_SECRET_HEADER, "not-the-secret")
        .send()
        .await
        .unwrap();
    assert_eq!(wrong.status(), reqwest::StatusCode::UNAUTHORIZED);
    let wrong_body: serde_json::Value = wrong.json().await.unwrap();
    assert_eq!(wrong_body["error"]["message"], body["error"]["message"]);

    // A prefix of the secret is not the secret.
    let prefix = client
        .get(format!("{base}/status"))
        .header(SHARED_SECRET_HEADER, &SECRET[..SECRET.len() - 1])
        .send()
        .await
        .unwrap();
    assert_eq!(prefix.status(), reqwest::StatusCode::UNAUTHORIZED);

    // Right secret, no signature: past the secret gate, refused by the next
    // one. A different message is the proof the first gate opened.
    let right = client
        .get(format!("{base}/status"))
        .header(SHARED_SECRET_HEADER, SECRET)
        .send()
        .await
        .unwrap();
    assert_eq!(right.status(), reqwest::StatusCode::UNAUTHORIZED);
    let right_body: serde_json::Value = right.json().await.unwrap();
    assert_eq!(
        right_body["error"]["message"],
        "Signature verification failed"
    );

    // `/register` is self-signed rather than workspace-signed, so the
    // secret is the only thing standing between an open port and a device
    // flow started in someone else's name.
    let register = client
        .post(format!("{base}/register"))
        .json(&serde_json::json!({ "workspace_name": "w" }))
        .send()
        .await
        .unwrap();
    assert_eq!(register.status(), reqwest::StatusCode::UNAUTHORIZED);
    let register_body: serde_json::Value = register.json().await.unwrap();
    assert_eq!(register_body["error"]["message"], body["error"]["message"]);

    daemon.abort();
}
