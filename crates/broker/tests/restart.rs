//! Restarting the broker over its encrypted token store.
//!
//! A workspace registers once and keeps working across broker restarts:
//! the OAuth tokens are written to `tokens.enc` on shutdown and read back
//! on startup. They are sealed with a key derived from the broker's own
//! P-256 private key, so a data directory whose `broker.key` is not the one
//! that wrote the store yields nothing — the workspace has to register
//! again rather than have its tokens read by whoever holds the file.
//!
//! Both halves are observed at the HTTP seam: a successor broker built over
//! the same temporary data directory, coming up through the daemon's own
//! startup path, answering a signed `/status` from the same workspace key.

use axum::http::StatusCode;

use crate::common::{TestBroker, TestWorkspace};

const SCOPES: &[&str] = &["credentials:discover", "credentials:vend"];

/// The successor is handed no registrations of its own, so anything it
/// knows about the workspace came off disk.
#[tokio::test(flavor = "multi_thread")]
async fn tokens_survive_a_restart_with_the_same_key_material() {
    let ws = TestWorkspace::generate();
    let first = TestBroker::builder()
        .with_registered(&ws, SCOPES)
        .build()
        .await;
    let (before, body) = first.send(ws.signed("GET", "/status", "")).await;
    assert_eq!(before, StatusCode::OK, "{body}");

    let restarted = first.restart(false).await;

    let (after, body) = restarted.send(ws.signed("GET", "/status", "")).await;
    assert_eq!(after, StatusCode::OK, "{body}");
    assert_eq!(body["data"]["registered"], true);
    assert_eq!(body["data"]["scopes"][0], "credentials:discover");
    assert_eq!(body["data"]["scopes"][1], "credentials:vend");
    assert_eq!(body["data"]["token_status"], "valid");
}

/// A successor whose key material differs cannot read the store. The
/// plaintext recovery store beside it holds only a refresh token, and
/// redeeming that needs a server willing to honour it — which this one is
/// not — so the workspace is simply not registered any more.
#[tokio::test(flavor = "multi_thread")]
async fn tokens_are_unreadable_after_a_restart_with_different_key_material() {
    let ws = TestWorkspace::generate();
    let first = TestBroker::builder()
        .with_registered(&ws, SCOPES)
        .build()
        .await;

    let restarted = first.restart(true).await;

    let (status, body) = restarted.send(ws.signed("GET", "/status", "")).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(body["error"]["code"], "reregistration_required");
}

/// The file itself: what the broker leaves on disk is ciphertext, and the
/// key that wrote it is the only one that opens it.
#[tokio::test(flavor = "multi_thread")]
async fn the_token_store_on_disk_is_ciphertext_readable_only_by_its_own_key() {
    let ws = TestWorkspace::generate();
    let broker = TestBroker::builder()
        .with_registered(&ws, SCOPES)
        .build()
        .await;
    let access_token = format!("access-{}", &ws.pk_hash()[..8]);
    let refresh_token = format!("refresh-{}", &ws.pk_hash()[..8]);

    agentcordon_broker::daemon::flush_state(&broker.state).await;

    let path = broker.state.config.token_store_path();
    let bytes = std::fs::read(&path).expect("token store written");
    let as_text = String::from_utf8_lossy(&bytes);
    assert!(
        !as_text.contains(&access_token),
        "access token in cleartext"
    );
    assert!(
        !as_text.contains(&refresh_token),
        "refresh token in cleartext"
    );

    let mine = agentcordon_broker::token_store::load(&path, &broker.state.encryption_key)
        .expect("the key that wrote it opens it")
        .expect("a store that was just written is present");
    assert_eq!(mine[&ws.pk_hash()].access_token, access_token);

    let someone_else = p256::SecretKey::random(&mut rand::thread_rng());
    assert!(
        agentcordon_broker::token_store::load(&path, &someone_else).is_err(),
        "another key must not open the store"
    );
}
