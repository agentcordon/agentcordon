//! Broker integration test harness.
//!
//! Builds the real broker router in-process over a temporary data directory,
//! with a `wiremock` server standing in for the AgentCordon server (and, when
//! a test needs one, for upstream APIs). Requests are signed with a test
//! workspace key exactly the way the CLI signs them, so the auth middleware
//! is exercised on every call.
//!
//! This is the broker's test seam. Tests observe HTTP responses and, where
//! the behaviour is a file on disk, the file. They do not reach into state.

#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use axum::Router;
use ed25519_dalek::SigningKey;
use http_body_util::BodyExt;
use tokio::sync::RwLock;
use wiremock::MockServer;

use agentcordon_broker::config::BrokerConfig;
use agentcordon_broker::routes::build_router;
use agentcordon_broker::state::{BrokerState, SharedState, TokenStatus, WorkspaceState};
use agentcordon_identity::WorkspaceKey;

/// A test workspace identity: the Ed25519 key the CLI would hold.
pub struct TestWorkspace {
    pub signing_key: SigningKey,
}

impl TestWorkspace {
    pub fn generate() -> Self {
        Self {
            signing_key: SigningKey::generate(&mut rand::thread_rng()),
        }
    }

    fn key(&self) -> WorkspaceKey {
        WorkspaceKey::from(self.signing_key.clone())
    }

    pub fn public_key_hex(&self) -> String {
        self.key().public_key_hex()
    }

    /// SHA-256 of the raw public key bytes, hex. The broker keys its state by this.
    pub fn pk_hash(&self) -> String {
        self.key().pk_hash()
    }

    /// Build a request signed the way `agentcordon` signs it: the identity
    /// crate's `METHOD\nPATH_WITH_QUERY\nTIMESTAMP\nNONCE\nBODY` payload,
    /// with the same signer the CLI uses and a fresh nonce.
    pub fn signed(&self, method: &str, path_and_query: &str, body: &str) -> Request<Body> {
        self.signed_at(method, path_and_query, body, now_secs())
    }

    /// Same as [`signed`], with an explicit timestamp for skew tests.
    pub fn signed_at(
        &self,
        method: &str,
        path_and_query: &str,
        body: &str,
        timestamp: i64,
    ) -> Request<Body> {
        self.signed_with_nonce(
            method,
            path_and_query,
            body,
            timestamp,
            &agentcordon_identity::generate_nonce(),
        )
    }

    /// Same as [`signed_at`], with an explicit nonce so a test can present
    /// the identical signed request twice.
    pub fn signed_with_nonce(
        &self,
        method: &str,
        path_and_query: &str,
        body: &str,
        timestamp: i64,
        nonce: &str,
    ) -> Request<Body> {
        let headers = agentcordon_identity::sign_request_with(
            &self.key(),
            method,
            path_and_query,
            body.as_bytes(),
            timestamp,
            nonce,
        );
        Request::builder()
            .method(method)
            .uri(path_and_query)
            .header("X-AC-PublicKey", headers.public_key)
            .header("X-AC-Timestamp", headers.timestamp)
            .header("X-AC-Nonce", headers.nonce)
            .header("X-AC-Signature", headers.signature)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .expect("build signed request")
    }

    /// The JSON body `agentcordon register` sends: self-signed with the
    /// current time and a fresh nonce.
    pub fn register_body(&self, workspace_name: &str, scopes: &[&str]) -> serde_json::Value {
        self.register_body_at(
            workspace_name,
            scopes,
            now_secs(),
            &agentcordon_identity::generate_nonce(),
        )
    }

    /// Same as [`register_body`], with an explicit timestamp and nonce.
    pub fn register_body_at(
        &self,
        workspace_name: &str,
        scopes: &[&str],
        timestamp: i64,
        nonce: &str,
    ) -> serde_json::Value {
        let scopes: Vec<String> = scopes.iter().map(|s| s.to_string()).collect();
        let p = agentcordon_identity::sign_register_at(
            &self.key(),
            workspace_name,
            &scopes,
            timestamp,
            nonce,
        );
        serde_json::json!({
            "workspace_name": p.workspace_name,
            "public_key": p.public_key,
            "scopes": p.scopes,
            "timestamp": p.timestamp,
            "nonce": p.nonce,
            "signature": p.signature,
        })
    }
}

/// The committed self-signed certificate the TLS tests serve. Test-only
/// material: the matching key is in the repository. See
/// `tests/fixtures/README.md`.
pub fn tls_cert_path() -> std::path::PathBuf {
    std::path::PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/localhost.pem"
    ))
}

/// The key that goes with [`tls_cert_path`].
pub fn tls_key_path() -> std::path::PathBuf {
    std::path::PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/localhost-key.pem"
    ))
}

pub fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_secs() as i64
}

/// An in-process broker with its fake server.
pub struct TestBroker {
    pub app: Router,
    pub state: SharedState,
    /// Stands in for the AgentCordon server. Register expectations on it.
    pub server: MockServer,
    /// Temporary data directory (keys, token store). Shared with any broker
    /// built by [`TestBroker::restart`], and removed when the last of them
    /// is dropped.
    pub data_dir: Arc<tempfile::TempDir>,
}

impl TestBroker {
    pub async fn new() -> Self {
        Self::builder().build().await
    }

    pub fn builder() -> TestBrokerBuilder {
        TestBrokerBuilder {
            registered: Vec::new(),
            allow_loopback: true,
            shared_secret: None,
            restart_of: None,
        }
    }

    /// Write the workspace tokens to disk the way a clean shutdown does
    /// (`daemon::flush_state`), then build a fresh broker over the same data
    /// directory — a restart.
    ///
    /// The successor loads through the daemon's own startup path, so what
    /// survives here is exactly what survives in production. It keeps this
    /// broker's P-256 key unless `new_key_material` is set, which stands in
    /// for a data directory whose `broker.key` was replaced.
    pub async fn restart(&self, new_key_material: bool) -> TestBroker {
        agentcordon_broker::daemon::flush_state(&self.state).await;
        let key = if new_key_material {
            p256::SecretKey::random(&mut rand::thread_rng())
        } else {
            self.state.encryption_key.clone()
        };
        TestBrokerBuilder {
            registered: Vec::new(),
            allow_loopback: self.state.config.proxy_allow_loopback,
            shared_secret: self.state.config.shared_secret.clone(),
            restart_of: Some((self.data_dir.clone(), key)),
        }
        .build()
        .await
    }

    /// Send a request and return status plus parsed JSON body (or Null).
    pub async fn send(&self, req: Request<Body>) -> (StatusCode, serde_json::Value) {
        use tower::ServiceExt;
        let resp = self
            .app
            .clone()
            .oneshot(req)
            .await
            .expect("router never errors");
        let status = resp.status();
        let bytes = resp
            .into_body()
            .collect()
            .await
            .expect("read body")
            .to_bytes();
        let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
        (status, json)
    }
}

pub struct TestBrokerBuilder {
    registered: Vec<(String, Vec<String>)>,
    allow_loopback: bool,
    shared_secret: Option<String>,
    /// Set by [`TestBroker::restart`]: the data directory to come up over,
    /// and the key material to read it with.
    restart_of: Option<(Arc<tempfile::TempDir>, p256::SecretKey)>,
}

impl TestBrokerBuilder {
    /// Pre-register a workspace as if its device flow had completed, with
    /// these OAuth scopes and a valid (fake) access token.
    pub fn with_registered(mut self, ws: &TestWorkspace, scopes: &[&str]) -> Self {
        self.registered
            .push((ws.pk_hash(), scopes.iter().map(|s| s.to_string()).collect()));
        self
    }

    pub fn allow_loopback(mut self, yes: bool) -> Self {
        self.allow_loopback = yes;
        self
    }

    /// Configure `--shared-secret`: every request except `/health` must
    /// then carry it in `X-AgentCordon-Broker-Secret`.
    pub fn with_shared_secret(mut self, secret: &str) -> Self {
        self.shared_secret = Some(secret.to_string());
        self
    }

    pub async fn build(self) -> TestBroker {
        let server = MockServer::start().await;
        let restart = self.restart_of.clone();
        let data_dir = match &restart {
            Some((dir, _)) => dir.clone(),
            None => Arc::new(tempfile::tempdir().expect("tempdir")),
        };

        let mut args = vec![
            "agentcordon-broker".to_string(),
            "--data-dir".to_string(),
            data_dir.path().display().to_string(),
            "--server-url".to_string(),
            server.uri(),
        ];
        if self.allow_loopback {
            args.push("--proxy-allow-loopback".to_string());
        }
        if let Some(secret) = &self.shared_secret {
            args.push("--shared-secret".to_string());
            args.push(secret.clone());
        }
        let config = <BrokerConfig as clap::Parser>::parse_from(args);

        let http_client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .expect("http client");

        // A restart comes up the way the daemon does: read the encrypted
        // token store with this key, falling back to the recovery store.
        let encryption_key = match &restart {
            Some((_, key)) => key.clone(),
            None => p256::SecretKey::random(&mut rand::thread_rng()),
        };
        let mut workspaces = if restart.is_some() {
            agentcordon_broker::daemon::load_with_recovery(&config, &encryption_key, &http_client)
                .await
        } else {
            HashMap::new()
        };
        for (pk_hash, scopes) in self.registered {
            workspaces.insert(
                pk_hash.clone(),
                WorkspaceState {
                    client_id: format!("client-{}", &pk_hash[..8]),
                    access_token: format!("access-{}", &pk_hash[..8]),
                    refresh_token: format!("refresh-{}", &pk_hash[..8]),
                    scopes,
                    token_expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
                    workspace_name: "test-workspace".to_string(),
                    token_status: TokenStatus::Valid,
                },
            );
        }

        let state: SharedState = Arc::new(BrokerState {
            workspaces: RwLock::new(workspaces),
            pending: RwLock::new(HashMap::new()),
            registration_errors: RwLock::new(HashMap::new()),
            mcp_configs: RwLock::new(HashMap::new()),
            server_url: server.uri(),
            http_client,
            upstream_client: agentcordon_broker::upstream::build_client().expect("upstream client"),
            encryption_key,
            config,
            nonces: agentcordon_broker::auth::NonceCache::default(),
            refresh_locks: agentcordon_broker::token_refresh::RefreshLocks::default(),
        });

        TestBroker {
            app: build_router(state.clone()),
            state,
            server,
            data_dir,
        }
    }
}

// ---------------------------------------------------------------------------
// Vend helpers: build what the server would return for a proxied call.
// ---------------------------------------------------------------------------

use base64::engine::general_purpose::STANDARD as B64_STANDARD;
use base64::Engine;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use wiremock::matchers::{method, path};
use wiremock::{Mock, ResponseTemplate};

use agent_cordon_core::crypto::ecies::{build_aad, CredentialEnvelopeEncryptor, EciesEncryptor};
use agent_cordon_core::wire::credentials::VendResponse;
use agent_cordon_core::wire::EncryptedEnvelopeWire;

/// The server's vend-device path for a credential name.
pub fn vend_path(credential_name: &str) -> String {
    format!("/api/v1/credentials/vend-device/{credential_name}")
}

/// ECIES-encrypt `material` (the `{value, metadata}` plaintext) to the test
/// broker's P-256 key exactly as the server does, shaped as the server's own
/// [`EncryptedEnvelopeWire`] so a renamed field breaks this harness too.
pub async fn vend_envelope(broker: &TestBroker, material: &serde_json::Value) -> serde_json::Value {
    let pub_point = broker
        .state
        .encryption_key
        .public_key()
        .to_encoded_point(false);
    let aad = build_aad("ws-test", "cred-test", "vnd_test", "0");
    let plaintext = serde_json::to_vec(material).expect("serialize material");
    let env = EciesEncryptor::new()
        .encrypt_for_device(pub_point.as_bytes(), &plaintext, &aad)
        .await
        .expect("ecies encrypt");
    serde_json::to_value(EncryptedEnvelopeWire {
        version: env.version,
        ephemeral_public_key: B64_STANDARD.encode(env.ephemeral_public_key),
        ciphertext: B64_STANDARD.encode(env.ciphertext),
        nonce: B64_STANDARD.encode(env.nonce),
        aad: B64_STANDARD.encode(env.aad),
    })
    .expect("serialise envelope")
}

/// A complete `data` object for a vend-device response, built from the
/// server's own [`VendResponse`].
pub async fn vend_body(
    broker: &TestBroker,
    credential_type: &str,
    secret: &str,
    allowed_url_pattern: Option<&str>,
) -> serde_json::Value {
    vend_body_with_metadata(
        broker,
        credential_type,
        secret,
        serde_json::Value::Null,
        allowed_url_pattern,
    )
    .await
}

/// Register a vend-device mock on the fake server that succeeds for any
/// request body.
pub async fn mock_vend(
    broker: &TestBroker,
    credential_name: &str,
    credential_type: &str,
    secret: &str,
    allowed_url_pattern: Option<&str>,
) {
    let data = vend_body(broker, credential_type, secret, allowed_url_pattern).await;
    Mock::given(method("POST"))
        .and(path(vend_path(credential_name)))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({ "data": data })))
        .mount(&broker.server)
        .await;
}

/// A `data` object for a vend-device response whose envelope carries the
/// credential's `metadata` as well as its value — what an `api_key_header`
/// or `api_key_query` credential needs so the broker knows which header or
/// parameter to put the key in.
pub async fn vend_body_with_metadata(
    broker: &TestBroker,
    credential_type: &str,
    secret: &str,
    metadata: serde_json::Value,
    allowed_url_pattern: Option<&str>,
) -> serde_json::Value {
    let material = if metadata.is_null() {
        serde_json::json!({ "value": secret })
    } else {
        serde_json::json!({ "value": secret, "metadata": metadata })
    };
    let envelope = vend_envelope(broker, &material).await;
    serde_json::to_value(VendResponse {
        credential_type: credential_type.to_string(),
        transform_name: None,
        allowed_url_pattern: allowed_url_pattern.map(str::to_string),
        encrypted_envelope: serde_json::from_value(envelope)
            .expect("vend_envelope produces the shared envelope type"),
        vend_id: "vnd_test".to_string(),
    })
    .expect("serialise vend response")
}

/// Mount a vend-device mock returning `data`.
pub async fn mock_vend_data(broker: &TestBroker, credential_name: &str, data: serde_json::Value) {
    Mock::given(method("POST"))
        .and(path(vend_path(credential_name)))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({ "data": data })))
        .mount(&broker.server)
        .await;
}

/// A pattern that admits every URL on a mock upstream.
pub fn pattern_for(upstream: &MockServer) -> String {
    format!("{}/*", upstream.uri())
}
