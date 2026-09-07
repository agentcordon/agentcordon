use std::fs;
use std::time::Duration;

use reqwest::Client;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use agentcordon_identity::{canonicalise_path_and_query, SignedHeaders, WorkspaceKey};

use crate::error::{self, CliError};
use crate::pin::{self, PinOutcome};
use crate::signing;

/// Environment variable naming an already-running broker.
pub const BROKER_URL_ENV: &str = "AGTCRDN_BROKER_URL";

/// Environment variable carrying the broker's `--shared-secret`, sent in
/// [`SHARED_SECRET_HEADER`] on every request.
pub const SHARED_SECRET_ENV: &str = "AGTCRDN_BROKER_SHARED_SECRET";

/// Header the broker checks when started with `--shared-secret`.
pub const SHARED_SECRET_HEADER: &str = "X-AgentCordon-Broker-Secret";

/// Environment variable naming a PEM file (a certificate or a CA bundle)
/// the CLI should trust in addition to the system roots when it talks to
/// the broker. A broker started with `--tls-cert`/`--tls-key` usually
/// serves its own certificate; this is how the CLI is told to accept it,
/// short of turning verification off — which the CLI never does.
pub const BROKER_CA_ENV: &str = "AGTCRDN_BROKER_CA";

/// Split a caller-supplied path-with-query like `"/foo?a=1"` into its
/// components and run them through `canonicalise_path_and_query`, so
/// `sign_request` always receives the canonical signed form. The outbound
/// HTTP URL is still built from the raw `path`; only the signed payload is
/// normalised. The broker verifier applies the identical canonicalisation
/// (the same function, from the identity crate) against `Uri::path()` /
/// `Uri::query()`.
fn canonical_sign_path(raw: &str) -> String {
    let (path, query) = match raw.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (raw, None),
    };
    canonicalise_path_and_query(path, query)
}

/// A broker the CLI found and health-checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredBroker {
    pub base_url: String,
    /// SHA-256 hex of the broker's public key, as published on `/health`.
    pub key_fingerprint: String,
    /// The broker's own version, as published on `/health`. `None` from a
    /// broker too old to report one.
    pub version: Option<String>,
}

/// Broker HTTP client with Ed25519 request signing.
pub struct BrokerClient {
    base_url: String,
    http: Client,
    keypair: WorkspaceKey,
    shared_secret: Option<String>,
    /// The broker's version from `/health`, kept so a command can compare it
    /// with this CLI's own. `None` from a broker too old to report one.
    broker_version: Option<String>,
}

/// Standard broker error envelope.
#[derive(Debug, Deserialize)]
pub struct BrokerErrorResponse {
    pub error: BrokerErrorDetail,
}

#[derive(Debug, Deserialize)]
pub struct BrokerErrorDetail {
    pub code: String,
    pub message: String,
}

impl BrokerClient {
    /// Create a new broker client: load the keypair, discover and
    /// health-check the broker, and verify its key against the workspace's
    /// pin (writing the pin on first use of a workspace enrolled before
    /// pinning existed).
    pub async fn connect() -> Result<Self, CliError> {
        let keypair = signing::load_keypair()?;
        let broker = discover_broker().await?;
        verify_pin(&broker)?;
        Self::build(broker.base_url, broker.version, keypair)
    }

    /// Create a broker client for registration. Pins the broker key: with
    /// `force` the pin is replaced unconditionally (the user is explicitly
    /// re-enrolling with this broker); without it a mismatch is refused
    /// like any other connection.
    pub async fn connect_for_registration(force: bool) -> Result<Self, CliError> {
        let keypair = signing::load_keypair()?;
        let broker = discover_broker().await?;
        if force {
            pin::write_pin(&signing::workspace_dir(), &broker.key_fingerprint)?;
            eprintln!(
                "Pinned broker key fingerprint {} for {}",
                broker.key_fingerprint, broker.base_url
            );
        } else {
            verify_pin(&broker)?;
        }
        Self::build(broker.base_url, broker.version, keypair)
    }

    fn build(
        base_url: String,
        broker_version: Option<String>,
        keypair: WorkspaceKey,
    ) -> Result<Self, CliError> {
        let http = http_client(Duration::from_secs(30))?;
        Ok(Self {
            base_url,
            http,
            keypair,
            shared_secret: shared_secret_from_env(),
            broker_version,
        })
    }

    /// The version the connected broker reports on `/health`.
    pub fn broker_version(&self) -> Option<&str> {
        self.broker_version.as_deref()
    }

    /// Access the keypair for computing identity, etc.
    pub fn keypair(&self) -> &WorkspaceKey {
        &self.keypair
    }

    /// The discovered broker base URL.
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    fn request(&self, method: reqwest::Method, path: &str) -> reqwest::RequestBuilder {
        let mut req = self
            .http
            .request(method, format!("{}{}", self.base_url, path));
        if let Some(secret) = &self.shared_secret {
            req = req.header(SHARED_SECRET_HEADER, secret);
        }
        req
    }

    /// Send a signed GET request.
    pub async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T, CliError> {
        let sign_path = canonical_sign_path(path);
        let headers = signing::sign_request(&self.keypair, "GET", &sign_path, "")?;

        let resp = self
            .request(reqwest::Method::GET, path)
            .headers(build_header_map(&headers)?)
            .send()
            .await
            .map_err(|e| CliError::general(format!("request failed: {e}")))?;

        handle_response(resp).await
    }

    /// Send a signed POST request with a JSON body.
    pub async fn post<B: Serialize, T: DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T, CliError> {
        let body_str = serde_json::to_string(body)
            .map_err(|e| CliError::general(format!("failed to serialize request: {e}")))?;
        let sign_path = canonical_sign_path(path);
        let headers = signing::sign_request(&self.keypair, "POST", &sign_path, &body_str)?;

        let resp = self
            .request(reqwest::Method::POST, path)
            .headers(build_header_map(&headers)?)
            .header("Content-Type", "application/json")
            .body(body_str)
            .send()
            .await
            .map_err(|e| CliError::general(format!("request failed: {e}")))?;

        handle_response(resp).await
    }

    /// Send a signed POST request with a JSON body and return raw (status, body).
    /// Used by handlers (e.g. proxy) that need to inspect rich error envelopes
    /// like the `candidates` field on a 300 Multiple Choices response.
    pub async fn post_raw<B: Serialize>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<(u16, String), CliError> {
        let body_str = serde_json::to_string(body)
            .map_err(|e| CliError::general(format!("failed to serialize request: {e}")))?;
        let sign_path = canonical_sign_path(path);
        let headers = signing::sign_request(&self.keypair, "POST", &sign_path, &body_str)?;

        let resp = self
            .request(reqwest::Method::POST, path)
            .headers(build_header_map(&headers)?)
            .header("Content-Type", "application/json")
            .body(body_str)
            .send()
            .await
            .map_err(|e| CliError::general(format!("request failed: {e}")))?;

        let status = resp.status().as_u16();
        let text = resp
            .text()
            .await
            .map_err(|e| CliError::general(format!("failed to read response: {e}")))?;
        Ok((status, text))
    }

    /// Send a signed POST request with an empty body. Returns raw (status, body).
    /// Used for simple control endpoints like `/deregister`.
    pub async fn post_signed_empty(&self, path: &str) -> Result<(u16, String), CliError> {
        let sign_path = canonical_sign_path(path);
        let headers = signing::sign_request(&self.keypair, "POST", &sign_path, "")?;

        let resp = self
            .request(reqwest::Method::POST, path)
            .headers(build_header_map(&headers)?)
            .send()
            .await
            .map_err(|e| CliError::general(format!("request failed: {e}")))?;

        let status = resp.status().as_u16();
        let text = resp
            .text()
            .await
            .map_err(|e| CliError::general(format!("failed to read response: {e}")))?;
        Ok((status, text))
    }

    /// Send an unsigned POST request (for registration, which carries its
    /// own self-signature in the body).
    pub async fn post_unsigned<B: Serialize, T: DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T, CliError> {
        let resp = self
            .request(reqwest::Method::POST, path)
            .json(body)
            .send()
            .await
            .map_err(|e| CliError::general(format!("request failed: {e}")))?;

        handle_response(resp).await
    }

    /// Send a signed GET and return raw response text (for status polling).
    pub async fn get_raw(&self, path: &str) -> Result<(u16, String), CliError> {
        let sign_path = canonical_sign_path(path);
        let headers = signing::sign_request(&self.keypair, "GET", &sign_path, "")?;

        let resp = self
            .request(reqwest::Method::GET, path)
            .headers(build_header_map(&headers)?)
            .send()
            .await
            .map_err(|e| CliError::general(format!("request failed: {e}")))?;

        let status = resp.status().as_u16();
        let text = resp
            .text()
            .await
            .map_err(|e| CliError::general(format!("failed to read response: {e}")))?;
        Ok((status, text))
    }
}

/// Compare the discovered broker's fingerprint with the workspace pin,
/// printing the one-line notice when a pin is written for the first time.
fn verify_pin(broker: &DiscoveredBroker) -> Result<(), CliError> {
    let dir = signing::workspace_dir();
    match pin::check_pin(&dir, &broker.base_url, &broker.key_fingerprint)? {
        PinOutcome::Matched => {}
        PinOutcome::Written => eprintln!(
            "Pinned broker key fingerprint {} in {} (first use of this workspace with a \
             key-publishing broker)",
            broker.key_fingerprint,
            pin::pin_path(&dir).display()
        ),
    }
    Ok(())
}

/// The HTTP client every broker connection goes through, honouring
/// [`BROKER_CA_ENV`].
pub(crate) fn http_client(timeout: Duration) -> Result<Client, CliError> {
    build_http_client(timeout, broker_ca_from_env().as_deref())
}

/// `AGTCRDN_BROKER_CA` as a path, ignoring an empty value.
fn broker_ca_from_env() -> Option<std::path::PathBuf> {
    std::env::var_os(BROKER_CA_ENV)
        .filter(|v| !v.is_empty())
        .map(std::path::PathBuf::from)
}

/// Inner form of [`http_client`] taking the CA path as a parameter, so the
/// trust decision is testable without touching process-global environment.
///
/// Every certificate in the PEM file is added as a root for this client
/// only. Verification is never disabled: a broker whose certificate is not
/// covered by the system roots or this file is refused.
fn build_http_client(
    timeout: Duration,
    ca_path: Option<&std::path::Path>,
) -> Result<Client, CliError> {
    let mut builder = Client::builder().timeout(timeout);

    if let Some(path) = ca_path {
        let pem = fs::read(path).map_err(|e| {
            CliError::general(format!(
                "{BROKER_CA_ENV}={}: cannot read the broker CA file: {e}",
                path.display()
            ))
        })?;
        let certs = reqwest::Certificate::from_pem_bundle(&pem).map_err(|e| {
            CliError::general(format!(
                "{BROKER_CA_ENV}={}: not a PEM certificate: {e}",
                path.display()
            ))
        })?;
        if certs.is_empty() {
            return Err(CliError::general(format!(
                "{BROKER_CA_ENV}={}: contains no CERTIFICATE block",
                path.display()
            )));
        }
        for cert in certs {
            builder = builder.add_root_certificate(cert);
        }
    }

    builder
        .build()
        .map_err(|e| CliError::general(format!("failed to create HTTP client: {e}")))
}

/// Flatten an error and its `source` chain into one line, so the rustls
/// reason survives instead of being hidden behind reqwest's generic
/// "error sending request".
fn error_chain(err: &dyn std::error::Error) -> String {
    let mut parts = vec![err.to_string()];
    let mut source = err.source();
    while let Some(e) = source {
        parts.push(e.to_string());
        source = e.source();
    }
    parts.join(": ")
}

/// Whether a flattened transport error is the peer's certificate being
/// rejected, as opposed to the broker simply not being there.
fn is_certificate_failure(detail: &str) -> bool {
    let d = detail.to_ascii_lowercase();
    d.contains("certificate")
        || d.contains("unknownissuer")
        || d.contains("notvalidfor")
        || d.contains("bad_certificate")
        || d.contains("self-signed")
        || d.contains("self signed")
}

/// Turn a failure to reach the broker into the error the user sees.
///
/// A rejected certificate on an `https://` broker is its own diagnosis: the
/// broker is running, this machine just does not trust what it presented.
/// That message names `AGTCRDN_BROKER_CA`, because pointing it at the
/// broker's certificate is the fix. Anything else stays the ordinary
/// "broker not running", exit code 2.
fn transport_failure(base_url: &str, detail: &str, ca_configured: bool) -> CliError {
    if !base_url.starts_with("https://") || !is_certificate_failure(detail) {
        return CliError::broker_not_running();
    }
    if ca_configured {
        CliError::general(format!(
            "the broker at {base_url} presented a certificate that the file in {BROKER_CA_ENV} \
             does not vouch for ({detail}). Point {BROKER_CA_ENV} at the certificate this \
             broker actually serves (its --tls-cert file, or the CA that issued it)."
        ))
    } else {
        CliError::general(format!(
            "the broker at {base_url} presented a certificate this machine does not trust \
             ({detail}). If it serves its own certificate (agentcordon-broker --tls-cert), set \
             {BROKER_CA_ENV} to that certificate in PEM form."
        ))
    }
}

fn shared_secret_from_env() -> Option<String> {
    std::env::var(SHARED_SECRET_ENV)
        .ok()
        .filter(|s| !s.trim().is_empty())
}

/// Build a reqwest::header::HeaderMap from signing headers.
fn build_header_map(headers: &SignedHeaders) -> Result<reqwest::header::HeaderMap, CliError> {
    let mut map = reqwest::header::HeaderMap::new();
    map.insert(
        "X-AC-PublicKey",
        headers
            .public_key
            .parse()
            .map_err(|_| CliError::general("invalid public key header value"))?,
    );
    map.insert(
        "X-AC-Timestamp",
        headers
            .timestamp
            .parse()
            .map_err(|_| CliError::general("invalid timestamp header value"))?,
    );
    map.insert(
        "X-AC-Nonce",
        headers
            .nonce
            .parse()
            .map_err(|_| CliError::general("invalid nonce header value"))?,
    );
    map.insert(
        "X-AC-Signature",
        headers
            .signature
            .parse()
            .map_err(|_| CliError::general("invalid signature header value"))?,
    );
    Ok(map)
}

/// Handle broker response: deserialize on success, map errors on failure.
async fn handle_response<T: DeserializeOwned>(resp: reqwest::Response) -> Result<T, CliError> {
    let status = resp.status().as_u16();

    if (200..300).contains(&status) {
        let body = resp
            .text()
            .await
            .map_err(|e| CliError::general(format!("failed to read response: {e}")))?;
        serde_json::from_str(&body)
            .map_err(|e| CliError::general(format!("invalid response JSON: {e}")))
    } else {
        let body = resp.text().await.unwrap_or_default();

        if let Ok(err_resp) = serde_json::from_str::<BrokerErrorResponse>(&body) {
            Err(error::from_broker_error(
                status,
                &err_resp.error.code,
                &err_resp.error.message,
            ))
        } else {
            Err(CliError::general(format!(
                "broker returned HTTP {status}: {body}"
            )))
        }
    }
}

/// The rule for `AGTCRDN_BROKER_URL`: loopback over plain HTTP, or HTTPS to
/// anywhere. Anything else is refused before a request is made, because a
/// plaintext broker on another host would carry signed requests (and the
/// broker's answers) across the network in the clear.
///
/// Returns the URL with a trailing `/` removed.
/// The broker URL a port file names. Older brokers wrote a bare port for a
/// plaintext broker on localhost; newer ones write the URL to dial, which
/// may be `https`. A URL is held to the same loopback-or-https rule as
/// `AGTCRDN_BROKER_URL`.
pub fn broker_url_from_port_file(contents: &str) -> Result<String, CliError> {
    let trimmed = contents.trim();
    if let Ok(port) = trimmed.parse::<u16>() {
        return Ok(format!("http://localhost:{port}"));
    }
    validate_broker_url(trimmed).map_err(|_| CliError::general("invalid broker port file"))
}

pub fn validate_broker_url(raw: &str) -> Result<String, CliError> {
    let trimmed = raw.trim().trim_end_matches('/');
    let parsed = url::Url::parse(trimmed).map_err(|e| {
        CliError::general(format!("{BROKER_URL_ENV}={raw:?} is not a valid URL: {e}"))
    })?;
    match parsed.scheme() {
        "https" if parsed.host().is_some() => Ok(trimmed.to_string()),
        "http" if is_loopback_host(parsed.host()) => Ok(trimmed.to_string()),
        "http" => Err(CliError::general(format!(
            "{BROKER_URL_ENV}={raw:?} is refused: plain http:// is only allowed to a loopback \
             address (localhost, 127.0.0.1, [::1]). Use https:// for a broker on another host."
        ))),
        other => Err(CliError::general(format!(
            "{BROKER_URL_ENV}={raw:?} is refused: scheme {other:?} is not supported; \
             use http:// to loopback or https://"
        ))),
    }
}

fn is_loopback_host(host: Option<url::Host<&str>>) -> bool {
    match host {
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        Some(url::Host::Domain(d)) => {
            let d = d.to_ascii_lowercase();
            d == "localhost" || d.ends_with(".localhost")
        }
        None => false,
    }
}

/// Discover the broker: `AGTCRDN_BROKER_URL` (validated), else the port
/// file. Either way the broker must answer `/health` and publish its key.
async fn discover_broker() -> Result<DiscoveredBroker, CliError> {
    let client = http_client(Duration::from_secs(2))?;

    // 1. Environment override
    if let Ok(url) = std::env::var(BROKER_URL_ENV) {
        let base_url = validate_broker_url(&url)?;
        return health_check(&client, base_url).await;
    }

    // 2. Port file
    let port_path = dirs_or_home()?.join("broker.port");
    let port_str = fs::read_to_string(&port_path).map_err(|_| CliError::broker_not_running())?;
    let base_url = broker_url_from_port_file(&port_str)?;

    health_check(&client, base_url).await
}

/// `GET /health`: the broker must answer `status: ok` and publish its key
/// fingerprint, which the caller pins.
async fn health_check(client: &Client, base_url: String) -> Result<DiscoveredBroker, CliError> {
    let resp = client
        .get(format!("{base_url}/health"))
        .send()
        .await
        .map_err(|e| {
            transport_failure(&base_url, &error_chain(&e), broker_ca_from_env().is_some())
        })?;

    if !resp.status().is_success() {
        return Err(CliError::broker_not_running());
    }

    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|_| CliError::broker_not_running())?;

    health_to_broker(base_url, &body)
}

/// Interpret a `/health` body. Split out so the rule is testable without a
/// socket.
fn health_to_broker(
    base_url: String,
    body: &serde_json::Value,
) -> Result<DiscoveredBroker, CliError> {
    if body.get("status").and_then(|v| v.as_str()) != Some("ok") {
        return Err(CliError::broker_not_running());
    }
    let key_fingerprint = body
        .get("key_fingerprint")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            CliError::general(format!(
                "broker at {base_url} did not publish its key fingerprint on /health; \
                 upgrade agentcordon-broker to a version that does"
            ))
        })?
        .to_string();
    let version = body
        .get("version")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    Ok(DiscoveredBroker {
        base_url,
        key_fingerprint,
        version,
    })
}

/// Get `~/.agentcordon/` path.
///
/// Returns an error if no user home directory can be resolved on the
/// current platform (e.g. `HOME` unset on Unix, `USERPROFILE` unset on
/// Windows). The caller surfaces this to the user rather than silently
/// writing to a nonsense path.
fn dirs_or_home() -> Result<std::path::PathBuf, CliError> {
    agentcordon_dir_from(dirs::home_dir())
}

/// Inner form of `dirs_or_home` taking the resolved home-dir lookup as a
/// parameter so the error path can be exercised under test without
/// relying on the host's `HOME` / passwd-database state.
fn agentcordon_dir_from(home: Option<std::path::PathBuf>) -> Result<std::path::PathBuf, CliError> {
    let home = home.ok_or_else(|| {
        CliError::general(
            "could not resolve user home directory; \
             set HOME (Unix/macOS) or USERPROFILE (Windows)",
        )
    })?;
    Ok(home.join(".agentcordon"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, MutexGuard};
    use tempfile::TempDir;

    /// Serialise env-var mutation across parallel tests. `HOME` /
    /// `USERPROFILE` are process-global, so tests that touch them must
    /// run one at a time. Copy of the `EnvGuard` pattern in
    /// `crates/cli/src/commands/init.rs:413-435`.
    struct EnvGuard {
        _lock: MutexGuard<'static, ()>,
        prior_home: Option<String>,
        prior_userprofile: Option<String>,
    }

    impl EnvGuard {
        fn new() -> Self {
            static LOCK: Mutex<()> = Mutex::new(());
            let lock = LOCK.lock().unwrap_or_else(|e| e.into_inner());
            let prior_home = std::env::var("HOME").ok();
            let prior_userprofile = std::env::var("USERPROFILE").ok();
            Self {
                _lock: lock,
                prior_home,
                prior_userprofile,
            }
        }

        fn set_home(&self, path: &std::path::Path) {
            // SAFETY: tests are serialised via the mutex above.
            unsafe {
                std::env::set_var("HOME", path);
            }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            // SAFETY: tests are serialised via the mutex above.
            unsafe {
                match &self.prior_home {
                    Some(v) => std::env::set_var("HOME", v),
                    None => std::env::remove_var("HOME"),
                }
                match &self.prior_userprofile {
                    Some(v) => std::env::set_var("USERPROFILE", v),
                    None => std::env::remove_var("USERPROFILE"),
                }
            }
        }
    }

    #[test]
    fn resolves_home_when_present() {
        let dir = TempDir::new().unwrap();
        let guard = EnvGuard::new();
        guard.set_home(dir.path());

        let resolved = dirs_or_home().expect("home should resolve");
        assert_eq!(resolved, dir.path().join(".agentcordon"));
    }

    /// Pins the error path of the resolver without depending on whether
    /// the host's `dirs::home_dir()` returns `None` — on Linux the crate
    /// falls back to `getpwuid_r`, so simply clearing `HOME` does not
    /// force `None`. `agentcordon_dir_from` takes the lookup result as
    /// input, letting us exercise the `None` branch directly.
    #[test]
    fn errors_when_no_home() {
        let err = agentcordon_dir_from(None).expect_err("missing home should error");
        assert!(
            err.message.contains("home directory"),
            "unexpected error message: {}",
            err.message
        );
    }

    // -- AGTCRDN_BROKER_URL rule ------------------------------------------

    /// Older brokers wrote a bare port (plaintext, localhost); newer ones
    /// write the URL to dial, which may be https. Both are accepted, and a
    /// URL still has to satisfy the loopback-or-https rule.
    #[test]
    fn port_file_accepts_bare_port_and_url_forms() {
        assert_eq!(
            broker_url_from_port_file("9876\n").unwrap(),
            "http://localhost:9876"
        );
        assert_eq!(
            broker_url_from_port_file("https://127.0.0.1:9876").unwrap(),
            "https://127.0.0.1:9876"
        );
        assert_eq!(
            broker_url_from_port_file("http://127.0.0.1:9876\n").unwrap(),
            "http://127.0.0.1:9876"
        );
        assert!(broker_url_from_port_file("http://10.0.0.5:9876").is_err());
        assert!(broker_url_from_port_file("not a port").is_err());
    }

    #[test]
    fn broker_url_accepts_plain_http_to_loopback() {
        for url in [
            "http://localhost:9876",
            "http://LOCALHOST:9876/",
            "http://broker.localhost:9876",
            "http://127.0.0.1:9876",
            "http://127.0.0.1",
            "http://[::1]:9876",
        ] {
            let ok = validate_broker_url(url).unwrap_or_else(|e| panic!("{url}: {e}"));
            assert!(!ok.ends_with('/'), "{ok}");
        }
    }

    #[test]
    fn broker_url_accepts_https_anywhere() {
        assert_eq!(
            validate_broker_url("https://broker.example.com/").unwrap(),
            "https://broker.example.com"
        );
        assert!(validate_broker_url("https://10.0.0.5:9876").is_ok());
    }

    #[test]
    fn broker_url_refuses_plain_http_off_loopback() {
        for url in [
            "http://broker.example.com",
            "http://10.0.0.5:9876",
            "http://192.168.1.20:9876",
            "http://[fe80::1]:9876",
            "http://0.0.0.0:9876",
            "http://localhost.evil.com",
        ] {
            let err = validate_broker_url(url).expect_err(url);
            assert!(err.message.contains("loopback"), "{url}: {}", err.message);
            assert!(
                err.message.contains("AGTCRDN_BROKER_URL"),
                "{}",
                err.message
            );
        }
    }

    #[test]
    fn broker_url_refuses_other_schemes_and_garbage() {
        for url in [
            "ftp://localhost:21",
            "file:///tmp/broker",
            "localhost:9876",
            "",
        ] {
            assert!(validate_broker_url(url).is_err(), "{url} must be refused");
        }
    }

    // -- AGTCRDN_BROKER_CA -------------------------------------------------

    /// The broker crate's committed test certificate. Test-only material;
    /// see `crates/broker/tests/fixtures/README.md`.
    const FIXTURE_CERT: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../broker/tests/fixtures/localhost.pem"
    );

    #[test]
    fn ca_pem_is_accepted_as_an_extra_root() {
        build_http_client(
            Duration::from_secs(1),
            Some(std::path::Path::new(FIXTURE_CERT)),
        )
        .expect("the fixture certificate is a usable root");
    }

    #[test]
    fn no_ca_still_builds_a_verifying_client() {
        build_http_client(Duration::from_secs(1), None).expect("default roots");
    }

    #[test]
    fn missing_ca_file_names_the_variable() {
        let err = build_http_client(
            Duration::from_secs(1),
            Some(std::path::Path::new("/nonexistent/ca.pem")),
        )
        .expect_err("must refuse");
        assert!(err.message.contains(BROKER_CA_ENV), "{}", err.message);
    }

    #[test]
    fn ca_file_without_a_certificate_names_the_variable() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("ca.pem");
        std::fs::write(&path, "not a certificate\n").unwrap();
        let err = build_http_client(Duration::from_secs(1), Some(&path)).expect_err("must refuse");
        assert!(err.message.contains(BROKER_CA_ENV), "{}", err.message);
    }

    // -- transport failures -------------------------------------------------

    const CERT_DETAIL: &str = "error sending request: invalid peer certificate: UnknownIssuer";

    #[test]
    fn untrusted_https_broker_points_at_the_ca_variable() {
        let err = transport_failure("https://broker.example.com", CERT_DETAIL, false);
        assert!(err.message.contains(BROKER_CA_ENV), "{}", err.message);
        assert!(err.message.contains("does not trust"), "{}", err.message);
    }

    #[test]
    fn wrong_ca_says_the_configured_file_does_not_cover_the_broker() {
        let err = transport_failure("https://broker.example.com", CERT_DETAIL, true);
        assert!(err.message.contains(BROKER_CA_ENV), "{}", err.message);
        assert!(err.message.contains("does not vouch"), "{}", err.message);
    }

    #[test]
    fn a_broker_that_is_not_listening_is_still_broker_not_running() {
        for base in ["https://broker.example.com", "http://localhost:9876"] {
            let err = transport_failure(base, "error sending request: connection refused", false);
            assert_eq!(err.code, crate::error::ExitCode::BrokerNotRunning, "{base}");
        }
    }

    #[test]
    fn certificate_wording_over_plain_http_is_not_a_trust_problem() {
        let err = transport_failure("http://localhost:9876", CERT_DETAIL, false);
        assert_eq!(err.code, crate::error::ExitCode::BrokerNotRunning);
    }

    #[test]
    fn error_chain_keeps_the_innermost_reason() {
        #[derive(Debug)]
        struct Inner;
        impl std::fmt::Display for Inner {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "invalid peer certificate: UnknownIssuer")
            }
        }
        impl std::error::Error for Inner {}

        #[derive(Debug)]
        struct Outer(Inner);
        impl std::fmt::Display for Outer {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "error sending request")
            }
        }
        impl std::error::Error for Outer {
            fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
                Some(&self.0)
            }
        }

        let flattened = error_chain(&Outer(Inner));
        assert_eq!(
            flattened,
            "error sending request: invalid peer certificate: UnknownIssuer"
        );
        assert!(is_certificate_failure(&flattened));
    }

    // -- /health interpretation --------------------------------------------

    #[test]
    fn health_with_fingerprint_is_a_broker() {
        let body = serde_json::json!({ "status": "ok", "key_fingerprint": "ab".repeat(32) });
        let found = health_to_broker("http://127.0.0.1:1".into(), &body).unwrap();
        assert_eq!(found.base_url, "http://127.0.0.1:1");
        assert_eq!(found.key_fingerprint, "ab".repeat(32));
    }

    #[test]
    fn health_without_fingerprint_is_refused_with_upgrade_hint() {
        let body = serde_json::json!({ "status": "ok" });
        let err = health_to_broker("http://127.0.0.1:1".into(), &body).expect_err("no key");
        assert!(
            err.message.contains("did not publish its key"),
            "{}",
            err.message
        );
        assert!(err.message.contains("upgrade"), "{}", err.message);
    }

    #[test]
    fn health_that_is_not_ok_is_not_a_broker() {
        let body = serde_json::json!({ "status": "degraded", "key_fingerprint": "ab".repeat(32) });
        let err = health_to_broker("http://127.0.0.1:1".into(), &body).expect_err("not ok");
        assert_eq!(err.code, crate::error::ExitCode::BrokerNotRunning);
    }
}
