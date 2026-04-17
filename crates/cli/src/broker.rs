use std::collections::HashMap;
use std::fs;
use std::time::Duration;

use reqwest::Client;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::error::{self, CliError};
use crate::signing::{self, Keypair, SignedHeaders};

/// Split a caller-supplied path-with-query like `"/foo?a=1"` into its
/// components and run them through `canonicalise_path_and_query`, so
/// `sign_request` always receives the canonical signed form. The outbound
/// HTTP URL is still built from the raw `path`; only the signed payload is
/// normalised. The broker verifier applies the identical canonicalisation
/// against `Uri::path()` / `Uri::query()`.
fn canonical_sign_path(raw: &str) -> String {
    let (path, query) = match raw.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (raw, None),
    };
    signing::canonicalise_path_and_query(path, query)
}

/// Broker HTTP client with Ed25519 request signing.
pub struct BrokerClient {
    base_url: String,
    http: Client,
    keypair: Keypair,
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
    /// Create a new broker client: discover broker, load keypair, verify health.
    pub async fn connect() -> Result<Self, CliError> {
        let keypair = signing::load_keypair()?;
        let base_url = discover_broker().await?;
        let http = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| CliError::general(format!("failed to create HTTP client: {e}")))?;

        Ok(Self {
            base_url,
            http,
            keypair,
        })
    }

    /// Create a broker client for registration (keypair loaded, but no auth check).
    pub async fn connect_for_registration() -> Result<Self, CliError> {
        let keypair = signing::load_keypair()?;
        let base_url = discover_broker().await?;
        let http = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| CliError::general(format!("failed to create HTTP client: {e}")))?;

        Ok(Self {
            base_url,
            http,
            keypair,
        })
    }

    /// Access the keypair for computing identity, etc.
    pub fn keypair(&self) -> &Keypair {
        &self.keypair
    }

    /// The discovered broker base URL.
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Send a signed GET request.
    pub async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T, CliError> {
        let sign_path = canonical_sign_path(path);
        let headers = signing::sign_request(&self.keypair, "GET", &sign_path, "")?;
        let url = format!("{}{}", self.base_url, path);

        let resp = self
            .http
            .get(&url)
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
        let url = format!("{}{}", self.base_url, path);

        let resp = self
            .http
            .post(&url)
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
        let url = format!("{}{}", self.base_url, path);

        let resp = self
            .http
            .post(&url)
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
        let url = format!("{}{}", self.base_url, path);

        let resp = self
            .http
            .post(&url)
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

    /// Send an unsigned POST request (for registration).
    pub async fn post_unsigned<B: Serialize, T: DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T, CliError> {
        let url = format!("{}{}", self.base_url, path);
        let resp = self
            .http
            .post(&url)
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
        let url = format!("{}{}", self.base_url, path);

        let resp = self
            .http
            .get(&url)
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

/// Discover the broker URL per spec Section 2.
async fn discover_broker() -> Result<String, CliError> {
    // 1. Environment override
    if let Ok(url) = std::env::var("AGTCRDN_BROKER_URL") {
        return Ok(url.trim_end_matches('/').to_string());
    }

    // 2. Port file
    let port_path = dirs_or_home()?.join("broker.port");
    let port_str = fs::read_to_string(&port_path).map_err(|_| CliError::broker_not_running())?;
    let port: u16 = port_str
        .trim()
        .parse()
        .map_err(|_| CliError::general("invalid broker port file"))?;

    let base_url = format!("http://localhost:{port}");

    // 3. Health check
    let client = Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .map_err(|e| CliError::general(format!("failed to create HTTP client: {e}")))?;

    let health_url = format!("{base_url}/health");
    let resp = client
        .get(&health_url)
        .send()
        .await
        .map_err(|_| CliError::broker_not_running())?;

    if !resp.status().is_success() {
        return Err(CliError::broker_not_running());
    }

    // Verify it's actually our broker
    let body: HashMap<String, serde_json::Value> = resp
        .json()
        .await
        .map_err(|_| CliError::broker_not_running())?;

    if body.get("status").and_then(|v| v.as_str()) != Some("ok") {
        return Err(CliError::broker_not_running());
    }

    Ok(base_url)
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
}
