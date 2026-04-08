use std::collections::HashMap;
use std::fs;
use std::time::Duration;

use reqwest::Client;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::error::{self, CliError};
use crate::signing::{self, Keypair, SignedHeaders};

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
        let headers = signing::sign_request(&self.keypair, "GET", path, "")?;
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
        let headers = signing::sign_request(&self.keypair, "POST", path, &body_str)?;
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
        let headers = signing::sign_request(&self.keypair, "POST", path, &body_str)?;
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
        let headers = signing::sign_request(&self.keypair, "POST", path, "")?;
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
        let headers = signing::sign_request(&self.keypair, "GET", path, "")?;
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
    let port_path = dirs_or_home().join("broker.port");
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
fn dirs_or_home() -> std::path::PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    std::path::PathBuf::from(home).join(".agentcordon")
}
