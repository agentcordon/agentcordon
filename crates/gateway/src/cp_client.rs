//! Shared control plane HTTP client for device-to-server communication.
//!
//! Uses the workspace identity JWT for authentication instead of a device
//! self-signed JWT. The workspace JWT is obtained via challenge-response
//! and cached by the device.

use std::collections::HashMap;

use base64::engine::general_purpose::STANDARD as B64_STANDARD;
use base64::Engine;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use agent_cordon_core::crypto::ecies::{
    CredentialEnvelopeDecryptor, EciesEncryptor, EncryptedEnvelope,
};

// ---------------------------------------------------------------------------
// Shared response types (previously duplicated across proxy, mcp_sync, permissions)
// ---------------------------------------------------------------------------

/// Generic wrapper for the control plane's `ApiResponse<T>` envelope.
#[derive(Debug, Deserialize)]
pub struct CpApiResponse<T> {
    pub data: T,
}

/// ECIES envelope from the CP vend response (base64-encoded fields).
#[derive(Debug, Deserialize)]
pub struct CpVendEnvelope {
    pub version: u8,
    pub ephemeral_public_key: String,
    pub ciphertext: String,
    pub nonce: String,
    pub aad: String,
}

/// Decrypted credential material — superset of all fields needed by proxy and mcp_sync.
#[derive(Debug, Deserialize)]
pub struct CredentialMaterial {
    /// Credential type (e.g., "bearer", "basic", "api_key_header", "api_key_query").
    #[serde(rename = "type")]
    pub credential_type: Option<String>,
    /// The raw credential value.
    pub value: String,
    /// Optional username (for basic auth).
    pub username: Option<String>,
    /// Optional metadata (e.g., header_name, param_name).
    #[serde(default)]
    pub metadata: HashMap<String, String>,
}

// ---------------------------------------------------------------------------
// CpClient — authenticated HTTP client for control plane calls
// ---------------------------------------------------------------------------

/// Authenticated HTTP client for workspace → control plane requests.
///
/// Uses the workspace identity JWT for all requests instead of a device
/// self-signed JWT.
pub struct CpClient<'a> {
    http: &'a reqwest::Client,
    base_url: &'a str,
    /// The workspace identity JWT to use for authentication.
    workspace_jwt: &'a str,
}

impl<'a> CpClient<'a> {
    pub fn new(http: &'a reqwest::Client, base_url: &'a str, workspace_jwt: &'a str) -> Self {
        Self {
            http,
            base_url: base_url.trim_end_matches('/'),
            workspace_jwt,
        }
    }

    /// GET `{base_url}{path}` and parse `CpApiResponse<T>`.
    pub async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T, CpClientError> {
        let url = format!("{}{}", self.base_url, path);
        let resp = self
            .http
            .get(&url)
            .header("Authorization", format!("Bearer {}", self.workspace_jwt))
            .send()
            .await
            .map_err(|e| CpClientError::RequestFailed(format!("request failed: {}", e)))?;

        self.parse_response(resp).await
    }

    /// GET with an extra header.
    pub async fn get_with_header<T: DeserializeOwned>(
        &self,
        path: &str,
        header_name: &str,
        header_value: &str,
    ) -> Result<T, CpClientError> {
        let url = format!("{}{}", self.base_url, path);
        let resp = self
            .http
            .get(&url)
            .header("Authorization", format!("Bearer {}", self.workspace_jwt))
            .header(header_name, header_value)
            .send()
            .await
            .map_err(|e| CpClientError::RequestFailed(format!("request failed: {}", e)))?;

        self.parse_response(resp).await
    }

    /// POST `{base_url}{path}` with a JSON body and parse `CpApiResponse<T>`.
    pub async fn post<T: DeserializeOwned, B: Serialize>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T, CpClientError> {
        let url = format!("{}{}", self.base_url, path);
        let resp = self
            .http
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.workspace_jwt))
            .json(body)
            .send()
            .await
            .map_err(|e| CpClientError::RequestFailed(format!("request failed: {}", e)))?;

        self.parse_response(resp).await
    }

    /// POST with an extra header.
    pub async fn post_with_header<T: DeserializeOwned, B: Serialize>(
        &self,
        path: &str,
        body: &B,
        header_name: &str,
        header_value: &str,
    ) -> Result<T, CpClientError> {
        let url = format!("{}{}", self.base_url, path);
        let resp = self
            .http
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.workspace_jwt))
            .header(header_name, header_value)
            .json(body)
            .send()
            .await
            .map_err(|e| CpClientError::RequestFailed(format!("request failed: {}", e)))?;

        self.parse_response(resp).await
    }

    /// POST with no body (empty POST).
    pub async fn post_empty<T: DeserializeOwned>(&self, path: &str) -> Result<T, CpClientError> {
        let url = format!("{}{}", self.base_url, path);
        let resp = self
            .http
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.workspace_jwt))
            .send()
            .await
            .map_err(|e| CpClientError::RequestFailed(format!("request failed: {}", e)))?;

        self.parse_response(resp).await
    }

    /// POST with no body but with an extra header.
    pub async fn post_empty_with_header<T: DeserializeOwned>(
        &self,
        path: &str,
        header_name: &str,
        header_value: &str,
    ) -> Result<T, CpClientError> {
        let url = format!("{}{}", self.base_url, path);
        let resp = self
            .http
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.workspace_jwt))
            .header(header_name, header_value)
            .send()
            .await
            .map_err(|e| CpClientError::RequestFailed(format!("request failed: {}", e)))?;

        self.parse_response(resp).await
    }

    /// Send a raw GET request and return the raw response (for call sites needing
    /// custom status code handling, e.g., 404/403 branching).
    pub async fn raw_get(&self, path: &str) -> Result<reqwest::Response, CpClientError> {
        let url = format!("{}{}", self.base_url, path);
        self.http
            .get(&url)
            .header("Authorization", format!("Bearer {}", self.workspace_jwt))
            .send()
            .await
            .map_err(|e| CpClientError::RequestFailed(format!("request failed: {}", e)))
    }

    /// Send a raw GET with an extra header.
    pub async fn raw_get_with_header(
        &self,
        path: &str,
        header_name: &str,
        header_value: &str,
    ) -> Result<reqwest::Response, CpClientError> {
        let url = format!("{}{}", self.base_url, path);
        self.http
            .get(&url)
            .header("Authorization", format!("Bearer {}", self.workspace_jwt))
            .header(header_name, header_value)
            .send()
            .await
            .map_err(|e| CpClientError::RequestFailed(format!("request failed: {}", e)))
    }

    /// Send a raw POST with no body and return the raw response.
    pub async fn raw_post_empty(&self, path: &str) -> Result<reqwest::Response, CpClientError> {
        let url = format!("{}{}", self.base_url, path);
        self.http
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.workspace_jwt))
            .send()
            .await
            .map_err(|e| CpClientError::RequestFailed(format!("request failed: {}", e)))
    }

    /// Send a raw POST with no body and an extra header.
    pub async fn raw_post_empty_with_header(
        &self,
        path: &str,
        header_name: &str,
        header_value: &str,
    ) -> Result<reqwest::Response, CpClientError> {
        let url = format!("{}{}", self.base_url, path);
        self.http
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.workspace_jwt))
            .header(header_name, header_value)
            .send()
            .await
            .map_err(|e| CpClientError::RequestFailed(format!("request failed: {}", e)))
    }

    /// Send a raw POST with JSON body and return the raw response.
    pub async fn raw_post<B: Serialize>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<reqwest::Response, CpClientError> {
        let url = format!("{}{}", self.base_url, path);
        self.http
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.workspace_jwt))
            .json(body)
            .send()
            .await
            .map_err(|e| CpClientError::RequestFailed(format!("request failed: {}", e)))
    }

    /// Send a raw POST with JSON body and an extra header.
    pub async fn raw_post_with_header<B: Serialize>(
        &self,
        path: &str,
        body: &B,
        header_name: &str,
        header_value: &str,
    ) -> Result<reqwest::Response, CpClientError> {
        let url = format!("{}{}", self.base_url, path);
        self.http
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.workspace_jwt))
            .header(header_name, header_value)
            .json(body)
            .send()
            .await
            .map_err(|e| CpClientError::RequestFailed(format!("request failed: {}", e)))
    }

    /// Parse a response into `CpApiResponse<T>` with standard error handling.
    async fn parse_response<T: DeserializeOwned>(
        &self,
        resp: reqwest::Response,
    ) -> Result<T, CpClientError> {
        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(CpClientError::ServerError {
                status: status.as_u16(),
                body: text,
            });
        }

        let envelope: CpApiResponse<T> = resp
            .json()
            .await
            .map_err(|e| CpClientError::InvalidResponse(format!("invalid response: {}", e)))?;

        Ok(envelope.data)
    }
}

// ---------------------------------------------------------------------------
// ECIES decrypt helper
// ---------------------------------------------------------------------------

/// Decode base64 fields from a `CpVendEnvelope` and decrypt using the workspace's
/// ECIES encryption key.
pub async fn decrypt_vend_envelope(
    envelope: &CpVendEnvelope,
    encryption_key: &p256::SecretKey,
) -> Result<CredentialMaterial, CpClientError> {
    let encrypted = EncryptedEnvelope {
        version: envelope.version,
        ephemeral_public_key: B64_STANDARD
            .decode(&envelope.ephemeral_public_key)
            .map_err(|e| {
                CpClientError::DecryptionFailed(format!("invalid ephemeral key encoding: {}", e))
            })?,
        ciphertext: B64_STANDARD.decode(&envelope.ciphertext).map_err(|e| {
            CpClientError::DecryptionFailed(format!("invalid ciphertext encoding: {}", e))
        })?,
        nonce: B64_STANDARD.decode(&envelope.nonce).map_err(|e| {
            CpClientError::DecryptionFailed(format!("invalid nonce encoding: {}", e))
        })?,
        aad: B64_STANDARD
            .decode(&envelope.aad)
            .map_err(|e| CpClientError::DecryptionFailed(format!("invalid aad encoding: {}", e)))?,
    };

    let enc_key_bytes = encryption_key.to_bytes();
    let ecies = EciesEncryptor::new();
    let plaintext = ecies
        .decrypt_envelope(enc_key_bytes.as_ref(), &encrypted)
        .await
        .map_err(|_| CpClientError::DecryptionFailed("ECIES decryption failed".to_string()))?;

    let material: CredentialMaterial = serde_json::from_slice(&plaintext).map_err(|e| {
        CpClientError::DecryptionFailed(format!("invalid credential material: {}", e))
    })?;

    Ok(material)
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors from CpClient operations.
#[derive(Debug, thiserror::Error)]
pub enum CpClientError {
    #[error("request failed: {0}")]
    RequestFailed(String),
    #[error("server returned {status}: {body}")]
    ServerError { status: u16, body: String },
    #[error("invalid response: {0}")]
    InvalidResponse(String),
    #[error("decryption failed: {0}")]
    DecryptionFailed(String),
}
