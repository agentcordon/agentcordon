//! Credential vend + ECIES decrypt — shared between CLI proxy and MCP serve.
//!
//! This module extracts the core credential acquisition flow so that both
//! `cli/proxy.rs` (direct-to-server) and `cli/mcp_serve.rs` can vend and
//! decrypt credentials without duplicating the logic.

use std::collections::HashMap;

use base64::engine::general_purpose::STANDARD as B64_STANDARD;
use base64::Engine;
use serde::Deserialize;

use agent_cordon_core::crypto::ecies::{
    CredentialEnvelopeDecryptor, EciesEncryptor, EncryptedEnvelope,
};

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Decrypted credential material returned after vend + ECIES decrypt.
///
/// This is the same shape as `cp_client::CredentialMaterial` but owned by
/// the vend module to avoid coupling callers to the CP client internals.
#[derive(Debug, Clone, Deserialize)]
pub struct VendedCredential {
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

/// Full vend result including server-provided metadata alongside decrypted material.
#[derive(Debug)]
pub struct VendResult {
    /// The decrypted credential material.
    pub credential: VendedCredential,
    /// The credential type as reported by the server (authoritative).
    pub server_credential_type: String,
    /// Optional transform name from the server (e.g., "bearer", "aws-sigv4").
    pub transform_name: Option<String>,
    /// The vend ID for audit correlation.
    pub vend_id: String,
}

impl VendResult {
    /// Effective credential type: prefers the material's embedded type, falls
    /// back to the server-provided type.
    pub fn effective_credential_type(&self) -> &str {
        self.credential
            .credential_type
            .as_deref()
            .unwrap_or(self.server_credential_type.as_str())
    }
}

/// Errors from credential vend operations.
#[derive(Debug, thiserror::Error)]
pub enum VendError {
    #[error("request failed: {0}")]
    RequestFailed(String),
    #[error("credential not found: {0}")]
    CredentialNotFound(String),
    #[error("access denied by server policy")]
    PolicyDenied,
    #[error("server error ({status}): {body}")]
    ServerError { status: u16, body: String },
    #[error("invalid response: {0}")]
    InvalidResponse(String),
    #[error("decryption failed: {0}")]
    DecryptionFailed(String),
}

// ---------------------------------------------------------------------------
// Internal response types (match the server's API shape)
// ---------------------------------------------------------------------------

/// Wrapper for the control plane's `ApiResponse<T>` envelope.
#[derive(Debug, Deserialize)]
struct ApiEnvelope<T> {
    data: T,
}

/// Server response from `POST /api/v1/credentials/{id}/vend`.
#[derive(Debug, Deserialize)]
struct ServerVendResponse {
    credential_type: String,
    transform_name: Option<String>,
    encrypted_envelope: ServerVendEnvelope,
    vend_id: String,
}

/// ECIES envelope from the server vend response (base64-encoded fields).
#[derive(Debug, Deserialize)]
struct ServerVendEnvelope {
    version: u8,
    ephemeral_public_key: String,
    ciphertext: String,
    nonce: String,
    aad: String,
}

// ---------------------------------------------------------------------------
// Core vend + decrypt
// ---------------------------------------------------------------------------

/// Vend a credential from the server and decrypt using the workspace P-256 key.
///
/// Flow:
/// 1. `POST /api/v1/credentials/{id}/vend` with workspace JWT
/// 2. Receive ECIES-encrypted credential material
/// 3. Decrypt locally using P-256 private key
/// 4. Return `VendResult` with decrypted material + server metadata
pub async fn vend_and_decrypt(
    http: &reqwest::Client,
    server_url: &str,
    jwt: &str,
    encryption_key: &p256::SecretKey,
    credential_id: &str,
) -> Result<VendResult, VendError> {
    let base = server_url.trim_end_matches('/');
    let url = format!("{}/api/v1/credentials/{}/vend", base, credential_id);

    // 1. POST to the server vend endpoint
    let resp = http
        .post(&url)
        .header("Authorization", format!("Bearer {}", jwt))
        .send()
        .await
        .map_err(|e| VendError::RequestFailed(format!("{}", e)))?;

    // 2. Handle error statuses
    let status = resp.status();
    if status == reqwest::StatusCode::NOT_FOUND {
        return Err(VendError::CredentialNotFound(credential_id.to_string()));
    }
    if status == reqwest::StatusCode::FORBIDDEN {
        return Err(VendError::PolicyDenied);
    }
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(VendError::ServerError {
            status: status.as_u16(),
            body,
        });
    }

    // 3. Parse the response envelope
    let envelope: ApiEnvelope<ServerVendResponse> = resp
        .json()
        .await
        .map_err(|e| VendError::InvalidResponse(format!("{}", e)))?;

    let vend_resp = envelope.data;

    // 4. Decrypt the ECIES envelope
    let credential = decrypt_envelope(&vend_resp.encrypted_envelope, encryption_key)?;

    Ok(VendResult {
        credential,
        server_credential_type: vend_resp.credential_type,
        transform_name: vend_resp.transform_name,
        vend_id: vend_resp.vend_id,
    })
}

/// Vend a credential by **name** using the `vend-device/{name}` endpoint, which
/// only checks `vend_credential` permission (not `list`). This avoids the 403
/// that occurs when resolving workspace-scoped credentials via `by-name/{name}`.
pub async fn vend_and_decrypt_by_name(
    http: &reqwest::Client,
    server_url: &str,
    jwt: &str,
    encryption_key: &p256::SecretKey,
    credential_name: &str,
) -> Result<VendResult, VendError> {
    let base = server_url.trim_end_matches('/');
    let url = format!(
        "{}/api/v1/credentials/vend-device/{}",
        base, credential_name
    );

    let resp = http
        .post(&url)
        .header("Authorization", format!("Bearer {}", jwt))
        .send()
        .await
        .map_err(|e| VendError::RequestFailed(format!("{}", e)))?;

    let status = resp.status();
    if status == reqwest::StatusCode::NOT_FOUND {
        return Err(VendError::CredentialNotFound(credential_name.to_string()));
    }
    if status == reqwest::StatusCode::FORBIDDEN {
        return Err(VendError::PolicyDenied);
    }
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(VendError::ServerError {
            status: status.as_u16(),
            body,
        });
    }

    let envelope: ApiEnvelope<ServerVendResponse> = resp
        .json()
        .await
        .map_err(|e| VendError::InvalidResponse(format!("{}", e)))?;

    let vend_resp = envelope.data;
    let credential = decrypt_envelope(&vend_resp.encrypted_envelope, encryption_key)?;

    Ok(VendResult {
        credential,
        server_credential_type: vend_resp.credential_type,
        transform_name: vend_resp.transform_name,
        vend_id: vend_resp.vend_id,
    })
}

/// Decode base64 fields from a vend envelope and decrypt using the workspace's
/// ECIES P-256 key. Runs synchronously (the ECIES decrypt is CPU-bound but fast).
fn decrypt_envelope(
    envelope: &ServerVendEnvelope,
    encryption_key: &p256::SecretKey,
) -> Result<VendedCredential, VendError> {
    let encrypted = EncryptedEnvelope {
        version: envelope.version,
        ephemeral_public_key: B64_STANDARD
            .decode(&envelope.ephemeral_public_key)
            .map_err(|e| VendError::DecryptionFailed(format!("invalid ephemeral key: {}", e)))?,
        ciphertext: B64_STANDARD
            .decode(&envelope.ciphertext)
            .map_err(|e| VendError::DecryptionFailed(format!("invalid ciphertext: {}", e)))?,
        nonce: B64_STANDARD
            .decode(&envelope.nonce)
            .map_err(|e| VendError::DecryptionFailed(format!("invalid nonce: {}", e)))?,
        aad: B64_STANDARD
            .decode(&envelope.aad)
            .map_err(|e| VendError::DecryptionFailed(format!("invalid aad: {}", e)))?,
    };

    let enc_key_bytes = encryption_key.to_bytes();
    let ecies = EciesEncryptor::new();

    // EciesEncryptor::decrypt_envelope is async but does no I/O — it's pure crypto.
    // We use block_in_place since this runs inside a tokio context.
    let plaintext = tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current()
            .block_on(ecies.decrypt_envelope(enc_key_bytes.as_ref(), &encrypted))
    })
    .map_err(|_| VendError::DecryptionFailed("ECIES decryption failed".to_string()))?;

    serde_json::from_slice(&plaintext)
        .map_err(|e| VendError::DecryptionFailed(format!("invalid credential material: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vend_result_effective_type_prefers_material() {
        let result = VendResult {
            credential: VendedCredential {
                credential_type: Some("bearer".to_string()),
                value: "tok".to_string(),
                username: None,
                metadata: HashMap::new(),
            },
            server_credential_type: "generic".to_string(),
            transform_name: None,
            vend_id: "v1".to_string(),
        };
        assert_eq!(result.effective_credential_type(), "bearer");
    }

    #[test]
    fn vend_result_effective_type_falls_back_to_server() {
        let result = VendResult {
            credential: VendedCredential {
                credential_type: None,
                value: "tok".to_string(),
                username: None,
                metadata: HashMap::new(),
            },
            server_credential_type: "api_key_header".to_string(),
            transform_name: None,
            vend_id: "v2".to_string(),
        };
        assert_eq!(result.effective_credential_type(), "api_key_header");
    }
}
