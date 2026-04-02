//! Credential vend + ECIES decrypt — broker-side implementation.
//!
//! Carried forward from `gateway/src/vend.rs`, adapted to use the broker's
//! server client and P-256 keypair.

use std::collections::HashMap;

use base64::engine::general_purpose::STANDARD as B64_STANDARD;
use base64::Engine;
use serde::Deserialize;

use agent_cordon_core::crypto::ecies::{
    CredentialEnvelopeDecryptor, EciesEncryptor, EncryptedEnvelope,
};

use crate::server_client::VendEnvelope;

/// Decrypted credential material.
#[derive(Debug, Clone, Deserialize)]
pub struct VendedCredential {
    #[serde(rename = "type")]
    pub credential_type: Option<String>,
    pub value: String,
    pub username: Option<String>,
    #[serde(default)]
    pub metadata: HashMap<String, String>,
}

/// Errors from vend operations.
#[derive(Debug, thiserror::Error)]
pub enum VendError {
    #[error("decryption failed: {0}")]
    DecryptionFailed(String),
}

/// Decrypt a vend envelope using the broker's P-256 private key.
pub fn decrypt_vend_envelope(
    envelope: &VendEnvelope,
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

    let plaintext = tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current()
            .block_on(ecies.decrypt_envelope(enc_key_bytes.as_ref(), &encrypted))
    })
    .map_err(|_| VendError::DecryptionFailed("ECIES decryption failed".to_string()))?;

    serde_json::from_slice(&plaintext)
        .map_err(|e| VendError::DecryptionFailed(format!("invalid credential material: {}", e)))
}
