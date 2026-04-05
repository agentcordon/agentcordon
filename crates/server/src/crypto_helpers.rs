//! Shared cryptographic helpers for broker public key parsing and
//! credential re-encryption (AES-GCM decrypt → ECIES encrypt).

use base64::engine::general_purpose::{STANDARD as B64_STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use uuid::Uuid;

use agent_cordon_core::crypto::ecies::{build_aad, CredentialEnvelopeEncryptor, EciesEncryptor};
use agent_cordon_core::crypto::SecretEncryptor;
use agent_cordon_core::domain::credential::StoredCredential;

use crate::response::ApiError;

/// Decode a base64url-encoded uncompressed P-256 point and validate its length.
pub fn parse_broker_public_key(encoded: &str) -> Result<Vec<u8>, ApiError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| ApiError::BadRequest("invalid base64url in broker_public_key".to_string()))?;
    if bytes.len() != 65 || bytes[0] != 0x04 {
        return Err(ApiError::BadRequest(
            "broker_public_key must be a 65-byte uncompressed P-256 point (0x04 || x || y)"
                .to_string(),
        ));
    }
    Ok(bytes)
}

/// ECIES-encrypted credential envelope fields for wire responses.
pub struct ReencryptedEnvelope {
    pub version: u8,
    pub ephemeral_public_key: String,
    pub ciphertext: String,
    pub nonce: String,
    pub aad: String,
}

/// Decrypt a stored credential (AES-GCM) and re-encrypt it for a device
/// using ECIES with the given P-256 public key.
///
/// `vend_id_prefix` controls the generated vend ID format (e.g. `"vnd"` → `"vnd_{uuid}"`).
///
/// Returns the base64-encoded ECIES envelope fields and the generated vend ID.
pub async fn reencrypt_credential_for_device(
    encryptor: &dyn SecretEncryptor,
    cred: &StoredCredential,
    workspace_id_str: &str,
    recipient_pub_bytes: &[u8],
) -> Result<(ReencryptedEnvelope, String), ApiError> {
    reencrypt_credential_for_device_with_prefix(
        encryptor,
        cred,
        workspace_id_str,
        recipient_pub_bytes,
        "sync",
    )
    .await
}

/// Like [`reencrypt_credential_for_device`] but with a custom vend-ID prefix.
pub async fn reencrypt_credential_for_device_with_prefix(
    encryptor: &dyn SecretEncryptor,
    cred: &StoredCredential,
    workspace_id_str: &str,
    recipient_pub_bytes: &[u8],
    vend_id_prefix: &str,
) -> Result<(ReencryptedEnvelope, String), ApiError> {
    // Decrypt credential material (AES-GCM with credential ID as AAD)
    let plaintext = encryptor.decrypt(
        &cred.encrypted_value,
        &cred.nonce,
        cred.id.0.to_string().as_bytes(),
    )?;

    // Wrap in JSON envelope matching CredentialMaterial format
    let plaintext_str = String::from_utf8(plaintext)
        .map_err(|_| ApiError::Internal("credential secret is not valid UTF-8".to_string()))?;
    let credential_material = serde_json::json!({ "value": plaintext_str });
    let material_bytes = serde_json::to_vec(&credential_material)
        .map_err(|e| ApiError::Internal(format!("failed to serialize credential material: {e}")))?;

    // Build AAD: workspace_id||credential_id||vend_id||timestamp
    let vend_id = format!("{}_{}", vend_id_prefix, Uuid::new_v4());
    let timestamp = chrono::Utc::now().timestamp().to_string();
    let aad = build_aad(
        workspace_id_str,
        &cred.id.0.to_string(),
        &vend_id,
        &timestamp,
    );

    // ECIES encrypt to recipient public key
    let ecies = EciesEncryptor::new();
    let envelope = ecies
        .encrypt_for_device(recipient_pub_bytes, &material_bytes, &aad)
        .await
        .map_err(|e| ApiError::Internal(format!("ECIES encryption failed: {e}")))?;

    Ok((
        ReencryptedEnvelope {
            version: envelope.version,
            ephemeral_public_key: B64_STANDARD.encode(&envelope.ephemeral_public_key),
            ciphertext: B64_STANDARD.encode(&envelope.ciphertext),
            nonce: B64_STANDARD.encode(&envelope.nonce),
            aad: B64_STANDARD.encode(&envelope.aad),
        },
        vend_id,
    ))
}
