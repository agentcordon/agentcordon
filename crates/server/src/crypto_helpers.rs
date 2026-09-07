//! Shared cryptographic helpers for broker public key parsing and
//! credential re-encryption (AES-GCM decrypt → ECIES encrypt).

use base64::engine::general_purpose::{STANDARD as B64_STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use serde_json::Value as JsonValue;
use uuid::Uuid;

use agent_cordon_core::crypto::ecies::{build_aad, CredentialEnvelopeEncryptor, EciesEncryptor};
use agent_cordon_core::crypto::key_ring::KeyRing;
use agent_cordon_core::domain::credential::{CredentialId, StoredCredential};
use agent_cordon_core::domain::workspace::Workspace;

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

/// The workspace's registered encryption key (a P-256 JWK) as an
/// uncompressed SEC1 point (65 bytes: 0x04 || x || y). A workspace without
/// one is a 422: the caller must supply `broker_public_key` instead.
pub fn workspace_encryption_point(workspace: &Workspace) -> Result<Vec<u8>, ApiError> {
    let encryption_key_str = workspace
        .encryption_public_key
        .as_ref()
        .ok_or_else(|| ApiError::UnprocessableEntity(
            "workspace encryption key not configured \u{2014} provide broker_public_key in the request body or register with an encryption key".to_string(),
        ))?;
    let jwk: serde_json::Value = serde_json::from_str(encryption_key_str)
        .map_err(|_| ApiError::Internal("invalid encryption public key JWK".to_string()))?;
    jwk_to_uncompressed_point(&jwk)
}

/// Convert a P-256 JWK to uncompressed SEC1 bytes (65 bytes: 0x04 || x || y).
fn jwk_to_uncompressed_point(jwk: &serde_json::Value) -> Result<Vec<u8>, ApiError> {
    let x = jwk
        .get("x")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ApiError::Internal("encryption key missing 'x' coordinate".to_string()))?;
    let y = jwk
        .get("y")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ApiError::Internal("encryption key missing 'y' coordinate".to_string()))?;

    let x_bytes = URL_SAFE_NO_PAD
        .decode(x)
        .map_err(|_| ApiError::Internal("invalid x coordinate encoding".to_string()))?;
    let y_bytes = URL_SAFE_NO_PAD
        .decode(y)
        .map_err(|_| ApiError::Internal("invalid y coordinate encoding".to_string()))?;

    let mut point = Vec::with_capacity(65);
    point.push(0x04);
    point.extend_from_slice(&x_bytes);
    point.extend_from_slice(&y_bytes);

    Ok(point)
}

/// ECIES-encrypted credential envelope fields for wire responses.
pub struct ReencryptedEnvelope {
    pub version: u8,
    pub ephemeral_public_key: String,
    pub ciphertext: String,
    pub nonce: String,
    pub aad: String,
}

/// ECIES-encrypt credential `material` (the JSON a broker will read as
/// `VendedCredential`: `{"value": ..., ...}`) to a device's P-256 public
/// key, bound by AAD to the workspace, the credential, and a fresh vend id.
///
/// `vend_id_prefix` controls the generated vend ID format (e.g. `"vnd"` →
/// `"vnd_{uuid}"`). Returns the base64-encoded envelope and the vend id.
pub async fn encrypt_material_for_device(
    credential_id: &CredentialId,
    workspace_id_str: &str,
    recipient_pub_bytes: &[u8],
    material: &serde_json::Value,
    vend_id_prefix: &str,
) -> Result<(ReencryptedEnvelope, String), ApiError> {
    let material_bytes = serde_json::to_vec(material)
        .map_err(|e| ApiError::Internal(format!("failed to serialize credential material: {e}")))?;

    // Build AAD: workspace_id||credential_id||vend_id||timestamp
    let vend_id = format!("{}_{}", vend_id_prefix, Uuid::new_v4());
    let timestamp = chrono::Utc::now().timestamp().to_string();
    let aad = build_aad(
        workspace_id_str,
        &credential_id.0.to_string(),
        &vend_id,
        &timestamp,
    );

    let envelope = EciesEncryptor::new()
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

/// The credential metadata a broker may hold: the string-valued entries only.
///
/// The broker reads this as a `HashMap<String, String>` and an injection
/// reads a name out of it (`header_name` for `api_key_header`, `param_name`
/// for `api_key_query`). Non-string values are dropped rather than sent,
/// because one of them would fail the broker's deserialization and take the
/// whole envelope — secret included — with it.
fn broker_visible_metadata(metadata: &serde_json::Value) -> serde_json::Map<String, JsonValue> {
    match metadata.as_object() {
        Some(map) => map
            .iter()
            .filter(|(_, v)| v.is_string())
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
        None => serde_json::Map::new(),
    }
}

/// Open a stored credential with the key ring (by its `key_version`) and
/// re-encrypt the value for a device using ECIES with the given P-256
/// public key. `vend_id_prefix` names the caller in the vend id.
///
/// The sealed material carries the credential's metadata next to its value:
/// a custom-header or query-parameter API key is useless to the broker
/// without the name to inject it under.
pub async fn reencrypt_credential_for_device(
    key_ring: &KeyRing,
    cred: &StoredCredential,
    workspace_id_str: &str,
    recipient_pub_bytes: &[u8],
    vend_id_prefix: &str,
) -> Result<(ReencryptedEnvelope, String), ApiError> {
    let plaintext = key_ring.decrypt_versioned(
        &cred.encrypted_value,
        &cred.nonce,
        cred.id.0.to_string().as_bytes(),
        cred.key_version,
    )?;
    let plaintext_str = String::from_utf8(plaintext)
        .map_err(|_| ApiError::Internal("credential secret is not valid UTF-8".to_string()))?;

    encrypt_material_for_device(
        &cred.id,
        workspace_id_str,
        recipient_pub_bytes,
        &serde_json::json!({
            "value": plaintext_str,
            "metadata": broker_visible_metadata(&cred.metadata),
        }),
        vend_id_prefix,
    )
    .await
}
