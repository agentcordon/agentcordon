//! ECIES (Elliptic Curve Integrated Encryption Scheme) for encrypting
//! credential material to a device's P-256 public key.
//!
//! Construction: ECIES-P256-HKDF-SHA256-AES256GCM
//!
//! 1. Generate ephemeral P-256 key pair (e_priv, e_pub)
//! 2. ECDH: shared_secret = ECDH(e_priv, device_encryption_pub)
//! 3. KDF: key_material = HKDF-SHA256(ikm: shared_secret, salt: empty, info: "agentcordon:ecies-credential-v1")
//! 4. enc_key = key_material[0..32]
//! 5. Encrypt: AES-256-GCM(key=enc_key, nonce=random_12_bytes, plaintext=credential, aad=device_id||credential_id||vend_id||timestamp)
//! 6. Output: EncryptedEnvelope { version: 0x01, ephemeral_public_key, ciphertext, nonce, aad }
//! 7. Zeroize ephemeral private key immediately

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use async_trait::async_trait;
use hkdf::Hkdf;
use p256::ecdh::EphemeralSecret;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::{PublicKey, SecretKey};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::error::CryptoError;

/// HKDF info label for ECIES credential encryption.
/// This label MUST be unique across all HKDF uses in the codebase.
pub const ECIES_HKDF_INFO: &[u8] = b"agentcordon:ecies-credential-v1";

/// Current envelope format version: P-256 ECIES.
const ENVELOPE_VERSION: u8 = 0x01;

/// Encrypted credential envelope. Sent from CP to Device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedEnvelope {
    /// Envelope format version (0x01 = P-256 ECIES)
    pub version: u8,
    /// Ephemeral P-256 public key (uncompressed, 65 bytes)
    pub ephemeral_public_key: Vec<u8>,
    /// AES-256-GCM ciphertext
    pub ciphertext: Vec<u8>,
    /// AES-256-GCM nonce (12 bytes)
    pub nonce: Vec<u8>,
    /// AAD used during encryption
    pub aad: Vec<u8>,
}

/// Trait for encrypting credential material to a device's public key.
#[async_trait]
pub trait CredentialEnvelopeEncryptor: Send + Sync {
    async fn encrypt_for_device(
        &self,
        device_encryption_public_key: &[u8], // uncompressed P-256 point, 65 bytes
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<EncryptedEnvelope, CryptoError>;
}

/// Trait for decrypting credential material on the device side.
#[async_trait]
pub trait CredentialEnvelopeDecryptor: Send + Sync {
    async fn decrypt_envelope(
        &self,
        device_encryption_private_key: &[u8], // P-256 scalar, 32 bytes
        envelope: &EncryptedEnvelope,
    ) -> Result<Vec<u8>, CryptoError>;
}

/// Build AAD bytes from the constituent fields.
///
/// Format: `device_id||credential_id||vend_id||timestamp`
pub fn build_aad(device_id: &str, credential_id: &str, vend_id: &str, timestamp: &str) -> Vec<u8> {
    format!(
        "{}||{}||{}||{}",
        device_id, credential_id, vend_id, timestamp
    )
    .into_bytes()
}

/// ECIES encryptor implementing both encrypt and decrypt traits.
///
/// Uses ECIES-P256-HKDF-SHA256-AES256GCM construction.
pub struct EciesEncryptor;

impl EciesEncryptor {
    /// Create a new ECIES encryptor.
    pub fn new() -> Self {
        Self
    }
}

impl Default for EciesEncryptor {
    fn default() -> Self {
        Self::new()
    }
}

/// Parse a P-256 public key from uncompressed SEC1 bytes (65 bytes, starting with 0x04).
fn parse_public_key(bytes: &[u8]) -> Result<PublicKey, CryptoError> {
    PublicKey::from_sec1_bytes(bytes).map_err(|_| {
        CryptoError::Encryption(format!(
            "invalid P-256 public key (expected 65-byte uncompressed point, got {} bytes)",
            bytes.len()
        ))
    })
}

/// Parse a P-256 secret key from a 32-byte scalar.
fn parse_secret_key(bytes: &[u8]) -> Result<SecretKey, CryptoError> {
    if bytes.len() != 32 {
        return Err(CryptoError::Decryption(format!(
            "invalid P-256 private key length (expected 32 bytes, got {})",
            bytes.len()
        )));
    }
    let arr: [u8; 32] = bytes.try_into().expect("length already checked");
    let field_bytes = p256::FieldBytes::from(arr);
    SecretKey::from_bytes(&field_bytes)
        .map_err(|_| CryptoError::Decryption("invalid P-256 private key scalar".to_string()))
}

/// Perform ECDH key agreement using the p256 ecdh module.
///
/// Returns the raw shared secret bytes (32 bytes) wrapped in Zeroizing.
fn ecdh_shared_secret(secret_key: &SecretKey, public_key: &PublicKey) -> Zeroizing<[u8; 32]> {
    let shared = p256::ecdh::diffie_hellman(secret_key.to_nonzero_scalar(), public_key.as_affine());
    let mut secret = Zeroizing::new([0u8; 32]);
    secret.copy_from_slice(shared.raw_secret_bytes().as_ref());
    secret
}

/// Derive a 256-bit AES key from the ECDH shared secret using HKDF-SHA256.
fn derive_encryption_key(shared_secret: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    let hk = Hkdf::<Sha256>::new(None, shared_secret);
    let mut okm = Zeroizing::new([0u8; 32]);
    hk.expand(ECIES_HKDF_INFO, okm.as_mut())
        .map_err(|e| CryptoError::KeyDerivation(e.to_string()))?;
    Ok(okm)
}

#[async_trait]
impl CredentialEnvelopeEncryptor for EciesEncryptor {
    async fn encrypt_for_device(
        &self,
        device_encryption_public_key: &[u8],
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<EncryptedEnvelope, CryptoError> {
        // 1. Parse the device's encryption public key
        let device_pub = parse_public_key(device_encryption_public_key)?;

        // 2. Generate ephemeral P-256 key pair (EphemeralSecret is consumed by diffie_hellman)
        let ephemeral = EphemeralSecret::random(&mut rand::rngs::OsRng);

        // Get ephemeral public key as uncompressed SEC1 bytes (65 bytes)
        let ephemeral_pub_bytes = ephemeral
            .public_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();

        // 3. ECDH: compute shared secret (consumes ephemeral, auto-zeroizing on drop)
        let shared = ephemeral.diffie_hellman(&device_pub);
        let mut shared_secret = Zeroizing::new([0u8; 32]);
        shared_secret.copy_from_slice(shared.raw_secret_bytes().as_ref());

        // 4. KDF: derive AES-256-GCM key from shared secret
        let enc_key = derive_encryption_key(&shared_secret)?;

        // 5. Encrypt: AES-256-GCM
        let cipher = Aes256Gcm::new_from_slice(enc_key.as_ref())
            .map_err(|e| CryptoError::Encryption(e.to_string()))?;

        let mut nonce_bytes = [0u8; 12];
        rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from(nonce_bytes);

        let payload = Payload {
            msg: plaintext,
            aad,
        };
        let ciphertext = cipher
            .encrypt(&nonce, payload)
            .map_err(|e| CryptoError::Encryption(e.to_string()))?;

        // 6. Output envelope
        Ok(EncryptedEnvelope {
            version: ENVELOPE_VERSION,
            ephemeral_public_key: ephemeral_pub_bytes,
            ciphertext,
            nonce: nonce_bytes.to_vec(),
            aad: aad.to_vec(),
        })
    }
}

#[async_trait]
impl CredentialEnvelopeDecryptor for EciesEncryptor {
    async fn decrypt_envelope(
        &self,
        device_encryption_private_key: &[u8],
        envelope: &EncryptedEnvelope,
    ) -> Result<Vec<u8>, CryptoError> {
        // Validate envelope version
        if envelope.version != ENVELOPE_VERSION {
            return Err(CryptoError::Decryption(format!(
                "unsupported envelope version: 0x{:02x} (expected 0x{:02x})",
                envelope.version, ENVELOPE_VERSION
            )));
        }

        // Validate nonce length
        if envelope.nonce.len() != 12 {
            return Err(CryptoError::Decryption(format!(
                "invalid nonce length: expected 12, got {}",
                envelope.nonce.len()
            )));
        }

        // 1. Parse the device's private key
        let device_secret = parse_secret_key(device_encryption_private_key)?;

        // 2. Parse the ephemeral public key from the envelope
        let ephemeral_pub = parse_public_key(&envelope.ephemeral_public_key).map_err(|_| {
            CryptoError::Decryption("invalid ephemeral public key in envelope".to_string())
        })?;

        // 3. ECDH: compute shared secret
        let shared_secret = ecdh_shared_secret(&device_secret, &ephemeral_pub);

        // 4. KDF: derive AES-256-GCM key
        let enc_key = derive_encryption_key(&shared_secret)?;

        // 5. Decrypt: AES-256-GCM
        let cipher = Aes256Gcm::new_from_slice(enc_key.as_ref())
            .map_err(|e| CryptoError::Decryption(e.to_string()))?;

        let nonce_arr: [u8; 12] = envelope.nonce[..12]
            .try_into()
            .map_err(|_| CryptoError::Decryption("invalid nonce".to_string()))?;
        let nonce = Nonce::from(nonce_arr);
        let payload = Payload {
            msg: &envelope.ciphertext,
            aad: &envelope.aad,
        };

        cipher
            .decrypt(&nonce, payload)
            .map_err(|e| CryptoError::Decryption(e.to_string()))
    }
}

#[cfg(test)]
mod tests;
