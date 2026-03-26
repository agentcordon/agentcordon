use ed25519_dalek::Verifier;
use sha2::{Digest, Sha256};

use crate::error::CryptoError;

/// Domain separator prefix for workspace challenge signatures (34 bytes).
pub const CHALLENGE_DOMAIN_SEPARATOR: &[u8] = b"agentcordon:workspace-challenge-v1";

/// Audience binding for workspace challenge signatures (26 bytes).
pub const CHALLENGE_AUDIENCE: &str = "agentcordon:workspace-auth";

/// Generate a new Ed25519 keypair for workspace identity.
pub fn generate_workspace_keypair() -> (ed25519_dalek::SigningKey, ed25519_dalek::VerifyingKey) {
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let verifying_key = signing_key.verifying_key();
    (signing_key, verifying_key)
}

/// Compute SHA-256 hex hash of the raw 32-byte Ed25519 public key.
pub fn compute_pk_hash(pubkey: &[u8]) -> String {
    let hash = Sha256::digest(pubkey);
    hex::encode(hash)
}

/// Build the 132-byte challenge payload for signing.
///
/// Layout:
///   "agentcordon:workspace-challenge-v1"  (34 bytes, domain separator)
///   || challenge_bytes                     (32 bytes)
///   || issued_at_unix_epoch_seconds        (8 bytes, big-endian)
///   || "agentcordon:workspace-auth"        (26 bytes, audience)
///   || public_key_bytes                    (32 bytes)
pub fn build_challenge_payload(
    challenge: &[u8],
    issued_at: i64,
    audience: &str,
    pubkey: &[u8],
) -> Vec<u8> {
    let mut payload = Vec::with_capacity(132);
    payload.extend_from_slice(CHALLENGE_DOMAIN_SEPARATOR); // 34 bytes
    payload.extend_from_slice(challenge); // 32 bytes
    payload.extend_from_slice(&issued_at.to_be_bytes()); // 8 bytes
    payload.extend_from_slice(audience.as_bytes()); // 26 bytes
    payload.extend_from_slice(pubkey); // 32 bytes
    payload
}

/// Verify an Ed25519 signature over a challenge payload.
pub fn verify_challenge_signature(
    pubkey: &[u8],
    signature: &[u8],
    payload: &[u8],
) -> Result<(), CryptoError> {
    let verifying_key =
        ed25519_dalek::VerifyingKey::from_bytes(pubkey.try_into().map_err(|_| {
            CryptoError::Decryption("invalid public key length (expected 32 bytes)".to_string())
        })?)
        .map_err(|e| CryptoError::Decryption(format!("invalid Ed25519 public key: {}", e)))?;

    let sig = ed25519_dalek::Signature::from_bytes(signature.try_into().map_err(|_| {
        CryptoError::Decryption("invalid signature length (expected 64 bytes)".to_string())
    })?);

    verifying_key.verify(payload, &sig).map_err(|e| {
        CryptoError::Decryption(format!("Ed25519 signature verification failed: {}", e))
    })
}

/// Save an Ed25519 keypair to disk (hex-encoded, SSH-style permissions).
pub fn save_keypair(
    dir: &std::path::Path,
    signing_key: &ed25519_dalek::SigningKey,
) -> Result<(), CryptoError> {
    use std::fs;

    // Ensure directory exists
    fs::create_dir_all(dir)
        .map_err(|e| CryptoError::Encryption(format!("failed to create key directory: {}", e)))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).map_err(|e| {
            CryptoError::Encryption(format!("failed to set directory permissions: {}", e))
        })?;
    }

    // Write private key (hex-encoded seed)
    let key_path = dir.join("workspace.key");
    fs::write(&key_path, hex::encode(signing_key.to_bytes()))
        .map_err(|e| CryptoError::Encryption(format!("failed to write private key: {}", e)))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600)).map_err(|e| {
            CryptoError::Encryption(format!("failed to set key permissions: {}", e))
        })?;
    }

    // Write public key (hex-encoded)
    let pub_path = dir.join("workspace.pub");
    fs::write(
        &pub_path,
        hex::encode(signing_key.verifying_key().to_bytes()),
    )
    .map_err(|e| CryptoError::Encryption(format!("failed to write public key: {}", e)))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&pub_path, fs::Permissions::from_mode(0o644)).map_err(|e| {
            CryptoError::Encryption(format!("failed to set public key permissions: {}", e))
        })?;
    }

    Ok(())
}

/// Load an Ed25519 signing key from disk, verifying 0600 permissions on Unix.
pub fn load_keypair(dir: &std::path::Path) -> Result<ed25519_dalek::SigningKey, CryptoError> {
    use std::fs;

    let key_path = dir.join("workspace.key");

    // Check permissions on Unix (refuse if too open, SSH-style)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let metadata = fs::metadata(&key_path)
            .map_err(|e| CryptoError::Decryption(format!("failed to read key file: {}", e)))?;
        let mode = metadata.permissions().mode() & 0o777;
        if mode != 0o600 {
            return Err(CryptoError::Decryption(format!(
                "workspace.key permissions are {:04o}, expected 0600 — refusing to load",
                mode
            )));
        }
    }

    #[cfg(not(unix))]
    tracing::warn!(
        path = %key_path.display(),
        "file permission enforcement is not available on this platform — \
         cannot verify that the private key is not world-readable"
    );

    let hex_seed = fs::read_to_string(&key_path)
        .map_err(|e| CryptoError::Decryption(format!("failed to read key file: {}", e)))?;
    let seed_bytes = hex::decode(hex_seed.trim())
        .map_err(|e| CryptoError::Decryption(format!("invalid hex in key file: {}", e)))?;
    let seed: [u8; 32] = seed_bytes.try_into().map_err(|_| {
        CryptoError::Decryption("key file must contain exactly 32 bytes (hex-encoded)".to_string())
    })?;

    Ok(ed25519_dalek::SigningKey::from_bytes(&seed))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Signer;

    #[test]
    fn test_generate_and_pk_hash() {
        let (sk, vk) = generate_workspace_keypair();
        let hash = compute_pk_hash(&vk.to_bytes());
        assert_eq!(hash.len(), 64); // SHA-256 hex = 64 chars
                                    // Deterministic for same key
        assert_eq!(hash, compute_pk_hash(&vk.to_bytes()));
        // Different keys produce different hashes
        let (_, vk2) = generate_workspace_keypair();
        assert_ne!(hash, compute_pk_hash(&vk2.to_bytes()));
        let _ = sk; // suppress unused warning
    }

    #[test]
    fn test_challenge_payload_length() {
        let challenge = [0u8; 32];
        let pubkey = [0u8; 32];
        let payload = build_challenge_payload(&challenge, 1234567890, CHALLENGE_AUDIENCE, &pubkey);
        assert_eq!(payload.len(), 132);
    }

    #[test]
    fn test_sign_and_verify_challenge() {
        let (sk, vk) = generate_workspace_keypair();
        let challenge = [42u8; 32];
        let issued_at = 1710000000i64;
        let payload =
            build_challenge_payload(&challenge, issued_at, CHALLENGE_AUDIENCE, &vk.to_bytes());

        let signature = sk.sign(&payload);
        verify_challenge_signature(&vk.to_bytes(), &signature.to_bytes(), &payload)
            .expect("valid signature should verify");
    }

    #[test]
    fn test_verify_bad_signature_fails() {
        let (_, vk) = generate_workspace_keypair();
        let payload = build_challenge_payload(&[0u8; 32], 0, CHALLENGE_AUDIENCE, &vk.to_bytes());
        let bad_sig = [0u8; 64];

        let result = verify_challenge_signature(&vk.to_bytes(), &bad_sig, &payload);
        assert!(result.is_err());
    }

    #[test]
    fn test_save_and_load_keypair() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key_dir = dir.path().join(".agentcordon");

        let (sk, _vk) = generate_workspace_keypair();
        save_keypair(&key_dir, &sk).expect("save");

        let loaded = load_keypair(&key_dir).expect("load");
        assert_eq!(sk.to_bytes(), loaded.to_bytes());
    }
}
