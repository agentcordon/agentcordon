use hkdf::Hkdf;
use p256::ecdsa::{SigningKey, VerifyingKey};
use sha2::Sha256;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::error::CryptoError;

/// Derive a 256-bit encryption key from a master secret + salt using HKDF-SHA256.
/// The returned key is wrapped in `Zeroizing` so it is automatically zeroed on drop.
pub fn derive_master_key(
    master_secret: &str,
    salt: &[u8],
) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    hkdf_derive(master_secret, salt, b"agentcordon:encryption-v2")
}

/// Derive a 256-bit session-hashing key from a master secret using HKDF-SHA256.
/// Uses domain-specific info label for separation from both the AES-GCM encryption
/// key and the JWT signing key.
pub fn derive_session_hash_key(
    master_secret: &str,
    salt: &[u8],
) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    hkdf_derive(master_secret, salt, b"agentcordon:session-hash-v2")
}

/// Derive a P-256 ECDSA signing key pair from a master secret using HKDF-SHA256.
///
/// Uses a domain-specific info label (`agentcordon:jwt-es256-v1`) to derive 32 bytes
/// of key material, which are used as the P-256 private key scalar. The public
/// (verifying) key is derived from the private key.
///
/// This produces a deterministic key pair for a given (master_secret, salt) pair.
pub fn derive_jwt_signing_keypair(
    master_secret: &str,
    salt: &[u8],
) -> Result<(SigningKey, VerifyingKey), CryptoError> {
    let seed = hkdf_derive(master_secret, salt, b"agentcordon:jwt-es256-v1")?;
    let signing_key = SigningKey::from_bytes(seed.as_ref().into())
        .map_err(|e| CryptoError::KeyDerivation(format!("P-256 key from HKDF output: {e}")))?;
    let verifying_key = VerifyingKey::from(&signing_key);
    Ok((signing_key, verifying_key))
}

/// Derive a P-256 ECDSA key pair from a master secret using HKDF-SHA256 with
/// a caller-supplied info label.
///
/// This is the generic version of [`derive_jwt_signing_keypair`] — use it when
/// you need a deterministic P-256 key pair with a custom domain-separation label
/// (e.g., combined-container device keys).
pub fn derive_p256_keypair(
    master_secret: &str,
    salt: &[u8],
    info_label: &[u8],
) -> Result<(SigningKey, VerifyingKey), CryptoError> {
    let seed = hkdf_derive(master_secret, salt, info_label)?;
    let signing_key = SigningKey::from_bytes(seed.as_ref().into())
        .map_err(|e| CryptoError::KeyDerivation(format!("P-256 key from HKDF output: {e}")))?;
    let verifying_key = VerifyingKey::from(&signing_key);
    Ok((signing_key, verifying_key))
}

/// Derive a deterministic device ID (UUID v4-format) from a master secret and salt
/// using HKDF-SHA256 with the label `agentcordon:device-id-v1`.
///
/// The first 16 bytes of HKDF output are used as UUID bytes (with version/variant
/// bits set per RFC 4122 v4 layout for consistency).
pub fn derive_device_id(master_secret: &str, salt: &[u8]) -> Uuid {
    let hk = Hkdf::<Sha256>::new(Some(salt), master_secret.as_bytes());
    let mut okm = [0u8; 16];
    hk.expand(b"agentcordon:device-id-v1", &mut okm)
        .expect("HKDF expand for device-id derivation");

    // Set version (4) and variant (RFC 4122) bits so the result is a valid UUID.
    okm[6] = (okm[6] & 0x0f) | 0x40; // version 4
    okm[8] = (okm[8] & 0x3f) | 0x80; // variant RFC 4122

    Uuid::from_bytes(okm)
}

/// Internal HKDF-SHA256 derivation with domain-specific info label.
fn hkdf_derive(ikm: &str, salt: &[u8], info: &[u8]) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm.as_bytes());
    let mut okm = Zeroizing::new([0u8; 32]);
    hk.expand(info, okm.as_mut())
        .map_err(|e| CryptoError::KeyDerivation(e.to_string()))?;
    Ok(okm)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_derivation_is_deterministic() {
        let secret = "my-master-secret";
        let salt = b"sixteen-byte-sal";
        let key1 = derive_master_key(secret, salt).expect("derivation should succeed");
        let key2 = derive_master_key(secret, salt).expect("derivation should succeed");
        assert_eq!(*key1, *key2, "same inputs must produce the same key");
    }

    #[test]
    fn different_secrets_produce_different_keys() {
        let salt = b"sixteen-byte-sal";
        let key1 = derive_master_key("secret-a", salt).expect("derivation should succeed");
        let key2 = derive_master_key("secret-b", salt).expect("derivation should succeed");
        assert_ne!(*key1, *key2);
    }

    #[test]
    fn different_salts_produce_different_keys() {
        let secret = "same-secret";
        let key1 =
            derive_master_key(secret, b"salt-aaa-aaa-aaa").expect("derivation should succeed");
        let key2 =
            derive_master_key(secret, b"salt-bbb-bbb-bbb").expect("derivation should succeed");
        assert_ne!(*key1, *key2);
    }

    #[test]
    fn short_salt_succeeds_with_hkdf() {
        // HKDF accepts any salt length (unlike Argon2 which requires >= 8 bytes)
        let result = derive_master_key("secret", b"short");
        assert!(result.is_ok(), "HKDF should accept short salts");
    }

    #[test]
    fn session_hash_key_derivation_is_deterministic() {
        let secret = "my-master-secret";
        let salt = b"sixteen-byte-sal";
        let key1 = derive_session_hash_key(secret, salt).expect("derivation should succeed");
        let key2 = derive_session_hash_key(secret, salt).expect("derivation should succeed");
        assert_eq!(
            *key1, *key2,
            "same inputs must produce the same session hash key"
        );
    }

    #[test]
    fn es256_keypair_derivation_is_deterministic() {
        let secret = "my-master-secret";
        let salt = b"sixteen-byte-sal";
        let (sk1, vk1) =
            derive_jwt_signing_keypair(secret, salt).expect("derivation should succeed");
        let (sk2, vk2) =
            derive_jwt_signing_keypair(secret, salt).expect("derivation should succeed");
        assert_eq!(
            sk1.to_bytes(),
            sk2.to_bytes(),
            "same inputs must produce the same signing key"
        );
        assert_eq!(vk1, vk2, "same inputs must produce the same verifying key");
    }

    #[test]
    fn es256_different_secrets_produce_different_keys() {
        let salt = b"sixteen-byte-sal";
        let (sk1, _) =
            derive_jwt_signing_keypair("secret-a", salt).expect("derivation should succeed");
        let (sk2, _) =
            derive_jwt_signing_keypair("secret-b", salt).expect("derivation should succeed");
        assert_ne!(sk1.to_bytes(), sk2.to_bytes());
    }

    #[test]
    fn session_hash_key_differs_from_master_key() {
        let secret = "my-master-secret";
        let salt = b"sixteen-byte-sal";
        let aes_key = derive_master_key(secret, salt).expect("AES key derivation");
        let session_key = derive_session_hash_key(secret, salt).expect("session key derivation");
        assert_ne!(
            *aes_key, *session_key,
            "session hash key must differ from AES key"
        );
    }

    // --- derive_device_id tests ---

    #[test]
    fn test_derive_device_id_deterministic() {
        let id1 = derive_device_id("my-secret", b"my-salt");
        let id2 = derive_device_id("my-secret", b"my-salt");
        assert_eq!(id1, id2, "same inputs must produce the same device ID");
    }

    #[test]
    fn test_derive_device_id_different_inputs() {
        let id1 = derive_device_id("secret-a", b"salt-a");
        let id2 = derive_device_id("secret-b", b"salt-b");
        assert_ne!(
            id1, id2,
            "different inputs must produce different device IDs"
        );

        // Also test same secret with different salt
        let id3 = derive_device_id("secret-a", b"salt-b");
        assert_ne!(
            id1, id3,
            "different salts must produce different device IDs"
        );

        // Same salt with different secret
        let id4 = derive_device_id("secret-b", b"salt-a");
        assert_ne!(
            id1, id4,
            "different secrets must produce different device IDs"
        );
    }

    #[test]
    fn test_derive_device_id_is_valid_uuid_v4() {
        let id = derive_device_id("test-secret", b"test-salt");
        // UUID v4 has version nibble 4 at position bytes[6] high nibble
        // and variant bits 10xx at position bytes[8] high 2 bits
        assert_eq!(
            id.get_version_num(),
            4,
            "derived device ID must be UUID v4 format"
        );
        // Check the variant is RFC 4122
        let bytes = id.as_bytes();
        assert_eq!(bytes[8] >> 6, 0b10, "variant bits must be RFC 4122 (10xx)");
    }

    // --- derive_p256_keypair tests ---

    #[test]
    fn test_derive_p256_keypair_deterministic() {
        let (sk1, vk1) =
            derive_p256_keypair("secret", b"salt", b"test-label-v1").expect("derive p256 keypair");
        let (sk2, vk2) =
            derive_p256_keypair("secret", b"salt", b"test-label-v1").expect("derive p256 keypair");
        assert_eq!(
            sk1.to_bytes(),
            sk2.to_bytes(),
            "same inputs must produce same signing key"
        );
        assert_eq!(vk1, vk2, "same inputs must produce same verifying key");
    }

    #[test]
    fn test_derive_p256_keypair_different_labels() {
        let (sk1, _) =
            derive_p256_keypair("secret", b"salt", b"label-a").expect("derive p256 keypair a");
        let (sk2, _) =
            derive_p256_keypair("secret", b"salt", b"label-b").expect("derive p256 keypair b");
        assert_ne!(
            sk1.to_bytes(),
            sk2.to_bytes(),
            "different labels must produce different keys"
        );
    }

    #[test]
    fn test_derive_p256_keypair_differs_from_jwt_keypair() {
        let secret = "same-secret";
        let salt = b"same-salt-value!";
        let (sk_jwt, _) = derive_jwt_signing_keypair(secret, salt).expect("derive JWT keypair");
        let (sk_custom, _) = derive_p256_keypair(secret, salt, b"agentcordon:custom-label-v1")
            .expect("derive custom keypair");
        assert_ne!(
            sk_jwt.to_bytes(),
            sk_custom.to_bytes(),
            "JWT keypair and custom-label keypair must differ (different HKDF info)"
        );
    }

    #[test]
    fn test_derived_p256_keypair_can_sign_jwt() {
        use crate::auth::jwt::JwtIssuer;

        let (sk, vk) = derive_p256_keypair("secret", b"salt", b"agentcordon:test-jwt-v1")
            .expect("derive keypair for JWT");

        // Create a JwtIssuer from the derived keypair and sign a token
        let issuer = JwtIssuer::new(&sk, &vk, "test-issuer".to_string(), 300);
        let claims = serde_json::json!({
            "iss": "test-issuer",
            "sub": "test-sub",
            "aud": "test-aud",
            "exp": chrono::Utc::now().timestamp() + 300,
            "iat": chrono::Utc::now().timestamp(),
            "nbf": chrono::Utc::now().timestamp(),
            "jti": "test-jti",
        });
        let token = issuer.sign_custom_claims(&claims);
        assert!(
            token.is_ok(),
            "derived P-256 keypair must produce valid JWT: {:?}",
            token.err()
        );

        // Validate the token
        let validated = issuer.validate_custom_audience(&token.unwrap(), "test-aud");
        assert!(
            validated.is_ok(),
            "JWT from derived keypair must validate: {:?}",
            validated.err()
        );
    }

    #[test]
    fn test_all_hkdf_labels_are_unique() {
        // Collect all known HKDF info labels used in this module and the broader codebase.
        // Each label must be unique to prevent key confusion across different derivation paths.
        let labels: Vec<&[u8]> = vec![
            b"agentcordon:encryption-v2",   // derive_master_key
            b"agentcordon:session-hash-v2", // derive_session_hash_key
            b"agentcordon:jwt-es256-v1",    // derive_jwt_signing_keypair
            b"agentcordon:device-id-v1",    // derive_device_id
        ];

        // Check all pairs for uniqueness
        for i in 0..labels.len() {
            for j in (i + 1)..labels.len() {
                assert_ne!(
                    labels[i],
                    labels[j],
                    "HKDF labels must be unique: {:?} vs {:?}",
                    std::str::from_utf8(labels[i]).unwrap(),
                    std::str::from_utf8(labels[j]).unwrap()
                );
            }
        }

        // Verify the labels actually match what the functions use by checking
        // that same secret+salt produces different output for each function.
        let secret = "label-uniqueness-test";
        let salt = b"test-salt-16byte";

        let master = derive_master_key(secret, salt).expect("master key");
        let session = derive_session_hash_key(secret, salt).expect("session key");
        let (jwt_sk, _) = derive_jwt_signing_keypair(secret, salt).expect("jwt keypair");

        // All three must be distinct
        assert_ne!(*master, *session, "master key != session key");
        #[allow(deprecated)]
        {
            assert_ne!(
                master.as_ref(),
                jwt_sk.to_bytes().as_slice(),
                "master key != jwt key material"
            );
            assert_ne!(
                session.as_ref(),
                jwt_sk.to_bytes().as_slice(),
                "session key != jwt key material"
            );
        }
    }
}
