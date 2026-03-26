use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use argon2::password_hash::SaltString;
use argon2::{PasswordHash, PasswordHasher, PasswordVerifier};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand::RngCore;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::crypto::{build_argon2, SecretEncryptor};
use crate::error::CryptoError;

/// Threshold at which a warning is emitted (2^31 encryptions).
const WARN_THRESHOLD: u64 = 1 << 31;
/// Hard limit at which encryption is refused (2^32 encryptions).
const FAIL_THRESHOLD: u64 = 1 << 32;
/// How often the counter is flushed to persistent storage.
pub const FLUSH_INTERVAL: u64 = 100;

/// AES-256-GCM encryptor backed by a 256-bit key.
///
/// Tracks encryption count per key to detect approaching nonce collision risk.
/// Warns at 2^31 encryptions and hard-fails at 2^32.
pub struct AesGcmEncryptor {
    cipher: Aes256Gcm,
    encryption_count: AtomicU64,
}

impl AesGcmEncryptor {
    /// Create a new encryptor from a 256-bit derived key.
    pub fn new(key: &[u8; 32]) -> Self {
        let cipher =
            Aes256Gcm::new_from_slice(key).expect("32-byte key is always valid for AES-256");
        Self {
            cipher,
            encryption_count: AtomicU64::new(0),
        }
    }

    /// Create a new encryptor with a pre-loaded encryption count (from DB).
    pub fn new_with_count(key: &[u8; 32], initial_count: u64) -> Self {
        let cipher =
            Aes256Gcm::new_from_slice(key).expect("32-byte key is always valid for AES-256");
        Self {
            cipher,
            encryption_count: AtomicU64::new(initial_count),
        }
    }

    /// Get the current encryption count.
    pub fn encryption_count(&self) -> u64 {
        self.encryption_count.load(Ordering::Relaxed)
    }

    /// Returns `true` if the counter should be flushed to persistent storage.
    pub fn should_flush(&self) -> bool {
        let count = self.encryption_count.load(Ordering::Relaxed);
        count > 0 && count.is_multiple_of(FLUSH_INTERVAL)
    }
}

impl SecretEncryptor for AesGcmEncryptor {
    fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
        // Atomic check-and-increment: fetch_add first, then check the previous
        // value. This prevents TOCTOU races where multiple threads could pass a
        // load-then-check and all encrypt beyond the threshold.
        let prev = self.encryption_count.fetch_add(1, Ordering::Relaxed);
        if prev >= FAIL_THRESHOLD {
            // Roll back the increment since we're not actually encrypting.
            self.encryption_count.fetch_sub(1, Ordering::Relaxed);
            return Err(CryptoError::NonceExhaustion);
        }

        // Warn at 2^31 threshold (log once when crossing).
        if prev == WARN_THRESHOLD {
            tracing::warn!(
                encryption_count = prev + 1,
                "crypto.nonce_safety: encryption count approaching limit, key rotation recommended"
            );
        }

        let mut nonce_bytes = [0u8; 12];
        rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from(nonce_bytes);

        let payload = Payload {
            msg: plaintext,
            aad,
        };
        let ciphertext = self
            .cipher
            .encrypt(&nonce, payload)
            .map_err(|e| CryptoError::Encryption(e.to_string()))?;

        Ok((ciphertext, nonce_bytes.to_vec()))
    }

    fn decrypt(&self, ciphertext: &[u8], nonce: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if nonce.len() != 12 {
            return Err(CryptoError::Decryption(format!(
                "invalid nonce length: expected 12, got {}",
                nonce.len()
            )));
        }
        let nonce_arr: &[u8; 12] = nonce
            .try_into()
            .map_err(|_| CryptoError::Decryption("nonce conversion failed".to_string()))?;
        let nonce = Nonce::from(*nonce_arr);
        let payload = Payload {
            msg: ciphertext,
            aad,
        };
        self.cipher
            .decrypt(&nonce, payload)
            .map_err(|e| CryptoError::Decryption(e.to_string()))
    }
}

/// Hash a secret with Argon2id + random salt. Returns the PHC string.
/// Used for OAuth client secrets, device bootstrap tokens, etc.
pub fn hash_secret(raw: &str) -> Result<String, CryptoError> {
    let salt = SaltString::generate(&mut rand::rngs::OsRng);
    let argon2 = build_argon2();
    let hash = argon2
        .hash_password(raw.as_bytes(), &salt)
        .map_err(|e| CryptoError::Encryption(e.to_string()))?;
    Ok(hash.to_string())
}

/// Verify a secret against a stored Argon2 hash. Constant-time.
pub fn verify_secret(raw: &str, stored_hash: &str) -> Result<bool, CryptoError> {
    let parsed_hash =
        PasswordHash::new(stored_hash).map_err(|e| CryptoError::Decryption(e.to_string()))?;
    let argon2 = build_argon2();
    match argon2.verify_password(raw.as_bytes(), &parsed_hash) {
        Ok(()) => Ok(true),
        Err(argon2::password_hash::Error::Password) => Ok(false),
        Err(e) => Err(CryptoError::Decryption(e.to_string())),
    }
}

/// Character set for human-readable auth codes: uppercase + digits, excluding ambiguous chars (0/O, 1/I/L).
const AUTH_CODE_CHARSET: &[u8] = b"23456789ABCDEFGHJKMNPQRSTUVWXYZ";

/// Generate a 6-character human-readable authorization code.
///
/// Uses `OsRng` for cryptographic randomness. Characters are drawn from a
/// 30-character alphabet (`23456789ABCDEFGHJKMNPQRSTUVWXYZ`) that avoids
/// ambiguous characters (0/O, 1/I/L). This yields ~29 bits of entropy,
/// sufficient for a short-lived, single-use, rate-limited code.
pub fn generate_auth_code() -> String {
    use rand::RngCore;
    let mut rng = rand::rngs::OsRng;
    let mut code = String::with_capacity(6);
    for _ in 0..6 {
        let mut buf = [0u8; 1];
        loop {
            rng.fill_bytes(&mut buf);
            // Reject values >= 240 to avoid modulo bias (240 = 30 * 8)
            if buf[0] < 240 {
                let idx = (buf[0] % 30) as usize;
                code.push(AUTH_CODE_CHARSET[idx] as char);
                break;
            }
        }
    }
    code
}

/// Generate a cryptographically random enrollment code ("enr_" + 16 base64url chars = 96 bits).
pub fn generate_enrollment_code() -> String {
    let mut bytes = [0u8; 12]; // 12 bytes = 96 bits -> 16 base64url chars
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    format!("enr_{}", URL_SAFE_NO_PAD.encode(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::key_derivation::derive_master_key;

    fn test_encryptor() -> AesGcmEncryptor {
        let key = derive_master_key("test-secret", b"sixteen-byte-sal")
            .expect("key derivation should succeed");
        AesGcmEncryptor::new(&key)
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let encryptor = test_encryptor();
        let plaintext = b"hello, agentic identity!";
        let (ciphertext, nonce) = encryptor
            .encrypt(plaintext, b"")
            .expect("encrypt should succeed");

        assert_ne!(
            ciphertext, plaintext,
            "ciphertext must differ from plaintext"
        );

        let decrypted = encryptor
            .decrypt(&ciphertext, &nonce, b"")
            .expect("decrypt should succeed");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn encrypt_decrypt_empty_plaintext() {
        let encryptor = test_encryptor();
        let plaintext = b"";
        let (ciphertext, nonce) = encryptor
            .encrypt(plaintext, b"")
            .expect("encrypt should succeed");
        let decrypted = encryptor
            .decrypt(&ciphertext, &nonce, b"")
            .expect("decrypt should succeed");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn decrypt_with_wrong_nonce_fails() {
        let encryptor = test_encryptor();
        let plaintext = b"secret data";
        let (ciphertext, _nonce) = encryptor
            .encrypt(plaintext, b"")
            .expect("encrypt should succeed");

        let wrong_nonce = vec![0u8; 12]; // all zeros — extremely unlikely to match
        let result = encryptor.decrypt(&ciphertext, &wrong_nonce, b"");
        assert!(result.is_err(), "decryption with wrong nonce must fail");
    }

    #[test]
    fn decrypt_with_wrong_key_fails() {
        let encryptor = test_encryptor();
        let plaintext = b"secret data";
        let (ciphertext, nonce) = encryptor
            .encrypt(plaintext, b"")
            .expect("encrypt should succeed");

        let other_key = derive_master_key("different-secret", b"sixteen-byte-sal")
            .expect("key derivation should succeed");
        let other_encryptor = AesGcmEncryptor::new(&other_key);
        let result = other_encryptor.decrypt(&ciphertext, &nonce, b"");
        assert!(result.is_err(), "decryption with wrong key must fail");
    }

    #[test]
    fn encrypt_decrypt_with_aad() {
        let encryptor = test_encryptor();
        let plaintext = b"secret data";
        let aad = b"cred-123";
        let (ciphertext, nonce) = encryptor
            .encrypt(plaintext, aad)
            .expect("encrypt should succeed");
        let decrypted = encryptor
            .decrypt(&ciphertext, &nonce, aad)
            .expect("decrypt with same AAD should succeed");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn aad_mismatch_fails() {
        let encryptor = test_encryptor();
        let plaintext = b"secret data";
        let (ciphertext, nonce) = encryptor
            .encrypt(plaintext, b"cred-123")
            .expect("encrypt should succeed");
        let result = encryptor.decrypt(&ciphertext, &nonce, b"cred-456");
        assert!(result.is_err(), "decryption with wrong AAD must fail");
    }

    #[test]
    fn empty_aad_works() {
        let encryptor = test_encryptor();
        let plaintext = b"hello world";
        let (ciphertext, nonce) = encryptor
            .encrypt(plaintext, b"")
            .expect("encrypt should succeed");
        let decrypted = encryptor
            .decrypt(&ciphertext, &nonce, b"")
            .expect("decrypt with empty AAD should succeed");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn encryption_count_increments() {
        let encryptor = test_encryptor();
        assert_eq!(encryptor.encryption_count(), 0);

        encryptor.encrypt(b"data1", b"").expect("encrypt 1");
        assert_eq!(encryptor.encryption_count(), 1);

        encryptor.encrypt(b"data2", b"").expect("encrypt 2");
        assert_eq!(encryptor.encryption_count(), 2);
    }

    #[test]
    fn new_with_count_preserves_initial_count() {
        let key = derive_master_key("test-secret", b"sixteen-byte-sal")
            .expect("key derivation should succeed");
        let encryptor = AesGcmEncryptor::new_with_count(&key, 500);
        assert_eq!(encryptor.encryption_count(), 500);

        encryptor.encrypt(b"data", b"").expect("encrypt");
        assert_eq!(encryptor.encryption_count(), 501);
    }

    #[test]
    fn nonce_exhaustion_at_threshold() {
        let key = derive_master_key("test-secret", b"sixteen-byte-sal")
            .expect("key derivation should succeed");
        let encryptor = AesGcmEncryptor::new_with_count(&key, FAIL_THRESHOLD);

        let result = encryptor.encrypt(b"data", b"");
        assert!(
            result.is_err(),
            "encryption must fail at exhaustion threshold"
        );
        match result.unwrap_err() {
            CryptoError::NonceExhaustion => {}
            other => panic!("expected NonceExhaustion, got: {:?}", other),
        }
    }

    #[test]
    fn should_flush_at_intervals() {
        let key = derive_master_key("test-secret", b"sixteen-byte-sal")
            .expect("key derivation should succeed");
        let encryptor = AesGcmEncryptor::new_with_count(&key, 99);
        assert!(!encryptor.should_flush());

        encryptor.encrypt(b"data", b"").expect("encrypt");
        assert_eq!(encryptor.encryption_count(), 100);
        assert!(encryptor.should_flush());
    }

    #[test]
    fn generated_auth_code_length_and_charset() {
        let charset = b"23456789ABCDEFGHJKMNPQRSTUVWXYZ";
        for _ in 0..100 {
            let code = generate_auth_code();
            assert_eq!(code.len(), 6, "auth code must be 6 characters");
            for ch in code.chars() {
                assert!(
                    charset.contains(&(ch as u8)),
                    "character '{}' not in allowed charset",
                    ch,
                );
            }
        }
    }

    #[test]
    fn generated_auth_codes_are_unique() {
        let code1 = generate_auth_code();
        let code2 = generate_auth_code();
        // With ~29 bits of entropy, collisions in 2 draws are astronomically unlikely
        assert_ne!(code1, code2, "two generated auth codes should differ");
    }
}
