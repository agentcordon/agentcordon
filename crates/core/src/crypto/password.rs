use argon2::password_hash::SaltString;
use argon2::{PasswordHash, PasswordHasher, PasswordVerifier};

use crate::crypto::build_argon2;
use crate::error::CryptoError;

/// Hash a password with Argon2id + random salt. Returns the PHC string.
pub fn hash_password(password: &str) -> Result<String, CryptoError> {
    let salt = SaltString::generate(&mut rand::rngs::OsRng);
    let argon2 = build_argon2();
    let hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| CryptoError::Encryption(e.to_string()))?;
    Ok(hash.to_string())
}

/// Async wrapper around `hash_password` that offloads Argon2id to a blocking thread pool,
/// preventing the Tokio runtime from stalling during the ~1.5s hash computation.
pub async fn hash_password_async(password: &str) -> Result<String, CryptoError> {
    let password = password.to_string();
    tokio::task::spawn_blocking(move || hash_password(&password))
        .await
        .map_err(|e| CryptoError::Encryption(format!("task join error: {e}")))?
}

/// Async wrapper around `verify_password` that offloads Argon2id to a blocking thread pool.
pub async fn verify_password_async(password: &str, hash: &str) -> Result<bool, CryptoError> {
    let password = password.to_string();
    let hash = hash.to_string();
    tokio::task::spawn_blocking(move || verify_password(&password, &hash))
        .await
        .map_err(|e| CryptoError::Decryption(format!("task join error: {e}")))?
}

/// Verify a password against a stored Argon2id hash. Constant-time comparison.
pub fn verify_password(password: &str, stored_hash: &str) -> Result<bool, CryptoError> {
    let parsed_hash =
        PasswordHash::new(stored_hash).map_err(|e| CryptoError::Decryption(e.to_string()))?;
    let argon2 = build_argon2();
    match argon2.verify_password(password.as_bytes(), &parsed_hash) {
        Ok(()) => Ok(true),
        Err(argon2::password_hash::Error::Password) => Ok(false),
        Err(e) => Err(CryptoError::Decryption(e.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_and_verify_roundtrip() {
        let password = "correct-horse-battery-staple";
        let hash = hash_password(password).expect("hashing should succeed");

        // Hash must be a valid PHC string with argon2id
        assert!(hash.starts_with("$argon2id$"));

        let verified = verify_password(password, &hash).expect("verify should succeed");
        assert!(verified, "correct password must verify");
    }

    #[test]
    fn wrong_password_returns_false() {
        let hash = hash_password("real-password").expect("hashing should succeed");

        let verified = verify_password("wrong-password", &hash).expect("verify should succeed");
        assert!(!verified, "wrong password must not verify");
    }

    #[test]
    fn different_hashes_for_same_password() {
        let password = "same-password";
        let hash1 = hash_password(password).expect("hashing should succeed");
        let hash2 = hash_password(password).expect("hashing should succeed");
        assert_ne!(hash1, hash2, "random salt should produce different hashes");

        // Both should still verify
        assert!(verify_password(password, &hash1).unwrap());
        assert!(verify_password(password, &hash2).unwrap());
    }

    #[test]
    fn empty_password_can_be_hashed() {
        let hash = hash_password("").expect("hashing empty password should succeed");
        assert!(verify_password("", &hash).unwrap());
        assert!(!verify_password("non-empty", &hash).unwrap());
    }

    #[test]
    fn invalid_hash_returns_error() {
        let result = verify_password("anything", "not-a-valid-hash");
        assert!(result.is_err(), "invalid hash format must return error");
    }
}
