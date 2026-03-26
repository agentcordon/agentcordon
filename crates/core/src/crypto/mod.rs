pub mod aes_gcm;
pub mod ecies;
pub mod ed25519;
pub mod kdf;
pub mod key_derivation;
pub mod password;
pub mod session;

use argon2::Argon2;

use crate::error::CryptoError;

/// Build an Argon2id instance with reduced-cost parameters for tests and
/// production-grade parameters otherwise.
///
/// Production: 64 MiB, 3 iterations, 4 lanes (hardened in v1.6.0).
/// Test:       256 KiB, 1 iteration, 1 lane (fast for CI).
pub(crate) fn build_argon2<'a>() -> Argon2<'a> {
    #[cfg(any(test, feature = "test-crypto"))]
    {
        Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            argon2::Params::new(256, 1, 1, None).unwrap(), // 256 KiB, 1 iteration, 1 lane
        )
    }
    #[cfg(not(any(test, feature = "test-crypto")))]
    {
        Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            argon2::Params::new(65536, 3, 4, None).unwrap(), // 64 MiB, 3 iterations, 4 lanes
        )
    }
}

/// Trait for encrypting/decrypting secret values at rest.
pub trait SecretEncryptor: Send + Sync {
    /// Encrypt plaintext with additional authenticated data (AAD).
    /// Returns (ciphertext, nonce).
    fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<(Vec<u8>, Vec<u8>), CryptoError>;

    /// Decrypt ciphertext given its nonce and additional authenticated data (AAD).
    fn decrypt(&self, ciphertext: &[u8], nonce: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError>;
}
