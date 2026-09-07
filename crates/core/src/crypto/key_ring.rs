//! Versioned master-key ring.
//!
//! One [`AesGcmEncryptor`] per master-secret version. Rows that record the
//! version they were sealed under (`credentials.key_version`,
//! `credential_secret_history.key_version`) are decrypted with that key;
//! rows without a version hint are tried against the current key and then
//! the previous one. Encryption always uses the current key and reports its
//! version so the caller can store it next to the ciphertext.
//!
//! The ring implements [`SecretEncryptor`], so every existing caller keeps
//! working: `encrypt` seals under the current key, `decrypt` tries current
//! then previous. Key derivation is unchanged (`derive_master_key`, HKDF
//! label `agentcordon:encryption-v2`); the ring only chooses which derived
//! key to use.

use std::sync::Arc;

use zeroize::Zeroizing;

use crate::crypto::aes_gcm::AesGcmEncryptor;
use crate::crypto::key_derivation::derive_master_key;
use crate::crypto::SecretEncryptor;
use crate::error::CryptoError;

/// A master secret plus the HKDF salt it is stretched with.
pub struct MasterSecret<'a> {
    pub secret: &'a str,
    pub kdf_salt: &'a [u8],
}

/// Current key plus, during a rotation window, the key it replaces.
///
/// Keys are shared (`Arc`) so a caller that built the current encryptor can
/// keep a handle on it, for instance to read its nonce counter.
pub struct KeyRing {
    current_version: i64,
    current: Arc<AesGcmEncryptor>,
    previous: Option<Arc<AesGcmEncryptor>>,
}

impl KeyRing {
    /// A ring holding one key. `current_version` must be at least 1.
    pub fn new(current_version: i64, current: Arc<AesGcmEncryptor>) -> Self {
        assert!(current_version >= 1, "master key version must be >= 1");
        Self {
            current_version,
            current,
            previous: None,
        }
    }

    /// Add the key for version `current_version - 1`.
    pub fn with_previous(mut self, previous: Arc<AesGcmEncryptor>) -> Self {
        assert!(
            self.current_version >= 2,
            "a previous key needs a current version of at least 2"
        );
        self.previous = Some(previous);
        self
    }

    /// Derive the ring from master secrets. `previous`, when given, is the
    /// secret for version `current_version - 1`.
    pub fn from_secrets(
        current: MasterSecret<'_>,
        current_version: i64,
        previous: Option<MasterSecret<'_>>,
    ) -> Result<Self, CryptoError> {
        if current_version < 1 {
            return Err(CryptoError::KeyDerivation(format!(
                "master key version must be at least 1, got {current_version}"
            )));
        }
        if previous.is_some() && current_version < 2 {
            return Err(CryptoError::KeyDerivation(
                "a previous master secret needs a current version of at least 2".to_string(),
            ));
        }
        if let Some(prev) = &previous {
            if prev.secret == current.secret {
                return Err(CryptoError::KeyDerivation(
                    "previous master secret must differ from the current one".to_string(),
                ));
            }
        }

        let current_key: Zeroizing<[u8; 32]> = derive_master_key(current.secret, current.kdf_salt)?;
        let mut ring = Self::new(
            current_version,
            Arc::new(AesGcmEncryptor::new(&current_key)),
        );
        if let Some(prev) = previous {
            let prev_key: Zeroizing<[u8; 32]> = derive_master_key(prev.secret, prev.kdf_salt)?;
            ring = ring.with_previous(Arc::new(AesGcmEncryptor::new(&prev_key)));
        }
        Ok(ring)
    }

    /// Version of the key new ciphertext is sealed under.
    pub fn current_version(&self) -> i64 {
        self.current_version
    }

    /// Version of the previous key, if one is loaded.
    pub fn previous_version(&self) -> Option<i64> {
        self.previous.as_ref().map(|_| self.current_version - 1)
    }

    /// The current key's encryptor, for its nonce counter.
    pub fn current(&self) -> &AesGcmEncryptor {
        &self.current
    }

    /// Whether `version` names a key this ring holds.
    pub fn knows_version(&self, version: i64) -> bool {
        version == self.current_version || Some(version) == self.previous_version()
    }

    fn key_for(&self, version: i64) -> Option<&AesGcmEncryptor> {
        if version == self.current_version {
            Some(&*self.current)
        } else if Some(version) == self.previous_version() {
            self.previous.as_deref()
        } else {
            None
        }
    }

    /// Seal under the current key. Returns `(ciphertext, nonce, key_version)`.
    pub fn encrypt_versioned(
        &self,
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>, i64), CryptoError> {
        let (ciphertext, nonce) = self.current.encrypt(plaintext, aad)?;
        Ok((ciphertext, nonce, self.current_version))
    }

    /// Open a row sealed under `key_version`.
    ///
    /// The named key is tried first. If it is not in the ring, or refuses
    /// the ciphertext, the other keys are tried in order (current, then
    /// previous). The fallback exists for rows written before versions
    /// meant anything: `key_version` used to be a re-encryption counter, so
    /// a legacy row's number says nothing about which secret sealed it.
    pub fn decrypt_versioned(
        &self,
        ciphertext: &[u8],
        nonce: &[u8],
        aad: &[u8],
        key_version: i64,
    ) -> Result<Vec<u8>, CryptoError> {
        let mut last_err = None;
        if let Some(key) = self.key_for(key_version) {
            match key.decrypt(ciphertext, nonce, aad) {
                Ok(pt) => return Ok(pt),
                Err(e) => last_err = Some(e),
            }
        }
        for (version, key) in self.keys() {
            if version == key_version {
                continue;
            }
            match key.decrypt(ciphertext, nonce, aad) {
                Ok(pt) => return Ok(pt),
                Err(e) => last_err = Some(e),
            }
        }
        Err(last_err
            .unwrap_or_else(|| CryptoError::Decryption("key ring holds no keys".to_string())))
    }

    /// Keys in trial order: current first, then previous.
    fn keys(&self) -> impl Iterator<Item = (i64, &AesGcmEncryptor)> {
        std::iter::once((self.current_version, &*self.current)).chain(
            self.previous
                .as_deref()
                .map(|p| (self.current_version - 1, p)),
        )
    }
}

impl SecretEncryptor for KeyRing {
    fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
        self.current.encrypt(plaintext, aad)
    }

    /// No version hint: try the current key, then the previous one.
    fn decrypt(&self, ciphertext: &[u8], nonce: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let mut last_err = None;
        for (_, key) in self.keys() {
            match key.decrypt(ciphertext, nonce, aad) {
                Ok(pt) => return Ok(pt),
                Err(e) => last_err = Some(e),
            }
        }
        Err(last_err
            .unwrap_or_else(|| CryptoError::Decryption("key ring holds no keys".to_string())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SALT: &[u8] = b"sixteen-byte-sal";

    fn secret(s: &str) -> MasterSecret<'_> {
        MasterSecret {
            secret: s,
            kdf_salt: SALT,
        }
    }

    fn v1_only() -> KeyRing {
        KeyRing::from_secrets(secret("secret-one"), 1, None).expect("ring")
    }

    fn v2_with_v1() -> KeyRing {
        KeyRing::from_secrets(secret("secret-two"), 2, Some(secret("secret-one"))).expect("ring")
    }

    fn v2_only() -> KeyRing {
        KeyRing::from_secrets(secret("secret-two"), 2, None).expect("ring")
    }

    #[test]
    fn encrypt_reports_the_current_version() {
        let ring = v2_with_v1();
        let (ct, nonce, version) = ring.encrypt_versioned(b"hello", b"aad").expect("encrypt");
        assert_eq!(version, 2);
        assert_eq!(
            ring.decrypt_versioned(&ct, &nonce, b"aad", 2)
                .expect("decrypt"),
            b"hello"
        );
    }

    #[test]
    fn decrypt_by_version_selects_the_previous_key() {
        let (ct, nonce, version) = v1_only()
            .encrypt_versioned(b"old", b"aad")
            .expect("encrypt");
        assert_eq!(version, 1);
        let ring = v2_with_v1();
        assert_eq!(
            ring.decrypt_versioned(&ct, &nonce, b"aad", 1)
                .expect("decrypt"),
            b"old"
        );
    }

    #[test]
    fn unhinted_decrypt_falls_back_to_the_previous_key() {
        let (ct, nonce) = v1_only().encrypt(b"old", b"aad").expect("encrypt");
        let ring = v2_with_v1();
        assert_eq!(ring.decrypt(&ct, &nonce, b"aad").expect("decrypt"), b"old");
    }

    #[test]
    fn legacy_counter_version_tries_every_key() {
        // A row whose key_version is an old re-encryption counter (7) but
        // which was sealed under what is now version 1.
        let (ct, nonce) = v1_only().encrypt(b"legacy", b"aad").expect("encrypt");
        let ring = v2_with_v1();
        assert!(!ring.knows_version(7));
        assert_eq!(
            ring.decrypt_versioned(&ct, &nonce, b"aad", 7)
                .expect("decrypt"),
            b"legacy"
        );
    }

    #[test]
    fn mislabeled_known_version_still_opens_with_another_key() {
        // Sealed under version 1 but labeled 2: the hinted key fails and the
        // ring falls through to the previous key.
        let (ct, nonce) = v1_only().encrypt(b"mislabeled", b"aad").expect("encrypt");
        let ring = v2_with_v1();
        assert_eq!(
            ring.decrypt_versioned(&ct, &nonce, b"aad", 2)
                .expect("decrypt"),
            b"mislabeled"
        );
    }

    #[test]
    fn without_the_previous_key_old_rows_do_not_open() {
        let (ct, nonce) = v1_only().encrypt(b"old", b"aad").expect("encrypt");
        let ring = v2_only();
        assert!(ring.decrypt_versioned(&ct, &nonce, b"aad", 1).is_err());
        assert!(ring.decrypt(&ct, &nonce, b"aad").is_err());
    }

    #[test]
    fn versions_are_reported() {
        let ring = v2_with_v1();
        assert_eq!(ring.current_version(), 2);
        assert_eq!(ring.previous_version(), Some(1));
        assert!(ring.knows_version(1));
        assert!(ring.knows_version(2));
        assert!(!ring.knows_version(3));
        assert_eq!(v1_only().previous_version(), None);
    }

    #[test]
    fn from_secrets_rejects_bad_configurations() {
        assert!(KeyRing::from_secrets(secret("secret-one"), 0, None).is_err());
        assert!(
            KeyRing::from_secrets(secret("secret-two"), 1, Some(secret("secret-one"))).is_err()
        );
        assert!(KeyRing::from_secrets(secret("same"), 2, Some(secret("same"))).is_err());
    }

    #[test]
    fn nonce_counter_lives_on_the_current_key() {
        let ring = v2_with_v1();
        assert_eq!(ring.current().encryption_count(), 0);
        ring.encrypt(b"a", b"").expect("encrypt");
        ring.encrypt_versioned(b"b", b"").expect("encrypt");
        assert_eq!(ring.current().encryption_count(), 2);
    }
}
