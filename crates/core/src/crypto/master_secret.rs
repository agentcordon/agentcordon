//! Master-secret strength and passphrase stretching.
//!
//! HKDF is a key *derivation* function, not a password hash: it spreads the
//! entropy of its input, it does not add any. Feeding a human-chosen
//! passphrase straight into [`derive_master_key`] therefore leaves the
//! encryption key exactly as guessable as the passphrase.
//!
//! [`resolve_secret`] is the entry point every master secret passes through
//! before key derivation. It classifies the secret and, when the secret is
//! weak, stretches it with Argon2id and a random 16-byte salt persisted next
//! to the database.
//!
//! # Upgrade safety
//!
//! Stretching changes the derived key, so switching it on for an install
//! that already holds credentials would make those credentials
//! undecryptable. Stretching is therefore applied only when
//!
//! * the salt file already exists (the install was stretched before), or
//! * the store is [`StoreState::Fresh`] (nothing can be lost).
//!
//! An existing install with a weak secret and no salt file keeps the legacy
//! derivation and gets a warning naming the fix (rotate to a strong secret
//! through the key-ring procedure).
//!
//! [`derive_master_key`]: crate::crypto::key_derivation::derive_master_key

use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use crate::crypto::Argon2Params;
use crate::error::CryptoError;

/// Bytes of material a secret must carry to be used without stretching.
pub const STRONG_SECRET_BYTES: usize = 32;

/// Shannon entropy, in bits per byte, that a secret's material must reach to
/// count as random. 32 random bytes score about 4.9; an English passphrase
/// scores under 4.
pub const MIN_ENTROPY_BITS_PER_BYTE: f64 = 4.0;

/// Length of the persisted Argon2id salt.
pub const SALT_BYTES: usize = 16;

/// Name of the salt file, written next to the database.
pub const SALT_FILE_NAME: &str = ".master-salt";

/// Whether a master secret carries enough random material to feed HKDF
/// directly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretStrength {
    /// At least [`STRONG_SECRET_BYTES`] of material at or above
    /// [`MIN_ENTROPY_BITS_PER_BYTE`].
    Strong,
    /// Anything else: a passphrase, a short random string, a long repetitive
    /// one.
    Weak,
}

/// Whether the store this secret protects already holds anything sealed
/// under the master key.
///
/// The distinction decides whether a weak secret may be stretched: on a
/// first boot no ciphertext can be orphaned by the change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreState {
    /// A first boot: nothing is sealed under the master key yet.
    Fresh,
    /// Data exists and must stay decryptable.
    Populated,
}

/// How the resolved secret reached its final form.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Derivation {
    /// The secret was strong; it feeds HKDF unchanged.
    Direct,
    /// The secret was weak and was stretched with Argon2id.
    Stretched,
    /// The secret was weak but stretching it would have orphaned existing
    /// ciphertext, so it feeds HKDF unchanged, as it did before this rule.
    LegacyWeak,
}

/// The secret to feed HKDF, plus how it got there.
///
/// `Debug` redacts the secret itself.
pub struct ResolvedSecret {
    /// The material to pass to `derive_master_key`.
    pub secret: Zeroizing<String>,
    pub derivation: Derivation,
    /// Set only for [`Derivation::LegacyWeak`]: an operator-facing message
    /// naming the fix.
    pub warning: Option<String>,
}

impl std::fmt::Debug for ResolvedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResolvedSecret")
            .field("secret", &"[REDACTED]")
            .field("derivation", &self.derivation)
            .field("warning", &self.warning)
            .finish()
    }
}

/// Shannon entropy of a byte string, in bits per byte.
pub fn shannon_entropy_bits_per_byte(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for b in bytes {
        counts[*b as usize] += 1;
    }
    let len = bytes.len() as f64;
    counts
        .iter()
        .filter(|c| **c > 0)
        .map(|c| {
            let p = *c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

/// The material a secret carries: its hex decoding, its base64 decoding, or
/// its raw bytes, whichever the secret plausibly is.
///
/// A decoding is only taken when it yields at least [`STRONG_SECRET_BYTES`];
/// otherwise the raw bytes are the material, so a short base64-looking
/// string is judged as the text it is.
fn secret_material(secret: &str) -> Vec<u8> {
    use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
    use base64::Engine;

    let trimmed = secret.trim();

    if trimmed.len() >= STRONG_SECRET_BYTES * 2
        && trimmed.len().is_multiple_of(2)
        && trimmed.bytes().all(|b| b.is_ascii_hexdigit())
    {
        if let Ok(bytes) = hex::decode(trimmed) {
            if bytes.len() >= STRONG_SECRET_BYTES {
                return bytes;
            }
        }
    }

    for engine in [&URL_SAFE_NO_PAD, &STANDARD_NO_PAD, &URL_SAFE, &STANDARD] {
        if let Ok(bytes) = engine.decode(trimmed) {
            if bytes.len() >= STRONG_SECRET_BYTES {
                return bytes;
            }
        }
    }

    trimmed.as_bytes().to_vec()
}

/// Classify a master secret.
///
/// Strong means: at least 32 bytes of material carrying at least 4 bits of
/// Shannon entropy per byte, where the material is the secret's hex decoding
/// (64+ hex characters), its base64 decoding (32+ bytes), or its raw UTF-8
/// bytes (32+ characters).
pub fn classify_secret(secret: &str) -> SecretStrength {
    let material = secret_material(secret);
    if material.len() >= STRONG_SECRET_BYTES
        && shannon_entropy_bits_per_byte(&material) >= MIN_ENTROPY_BITS_PER_BYTE
    {
        SecretStrength::Strong
    } else {
        SecretStrength::Weak
    }
}

/// The salt file that sits next to `db_path`.
pub fn salt_file_path(db_path: &str) -> PathBuf {
    let db = Path::new(db_path);
    let parent = db.parent().unwrap_or(Path::new("."));
    parent.join(SALT_FILE_NAME)
}

/// Stretch `secret` into 32 bytes of key material with Argon2id, returned
/// hex-encoded so it can feed HKDF in place of the raw secret.
pub fn stretch_secret(
    secret: &str,
    salt: &[u8],
    params: Argon2Params,
) -> Result<Zeroizing<String>, CryptoError> {
    let mut out = Zeroizing::new([0u8; 32]);
    params
        .build()
        .hash_password_into(secret.as_bytes(), salt, out.as_mut())
        .map_err(|e| CryptoError::KeyDerivation(format!("Argon2id stretching failed: {e}")))?;
    Ok(Zeroizing::new(hex::encode(out.as_ref())))
}

fn read_salt(path: &Path) -> Result<Option<Vec<u8>>, CryptoError> {
    match std::fs::read_to_string(path) {
        Ok(contents) => {
            let salt = hex::decode(contents.trim()).map_err(|e| {
                CryptoError::KeyDerivation(format!(
                    "master salt file {} is not hex: {e}",
                    path.display()
                ))
            })?;
            if salt.len() < SALT_BYTES {
                return Err(CryptoError::KeyDerivation(format!(
                    "master salt file {} holds {} bytes, expected at least {SALT_BYTES}",
                    path.display(),
                    salt.len()
                )));
            }
            Ok(Some(salt))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(CryptoError::KeyDerivation(format!(
            "failed to read master salt file {}: {e}",
            path.display()
        ))),
    }
}

fn create_salt(path: &Path) -> Result<Vec<u8>, CryptoError> {
    use rand::RngCore;

    let mut salt = vec![0u8; SALT_BYTES];
    rand::rngs::OsRng.fill_bytes(&mut salt);

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            CryptoError::KeyDerivation(format!(
                "failed to create directory {} for the master salt: {e}",
                parent.display()
            ))
        })?;
    }

    let encoded = hex::encode(&salt);
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| {
                CryptoError::KeyDerivation(format!(
                    "failed to create master salt file {}: {e}",
                    path.display()
                ))
            })?;
        file.write_all(encoded.as_bytes()).map_err(|e| {
            CryptoError::KeyDerivation(format!(
                "failed to write master salt file {}: {e}",
                path.display()
            ))
        })?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, encoded.as_bytes()).map_err(|e| {
            CryptoError::KeyDerivation(format!(
                "failed to write master salt file {}: {e}",
                path.display()
            ))
        })?;
    }

    Ok(salt)
}

/// The message logged when a weak secret is kept unstretched because the
/// store already holds credentials.
fn legacy_warning(variable: &str) -> String {
    format!(
        "{variable} carries less than {STRONG_SECRET_BYTES} bytes of random material. \
         It is used unstretched because this database already holds credentials and \
         stretching it now would make them undecryptable. Fix: rotate to a strong secret \
         (64 hex characters, or 32 random bytes) with the key-ring procedure in \
         docs/master-key.md — set AGTCRDN_PREVIOUS_MASTER_SECRET to the current secret, \
         bump AGTCRDN_MASTER_KEY_VERSION, restart, then POST /api/v1/admin/rotate-key."
    )
}

/// Resolve a master secret into the material HKDF should use.
///
/// `salt_path` is where the Argon2id salt lives; pass `None` when there is
/// nowhere to persist one (an in-memory database, a test harness), which
/// forces the legacy path without a warning. `variable` names the
/// environment variable in the warning text.
pub fn resolve_secret(
    secret: &str,
    salt_path: Option<&Path>,
    store_state: StoreState,
    params: Argon2Params,
    variable: &str,
) -> Result<ResolvedSecret, CryptoError> {
    if classify_secret(secret) == SecretStrength::Strong {
        return Ok(ResolvedSecret {
            secret: Zeroizing::new(secret.to_string()),
            derivation: Derivation::Direct,
            warning: None,
        });
    }

    let legacy = |warning: Option<String>| ResolvedSecret {
        secret: Zeroizing::new(secret.to_string()),
        derivation: Derivation::LegacyWeak,
        warning,
    };

    let Some(salt_path) = salt_path else {
        return Ok(legacy(None));
    };

    let salt = match read_salt(salt_path)? {
        Some(salt) => salt,
        None => match store_state {
            StoreState::Fresh => create_salt(salt_path)?,
            StoreState::Populated => {
                return Ok(legacy(Some(legacy_warning(variable))));
            }
        },
    };

    Ok(ResolvedSecret {
        secret: stretch_secret(secret, &salt, params)?,
        derivation: Derivation::Stretched,
        warning: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params() -> Argon2Params {
        Argon2Params::FAST
    }

    fn random_hex_secret() -> String {
        use rand::RngCore;
        let mut bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        hex::encode(bytes)
    }

    // --- classification ---

    #[test]
    fn sixty_four_hex_characters_are_strong() {
        assert_eq!(
            classify_secret(&random_hex_secret()),
            SecretStrength::Strong
        );
    }

    #[test]
    fn base64_of_thirty_two_random_bytes_is_strong() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        use rand::RngCore;
        let mut bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        let secret = URL_SAFE_NO_PAD.encode(bytes);
        assert_eq!(secret.len(), 43);
        assert_eq!(classify_secret(&secret), SecretStrength::Strong);
    }

    #[test]
    fn every_generated_random_secret_classifies_strong() {
        // The entropy floor must not reject the material the server itself
        // generates: 32 random bytes score ~4.9 bits per byte.
        for _ in 0..200 {
            let secret = random_hex_secret();
            assert_eq!(
                classify_secret(&secret),
                SecretStrength::Strong,
                "{secret} must be strong"
            );
        }
    }

    #[test]
    fn shannon_entropy_separates_random_material_from_a_passphrase() {
        use rand::RngCore;
        let mut random = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut random);
        let random_entropy = shannon_entropy_bits_per_byte(&random);
        let passphrase_entropy = shannon_entropy_bits_per_byte(b"correct horse battery staple pls");

        assert!(
            random_entropy >= MIN_ENTROPY_BITS_PER_BYTE,
            "32 random bytes scored {random_entropy}"
        );
        assert!(
            passphrase_entropy < MIN_ENTROPY_BITS_PER_BYTE,
            "a 32-character passphrase scored {passphrase_entropy}"
        );
        assert_eq!(shannon_entropy_bits_per_byte(&[7u8; 64]), 0.0);
        assert_eq!(shannon_entropy_bits_per_byte(&[]), 0.0);
    }

    #[test]
    fn a_long_passphrase_is_weak() {
        assert_eq!(
            classify_secret("correct horse battery staple pls"),
            SecretStrength::Weak
        );
    }

    #[test]
    fn a_short_random_secret_is_weak() {
        // 16 random-looking characters: high entropy per byte, not enough
        // material.
        assert_eq!(classify_secret("Xq7#mZ2!vB9$kR4%"), SecretStrength::Weak);
    }

    #[test]
    fn a_long_repetitive_secret_is_weak_even_though_it_decodes_as_base64() {
        // 43 'a's decode as base64 into 32 bytes; the entropy floor is what
        // catches it.
        let secret = "a".repeat(43);
        assert_eq!(classify_secret(&secret), SecretStrength::Weak);
    }

    // --- stretching ---

    #[test]
    fn stretching_is_deterministic_and_salt_dependent() {
        let a = stretch_secret("passphrase", b"sixteen-byte-sal", params()).expect("stretch");
        let b = stretch_secret("passphrase", b"sixteen-byte-sal", params()).expect("stretch");
        let c = stretch_secret("passphrase", b"another-16-bytes", params()).expect("stretch");
        assert_eq!(*a, *b);
        assert_ne!(*a, *c);
        assert_eq!(a.len(), 64, "stretched material is 32 bytes, hex-encoded");
    }

    // --- the three branches ---

    #[test]
    fn a_strong_secret_derives_directly_and_writes_no_salt() {
        let dir = tempfile::tempdir().expect("tempdir");
        let salt = dir.path().join(SALT_FILE_NAME);
        let secret = random_hex_secret();

        let resolved = resolve_secret(
            &secret,
            Some(&salt),
            StoreState::Fresh,
            params(),
            "AGTCRDN_MASTER_SECRET",
        )
        .expect("resolve");

        assert_eq!(resolved.derivation, Derivation::Direct);
        assert_eq!(*resolved.secret, secret);
        assert!(resolved.warning.is_none());
        assert!(!salt.exists(), "a strong secret needs no salt file");
    }

    #[test]
    fn a_fresh_install_stretches_a_weak_secret_and_persists_the_salt() {
        let dir = tempfile::tempdir().expect("tempdir");
        let salt = dir.path().join(SALT_FILE_NAME);

        let resolved = resolve_secret(
            "short-passphrase",
            Some(&salt),
            StoreState::Fresh,
            params(),
            "AGTCRDN_MASTER_SECRET",
        )
        .expect("resolve");

        assert_eq!(resolved.derivation, Derivation::Stretched);
        assert_ne!(*resolved.secret, "short-passphrase");
        assert!(resolved.warning.is_none());
        assert!(salt.exists(), "the salt must be persisted");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&salt)
                .expect("metadata")
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "salt file must be owner-only");
        }
    }

    #[test]
    fn a_persisted_salt_is_reused_so_the_key_is_stable_across_restarts() {
        let dir = tempfile::tempdir().expect("tempdir");
        let salt = dir.path().join(SALT_FILE_NAME);

        let first = resolve_secret(
            "short-passphrase",
            Some(&salt),
            StoreState::Fresh,
            params(),
            "AGTCRDN_MASTER_SECRET",
        )
        .expect("first boot");
        let salt_bytes = std::fs::read(&salt).expect("salt file");

        // A later boot: credentials now exist, and the salt file decides.
        let second = resolve_secret(
            "short-passphrase",
            Some(&salt),
            StoreState::Populated,
            params(),
            "AGTCRDN_MASTER_SECRET",
        )
        .expect("second boot");

        assert_eq!(second.derivation, Derivation::Stretched);
        assert_eq!(*first.secret, *second.secret);
        assert_eq!(
            salt_bytes,
            std::fs::read(&salt).expect("salt file"),
            "the salt is never rotated automatically"
        );
    }

    #[test]
    fn an_existing_install_without_a_salt_keeps_the_legacy_derivation() {
        let dir = tempfile::tempdir().expect("tempdir");
        let salt = dir.path().join(SALT_FILE_NAME);

        let resolved = resolve_secret(
            "short-passphrase",
            Some(&salt),
            StoreState::Populated,
            params(),
            "AGTCRDN_MASTER_SECRET",
        )
        .expect("resolve");

        assert_eq!(resolved.derivation, Derivation::LegacyWeak);
        assert_eq!(
            *resolved.secret, "short-passphrase",
            "the derived key must not change on upgrade"
        );
        assert!(!salt.exists(), "no salt is written on the legacy path");
        let warning = resolved.warning.expect("a warning names the fix");
        assert!(warning.contains("AGTCRDN_MASTER_SECRET"), "{warning}");
        assert!(warning.contains("rotate"), "{warning}");
        assert!(warning.contains("docs/master-key.md"), "{warning}");
    }

    #[test]
    fn without_a_salt_path_a_weak_secret_is_used_as_is_and_stays_quiet() {
        let resolved = resolve_secret(
            "short-passphrase",
            None,
            StoreState::Fresh,
            params(),
            "AGTCRDN_MASTER_SECRET",
        )
        .expect("resolve");
        assert_eq!(resolved.derivation, Derivation::LegacyWeak);
        assert_eq!(*resolved.secret, "short-passphrase");
        assert!(resolved.warning.is_none());
    }

    #[test]
    fn a_corrupt_salt_file_is_an_error_rather_than_a_new_key() {
        let dir = tempfile::tempdir().expect("tempdir");
        let salt = dir.path().join(SALT_FILE_NAME);
        std::fs::write(&salt, "not hex at all").expect("write");

        let err = resolve_secret(
            "short-passphrase",
            Some(&salt),
            StoreState::Populated,
            params(),
            "AGTCRDN_MASTER_SECRET",
        )
        .expect_err("a corrupt salt must not be silently replaced");
        assert!(format!("{err}").contains("not hex"), "{err}");
    }

    #[test]
    fn salt_file_sits_next_to_the_database() {
        assert_eq!(
            salt_file_path("/var/lib/agentcordon/agent-cordon.db"),
            PathBuf::from("/var/lib/agentcordon/.master-salt")
        );
    }
}
