//! The workspace key and the names derived from it.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::request::VerifyError;

/// Prefix of the identity string: `sha256:<pk_hash>`.
pub const IDENTITY_PREFIX: &str = "sha256:";

/// A workspace's Ed25519 key.
///
/// The CLI holds one of these per workspace directory; the broker only ever
/// sees the public half over the wire.
#[derive(Clone)]
pub struct WorkspaceKey {
    signing_key: SigningKey,
}

impl WorkspaceKey {
    /// Generate a fresh key from the OS CSPRNG.
    pub fn generate() -> Self {
        Self {
            signing_key: SigningKey::generate(&mut rand::rngs::OsRng),
        }
    }

    /// Rebuild a key from its 32-byte seed (the bytes stored in `workspace.key`).
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self {
            signing_key: SigningKey::from_bytes(seed),
        }
    }

    /// The 32-byte seed as lowercase hex: the exact body of `workspace.key`.
    pub fn seed_hex(&self) -> String {
        hex::encode(self.signing_key.to_bytes())
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Raw 32-byte public key.
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    /// Hex-encoded public key (64 chars): the `X-AC-PublicKey` header value
    /// and the body of `workspace.pub`.
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.public_key_bytes())
    }

    /// SHA-256 of the raw public key bytes, lowercase hex. The broker and
    /// server key workspace state by this.
    pub fn pk_hash(&self) -> String {
        pk_hash_of(&self.public_key_bytes())
    }

    /// Full identity string: `sha256:<pk_hash>`.
    pub fn identity(&self) -> String {
        identity_string(&self.pk_hash())
    }

    /// Sign arbitrary bytes. Prefer [`crate::sign_request`] and
    /// [`crate::sign_register`], which fix the payload; this exists for the
    /// payload builders and for tests.
    pub fn sign(&self, message: &[u8]) -> Signature {
        self.signing_key.sign(message)
    }
}

impl From<SigningKey> for WorkspaceKey {
    fn from(signing_key: SigningKey) -> Self {
        Self { signing_key }
    }
}

impl std::fmt::Debug for WorkspaceKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WorkspaceKey")
            .field("public_key", &self.public_key_hex())
            .finish_non_exhaustive()
    }
}

/// `pk_hash` of raw public key bytes: SHA-256, lowercase hex.
pub fn pk_hash_of(public_key: &[u8]) -> String {
    hex::encode(Sha256::digest(public_key))
}

/// `pk_hash` of a hex-encoded public key (hashes the decoded raw bytes).
///
/// Fails only on non-hex input; the length is not checked here because a
/// caller that needs a usable key has already gone through
/// [`crate::verify_request`] or [`crate::verify_register`].
pub fn pk_hash_from_hex(public_key_hex: &str) -> Result<String, VerifyError> {
    let bytes = hex::decode(public_key_hex).map_err(|_| VerifyError::InvalidPublicKey)?;
    Ok(pk_hash_of(&bytes))
}

/// Identity string for a `pk_hash`: `sha256:<pk_hash>`.
pub fn identity_string(pk_hash: &str) -> String {
    format!("{IDENTITY_PREFIX}{pk_hash}")
}

/// Parse a hex public key into a verifying key: must be 64 hex chars
/// encoding a valid Ed25519 point.
pub(crate) fn parse_public_key(public_key_hex: &str) -> Result<VerifyingKey, VerifyError> {
    let bytes = hex::decode(public_key_hex).map_err(|_| VerifyError::InvalidPublicKey)?;
    let array: [u8; 32] = bytes
        .try_into()
        .map_err(|_| VerifyError::InvalidPublicKey)?;
    VerifyingKey::from_bytes(&array).map_err(|_| VerifyError::InvalidPublicKey)
}

/// Parse a hex signature: must be 128 hex chars.
pub(crate) fn parse_signature(signature_hex: &str) -> Result<Signature, VerifyError> {
    let bytes = hex::decode(signature_hex).map_err(|_| VerifyError::InvalidSignature)?;
    let array: [u8; 64] = bytes
        .try_into()
        .map_err(|_| VerifyError::InvalidSignature)?;
    Ok(Signature::from_bytes(&array))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pk_hash_is_64_hex_chars_of_raw_bytes() {
        let key = WorkspaceKey::generate();
        let hash = key.pk_hash();
        assert_eq!(hash.len(), 64);
        assert!(hash
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()));
        assert_eq!(pk_hash_from_hex(&key.public_key_hex()).unwrap(), hash);
        assert_eq!(key.identity(), format!("sha256:{hash}"));
    }

    #[test]
    fn pk_hash_from_hex_rejects_non_hex() {
        assert!(matches!(
            pk_hash_from_hex("not hex"),
            Err(VerifyError::InvalidPublicKey)
        ));
    }

    #[test]
    fn parse_public_key_rejects_wrong_length() {
        assert!(parse_public_key("abcd").is_err());
        assert!(parse_public_key(&"ab".repeat(33)).is_err());
        let key = WorkspaceKey::generate();
        assert!(parse_public_key(&key.public_key_hex()).is_ok());
    }

    #[test]
    fn debug_does_not_print_the_seed() {
        let key = WorkspaceKey::generate();
        let shown = format!("{key:?}");
        assert!(shown.contains(&key.public_key_hex()));
        assert!(!shown.contains(&key.seed_hex()));
    }
}
