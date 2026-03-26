use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use argon2::Argon2;
use async_trait::async_trait;
use p256::SecretKey;
use rand::RngCore;
use zeroize::Zeroizing;

use agent_cordon_core::crypto::ed25519;

/// Errors from key storage operations.
#[derive(Debug, thiserror::Error)]
pub enum KeyStorageError {
    #[error("key not found")]
    NotFound,
    #[error("IO error: {0}")]
    Io(String),
    #[error("crypto error: {0}")]
    Crypto(String),
}

/// Pluggable key storage backend for P-256 encryption private keys.
#[async_trait]
pub trait KeyStorage: Send + Sync {
    /// Load the P-256 encryption private key, if it exists.
    async fn load_encryption_key(&self) -> Result<Option<Zeroizing<Vec<u8>>>, KeyStorageError>;

    /// Store the P-256 encryption private key.
    async fn store_encryption_key(&self, key_bytes: &[u8]) -> Result<(), KeyStorageError>;

    /// Delete key from storage.
    async fn delete_keys(&self) -> Result<(), KeyStorageError>;
}

/// Encrypted file-based key storage.
///
/// Stores P-256 private keys as AES-256-GCM encrypted files on disk,
/// with the encryption key derived from a user-provided passphrase via Argon2id.
pub struct EncryptedFileKeyStorage {
    /// Base directory for key files.
    pub base_path: PathBuf,
    /// Passphrase used to derive the file encryption key.
    pub passphrase: Option<String>,
}

/// Build an Argon2id instance with production-grade or test-friendly parameters.
fn build_argon2<'a>() -> Argon2<'a> {
    #[cfg(test)]
    {
        Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            argon2::Params::new(256, 1, 1, None).unwrap(), // lightweight for tests
        )
    }
    #[cfg(not(test))]
    {
        Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            argon2::Params::new(65536, 3, 4, None).unwrap(), // 64 MiB, 3 iterations, 4 lanes
        )
    }
}

/// Derive a 256-bit AES key from a passphrase and salt using Argon2id.
fn derive_file_key(passphrase: &str, salt: &[u8]) -> Result<Zeroizing<[u8; 32]>, KeyStorageError> {
    let argon2 = build_argon2();
    let mut key = Zeroizing::new([0u8; 32]);
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, key.as_mut())
        .map_err(|e| KeyStorageError::Crypto(format!("key derivation failed: {e}")))?;
    Ok(key)
}

/// Encrypt plaintext with AES-256-GCM using a key derived from the passphrase.
/// Returns file contents: salt (16 bytes) || nonce (12 bytes) || ciphertext.
fn encrypt_key_material(passphrase: &str, plaintext: &[u8]) -> Result<Vec<u8>, KeyStorageError> {
    let mut salt = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut salt);

    let key = derive_file_key(passphrase, &salt)?;
    let cipher = Aes256Gcm::new_from_slice(key.as_ref())
        .map_err(|e| KeyStorageError::Crypto(e.to_string()))?;

    let mut nonce_bytes = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from(nonce_bytes);

    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| KeyStorageError::Crypto(format!("encryption failed: {e}")))?;

    let mut data = Vec::with_capacity(16 + 12 + ciphertext.len());
    data.extend_from_slice(&salt);
    data.extend_from_slice(&nonce_bytes);
    data.extend_from_slice(&ciphertext);
    Ok(data)
}

/// Decrypt file contents (salt || nonce || ciphertext) using passphrase-derived key.
fn decrypt_key_material(
    passphrase: &str,
    data: &[u8],
) -> Result<Zeroizing<Vec<u8>>, KeyStorageError> {
    if data.len() < 28 {
        return Err(KeyStorageError::Crypto(
            "encrypted file too short".to_string(),
        ));
    }

    let salt = &data[..16];
    let nonce_bytes = &data[16..28];
    let ciphertext = &data[28..];

    let key = derive_file_key(passphrase, salt)?;
    let cipher = Aes256Gcm::new_from_slice(key.as_ref())
        .map_err(|e| KeyStorageError::Crypto(e.to_string()))?;
    let nonce_arr: [u8; 12] = nonce_bytes
        .try_into()
        .map_err(|_| KeyStorageError::Crypto("invalid nonce length".to_string()))?;
    let nonce = Nonce::from(nonce_arr);

    let plaintext = cipher
        .decrypt(&nonce, ciphertext)
        .map_err(|e| KeyStorageError::Crypto(format!("decryption failed: {e}")))?;

    Ok(Zeroizing::new(plaintext))
}

impl EncryptedFileKeyStorage {
    fn encryption_key_path(&self) -> PathBuf {
        self.base_path.join("encryption.key.enc")
    }

    fn passphrase(&self) -> Result<&str, KeyStorageError> {
        self.passphrase
            .as_deref()
            .ok_or_else(|| KeyStorageError::Crypto("passphrase not configured".to_string()))
    }

    /// Encrypt key bytes and write to disk with 0600 permissions.
    async fn encrypt_and_store(
        &self,
        path: PathBuf,
        plaintext: &[u8],
    ) -> Result<(), KeyStorageError> {
        let passphrase = self.passphrase()?.to_string();
        let plaintext = plaintext.to_vec();

        tokio::task::spawn_blocking(move || {
            let data = encrypt_key_material(&passphrase, &plaintext)?;

            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).map_err(|e| KeyStorageError::Io(e.to_string()))?;
            }

            std::fs::write(&path, &data).map_err(|e| KeyStorageError::Io(e.to_string()))?;

            #[cfg(unix)]
            {
                let perms = std::fs::Permissions::from_mode(0o600);
                std::fs::set_permissions(&path, perms)
                    .map_err(|e| KeyStorageError::Io(e.to_string()))?;
            }

            Ok(())
        })
        .await
        .map_err(|e| KeyStorageError::Io(format!("task join error: {e}")))?
    }

    /// Read encrypted file and decrypt. Returns None if file does not exist.
    async fn load_and_decrypt(
        &self,
        path: PathBuf,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, KeyStorageError> {
        let passphrase = self.passphrase()?.to_string();

        tokio::task::spawn_blocking(move || {
            let data = match std::fs::read(&path) {
                Ok(d) => d,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                Err(e) => return Err(KeyStorageError::Io(e.to_string())),
            };

            decrypt_key_material(&passphrase, &data).map(Some)
        })
        .await
        .map_err(|e| KeyStorageError::Io(format!("task join error: {e}")))?
    }
}

#[async_trait]
impl KeyStorage for EncryptedFileKeyStorage {
    async fn load_encryption_key(&self) -> Result<Option<Zeroizing<Vec<u8>>>, KeyStorageError> {
        self.load_and_decrypt(self.encryption_key_path()).await
    }

    async fn store_encryption_key(&self, key_bytes: &[u8]) -> Result<(), KeyStorageError> {
        self.encrypt_and_store(self.encryption_key_path(), key_bytes)
            .await
    }

    async fn delete_keys(&self) -> Result<(), KeyStorageError> {
        let path = self.encryption_key_path();
        match tokio::fs::remove_file(&path).await {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(KeyStorageError::Io(e.to_string())),
        }
        Ok(())
    }
}

/// Workspace identity — Ed25519 for authentication + P-256 for ECIES encryption.
///
/// The workspace IS the device. One identity. One JWT.
pub struct WorkspaceIdentity {
    /// Ed25519 private key for challenge-response authentication.
    pub ed25519_key: ed25519_dalek::SigningKey,
    /// P-256 private key for ECIES credential decryption (`use: enc`).
    pub encryption_key: SecretKey,
    /// SHA-256 hash of the Ed25519 public key (hex), with `sha256:` prefix.
    pub pk_hash: String,
}

impl WorkspaceIdentity {
    /// Load workspace identity from a directory containing Ed25519 + P-256 keys.
    ///
    /// Expects:
    /// - `workspace.key` / `workspace.pub` — Ed25519 keypair
    /// - `encryption.key` / `encryption.pub` — P-256 keypair (raw 32-byte scalar / 65-byte point)
    pub fn load_from_dir(dir: &Path) -> Result<Self, String> {
        let ed25519_key = ed25519::load_keypair(dir)
            .map_err(|e| format!("failed to load Ed25519 keypair: {}", e))?;

        let enc_key_path = dir.join("encryption.key");
        let enc_key_bytes = std::fs::read(&enc_key_path)
            .map_err(|e| format!("failed to read encryption key: {}", e))?;
        let encryption_key = SecretKey::from_slice(&enc_key_bytes)
            .map_err(|e| format!("invalid P-256 encryption key: {}", e))?;

        let pubkey = ed25519_key.verifying_key();
        let pk_hash_hex = ed25519::compute_pk_hash(&pubkey.to_bytes());
        let pk_hash = format!("sha256:{}", pk_hash_hex);

        Ok(Self {
            ed25519_key,
            encryption_key,
            pk_hash,
        })
    }

    /// Generate a new ephemeral identity with random keys.
    ///
    /// Intended for development/bootstrap; keys are not persisted.
    pub fn new_ephemeral() -> Self {
        let mut rng = rand::rngs::OsRng;
        let ed25519_key = ed25519_dalek::SigningKey::generate(&mut rng);
        let pubkey = ed25519_key.verifying_key();
        let pk_hash_hex = ed25519::compute_pk_hash(&pubkey.to_bytes());
        let pk_hash = format!("sha256:{}", pk_hash_hex);

        Self {
            ed25519_key,
            encryption_key: SecretKey::random(&mut rng),
            pk_hash,
        }
    }

    /// Save P-256 encryption keypair to a directory (raw format, 0600 perms).
    pub fn save_encryption_key(dir: &Path, secret_key: &SecretKey) -> Result<(), String> {
        use p256::elliptic_curve::sec1::ToEncodedPoint;

        let key_path = dir.join("encryption.key");
        let pub_path = dir.join("encryption.pub");

        // Save raw 32-byte secret scalar
        std::fs::write(&key_path, &*secret_key.to_bytes())
            .map_err(|e| format!("failed to write encryption key: {}", e))?;

        // Save uncompressed 65-byte public point
        let pubkey = secret_key.public_key();
        let point = pubkey.to_encoded_point(false);
        std::fs::write(&pub_path, point.as_bytes())
            .map_err(|e| format!("failed to write encryption public key: {}", e))?;

        #[cfg(unix)]
        {
            let perms = std::fs::Permissions::from_mode(0o600);
            std::fs::set_permissions(&key_path, perms)
                .map_err(|e| format!("failed to set permissions: {}", e))?;
        }

        Ok(())
    }

    /// Check if encryption keys exist in a directory.
    pub fn has_encryption_key(dir: &Path) -> bool {
        dir.join("encryption.key").exists() && dir.join("encryption.pub").exists()
    }

    /// Get the P-256 encryption public key fingerprint (SHA-256 of uncompressed point, hex).
    pub fn encryption_fingerprint(&self) -> String {
        use p256::elliptic_curve::sec1::ToEncodedPoint;
        use sha2::{Digest, Sha256};

        let pubkey = self.encryption_key.public_key();
        let point = pubkey.to_encoded_point(false);
        let hash = Sha256::digest(point.as_bytes());
        hex::encode(hash)
    }
}
