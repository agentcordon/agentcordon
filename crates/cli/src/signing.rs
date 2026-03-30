use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::error::CliError;

/// Loaded workspace keypair.
pub struct Keypair {
    pub signing_key: SigningKey,
    pub verifying_key: VerifyingKey,
}

impl Keypair {
    /// Hex-encoded public key (64 chars).
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.verifying_key.to_bytes())
    }

    /// SHA-256 hash of the raw public key bytes, hex-encoded.
    pub fn pk_hash(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.verifying_key.to_bytes());
        hex::encode(hasher.finalize())
    }

    /// Full identity string: `sha256:<hash>`.
    pub fn identity(&self) -> String {
        format!("sha256:{}", self.pk_hash())
    }
}

/// Resolve the `.agentcordon/` directory from `AGTCRDN_WORKSPACE_DIR` or cwd.
pub fn workspace_dir() -> PathBuf {
    let base = std::env::var("AGTCRDN_WORKSPACE_DIR")
        .unwrap_or_else(|_| ".".to_string());
    PathBuf::from(base).join(".agentcordon")
}

/// Load the Ed25519 keypair from `.agentcordon/`, enforcing file permissions.
pub fn load_keypair() -> Result<Keypair, CliError> {
    let dir = workspace_dir();
    let key_path = dir.join("workspace.key");
    let pub_path = dir.join("workspace.pub");

    if !key_path.exists() {
        return Err(CliError::general(
            "no keypair found. Run: agentcordon init",
        ));
    }

    // Check directory permissions
    check_permissions(&dir, 0o700, "directory .agentcordon/")?;
    // Check private key permissions
    check_permissions(&key_path, 0o600, "private key workspace.key")?;

    let seed_hex = fs::read_to_string(&key_path)
        .map_err(|e| CliError::general(format!("failed to read private key: {e}")))?;
    let seed_bytes = hex::decode(seed_hex.trim())
        .map_err(|e| CliError::general(format!("invalid private key format: {e}")))?;

    let seed: [u8; 32] = seed_bytes
        .try_into()
        .map_err(|_| CliError::general("private key must be 32 bytes"))?;

    let signing_key = SigningKey::from_bytes(&seed);
    let verifying_key = signing_key.verifying_key();

    // Verify public key file matches
    if pub_path.exists() {
        let pub_hex = fs::read_to_string(&pub_path)
            .map_err(|e| CliError::general(format!("failed to read public key: {e}")))?;
        let pub_bytes = hex::decode(pub_hex.trim())
            .map_err(|e| CliError::general(format!("invalid public key format: {e}")))?;
        if pub_bytes != verifying_key.to_bytes() {
            return Err(CliError::general(
                "public key file does not match private key",
            ));
        }
    }

    Ok(Keypair {
        signing_key,
        verifying_key,
    })
}

/// Check that file/dir permissions are not more permissive than `max_mode`.
fn check_permissions(path: &Path, max_mode: u32, label: &str) -> Result<(), CliError> {
    let metadata = fs::metadata(path)
        .map_err(|e| CliError::general(format!("cannot stat {label}: {e}")))?;
    let mode = metadata.permissions().mode() & 0o777;
    if mode & !max_mode != 0 {
        return Err(CliError::general(format!(
            "{label} has permissions {mode:04o}, expected {max_mode:04o} or stricter. \
             Fix with: chmod {max_mode:04o} {}",
            path.display()
        )));
    }
    Ok(())
}

/// Build the signed payload and produce signing headers.
pub fn sign_request(
    keypair: &Keypair,
    method: &str,
    path: &str,
    body: &str,
) -> Result<SignedHeaders, CliError> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| CliError::general(format!("system clock error: {e}")))?
        .as_secs()
        .to_string();

    let signed_bytes = format!("{method}\n{path}\n{timestamp}\n{body}");
    let signature = keypair.signing_key.sign(signed_bytes.as_bytes());

    Ok(SignedHeaders {
        public_key: keypair.public_key_hex(),
        timestamp,
        signature: hex::encode(signature.to_bytes()),
    })
}

/// Headers to attach to a signed broker request.
pub struct SignedHeaders {
    pub public_key: String,
    pub timestamp: String,
    pub signature: String,
}
