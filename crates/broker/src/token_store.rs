//! Encrypted at-rest storage of OAuth tokens.
//!
//! Tokens are serialized to JSON, then encrypted with AES-256-GCM using
//! a key derived from the broker's P-256 private key via HKDF.

use std::collections::HashMap;
use std::path::Path;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;
use tracing::warn;
use zeroize::Zeroizing;

use crate::state::{RecoveryEntry, SharedState, WorkspaceState};

const HKDF_SALT: &[u8] = b"agentcordon:broker-token-store-salt-v1";
const HKDF_INFO: &[u8] = b"agentcordon:broker-token-store-v1";
const NONCE_LEN: usize = 12;

/// Derive an AES-256-GCM key from the P-256 private key via HKDF.
///
/// NOTE: Changing the salt is a breaking change — existing encrypted token
/// stores will fail to decrypt and will need re-encryption on upgrade.
fn derive_encryption_key(p256_key: &p256::SecretKey) -> Zeroizing<[u8; 32]> {
    let key_bytes = p256_key.to_bytes();
    let hk = Hkdf::<Sha256>::new(Some(HKDF_SALT), key_bytes.as_ref());
    let mut okm = Zeroizing::new([0u8; 32]);
    hk.expand(HKDF_INFO, okm.as_mut())
        .expect("HKDF expand should not fail for 32-byte output");
    okm
}

/// Encrypt workspace states and write to disk.
pub fn save(
    path: &Path,
    workspaces: &HashMap<String, WorkspaceState>,
    p256_key: &p256::SecretKey,
) -> Result<(), String> {
    let plaintext =
        serde_json::to_vec(workspaces).map_err(|e| format!("serialize failed: {}", e))?;

    let aes_key = derive_encryption_key(p256_key);
    let cipher = Aes256Gcm::new_from_slice(aes_key.as_ref())
        .map_err(|e| format!("cipher init failed: {}", e))?;

    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce_bytes);
    let nonce = Nonce::from(nonce_bytes);

    let ciphertext = cipher
        .encrypt(&nonce, plaintext.as_ref())
        .map_err(|e| format!("encryption failed: {}", e))?;

    // Format: nonce (12 bytes) || ciphertext
    let mut output = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&ciphertext);

    // Atomic write: write to a temp file created owner-only, then rename
    // into place. This prevents data loss if the process crashes mid-write
    // and never leaves the ciphertext readable by other users.
    let tmp_path = path.with_extension("tmp");
    write_private_file(&tmp_path, &output).map_err(|e| format!("write failed: {}", e))?;
    std::fs::rename(&tmp_path, path).map_err(|e| format!("rename failed: {}", e))?;

    Ok(())
}

/// Create (or truncate) `path` with mode `0600` and write `contents`.
///
/// The mode is passed to `open(2)` so the file never exists with wider
/// permissions; an existing file is also chmod'ed to `0600` because
/// `open` does not change the mode of a file that already exists. Every
/// artifact the broker writes goes through here.
pub fn write_private_file(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts.open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    file.write_all(contents)?;
    file.flush()
}

/// Load and decrypt workspace states from disk.
///
/// Returns `Err` if the file does not exist or cannot be decrypted,
/// allowing callers to fall back to the recovery store.
pub fn load(
    path: &Path,
    p256_key: &p256::SecretKey,
) -> Result<Option<HashMap<String, WorkspaceState>>, String> {
    // A broker that has never registered a workspace has no store yet. That
    // is the first run, not a failure, and the caller must be able to tell
    // the two apart: a missing file needs no recovery and no warning, while
    // an unreadable one needs both.
    if !path.exists() {
        return Ok(None);
    }

    let data = std::fs::read(path).map_err(|e| format!("read failed: {}", e))?;
    if data.len() < NONCE_LEN + 1 {
        return Err("token store file too short".to_string());
    }

    let (nonce_bytes, ciphertext) = data.split_at(NONCE_LEN);
    let nonce_arr: [u8; NONCE_LEN] = nonce_bytes
        .try_into()
        .map_err(|_| "invalid nonce length".to_string())?;
    let nonce = Nonce::from(nonce_arr);

    let aes_key = derive_encryption_key(p256_key);
    let cipher = Aes256Gcm::new_from_slice(aes_key.as_ref())
        .map_err(|e| format!("cipher init failed: {}", e))?;

    let plaintext = cipher
        .decrypt(&nonce, ciphertext)
        .map_err(|_| "decryption failed — key may have changed".to_string())?;

    let workspaces: HashMap<String, WorkspaceState> =
        serde_json::from_slice(&plaintext).map_err(|e| format!("deserialize failed: {}", e))?;

    Ok(Some(workspaces))
}

// ---------------------------------------------------------------------------
// Plaintext recovery store (`workspaces.json`)
// ---------------------------------------------------------------------------

/// Write the recovery store to disk.
///
/// Performs an atomic write (temp + rename) and sets file permissions to 0600
/// on Unix to protect the refresh tokens at rest.
pub fn save_recovery(path: &Path, entries: &HashMap<String, RecoveryEntry>) -> Result<(), String> {
    let json = serde_json::to_vec_pretty(entries)
        .map_err(|e| format!("serialize recovery store failed: {e}"))?;

    let tmp_path = path.with_extension("json.tmp");
    std::fs::write(&tmp_path, &json).map_err(|e| format!("write recovery store failed: {e}"))?;

    // Set restrictive permissions before renaming into place
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(&tmp_path, perms)
            .map_err(|e| format!("set recovery store permissions failed: {e}"))?;
    }

    std::fs::rename(&tmp_path, path).map_err(|e| format!("rename recovery store failed: {e}"))?;

    Ok(())
}

/// Load the recovery store from disk.
///
/// Returns an empty map if the file does not exist or cannot be parsed.
/// Warns on parse failure so operators can investigate corruption.
pub fn load_recovery(path: &Path) -> HashMap<String, RecoveryEntry> {
    if !path.exists() {
        return HashMap::new();
    }

    // Warn if file permissions are too open
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(metadata) = std::fs::metadata(path) {
            let mode = metadata.permissions().mode() & 0o777;
            if mode != 0o600 {
                warn!(
                    path = %path.display(),
                    mode = format!("{mode:o}"),
                    "recovery store has too-open permissions (expected 0600)"
                );
            }
        }
    }

    match std::fs::read(path) {
        Ok(data) => match serde_json::from_slice::<HashMap<String, RecoveryEntry>>(&data) {
            Ok(entries) => entries,
            Err(e) => {
                warn!(
                    error = %e,
                    path = %path.display(),
                    "failed to parse recovery store, returning empty"
                );
                HashMap::new()
            }
        },
        Err(e) => {
            warn!(
                error = %e,
                path = %path.display(),
                "failed to read recovery store, returning empty"
            );
            HashMap::new()
        }
    }
}

/// Convenience helper: read all workspaces from shared state, map to recovery
/// entries, and save to disk.
///
/// Called from multiple persistence points (device approval, refresh,
/// deregister, shutdown) to keep the recovery store in sync.
pub async fn save_recovery_store(state: &SharedState) {
    let entries: HashMap<String, RecoveryEntry> = {
        let workspaces = state.workspaces.read().await;
        workspaces
            .iter()
            .map(|(pk_hash, ws)| (pk_hash.clone(), ws.to_recovery_entry()))
            .collect()
    };

    if let Err(e) = save_recovery(&state.config.recovery_store_path(), &entries) {
        warn!(error = %e, "failed to save recovery store");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use p256::elliptic_curve::rand_core::OsRng;

    #[cfg(unix)]
    #[test]
    fn token_store_is_written_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let key = p256::SecretKey::random(&mut OsRng);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tokens.enc");

        save(&path, &HashMap::new(), &key).unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "tokens.enc mode {mode:o}");
        assert!(!dir.path().join("tokens.tmp").exists());
    }

    #[cfg(unix)]
    #[test]
    fn write_private_file_tightens_an_existing_wider_file() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f");
        std::fs::write(&path, b"old").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        write_private_file(&path, b"new").unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert_eq!(std::fs::read(&path).unwrap(), b"new");
    }

    /// A broker starting for the first time has no `tokens.enc` yet. That is
    /// the normal first run, not a failure: reporting it as one made the
    /// daemon warn "encrypted token store failed, attempting recovery" at
    /// the very first command a new user ran, which reads like data loss.
    #[test]
    fn a_token_store_that_does_not_exist_yet_is_not_a_failure() {
        let key = p256::SecretKey::random(&mut OsRng);
        // A private temp dir, so the file is guaranteed absent: a fixed
        // /tmp path could be occupied by another run and the assertion
        // would then hold for the wrong reason.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nonexistent-token-store");

        let result = load(&path, &key);

        assert!(
            matches!(result, Ok(None)),
            "an absent store is `Ok(None)`, not an error: {result:?}"
        );
    }

    /// A store that exists but cannot be opened *is* a failure, and stays
    /// one: a wrong key or a truncated file is exactly what recovery is for.
    #[test]
    fn a_token_store_that_cannot_be_read_is_still_a_failure() {
        let key = p256::SecretKey::random(&mut OsRng);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tokens.enc");
        std::fs::write(&path, b"not an encrypted token store").unwrap();

        assert!(load(&path, &key).is_err());
    }

    /// A store that is there and readable comes back as itself.
    #[test]
    fn a_saved_token_store_loads_back() {
        let key = p256::SecretKey::random(&mut OsRng);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tokens.enc");
        save(&path, &HashMap::new(), &key).unwrap();

        let loaded = load(&path, &key).expect("load");

        assert!(loaded.is_some_and(|w| w.is_empty()));
    }

    #[test]
    fn test_recovery_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("workspaces.json");

        let mut entries = HashMap::new();
        entries.insert(
            "abc123".to_string(),
            RecoveryEntry {
                client_id: "client1".to_string(),
                refresh_token: "rt_test".to_string(),
                workspace_name: "test-ws".to_string(),
                scopes: vec!["credentials:discover".to_string()],
                registered_at: Utc::now(),
            },
        );

        save_recovery(&path, &entries).unwrap();
        let loaded = load_recovery(&path);

        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded["abc123"].client_id, "client1");
        assert_eq!(loaded["abc123"].workspace_name, "test-ws");
        assert_eq!(loaded["abc123"].scopes, vec!["credentials:discover"]);
    }

    #[test]
    fn test_recovery_load_missing_file() {
        // Private temp dir for the same reason as above: an existing file at
        // a fixed /tmp path makes this assert pass or fail on leftovers.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nonexistent-workspaces.json");
        let result = load_recovery(&path);
        assert!(result.is_empty());
    }

    #[test]
    fn test_recovery_load_corrupt_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("workspaces.json");
        std::fs::write(&path, b"not valid json").unwrap();

        let result = load_recovery(&path);
        assert!(result.is_empty());
    }

    #[test]
    fn test_recovery_file_permissions() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("workspaces.json");

        let entries = HashMap::new();
        save_recovery(&path, &entries).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let metadata = std::fs::metadata(&path).unwrap();
            let mode = metadata.permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "recovery store should have 0600 permissions");
        }
    }

    #[test]
    fn test_recovery_atomic_write() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("workspaces.json");

        // Write initial data
        let mut entries = HashMap::new();
        entries.insert(
            "ws1".to_string(),
            RecoveryEntry {
                client_id: "c1".to_string(),
                refresh_token: "rt1".to_string(),
                workspace_name: "workspace-1".to_string(),
                scopes: vec![],
                registered_at: Utc::now(),
            },
        );
        save_recovery(&path, &entries).unwrap();

        // Overwrite with new data
        entries.insert(
            "ws2".to_string(),
            RecoveryEntry {
                client_id: "c2".to_string(),
                refresh_token: "rt2".to_string(),
                workspace_name: "workspace-2".to_string(),
                scopes: vec!["credentials:vend".to_string()],
                registered_at: Utc::now(),
            },
        );
        save_recovery(&path, &entries).unwrap();

        let loaded = load_recovery(&path);
        assert_eq!(loaded.len(), 2);
        assert!(loaded.contains_key("ws1"));
        assert!(loaded.contains_key("ws2"));

        // Verify no temp file left behind
        assert!(!dir.path().join("workspaces.json.tmp").exists());
    }

    #[test]
    fn test_workspace_state_to_recovery_entry() {
        let ws = WorkspaceState {
            client_id: "c1".to_string(),
            access_token: "at_secret".to_string(),
            refresh_token: "rt_secret".to_string(),
            scopes: vec!["credentials:discover".to_string()],
            token_expires_at: Utc::now(),
            workspace_name: "my-ws".to_string(),
            token_status: crate::state::TokenStatus::Valid,
        };

        let entry = ws.to_recovery_entry();
        assert_eq!(entry.client_id, "c1");
        assert_eq!(entry.refresh_token, "rt_secret");
        assert_eq!(entry.workspace_name, "my-ws");
        assert_eq!(entry.scopes, vec!["credentials:discover"]);
        // Recovery entry should NOT contain the access token
        // (it's not a field on RecoveryEntry by design)
    }
}
