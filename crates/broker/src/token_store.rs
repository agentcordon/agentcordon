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

    // Atomic write: write to temp file, then rename into place.
    // This prevents data loss if the process crashes mid-write.
    let tmp_path = path.with_extension("tmp");
    std::fs::write(&tmp_path, &output).map_err(|e| format!("write failed: {}", e))?;
    std::fs::rename(&tmp_path, path).map_err(|e| format!("rename failed: {}", e))?;

    Ok(())
}

/// Load and decrypt workspace states from disk.
///
/// Returns `Err` if the file does not exist or cannot be decrypted,
/// allowing callers to fall back to the recovery store.
pub fn load(
    path: &Path,
    p256_key: &p256::SecretKey,
) -> Result<HashMap<String, WorkspaceState>, String> {
    if !path.exists() {
        return Err("token store file not found".to_string());
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

    Ok(workspaces)
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
/// Called from multiple persistence points (callback, refresh, deregister,
/// shutdown) to keep the recovery store in sync.
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

    #[test]
    fn test_round_trip() {
        let key = p256::SecretKey::random(&mut OsRng);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tokens.enc");

        let mut workspaces = HashMap::new();
        workspaces.insert(
            "abc123".to_string(),
            WorkspaceState {
                client_id: "client1".to_string(),
                access_token: "access1".to_string(),
                refresh_token: "refresh1".to_string(),
                scopes: vec!["credentials:discover".to_string()],
                token_expires_at: Utc::now(),
                workspace_name: "test-ws".to_string(),
                token_status: crate::state::TokenStatus::Valid,
            },
        );

        save(&path, &workspaces, &key).unwrap();
        let loaded = load(&path, &key).unwrap();

        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded["abc123"].client_id, "client1");
        assert_eq!(loaded["abc123"].access_token, "access1");
    }

    #[test]
    fn test_load_missing_file_returns_empty() {
        let key = p256::SecretKey::random(&mut OsRng);
        let path = std::path::PathBuf::from("/tmp/nonexistent_token_store_test");
        let result = load(&path, &key);
        assert!(result.is_err(), "load() should return Err for missing file");
    }

    #[test]
    fn test_wrong_key_fails() {
        let key1 = p256::SecretKey::random(&mut OsRng);
        let key2 = p256::SecretKey::random(&mut OsRng);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tokens.enc");

        let mut workspaces = HashMap::new();
        workspaces.insert(
            "abc".to_string(),
            WorkspaceState {
                client_id: "c".to_string(),
                access_token: "a".to_string(),
                refresh_token: "r".to_string(),
                scopes: vec![],
                token_expires_at: Utc::now(),
                workspace_name: "ws".to_string(),
                token_status: crate::state::TokenStatus::Valid,
            },
        );

        save(&path, &workspaces, &key1).unwrap();
        assert!(load(&path, &key2).is_err());
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
        let path = std::path::PathBuf::from("/tmp/nonexistent_recovery_test_12345.json");
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
