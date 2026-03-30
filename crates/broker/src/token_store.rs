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

use crate::state::WorkspaceState;

const HKDF_INFO: &[u8] = b"agentcordon:broker-token-store-v1";
const NONCE_LEN: usize = 12;

/// Derive an AES-256-GCM key from the P-256 private key via HKDF.
fn derive_encryption_key(p256_key: &p256::SecretKey) -> [u8; 32] {
    let key_bytes = p256_key.to_bytes();
    let hk = Hkdf::<Sha256>::new(None, key_bytes.as_ref());
    let mut okm = [0u8; 32];
    hk.expand(HKDF_INFO, &mut okm)
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
    let cipher =
        Aes256Gcm::new_from_slice(&aes_key).map_err(|e| format!("cipher init failed: {}", e))?;

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

    std::fs::write(path, &output).map_err(|e| format!("write failed: {}", e))?;

    Ok(())
}

/// Load and decrypt workspace states from disk.
///
/// Returns an empty map if the file does not exist.
pub fn load(
    path: &Path,
    p256_key: &p256::SecretKey,
) -> Result<HashMap<String, WorkspaceState>, String> {
    if !path.exists() {
        return Ok(HashMap::new());
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
    let cipher =
        Aes256Gcm::new_from_slice(&aes_key).map_err(|e| format!("cipher init failed: {}", e))?;

    let plaintext = cipher
        .decrypt(&nonce, ciphertext)
        .map_err(|_| "decryption failed — key may have changed".to_string())?;

    let workspaces: HashMap<String, WorkspaceState> =
        serde_json::from_slice(&plaintext).map_err(|e| format!("deserialize failed: {}", e))?;

    Ok(workspaces)
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
                token_status: "valid".to_string(),
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
        let result = load(&path, &key).unwrap();
        assert!(result.is_empty());
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
                token_status: "valid".to_string(),
            },
        );

        save(&path, &workspaces, &key1).unwrap();
        assert!(load(&path, &key2).is_err());
    }
}
