//! P4: Encrypted File Key Storage tests for the v2.0 workspace unification branch.
//!
//! Tests `EncryptedFileKeyStorage` from `crates/gateway/src/identity.rs`.
//! Covers: happy-path roundtrips, overwrite, delete, error handling,
//! and security properties (not plaintext, different passphrases, salt randomness).

use agentcordon::identity::{EncryptedFileKeyStorage, KeyStorage};

// ---------------------------------------------------------------------------
// Helper: build storage with a given dir and passphrase
// ---------------------------------------------------------------------------

fn make_storage(dir: &std::path::Path, passphrase: Option<&str>) -> EncryptedFileKeyStorage {
    EncryptedFileKeyStorage {
        base_path: dir.to_path_buf(),
        passphrase: passphrase.map(String::from),
    }
}

// ---------------------------------------------------------------------------
// 1. test_roundtrip_store_and_load
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_roundtrip_store_and_load() {
    let dir = tempfile::tempdir().expect("tempdir");
    let storage = make_storage(dir.path(), Some("test-passphrase"));

    let key_bytes: Vec<u8> = (0..32).collect();
    storage
        .store_encryption_key(&key_bytes)
        .await
        .expect("store should succeed");

    let loaded = storage
        .load_encryption_key()
        .await
        .expect("load should succeed");

    assert!(loaded.is_some(), "loaded key should be Some");
    assert_eq!(
        &*loaded.unwrap(),
        key_bytes.as_slice(),
        "loaded key should match stored key"
    );
}

// ---------------------------------------------------------------------------
// 2. test_load_nonexistent_returns_none
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_load_nonexistent_returns_none() {
    let dir = tempfile::tempdir().expect("tempdir");
    let storage = make_storage(dir.path(), Some("test-passphrase"));

    let loaded = storage
        .load_encryption_key()
        .await
        .expect("load should succeed (returning None)");

    assert!(
        loaded.is_none(),
        "loading from empty dir should return None"
    );
}

// ---------------------------------------------------------------------------
// 3. test_delete_removes_file
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_delete_removes_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let storage = make_storage(dir.path(), Some("test-passphrase"));

    let key_bytes: Vec<u8> = (0..32).collect();
    storage
        .store_encryption_key(&key_bytes)
        .await
        .expect("store");

    // Verify file exists
    assert!(
        dir.path().join("encryption.key.enc").exists(),
        "encrypted key file should exist after store"
    );

    storage.delete_keys().await.expect("delete should succeed");

    // Verify file is gone
    assert!(
        !dir.path().join("encryption.key.enc").exists(),
        "encrypted key file should be deleted"
    );

    // Load should now return None
    let loaded = storage
        .load_encryption_key()
        .await
        .expect("load after delete");
    assert!(loaded.is_none(), "load after delete should return None");
}

// ---------------------------------------------------------------------------
// 4. test_overwrite_second_save_wins
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_overwrite_second_save_wins() {
    let dir = tempfile::tempdir().expect("tempdir");
    let storage = make_storage(dir.path(), Some("test-passphrase"));

    let key1: Vec<u8> = vec![0xAA; 32];
    let key2: Vec<u8> = vec![0xBB; 32];

    storage
        .store_encryption_key(&key1)
        .await
        .expect("store key1");
    storage
        .store_encryption_key(&key2)
        .await
        .expect("store key2");

    let loaded = storage.load_encryption_key().await.expect("load");
    assert_eq!(
        &*loaded.unwrap(),
        key2.as_slice(),
        "second store should overwrite the first"
    );
}

// ---------------------------------------------------------------------------
// 5. test_delete_nonexistent_is_ok
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_delete_nonexistent_is_ok() {
    let dir = tempfile::tempdir().expect("tempdir");
    let storage = make_storage(dir.path(), Some("test-passphrase"));

    // Should not error when file doesn't exist
    storage
        .delete_keys()
        .await
        .expect("delete nonexistent should succeed");
}

// ---------------------------------------------------------------------------
// 6. test_double_delete
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_double_delete() {
    let dir = tempfile::tempdir().expect("tempdir");
    let storage = make_storage(dir.path(), Some("test-passphrase"));

    let key_bytes: Vec<u8> = (0..32).collect();
    storage
        .store_encryption_key(&key_bytes)
        .await
        .expect("store");

    storage.delete_keys().await.expect("first delete");
    storage
        .delete_keys()
        .await
        .expect("second delete should also succeed");
}

// ---------------------------------------------------------------------------
// 7. test_wrong_passphrase_fails_to_load
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_wrong_passphrase_fails_to_load() {
    let dir = tempfile::tempdir().expect("tempdir");

    // Store with passphrase "correct-horse"
    let store_storage = make_storage(dir.path(), Some("correct-horse"));
    let key_bytes: Vec<u8> = (0..32).collect();
    store_storage
        .store_encryption_key(&key_bytes)
        .await
        .expect("store");

    // Try to load with wrong passphrase "wrong-battery"
    let wrong_storage = make_storage(dir.path(), Some("wrong-battery"));
    let result = wrong_storage.load_encryption_key().await;

    assert!(result.is_err(), "loading with wrong passphrase should fail");
}

// ---------------------------------------------------------------------------
// 8. test_no_passphrase_fails
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_no_passphrase_fails_to_store() {
    let dir = tempfile::tempdir().expect("tempdir");
    let storage = make_storage(dir.path(), None);

    let key_bytes: Vec<u8> = (0..32).collect();
    let result = storage.store_encryption_key(&key_bytes).await;

    assert!(result.is_err(), "store without passphrase should fail");
}

#[tokio::test]
async fn test_no_passphrase_fails_to_load() {
    let dir = tempfile::tempdir().expect("tempdir");

    // Store with a real passphrase first
    let store_storage = make_storage(dir.path(), Some("real-passphrase"));
    let key_bytes: Vec<u8> = (0..32).collect();
    store_storage
        .store_encryption_key(&key_bytes)
        .await
        .expect("store");

    // Try to load with no passphrase
    let no_pass_storage = make_storage(dir.path(), None);
    let result = no_pass_storage.load_encryption_key().await;

    assert!(result.is_err(), "load without passphrase should fail");
}

// ---------------------------------------------------------------------------
// 9. test_truncated_file_fails
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_truncated_file_fails() {
    let dir = tempfile::tempdir().expect("tempdir");
    let storage = make_storage(dir.path(), Some("test-passphrase"));

    // Store a valid key first
    let key_bytes: Vec<u8> = (0..32).collect();
    storage
        .store_encryption_key(&key_bytes)
        .await
        .expect("store");

    // Truncate the file to less than the minimum (28 bytes = 16 salt + 12 nonce)
    let enc_path = dir.path().join("encryption.key.enc");
    std::fs::write(&enc_path, [0u8; 10]).expect("truncate");

    let result = storage.load_encryption_key().await;
    assert!(result.is_err(), "loading truncated file should fail");
}

// ---------------------------------------------------------------------------
// 10. test_corrupted_ciphertext_fails
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_corrupted_ciphertext_fails() {
    let dir = tempfile::tempdir().expect("tempdir");
    let storage = make_storage(dir.path(), Some("test-passphrase"));

    // Store a valid key
    let key_bytes: Vec<u8> = (0..32).collect();
    storage
        .store_encryption_key(&key_bytes)
        .await
        .expect("store");

    // Read the file and corrupt the ciphertext portion (after salt+nonce = 28 bytes)
    let enc_path = dir.path().join("encryption.key.enc");
    let mut data = std::fs::read(&enc_path).expect("read");
    assert!(data.len() > 28, "file should be longer than header");
    // Flip all bits in the ciphertext
    for byte in &mut data[28..] {
        *byte ^= 0xFF;
    }
    std::fs::write(&enc_path, &data).expect("write corrupted");

    let result = storage.load_encryption_key().await;
    assert!(
        result.is_err(),
        "loading file with corrupted ciphertext should fail"
    );
}

// ---------------------------------------------------------------------------
// 11. test_stored_file_is_not_plaintext
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_stored_file_is_not_plaintext() {
    let dir = tempfile::tempdir().expect("tempdir");
    let storage = make_storage(dir.path(), Some("test-passphrase"));

    let key_bytes: Vec<u8> = vec![0x42; 32];
    storage
        .store_encryption_key(&key_bytes)
        .await
        .expect("store");

    let enc_path = dir.path().join("encryption.key.enc");
    let file_contents = std::fs::read(&enc_path).expect("read");

    // The file should NOT contain the plaintext key bytes as a substring
    let plaintext_found = file_contents
        .windows(key_bytes.len())
        .any(|window| window == key_bytes.as_slice());

    assert!(
        !plaintext_found,
        "encrypted file should not contain plaintext key bytes"
    );

    // File should be longer than the plaintext (salt + nonce + ciphertext + GCM tag)
    assert!(
        file_contents.len() > key_bytes.len(),
        "encrypted file should be larger than raw key"
    );
}

// ---------------------------------------------------------------------------
// 12. test_different_passphrases_produce_different_output
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_different_passphrases_produce_different_output() {
    let dir1 = tempfile::tempdir().expect("tempdir1");
    let dir2 = tempfile::tempdir().expect("tempdir2");

    let storage1 = make_storage(dir1.path(), Some("passphrase-alpha"));
    let storage2 = make_storage(dir2.path(), Some("passphrase-beta"));

    let key_bytes: Vec<u8> = vec![0x42; 32];
    storage1
        .store_encryption_key(&key_bytes)
        .await
        .expect("store1");
    storage2
        .store_encryption_key(&key_bytes)
        .await
        .expect("store2");

    let file1 = std::fs::read(dir1.path().join("encryption.key.enc")).expect("read1");
    let file2 = std::fs::read(dir2.path().join("encryption.key.enc")).expect("read2");

    // Different passphrases + different random salts = completely different files
    assert_ne!(
        file1, file2,
        "same key with different passphrases should produce different encrypted output"
    );
}

// ---------------------------------------------------------------------------
// 13. test_same_passphrase_different_salt_produces_different_output
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_same_passphrase_different_salt_produces_different_output() {
    let dir = tempfile::tempdir().expect("tempdir");
    let storage = make_storage(dir.path(), Some("same-passphrase"));

    let key_bytes: Vec<u8> = vec![0x42; 32];

    // Store once, read the file
    storage
        .store_encryption_key(&key_bytes)
        .await
        .expect("store1");
    let file1 = std::fs::read(dir.path().join("encryption.key.enc")).expect("read1");

    // Store again (new random salt + nonce), read the file
    storage
        .store_encryption_key(&key_bytes)
        .await
        .expect("store2");
    let file2 = std::fs::read(dir.path().join("encryption.key.enc")).expect("read2");

    // Due to random salt and nonce, the files should differ
    assert_ne!(
        file1, file2,
        "storing same key twice should produce different encrypted files (random salt/nonce)"
    );

    // But both should decrypt to the same key
    let loaded = storage.load_encryption_key().await.expect("load");
    assert_eq!(
        &*loaded.unwrap(),
        key_bytes.as_slice(),
        "second store should still decrypt correctly"
    );
}

// ---------------------------------------------------------------------------
// Extra: test_file_permissions_0600
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_encrypted_file_permissions_0600() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().expect("tempdir");
    let storage = make_storage(dir.path(), Some("test-passphrase"));

    let key_bytes: Vec<u8> = (0..32).collect();
    storage
        .store_encryption_key(&key_bytes)
        .await
        .expect("store");

    let enc_path = dir.path().join("encryption.key.enc");
    let metadata = std::fs::metadata(&enc_path).expect("metadata");
    let mode = metadata.permissions().mode() & 0o777;

    assert_eq!(
        mode, 0o600,
        "encrypted key file should have 0600 permissions, got {:04o}",
        mode
    );
}
