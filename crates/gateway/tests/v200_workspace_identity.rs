#![allow(deprecated)]
//! P1: Workspace Identity tests for the v2.0 workspace unification branch.
//!
//! Tests `WorkspaceIdentity` from `crates/gateway/src/identity.rs`.
//! Covers: ephemeral creation, key persistence, load_from_dir roundtrips,
//! encryption fingerprints, error handling, and ECIES integration.

use std::os::unix::fs::PermissionsExt;

use agent_cordon_core::crypto::ecies::{
    build_aad, CredentialEnvelopeDecryptor, CredentialEnvelopeEncryptor, EciesEncryptor,
};
use agentcordon::identity::WorkspaceIdentity;
use p256::elliptic_curve::sec1::ToEncodedPoint;

// ---------------------------------------------------------------------------
// 1. test_new_ephemeral_creates_valid_identity
// ---------------------------------------------------------------------------

#[test]
fn test_new_ephemeral_creates_valid_identity() {
    let id = WorkspaceIdentity::new_ephemeral();

    // pk_hash must start with "sha256:"
    assert!(
        id.pk_hash.starts_with("sha256:"),
        "pk_hash should start with 'sha256:', got: {}",
        id.pk_hash
    );

    // After the prefix, there should be exactly 64 hex characters (SHA-256 digest)
    let hex_part = &id.pk_hash["sha256:".len()..];
    assert_eq!(
        hex_part.len(),
        64,
        "hex portion should be 64 chars, got {}",
        hex_part.len()
    );
    assert!(
        hex_part.chars().all(|c| c.is_ascii_hexdigit()),
        "hex portion must be valid hex, got: {}",
        hex_part
    );
}

// ---------------------------------------------------------------------------
// 2. test_save_and_load_encryption_key_roundtrip
// ---------------------------------------------------------------------------

#[test]
fn test_save_and_load_encryption_key_roundtrip() {
    let dir = tempfile::tempdir().expect("tempdir");
    let secret = p256::SecretKey::random(&mut rand::rngs::OsRng);

    WorkspaceIdentity::save_encryption_key(dir.path(), &secret).expect("save should succeed");

    // Read back the raw 32-byte scalar
    let loaded_bytes = std::fs::read(dir.path().join("encryption.key")).expect("read key");
    let loaded_key = p256::SecretKey::from_slice(&loaded_bytes).expect("parse loaded key");

    assert_eq!(
        secret.to_bytes().as_slice(),
        loaded_key.to_bytes().as_slice(),
        "loaded key should match saved key"
    );

    // Read back the uncompressed public point (65 bytes)
    let loaded_pub = std::fs::read(dir.path().join("encryption.pub")).expect("read pub");
    let expected_pub = secret.public_key().to_encoded_point(false);
    assert_eq!(
        loaded_pub,
        expected_pub.as_bytes(),
        "public key file should match derived public key"
    );
}

// ---------------------------------------------------------------------------
// 3. test_load_from_dir_full_roundtrip
// ---------------------------------------------------------------------------

#[test]
fn test_load_from_dir_full_roundtrip() {
    let dir = tempfile::tempdir().expect("tempdir");
    let key_dir = dir.path().join(".agentcordon");

    // Save Ed25519 keypair
    let (ed25519_sk, _vk) = agent_cordon_core::crypto::ed25519::generate_workspace_keypair();
    agent_cordon_core::crypto::ed25519::save_keypair(&key_dir, &ed25519_sk).expect("save ed25519");

    // Save P-256 encryption keypair
    let enc_key = p256::SecretKey::random(&mut rand::rngs::OsRng);
    WorkspaceIdentity::save_encryption_key(&key_dir, &enc_key).expect("save encryption key");

    // Load from dir
    let loaded = WorkspaceIdentity::load_from_dir(&key_dir).expect("load_from_dir");

    // Verify Ed25519 key matches
    assert_eq!(
        ed25519_sk.to_bytes(),
        loaded.ed25519_key.to_bytes(),
        "Ed25519 key should match"
    );

    // Verify P-256 key matches
    assert_eq!(
        enc_key.to_bytes().as_slice(),
        loaded.encryption_key.to_bytes().as_slice(),
        "P-256 encryption key should match"
    );

    // Verify pk_hash is derived from the Ed25519 public key
    assert!(loaded.pk_hash.starts_with("sha256:"));
}

// ---------------------------------------------------------------------------
// 4. test_encryption_fingerprint_deterministic
// ---------------------------------------------------------------------------

#[test]
fn test_encryption_fingerprint_deterministic() {
    let id = WorkspaceIdentity::new_ephemeral();

    let fp1 = id.encryption_fingerprint();
    let fp2 = id.encryption_fingerprint();

    assert_eq!(
        fp1, fp2,
        "fingerprint should be deterministic for the same identity"
    );
    assert_eq!(
        fp1.len(),
        64,
        "fingerprint should be 64 hex chars (SHA-256)"
    );
    assert!(
        fp1.chars().all(|c| c.is_ascii_hexdigit()),
        "fingerprint must be valid hex"
    );
}

// ---------------------------------------------------------------------------
// 5. test_has_encryption_key_both_files
// ---------------------------------------------------------------------------

#[test]
fn test_has_encryption_key_both_files() {
    let dir = tempfile::tempdir().expect("tempdir");
    let secret = p256::SecretKey::random(&mut rand::rngs::OsRng);
    WorkspaceIdentity::save_encryption_key(dir.path(), &secret).expect("save");

    assert!(
        WorkspaceIdentity::has_encryption_key(dir.path()),
        "has_encryption_key should return true when both files exist"
    );
}

// ---------------------------------------------------------------------------
// 6. test_save_encryption_key_twice_overwrites
// ---------------------------------------------------------------------------

#[test]
fn test_save_encryption_key_twice_overwrites() {
    let dir = tempfile::tempdir().expect("tempdir");

    let key1 = p256::SecretKey::random(&mut rand::rngs::OsRng);
    let key2 = p256::SecretKey::random(&mut rand::rngs::OsRng);

    WorkspaceIdentity::save_encryption_key(dir.path(), &key1).expect("save key1");
    WorkspaceIdentity::save_encryption_key(dir.path(), &key2).expect("save key2");

    // Second save should win
    let loaded_bytes = std::fs::read(dir.path().join("encryption.key")).expect("read");
    let loaded = p256::SecretKey::from_slice(&loaded_bytes).expect("parse");
    assert_eq!(
        key2.to_bytes().as_slice(),
        loaded.to_bytes().as_slice(),
        "second save should overwrite the first"
    );
}

// ---------------------------------------------------------------------------
// 7. test_load_from_dir_twice_same_result
// ---------------------------------------------------------------------------

#[test]
fn test_load_from_dir_twice_same_result() {
    let dir = tempfile::tempdir().expect("tempdir");
    let key_dir = dir.path().join(".agentcordon");

    let (ed25519_sk, _) = agent_cordon_core::crypto::ed25519::generate_workspace_keypair();
    agent_cordon_core::crypto::ed25519::save_keypair(&key_dir, &ed25519_sk).expect("save ed25519");

    let enc_key = p256::SecretKey::random(&mut rand::rngs::OsRng);
    WorkspaceIdentity::save_encryption_key(&key_dir, &enc_key).expect("save enc");

    let loaded1 = WorkspaceIdentity::load_from_dir(&key_dir).expect("load 1");
    let loaded2 = WorkspaceIdentity::load_from_dir(&key_dir).expect("load 2");

    assert_eq!(loaded1.pk_hash, loaded2.pk_hash);
    assert_eq!(
        loaded1.ed25519_key.to_bytes(),
        loaded2.ed25519_key.to_bytes()
    );
    assert_eq!(
        loaded1.encryption_key.to_bytes().as_slice(),
        loaded2.encryption_key.to_bytes().as_slice()
    );
}

// ---------------------------------------------------------------------------
// 8. test_load_from_dir_missing_ed25519_fails
// ---------------------------------------------------------------------------

#[test]
fn test_load_from_dir_missing_ed25519_fails() {
    let dir = tempfile::tempdir().expect("tempdir");

    // Only save encryption key, not Ed25519
    let enc_key = p256::SecretKey::random(&mut rand::rngs::OsRng);
    WorkspaceIdentity::save_encryption_key(dir.path(), &enc_key).expect("save enc");

    let result = WorkspaceIdentity::load_from_dir(dir.path());
    assert!(
        result.is_err(),
        "load_from_dir should fail without Ed25519 keypair"
    );
    let err_msg = match result {
        Err(e) => e,
        Ok(_) => panic!("expected error"),
    };
    assert!(
        err_msg.contains("Ed25519") || err_msg.contains("key"),
        "error should mention key issue, got: {}",
        err_msg
    );
}

// ---------------------------------------------------------------------------
// 9. test_load_from_dir_missing_encryption_key_fails
// ---------------------------------------------------------------------------

#[test]
fn test_load_from_dir_missing_encryption_key_fails() {
    let dir = tempfile::tempdir().expect("tempdir");
    let key_dir = dir.path().join(".agentcordon");

    // Only save Ed25519, not encryption key
    let (ed25519_sk, _) = agent_cordon_core::crypto::ed25519::generate_workspace_keypair();
    agent_cordon_core::crypto::ed25519::save_keypair(&key_dir, &ed25519_sk).expect("save ed25519");

    let result = WorkspaceIdentity::load_from_dir(&key_dir);
    assert!(
        result.is_err(),
        "load_from_dir should fail without encryption key"
    );
    let err_msg = match result {
        Err(e) => e,
        Ok(_) => panic!("expected error"),
    };
    assert!(
        err_msg.contains("encryption") || err_msg.contains("key"),
        "error should mention encryption key, got: {}",
        err_msg
    );
}

// ---------------------------------------------------------------------------
// 10. test_load_from_dir_corrupt_encryption_key
// ---------------------------------------------------------------------------

#[test]
fn test_load_from_dir_corrupt_encryption_key() {
    let dir = tempfile::tempdir().expect("tempdir");
    let key_dir = dir.path().join(".agentcordon");

    let (ed25519_sk, _) = agent_cordon_core::crypto::ed25519::generate_workspace_keypair();
    agent_cordon_core::crypto::ed25519::save_keypair(&key_dir, &ed25519_sk).expect("save ed25519");

    // Write 5 random bytes as corrupt encryption key
    std::fs::write(
        key_dir.join("encryption.key"),
        [0xDE, 0xAD, 0xBE, 0xEF, 0x42],
    )
    .expect("write corrupt key");
    // Also need encryption.pub for load_from_dir to get to the parsing step
    std::fs::write(key_dir.join("encryption.pub"), [0x00; 65]).expect("write dummy pub");

    let result = WorkspaceIdentity::load_from_dir(&key_dir);
    assert!(
        result.is_err(),
        "load_from_dir should fail with corrupt 5-byte encryption key"
    );
}

// ---------------------------------------------------------------------------
// 11. test_load_from_dir_empty_dir_fails
// ---------------------------------------------------------------------------

#[test]
fn test_load_from_dir_empty_dir_fails() {
    let dir = tempfile::tempdir().expect("tempdir");

    let result = WorkspaceIdentity::load_from_dir(dir.path());
    assert!(
        result.is_err(),
        "load_from_dir should fail on empty directory"
    );
}

// ---------------------------------------------------------------------------
// 12-14. test_has_encryption_key_missing_*
// ---------------------------------------------------------------------------

#[test]
fn test_has_encryption_key_missing_private() {
    let dir = tempfile::tempdir().expect("tempdir");

    // Write only the public key file
    std::fs::write(dir.path().join("encryption.pub"), b"dummy pub").expect("write pub");

    assert!(
        !WorkspaceIdentity::has_encryption_key(dir.path()),
        "has_encryption_key should be false when private key missing"
    );
}

#[test]
fn test_has_encryption_key_missing_public() {
    let dir = tempfile::tempdir().expect("tempdir");

    // Write only the private key file
    std::fs::write(dir.path().join("encryption.key"), b"dummy key").expect("write key");

    assert!(
        !WorkspaceIdentity::has_encryption_key(dir.path()),
        "has_encryption_key should be false when public key missing"
    );
}

#[test]
fn test_has_encryption_key_missing_both() {
    let dir = tempfile::tempdir().expect("tempdir");

    assert!(
        !WorkspaceIdentity::has_encryption_key(dir.path()),
        "has_encryption_key should be false when neither file exists"
    );
}

// ---------------------------------------------------------------------------
// 15. test_ecies_encrypt_decrypt_with_workspace_identity
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_ecies_encrypt_decrypt_with_workspace_identity() {
    let id = WorkspaceIdentity::new_ephemeral();

    // Get the P-256 public key as uncompressed SEC1 bytes (65 bytes)
    let pub_point = id.encryption_key.public_key().to_encoded_point(false);
    let pub_bytes = pub_point.as_bytes();

    let plaintext = b"super-secret-api-key-12345";
    let aad = build_aad("device-1", "cred-1", "vend-1", "1710000000");

    // Encrypt to the identity's public key
    let ecies = EciesEncryptor::new();
    let envelope = ecies
        .encrypt_for_device(pub_bytes, plaintext, &aad)
        .await
        .expect("encryption should succeed");

    // Decrypt with the identity's private key
    let decrypted = ecies
        .decrypt_envelope(id.encryption_key.to_bytes().as_slice(), &envelope)
        .await
        .expect("decryption should succeed");

    assert_eq!(
        decrypted, plaintext,
        "decrypted plaintext should match original"
    );
}

// ---------------------------------------------------------------------------
// 16. test_encryption_key_file_permissions
// ---------------------------------------------------------------------------

#[test]
fn test_encryption_key_file_permissions() {
    let dir = tempfile::tempdir().expect("tempdir");
    let secret = p256::SecretKey::random(&mut rand::rngs::OsRng);

    WorkspaceIdentity::save_encryption_key(dir.path(), &secret).expect("save");

    let key_path = dir.path().join("encryption.key");
    let metadata = std::fs::metadata(&key_path).expect("metadata");
    let mode = metadata.permissions().mode() & 0o777;

    assert_eq!(
        mode, 0o600,
        "encryption.key should have 0600 permissions, got {:04o}",
        mode
    );
}

// ---------------------------------------------------------------------------
// 17. test_pk_hash_prefix_always_sha256
// ---------------------------------------------------------------------------

#[test]
fn test_pk_hash_prefix_always_sha256() {
    for _ in 0..10 {
        let id = WorkspaceIdentity::new_ephemeral();
        assert!(
            id.pk_hash.starts_with("sha256:"),
            "all ephemeral identities should have sha256: prefix, got: {}",
            id.pk_hash
        );
    }
}

// ---------------------------------------------------------------------------
// 18. test_two_identities_have_different_keys
// ---------------------------------------------------------------------------

#[test]
fn test_two_identities_have_different_keys() {
    let id1 = WorkspaceIdentity::new_ephemeral();
    let id2 = WorkspaceIdentity::new_ephemeral();

    assert_ne!(
        id1.ed25519_key.to_bytes(),
        id2.ed25519_key.to_bytes(),
        "two ephemeral identities should have different Ed25519 keys"
    );
    assert_ne!(
        id1.encryption_key.to_bytes().as_slice(),
        id2.encryption_key.to_bytes().as_slice(),
        "two ephemeral identities should have different P-256 keys"
    );
    assert_ne!(
        id1.pk_hash, id2.pk_hash,
        "two ephemeral identities should have different pk_hash"
    );
}
