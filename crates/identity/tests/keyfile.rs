//! On-disk key file format and permission policy.
//!
//! The format is what `agentcordon init` has always written: `workspace.key`
//! holds the 32-byte seed as lowercase hex, `workspace.pub` the 32-byte
//! public key as lowercase hex, both inside a `0700` directory, the private
//! key `0600` and the public key `0644`. Existing key files must keep
//! loading unchanged.

use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use agentcordon_identity::{
    create_workspace_key, load_workspace_key, read_public_key_hex, workspace_key_exists,
    KeyFileError, WorkspaceKey, KEY_FILE_NAME, PUB_FILE_NAME,
};

const SEED_HEX: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
const PUBLIC_KEY_HEX: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";

/// Write a key directory exactly the way a pre-crate `agentcordon init` did.
fn write_legacy_layout(dir: &std::path::Path, seed_hex: &str, pub_hex: Option<&str>) {
    fs::create_dir_all(dir).unwrap();
    // A trailing newline is tolerated: the loader trims.
    fs::write(dir.join(KEY_FILE_NAME), format!("{seed_hex}\n")).unwrap();
    if let Some(p) = pub_hex {
        fs::write(dir.join(PUB_FILE_NAME), p).unwrap();
    }
    #[cfg(unix)]
    {
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(dir.join(KEY_FILE_NAME), fs::Permissions::from_mode(0o600)).unwrap();
    }
}

#[test]
fn loads_existing_key_file_written_by_previous_cli() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join(".agentcordon");
    write_legacy_layout(&dir, SEED_HEX, Some(PUBLIC_KEY_HEX));

    let key = load_workspace_key(&dir).unwrap();
    assert_eq!(key.seed_hex(), SEED_HEX);
    assert_eq!(key.public_key_hex(), PUBLIC_KEY_HEX);
    assert_eq!(read_public_key_hex(&dir).unwrap(), PUBLIC_KEY_HEX);
}

#[test]
fn loads_when_public_key_file_is_absent() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join(".agentcordon");
    write_legacy_layout(&dir, SEED_HEX, None);

    let key = load_workspace_key(&dir).unwrap();
    assert_eq!(key.public_key_hex(), PUBLIC_KEY_HEX);
}

#[test]
fn rejects_public_key_file_that_does_not_match() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join(".agentcordon");
    let other = WorkspaceKey::generate().public_key_hex();
    write_legacy_layout(&dir, SEED_HEX, Some(&other));

    let err = load_workspace_key(&dir).unwrap_err();
    assert!(matches!(err, KeyFileError::PublicKeyMismatch), "{err}");
}

#[test]
fn missing_key_file_is_not_found() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join(".agentcordon");
    assert!(!workspace_key_exists(&dir));
    let err = load_workspace_key(&dir).unwrap_err();
    assert!(matches!(err, KeyFileError::NotFound { .. }), "{err}");
}

#[test]
fn rejects_seed_that_is_not_32_bytes() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join(".agentcordon");
    write_legacy_layout(&dir, "abcd", Some(PUBLIC_KEY_HEX));

    let err = load_workspace_key(&dir).unwrap_err();
    assert!(matches!(err, KeyFileError::PrivateKeyLength), "{err}");
    assert_eq!(err.to_string(), "private key must be 32 bytes");
}

#[test]
fn rejects_seed_that_is_not_hex() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join(".agentcordon");
    write_legacy_layout(&dir, "zz", Some(PUBLIC_KEY_HEX));

    let err = load_workspace_key(&dir).unwrap_err();
    assert!(matches!(err, KeyFileError::PrivateKeyFormat(_)), "{err}");
    assert!(err.to_string().starts_with("invalid private key format: "));
}

#[test]
fn create_writes_both_files_and_round_trips() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join(".agentcordon");

    let created = create_workspace_key(&dir).unwrap();
    assert!(workspace_key_exists(&dir));

    let key_body = fs::read_to_string(dir.join(KEY_FILE_NAME)).unwrap();
    let pub_body = fs::read_to_string(dir.join(PUB_FILE_NAME)).unwrap();
    assert_eq!(key_body, created.seed_hex(), "seed is bare lowercase hex");
    assert_eq!(
        pub_body,
        created.public_key_hex(),
        "pub is bare lowercase hex"
    );
    assert_eq!(key_body.len(), 64);
    assert_eq!(pub_body.len(), 64);

    let loaded = load_workspace_key(&dir).unwrap();
    assert_eq!(loaded.seed_hex(), created.seed_hex());
    assert_eq!(loaded.pk_hash(), created.pk_hash());
}

#[cfg(unix)]
#[test]
fn create_sets_permissions_from_the_first_instant() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join(".agentcordon");
    create_workspace_key(&dir).unwrap();

    let mode = |p: &std::path::Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&dir), 0o700);
    let key_mode = mode(&dir.join(KEY_FILE_NAME));
    let pub_mode = mode(&dir.join(PUB_FILE_NAME));
    // The active umask may mask bits off; the files must never be wider
    // than asked for, and owner-read must be present.
    assert_eq!(key_mode & !0o600, 0, "private key mode {key_mode:o}");
    assert_eq!(pub_mode & !0o644, 0, "public key mode {pub_mode:o}");
    assert_eq!(key_mode & 0o400, 0o400);
    assert_eq!(pub_mode & 0o400, 0o400);
}

#[test]
fn create_refuses_to_overwrite_an_existing_key() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join(".agentcordon");
    write_legacy_layout(&dir, SEED_HEX, Some(PUBLIC_KEY_HEX));

    let err = create_workspace_key(&dir).unwrap_err();
    assert!(matches!(err, KeyFileError::AlreadyExists { .. }), "{err}");
    assert!(err.to_string().contains("appeared concurrently"), "{err}");
    // The pre-existing key is untouched.
    assert_eq!(load_workspace_key(&dir).unwrap().seed_hex(), SEED_HEX);
}

#[cfg(unix)]
#[test]
fn load_refuses_a_world_readable_private_key() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join(".agentcordon");
    write_legacy_layout(&dir, SEED_HEX, Some(PUBLIC_KEY_HEX));
    fs::set_permissions(dir.join(KEY_FILE_NAME), fs::Permissions::from_mode(0o644)).unwrap();

    let err = load_workspace_key(&dir).unwrap_err();
    assert!(matches!(err, KeyFileError::Permissions { .. }), "{err}");
    let msg = err.to_string();
    assert!(
        msg.contains("private key workspace.key has permissions 0644, expected 0600 or stricter"),
        "{msg}"
    );
    assert!(msg.contains("chmod 0600"), "{msg}");
}

#[cfg(unix)]
#[test]
fn load_refuses_a_group_accessible_directory() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join(".agentcordon");
    write_legacy_layout(&dir, SEED_HEX, Some(PUBLIC_KEY_HEX));
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o750)).unwrap();

    let err = load_workspace_key(&dir).unwrap_err();
    assert!(matches!(err, KeyFileError::Permissions { .. }), "{err}");
    assert!(
        err.to_string()
            .contains("directory .agentcordon/ has permissions 0750, expected 0700 or stricter"),
        "{err}"
    );
}
