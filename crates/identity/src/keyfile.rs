//! On-disk key file format and permission policy.
//!
//! Layout, unchanged since the first `agentcordon init`:
//!
//! ```text
//! <workspace>/.agentcordon/            mode 0700
//! <workspace>/.agentcordon/workspace.key   32-byte seed, lowercase hex, mode 0600
//! <workspace>/.agentcordon/workspace.pub   32-byte public key, lowercase hex, mode 0644
//! ```
//!
//! Loading refuses a directory or private key that is more permissive than
//! the policy. Creating writes each file with `O_CREAT | O_EXCL` and the
//! final mode in one `open(2)`, so the key never exists with wider
//! permissions than asked for and a concurrent `init` cannot overwrite it.
//! Modes are enforced on Unix only; Windows relies on NTFS ACLs inherited
//! from the user's profile directory.

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use crate::key::WorkspaceKey;

/// Name of the per-workspace directory holding the key files.
pub const WORKSPACE_DIR_NAME: &str = ".agentcordon";
/// Private key file: the seed as hex.
pub const KEY_FILE_NAME: &str = "workspace.key";
/// Public key file: the public key as hex.
pub const PUB_FILE_NAME: &str = "workspace.pub";
/// Required mode of the directory.
pub const DIR_MODE: u32 = 0o700;
/// Required mode of the private key file.
pub const KEY_MODE: u32 = 0o600;
/// Mode the public key file is created with (not enforced on load).
pub const PUB_MODE: u32 = 0o644;

const DIR_LABEL: &str = "directory .agentcordon/";
const KEY_LABEL: &str = "private key workspace.key";
const PUB_LABEL: &str = "public key";

#[derive(Debug, thiserror::Error)]
pub enum KeyFileError {
    /// No `workspace.key` at this path. The CLI turns this into
    /// "run `agentcordon init`".
    #[error("no private key at {}", path.display())]
    NotFound { path: PathBuf },
    /// The directory or private key is wider than the policy allows.
    #[error(
        "{label} has permissions {mode:04o}, expected {max_mode:04o} or stricter. \
         Fix with: chmod {max_mode:04o} {}",
        path.display()
    )]
    Permissions {
        label: &'static str,
        mode: u32,
        max_mode: u32,
        path: PathBuf,
    },
    #[error("invalid private key format: {0}")]
    PrivateKeyFormat(hex::FromHexError),
    #[error("private key must be 32 bytes")]
    PrivateKeyLength,
    #[error("invalid public key format: {0}")]
    PublicKeyFormat(hex::FromHexError),
    #[error("public key file does not match private key")]
    PublicKeyMismatch,
    /// A file to be created already exists: another `init` raced this one.
    #[error("{label} appeared concurrently")]
    AlreadyExists { label: &'static str, path: PathBuf },
    #[error("{context}: {source}")]
    Io {
        context: String,
        #[source]
        source: io::Error,
    },
}

fn io_err(context: impl Into<String>) -> impl FnOnce(io::Error) -> KeyFileError {
    move |source| KeyFileError::Io {
        context: context.into(),
        source,
    }
}

/// Whether a private key file exists in `dir`.
pub fn workspace_key_exists(dir: &Path) -> bool {
    dir.join(KEY_FILE_NAME).exists()
}

/// Load the workspace key from `dir`, enforcing the permission policy on
/// the directory and the private key and checking that `workspace.pub`,
/// if present, matches the seed.
pub fn load_workspace_key(dir: &Path) -> Result<WorkspaceKey, KeyFileError> {
    let key_path = dir.join(KEY_FILE_NAME);
    let pub_path = dir.join(PUB_FILE_NAME);

    if !key_path.exists() {
        return Err(KeyFileError::NotFound { path: key_path });
    }

    check_permissions(dir, DIR_MODE, DIR_LABEL)?;
    check_permissions(&key_path, KEY_MODE, KEY_LABEL)?;

    let seed_hex = fs::read_to_string(&key_path).map_err(io_err("failed to read private key"))?;
    let seed_bytes = hex::decode(seed_hex.trim()).map_err(KeyFileError::PrivateKeyFormat)?;
    let seed: [u8; 32] = seed_bytes
        .try_into()
        .map_err(|_| KeyFileError::PrivateKeyLength)?;
    let key = WorkspaceKey::from_seed(&seed);

    if pub_path.exists() {
        let pub_hex = fs::read_to_string(&pub_path).map_err(io_err("failed to read public key"))?;
        let pub_bytes = hex::decode(pub_hex.trim()).map_err(KeyFileError::PublicKeyFormat)?;
        if pub_bytes != key.public_key_bytes() {
            return Err(KeyFileError::PublicKeyMismatch);
        }
    }

    Ok(key)
}

/// Read `workspace.pub` from `dir` (trimmed hex). Does not enforce
/// permissions: the public key is not secret.
pub fn read_public_key_hex(dir: &Path) -> Result<String, KeyFileError> {
    let pub_hex =
        fs::read_to_string(dir.join(PUB_FILE_NAME)).map_err(io_err("failed to read public key"))?;
    Ok(pub_hex.trim().to_string())
}

/// Generate a new key and write it to `dir`, creating the directory with
/// [`DIR_MODE`] if needed. Fails without touching anything if a key file
/// already exists.
pub fn create_workspace_key(dir: &Path) -> Result<WorkspaceKey, KeyFileError> {
    fs::create_dir_all(dir).map_err(io_err("failed to create .agentcordon/"))?;
    #[cfg(unix)]
    fs::set_permissions(dir, fs::Permissions::from_mode(DIR_MODE))
        .map_err(io_err("failed to set directory permissions"))?;

    let key = WorkspaceKey::generate();
    create_new_file(
        &dir.join(KEY_FILE_NAME),
        KEY_MODE,
        key.seed_hex().as_bytes(),
        KEY_LABEL_SHORT,
    )?;
    create_new_file(
        &dir.join(PUB_FILE_NAME),
        PUB_MODE,
        key.public_key_hex().as_bytes(),
        PUB_LABEL,
    )?;
    Ok(key)
}

const KEY_LABEL_SHORT: &str = "private key";

/// Create a file atomically at `path` with the given body.
///
/// Uses `O_CREAT | O_EXCL` (Unix) / `CREATE_NEW` (Windows) so the file is
/// created in a single syscall that fails if anything already exists at
/// the path. On Unix, `mode` is passed to `open(2)` so the file is created
/// with the requested permissions from the first instant it exists.
fn create_new_file(
    path: &Path,
    _mode: u32,
    body: &[u8],
    label: &'static str,
) -> Result<(), KeyFileError> {
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    opts.mode(_mode);

    let mut file = match opts.open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
            return Err(KeyFileError::AlreadyExists {
                label,
                path: path.to_path_buf(),
            });
        }
        Err(e) => return Err(io_err(format!("failed to write {label}"))(e)),
    };
    file.write_all(body)
        .map_err(io_err(format!("failed to write {label}")))
}

/// Check that file/dir permissions are not more permissive than `max_mode`.
#[cfg(unix)]
fn check_permissions(path: &Path, max_mode: u32, label: &'static str) -> Result<(), KeyFileError> {
    let metadata = fs::metadata(path).map_err(io_err(format!("cannot stat {label}")))?;
    let mode = metadata.permissions().mode() & 0o777;
    if mode & !max_mode != 0 {
        return Err(KeyFileError::Permissions {
            label,
            mode,
            max_mode,
            path: path.to_path_buf(),
        });
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_permissions(
    _path: &Path,
    _max_mode: u32,
    _label: &'static str,
) -> Result<(), KeyFileError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_new_file_writes_exact_body() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("key");

        create_new_file(&path, 0o600, b"hello world", "private key").unwrap();

        assert_eq!(fs::read_to_string(&path).unwrap(), "hello world");
    }

    #[test]
    fn create_new_file_rejects_existing_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("key");
        fs::write(&path, b"pre-existing").unwrap();

        let err = create_new_file(&path, 0o600, b"new content", "private key").unwrap_err();

        assert!(matches!(err, KeyFileError::AlreadyExists { .. }));
        assert_eq!(err.to_string(), "private key appeared concurrently");
        // Never overwrite on race.
        assert_eq!(fs::read_to_string(&path).unwrap(), "pre-existing");
    }

    #[cfg(unix)]
    #[test]
    fn create_new_file_sets_mode_atomically() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join(KEY_FILE_NAME);
        let pub_path = dir.path().join(PUB_FILE_NAME);

        create_new_file(&key_path, 0o600, b"seed", "private key").unwrap();
        create_new_file(&pub_path, 0o644, b"pk", "public key").unwrap();

        let key_mode = fs::metadata(&key_path).unwrap().permissions().mode() & 0o777;
        let pub_mode = fs::metadata(&pub_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(key_mode & !0o600, 0, "private key mode {key_mode:o}");
        assert_eq!(pub_mode & !0o644, 0, "public key mode {pub_mode:o}");
        assert_eq!(key_mode & 0o400, 0o400);
        assert_eq!(pub_mode & 0o400, 0o400);
    }
}
