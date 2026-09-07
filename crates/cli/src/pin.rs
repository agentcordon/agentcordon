//! The pinned broker key.
//!
//! `agentcordon register` records the fingerprint the broker published on
//! `/health` in `.agentcordon/broker.fingerprint`, next to the workspace
//! key. Every later connection compares the live fingerprint to the pin
//! and refuses a broker whose key differs; a workspace enrolled before
//! pinning existed gets its pin written on first successful use.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::error::CliError;

/// File next to `workspace.key` holding the pinned fingerprint (SHA-256
/// hex of the broker's uncompressed P-256 public key).
pub const PIN_FILE_NAME: &str = "broker.fingerprint";

/// Mode the pin file is created with.
pub const PIN_MODE: u32 = 0o600;

/// Result of comparing a live fingerprint with the workspace's pin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PinOutcome {
    /// The pin exists and equals the live fingerprint.
    Matched,
    /// No pin existed; it was written now. The caller prints a notice.
    Written,
}

/// Where the pin lives for a workspace directory.
pub fn pin_path(workspace_dir: &Path) -> PathBuf {
    workspace_dir.join(PIN_FILE_NAME)
}

/// Read the pinned fingerprint, if any. Whitespace is trimmed; an empty
/// file counts as no pin.
pub fn read_pin(workspace_dir: &Path) -> Result<Option<String>, CliError> {
    match fs::read_to_string(pin_path(workspace_dir)) {
        Ok(s) => {
            let trimmed = s.trim();
            Ok((!trimmed.is_empty()).then(|| trimmed.to_string()))
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(CliError::general(format!(
            "failed to read broker pin {}: {e}",
            pin_path(workspace_dir).display()
        ))),
    }
}

/// Write (or replace) the pin, owner-only.
pub fn write_pin(workspace_dir: &Path, fingerprint: &str) -> Result<(), CliError> {
    validate_fingerprint(fingerprint)?;
    let path = pin_path(workspace_dir);
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(PIN_MODE);
    }
    let write = || -> io::Result<()> {
        use std::io::Write;
        let mut file = opts.open(&path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(fs::Permissions::from_mode(PIN_MODE))?;
        }
        file.write_all(fingerprint.as_bytes())?;
        file.write_all(b"\n")
    };
    write().map_err(|e| {
        CliError::general(format!(
            "failed to write broker pin {}: {e}",
            path.display()
        ))
    })
}

/// Compare the broker's live fingerprint with the pin.
///
/// - Pin present and equal: [`PinOutcome::Matched`].
/// - No pin: write it and return [`PinOutcome::Written`].
/// - Pin present and different: refuse with a message naming both values
///   and the way out (`agentcordon register --force` re-pins).
pub fn check_pin(
    workspace_dir: &Path,
    broker_url: &str,
    live_fingerprint: &str,
) -> Result<PinOutcome, CliError> {
    validate_fingerprint(live_fingerprint)?;
    match read_pin(workspace_dir)? {
        Some(pinned) if pinned == live_fingerprint => Ok(PinOutcome::Matched),
        Some(pinned) => Err(CliError::auth_failed(format!(
            "broker key mismatch: the broker at {broker_url} presents key fingerprint \
             {live_fingerprint} but this workspace pinned {pinned} (in {}).\n\
             Either a different broker is answering on this address, or the broker's key \
             was regenerated. If you trust this broker, re-enroll with: \
             agentcordon register --force",
            pin_path(workspace_dir).display()
        ))),
        None => {
            write_pin(workspace_dir, live_fingerprint)?;
            Ok(PinOutcome::Written)
        }
    }
}

/// A fingerprint is 64 lowercase hex characters (SHA-256).
fn validate_fingerprint(fingerprint: &str) -> Result<(), CliError> {
    let ok = fingerprint.len() == 64
        && fingerprint
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    if ok {
        Ok(())
    } else {
        Err(CliError::general(format!(
            "broker published a malformed key fingerprint ({fingerprint:?}); \
             expected 64 hex characters"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ExitCode;

    const FP_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const FP_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    #[test]
    fn missing_pin_reads_as_none() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(read_pin(dir.path()).unwrap(), None);
    }

    #[test]
    fn write_then_read_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        write_pin(dir.path(), FP_A).unwrap();
        assert_eq!(read_pin(dir.path()).unwrap(), Some(FP_A.to_string()));
        assert_eq!(pin_path(dir.path()), dir.path().join("broker.fingerprint"));
    }

    #[cfg(unix)]
    #[test]
    fn pin_file_is_owner_only_even_when_replacing_a_wider_file() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = pin_path(dir.path());
        fs::write(&path, "old").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

        write_pin(dir.path(), FP_A).unwrap();

        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "pin mode {mode:o}");
    }

    #[test]
    fn check_writes_pin_on_first_use_and_matches_after() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            check_pin(dir.path(), "http://127.0.0.1:1", FP_A).unwrap(),
            PinOutcome::Written
        );
        assert_eq!(read_pin(dir.path()).unwrap(), Some(FP_A.to_string()));
        assert_eq!(
            check_pin(dir.path(), "http://127.0.0.1:1", FP_A).unwrap(),
            PinOutcome::Matched
        );
    }

    #[test]
    fn check_refuses_mismatch_and_keeps_the_pin() {
        let dir = tempfile::tempdir().unwrap();
        write_pin(dir.path(), FP_A).unwrap();

        let err = check_pin(dir.path(), "http://127.0.0.1:1", FP_B).expect_err("mismatch");

        assert_eq!(err.code, ExitCode::AuthFailed);
        assert!(
            err.message.contains("broker key mismatch"),
            "{}",
            err.message
        );
        assert!(err.message.contains(FP_A) && err.message.contains(FP_B));
        assert!(err.message.contains("register --force"));
        assert_eq!(read_pin(dir.path()).unwrap(), Some(FP_A.to_string()));
    }

    #[test]
    fn malformed_live_fingerprint_is_refused_without_writing() {
        let dir = tempfile::tempdir().unwrap();
        let err = check_pin(dir.path(), "http://127.0.0.1:1", "not-hex").expect_err("malformed");
        assert!(err.message.contains("malformed"), "{}", err.message);
        assert_eq!(read_pin(dir.path()).unwrap(), None);
    }

    #[test]
    fn whitespace_only_pin_counts_as_none() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(pin_path(dir.path()), "  \n").unwrap();
        assert_eq!(read_pin(dir.path()).unwrap(), None);
    }
}
