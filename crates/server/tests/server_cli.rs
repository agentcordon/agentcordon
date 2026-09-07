//! The `agent-cordon-server` binary's command line.
//!
//! The first thing a new operator does with a binary is ask it what it takes.
//! `agent-cordon-server --help` used to print nothing, never exit, and boot a
//! real server on `0.0.0.0:3140` — binding a public port and writing
//! `data/agent-cordon.db` and `data/.secret` (a master key) into whatever
//! directory the operator happened to be standing in, which for a
//! from-source install is the git working tree.
//!
//! These tests drive the built binary as a user does, in a scratch directory,
//! and assert the two things that make `--help` safe: it exits, and it leaves
//! nothing behind.

use std::path::Path;
use std::process::{Command, Stdio};

/// Run the built server binary with `args`, with `cwd` as its working
/// directory and a scrubbed environment, and return (exit code, stdout,
/// stderr).
///
/// The environment matters: `AGTCRDN_*` variables inherited from the test
/// runner would change what the binary does, and a bare `--help` must not
/// depend on any of them.
fn run_server(cwd: &Path, args: &[&str]) -> (Option<i32>, String, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_agent-cordon-server"));
    cmd.current_dir(cwd)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (key, _) in std::env::vars() {
        if key.starts_with("AGTCRDN_") {
            cmd.env_remove(key);
        }
    }
    let out = cmd.output().expect("the server binary runs");
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// Every path under `dir`, relative and sorted. A `--help` that starts a
/// server leaves `data/agent-cordon.db`, its WAL and shm siblings, the
/// instance lock, and `.secret` here.
fn tree(dir: &Path) -> Vec<String> {
    fn walk(dir: &Path, base: &Path, out: &mut Vec<String>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            out.push(
                path.strip_prefix(base)
                    .unwrap_or(&path)
                    .display()
                    .to_string(),
            );
            if path.is_dir() {
                walk(&path, base, out);
            }
        }
    }
    let mut out = Vec::new();
    walk(dir, dir, &mut out);
    out.sort();
    out
}

#[test]
fn help_prints_usage_and_exits_zero() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (code, stdout, stderr) = run_server(dir.path(), &["--help"]);

    assert_eq!(
        code,
        Some(0),
        "--help must exit 0; stdout={stdout:?} stderr={stderr:?}"
    );
    assert!(
        stdout.contains("Usage:") && stdout.contains("agent-cordon-server"),
        "--help must print usage on stdout, got: {stdout:?}"
    );
}

#[test]
fn help_lists_the_documented_environment_variables() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (_, stdout, _) = run_server(dir.path(), &["--help"]);

    // The server is configured by environment, so `--help` is the only place
    // the binary itself can say so. These are the ones docs/configuration.md
    // documents as load-bearing on a first boot.
    for var in [
        "AGTCRDN_LISTEN_ADDR",
        "AGTCRDN_BASE_URL",
        "AGTCRDN_DB_PATH",
        "AGTCRDN_MASTER_SECRET",
        "AGTCRDN_ROOT_USERNAME",
        "AGTCRDN_ROOT_PASSWORD",
        "AGTCRDN_LOG_LEVEL",
        "AGTCRDN_LOG_FORMAT",
        "AGTCRDN_MCP_TEMPLATES_DIR",
    ] {
        assert!(
            stdout.contains(var),
            "--help should document {var}; got:\n{stdout}"
        );
    }
}

#[test]
fn help_binds_nothing_and_writes_nothing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (code, _, _) = run_server(dir.path(), &["--help"]);

    // The process exited, so it is not serving anything; what remains to
    // check is that it did not create a database or a master key on the way.
    assert_eq!(code, Some(0));
    assert!(
        tree(dir.path()).is_empty(),
        "--help must not create files; found {:?}",
        tree(dir.path())
    );
}

#[test]
fn version_prints_the_crate_version_and_exits_zero() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (code, stdout, stderr) = run_server(dir.path(), &["--version"]);

    assert_eq!(code, Some(0), "--version must exit 0; stderr={stderr:?}");
    assert!(
        stdout.contains(env!("CARGO_PKG_VERSION")),
        "--version must print {}, got {stdout:?}",
        env!("CARGO_PKG_VERSION")
    );
    assert!(
        tree(dir.path()).is_empty(),
        "--version must not create files"
    );
}

#[test]
fn an_unknown_argument_is_an_error_and_starts_nothing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (code, stdout, stderr) = run_server(dir.path(), &["--not-a-flag"]);

    assert_eq!(
        code,
        Some(2),
        "an unknown argument must exit 2; stdout={stdout:?} stderr={stderr:?}"
    );
    assert!(
        stderr.contains("--not-a-flag"),
        "the error should name the offending argument, got: {stderr:?}"
    );
    assert!(
        tree(dir.path()).is_empty(),
        "a rejected command line must not create files; found {:?}",
        tree(dir.path())
    );
}

/// The key-derivation knobs are part of setting a master secret up, and
/// `--help` closes by calling docs/configuration.md "the full table" —
/// which did not list them either. A reader doing master-secret setup from
/// `--help` alone could not discover that the Argon2 cost of a weak secret
/// is tunable, or that a KDF salt override exists that must be applied
/// consistently across a rotation.
#[test]
fn help_documents_the_key_derivation_variables() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (_, stdout, _) = run_server(dir.path(), &["--help"]);

    for var in [
        "AGTCRDN_KDF_SALT",
        "AGTCRDN_ARGON2_M_COST_KIB",
        "AGTCRDN_ARGON2_T_COST",
        "AGTCRDN_ARGON2_P_COST",
    ] {
        assert!(
            stdout.contains(var),
            "--help should document {var}; got:\n{stdout}"
        );
    }
}
