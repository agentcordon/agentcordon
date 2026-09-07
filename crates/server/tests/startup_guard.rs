//! The replica startup guard.
//!
//! Two server processes over one SQLite file give split-brain policy
//! enforcement: each has its own policy cache, rate limiters and SSE bus. The
//! guard is an advisory `flock` on `<db>.lock`, taken before migrations and
//! held for the process lifetime, with `AGTCRDN_REPLICA_MODE=unsafe-shared`
//! as the documented escape hatch.

use agent_cordon_server::config::{AppConfig, ReplicaMode};

fn config_at(db_path: &std::path::Path) -> AppConfig {
    let mut config = AppConfig::test_default();
    config.db_path = db_path.to_string_lossy().to_string();
    config.replica_mode = ReplicaMode::Single;
    config
}

#[test]
fn a_second_instance_on_the_same_database_is_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db = dir.path().join("agent-cordon.db");
    let config = config_at(&db);

    let first = config
        .acquire_instance_lock()
        .expect("the first instance starts");
    assert!(first.is_some(), "a file-backed database must be locked");

    let err = config
        .acquire_instance_lock()
        .expect_err("the second instance must be refused");
    assert!(
        err.contains("agent-cordon.db.lock"),
        "the error names the lock file: {err}"
    );
    assert!(
        err.contains("AGTCRDN_REPLICA_MODE=unsafe-shared"),
        "the error names the escape hatch: {err}"
    );

    drop(first);
}

#[test]
fn releasing_the_lock_lets_the_next_instance_start() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db = dir.path().join("agent-cordon.db");
    let config = config_at(&db);

    let first = config.acquire_instance_lock().expect("first instance");
    drop(first);

    let second = config
        .acquire_instance_lock()
        .expect("the lock is released when the holder exits");
    assert!(second.is_some());
}

#[test]
fn the_unsafe_shared_escape_hatch_allows_a_second_instance() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db = dir.path().join("agent-cordon.db");
    let mut config = config_at(&db);

    let _first = config.acquire_instance_lock().expect("first instance");

    config.replica_mode = ReplicaMode::UnsafeShared;
    let second = config
        .acquire_instance_lock()
        .expect("unsafe-shared bypasses the guard");
    assert!(second.is_none(), "no lock is taken in unsafe-shared mode");
}

#[test]
fn an_in_memory_database_is_exempt() {
    let config = AppConfig::test_default();
    assert_eq!(config.db_path, ":memory:");
    for _ in 0..2 {
        assert!(
            config
                .acquire_instance_lock()
                .expect("in-memory databases are never shared")
                .is_none(),
            "an in-memory database needs no lock file"
        );
    }
}

#[test]
fn replica_mode_parses_only_documented_values() {
    assert_eq!(ReplicaMode::parse(None), Ok(ReplicaMode::Single));
    assert_eq!(ReplicaMode::parse(Some("single")), Ok(ReplicaMode::Single));
    assert_eq!(
        ReplicaMode::parse(Some("unsafe-shared")),
        Ok(ReplicaMode::UnsafeShared)
    );
    let err = ReplicaMode::parse(Some("yes")).expect_err("an unknown mode must not start");
    assert!(err.contains("AGTCRDN_REPLICA_MODE"), "{err}");
    assert!(err.contains("unsafe-shared"), "{err}");
}
