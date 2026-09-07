//! SQLite is the only storage backend.
//!
//! The Postgres backend was deleted in 0.4.0. A user upgrading with an old
//! `.env` still has `AGTCRDN_DB_TYPE=postgres` and `AGTCRDN_DB_URL=postgres://…`
//! in it. Startup must refuse that configuration with a message that names the
//! variable and says what to do, rather than opening a SQLite file called
//! `postgres://…` or dying on an "unknown backend" branch that still lists
//! `postgres` as a choice.

use agent_cordon_server::config::AppConfig;
use serial_test::serial;
use tempfile::TempDir;

/// Point `from_env` at a scratch directory and clear every database variable
/// this file plays with, so one test's leftovers cannot pass another.
fn clean_env(tmp: &TempDir) {
    std::env::set_var("AGTCRDN_MASTER_SECRET", "test-master-secret-32-bytes-long!");
    std::env::remove_var("AGTCRDN_KDF_SALT");
    std::env::remove_var("AGTCRDN_DB_TYPE");
    std::env::remove_var("AGTCRDN_DB_URL");
    std::env::set_var(
        "AGTCRDN_DB_PATH",
        tmp.path().join("agent-cordon.db").to_str().expect("utf-8"),
    );
}

fn clear_env() {
    std::env::remove_var("AGTCRDN_MASTER_SECRET");
    std::env::remove_var("AGTCRDN_DB_TYPE");
    std::env::remove_var("AGTCRDN_DB_URL");
    std::env::remove_var("AGTCRDN_DB_PATH");
}

#[test]
#[serial]
fn db_type_postgres_is_refused_by_name() {
    let tmp = TempDir::new().expect("temp dir");
    clean_env(&tmp);
    std::env::set_var("AGTCRDN_DB_TYPE", "postgres");

    let err = AppConfig::from_env().expect_err("postgres backend no longer exists");
    clear_env();

    assert!(err.contains("AGTCRDN_DB_TYPE"), "{err}");
    assert!(err.contains("postgres"), "{err}");
    assert!(err.contains("SQLite"), "{err}");
}

#[test]
#[serial]
fn db_url_is_refused_because_only_postgres_ever_used_it() {
    let tmp = TempDir::new().expect("temp dir");
    clean_env(&tmp);
    std::env::set_var(
        "AGTCRDN_DB_URL",
        "postgres://user:pass@localhost:5432/agentcordon",
    );

    let err = AppConfig::from_env().expect_err("AGTCRDN_DB_URL is no longer a setting");
    clear_env();

    assert!(err.contains("AGTCRDN_DB_URL"), "{err}");
    assert!(err.contains("AGTCRDN_DB_PATH"), "{err}");
    // The message must not leak the password out of the URL into the log.
    assert!(!err.contains("pass@"), "connection URL leaked: {err}");
}

#[test]
#[serial]
fn a_postgres_url_in_the_sqlite_path_is_refused() {
    let tmp = TempDir::new().expect("temp dir");
    clean_env(&tmp);
    std::env::set_var("AGTCRDN_DB_PATH", "postgresql://localhost/agentcordon");

    let err = AppConfig::from_env().expect_err("a connection URL is not a file path");
    clear_env();

    assert!(err.contains("AGTCRDN_DB_PATH"), "{err}");
    assert!(err.contains("file path"), "{err}");
}

#[test]
#[serial]
fn db_type_sqlite_is_still_accepted() {
    let tmp = TempDir::new().expect("temp dir");
    clean_env(&tmp);
    std::env::set_var("AGTCRDN_DB_TYPE", "sqlite");

    let config = AppConfig::from_env().expect("sqlite is the backend");
    clear_env();

    assert!(config.db_path.ends_with("agent-cordon.db"));
}

#[test]
#[serial]
fn an_unknown_db_type_names_sqlite_as_the_only_choice() {
    let tmp = TempDir::new().expect("temp dir");
    clean_env(&tmp);
    std::env::set_var("AGTCRDN_DB_TYPE", "mysql");

    let err = AppConfig::from_env().expect_err("there is one backend");
    clear_env();

    assert!(err.contains("mysql"), "{err}");
    assert!(!err.contains("postgres"), "postgres is gone: {err}");
}
