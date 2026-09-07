//! Master-secret strength, stretching, and upgrade safety at the config
//! boundary.
//!
//! `AppConfig::finalize_master_secret` is the entry point every master secret
//! passes through once the store is open and the server knows whether any
//! credential exists. It decides between three branches: direct (strong
//! secret), stretched (weak secret, fresh install or an existing salt file),
//! and legacy (weak secret on an install that already holds credentials).

use agent_cordon_core::crypto::master_secret::{classify_secret, SecretStrength, StoreState};
use agent_cordon_core::crypto::Argon2Params;
use agent_cordon_server::config::AppConfig;

const WEAK: &str = "hunter2-hunter2!";
const STRONG: &str = "5a2f8c1d9e4b7a3f6c0d8e2b5a9f4c7d1e3b6a0c8f2d5e9b4a7c1f3d6e0b8a2c";

fn config_in(dir: &std::path::Path, secret: &str) -> AppConfig {
    let mut config = AppConfig::test_default();
    config.db_path = dir.join("agent-cordon.db").to_string_lossy().to_string();
    config.master_secret = secret.to_string();
    config.argon2 = Argon2Params::FAST;
    config
}

fn salt_file(dir: &std::path::Path) -> std::path::PathBuf {
    dir.join(".master-salt")
}

#[test]
fn a_fresh_install_stretches_a_weak_secret_and_persists_the_salt() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut config = config_in(dir.path(), WEAK);

    let warning = config
        .finalize_master_secret(StoreState::Fresh)
        .expect("finalize");

    assert!(
        warning.is_none(),
        "a fresh install is fixed, not warned about"
    );
    assert_ne!(config.master_secret, WEAK, "the secret must be stretched");
    assert_eq!(config.master_secret.len(), 64);
    assert!(salt_file(dir.path()).exists(), "the salt is persisted");

    // A restart re-derives the same key from the persisted salt.
    let mut restarted = config_in(dir.path(), WEAK);
    restarted
        .finalize_master_secret(StoreState::Populated)
        .expect("restart");
    assert_eq!(restarted.master_secret, config.master_secret);
}

#[test]
fn an_existing_install_with_a_weak_secret_and_no_salt_keeps_its_key() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut config = config_in(dir.path(), WEAK);

    let warning = config
        .finalize_master_secret(StoreState::Populated)
        .expect("finalize")
        .expect("a warning names the fix");

    assert_eq!(
        config.master_secret, WEAK,
        "upgrading must not change the derived key"
    );
    assert!(
        !salt_file(dir.path()).exists(),
        "no salt is written on the legacy path"
    );
    assert!(warning.contains("AGTCRDN_MASTER_SECRET"), "{warning}");
    assert!(warning.contains("rotate"), "{warning}");
}

#[test]
fn a_strong_secret_is_used_directly() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut config = config_in(dir.path(), STRONG);

    let warning = config
        .finalize_master_secret(StoreState::Fresh)
        .expect("finalize");

    assert!(warning.is_none());
    assert_eq!(config.master_secret, STRONG);
    assert!(
        !salt_file(dir.path()).exists(),
        "a strong secret needs no salt"
    );
}

#[test]
fn the_previous_master_secret_follows_the_same_rule() {
    let dir = tempfile::tempdir().expect("tempdir");

    // No salt file: the previous secret, weak, is left alone so rows sealed
    // under it still open.
    let mut config = config_in(dir.path(), STRONG);
    config.master_key_version = 2;
    config.previous_master_secret = Some(WEAK.to_string());
    config
        .finalize_master_secret(StoreState::Populated)
        .expect("finalize");
    assert_eq!(config.previous_master_secret.as_deref(), Some(WEAK));

    // With a salt file present the previous secret was stretched when it was
    // current, so it must be stretched now too.
    let mut fresh = config_in(dir.path(), WEAK);
    fresh
        .finalize_master_secret(StoreState::Fresh)
        .expect("write the salt");
    let stretched_weak = fresh.master_secret.clone();

    let mut rotated = config_in(dir.path(), STRONG);
    rotated.master_key_version = 2;
    rotated.previous_master_secret = Some(WEAK.to_string());
    rotated
        .finalize_master_secret(StoreState::Populated)
        .expect("finalize");
    assert_eq!(
        rotated.previous_master_secret.as_deref(),
        Some(stretched_weak.as_str()),
        "the previous secret is stretched with the same salt"
    );
}

#[test]
fn a_weak_previous_secret_never_creates_a_salt_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut config = config_in(dir.path(), STRONG);
    config.master_key_version = 2;
    config.previous_master_secret = Some(WEAK.to_string());

    config
        .finalize_master_secret(StoreState::Fresh)
        .expect("finalize");

    assert!(
        !salt_file(dir.path()).exists(),
        "the previous secret is historical; it must not define a new salt"
    );
    assert_eq!(config.previous_master_secret.as_deref(), Some(WEAK));
}

#[test]
fn an_in_memory_database_takes_the_legacy_path_without_warning() {
    let mut config = AppConfig::test_default();
    config.master_secret = WEAK.to_string();

    let warning = config
        .finalize_master_secret(StoreState::Fresh)
        .expect("finalize");

    assert!(warning.is_none());
    assert_eq!(config.master_secret, WEAK);
}

#[test]
fn the_auto_generated_secret_file_is_strong() {
    let generated = AppConfig::generate_master_secret();
    assert_eq!(generated.len(), 64, "32 random bytes, hex-encoded");
    assert!(generated.bytes().all(|b| b.is_ascii_hexdigit()));
    assert_eq!(classify_secret(&generated), SecretStrength::Strong);
    assert_ne!(generated, AppConfig::generate_master_secret());
}

#[test]
fn the_test_harness_installs_cheap_argon2_parameters() {
    let config = AppConfig::test_default();
    assert_eq!(config.argon2, Argon2Params::FAST);
    assert_eq!(
        agent_cordon_core::crypto::argon2_params(),
        Argon2Params::FAST,
        "building a test config must install the cheap parameters"
    );
}
