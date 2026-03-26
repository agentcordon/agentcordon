//! P2: Workspace State tests for the v2.0 workspace unification branch.
//!
//! Tests `WorkspaceState` and related functions from `crates/gateway/src/cli/state.rs`.
//! Covers: load/save roundtrips, error handling, URL resolution,
//! JWT validity checks, and workspace key detection.
//!
//! Many tests use `std::env::set_current_dir` and `std::env::set_var` which
//! are not thread-safe, so all such tests are marked `#[serial]`.

use agentcordon::cli_state::{has_workspace_key, WorkspaceState};
use serial_test::serial;
use std::path::PathBuf;

/// Helper: save the current working directory, chdir to `dir`, run `f`,
/// then restore the original directory. Panics on chdir failure.
fn with_cwd<F: FnOnce()>(dir: &std::path::Path, f: F) {
    let orig = std::env::current_dir().expect("get original cwd");
    std::env::set_current_dir(dir).expect("chdir to tempdir");
    f();
    std::env::set_current_dir(&orig).expect("restore original cwd");
}

// ===========================================================================
// Load/Save (4 tests)
// ===========================================================================

/// 1. Loading from an empty directory returns a default (all-None) state.
#[test]
#[serial]
fn test_load_missing_file_returns_default() {
    let tmp = tempfile::tempdir().expect("tempdir");
    with_cwd(tmp.path(), || {
        let state = WorkspaceState::load();
        assert!(state.agent_id.is_none());
        assert!(state.workspace_pk_hash.is_none());
        assert!(state.workspace_public_key.is_none());
        assert!(state.jwt.is_none());
        assert!(state.jwt_expires_at.is_none());
        assert!(state.server_url.is_none());
    });
}

/// 2. `save()` creates `.agentcordon/state.json` even when the dir is missing.
#[test]
#[serial]
fn test_save_creates_dir_and_file() {
    let tmp = tempfile::tempdir().expect("tempdir");
    with_cwd(tmp.path(), || {
        let state = WorkspaceState {
            agent_id: Some("test-agent".into()),
            ..Default::default()
        };
        state.save().expect("save should succeed");

        let expected = tmp.path().join(".agentcordon").join("state.json");
        assert!(
            expected.exists(),
            "state.json should exist at {}",
            expected.display()
        );
    });
}

/// 3. Set all fields, save, load, verify they match.
#[test]
#[serial]
fn test_roundtrip_all_fields() {
    let tmp = tempfile::tempdir().expect("tempdir");
    with_cwd(tmp.path(), || {
        let original = WorkspaceState {
            agent_id: Some("agent-42".into()),
            workspace_pk_hash: Some("sha256:abcdef".into()),
            workspace_public_key: Some("pk-data".into()),
            jwt: Some("eyJ.token.here".into()),
            jwt_expires_at: Some("1710000000".into()),
            server_url: Some("https://example.com".into()),
        };
        original.save().expect("save");

        let loaded = WorkspaceState::load();
        assert_eq!(loaded.agent_id.as_deref(), Some("agent-42"));
        assert_eq!(loaded.workspace_pk_hash.as_deref(), Some("sha256:abcdef"));
        assert_eq!(loaded.workspace_public_key.as_deref(), Some("pk-data"));
        assert_eq!(loaded.jwt.as_deref(), Some("eyJ.token.here"));
        assert_eq!(loaded.jwt_expires_at.as_deref(), Some("1710000000"));
        assert_eq!(loaded.server_url.as_deref(), Some("https://example.com"));
    });
}

/// 4. When only some fields are set, `skip_serializing_if` omits null keys.
#[test]
#[serial]
fn test_partial_roundtrip_skip_serializing() {
    let tmp = tempfile::tempdir().expect("tempdir");
    with_cwd(tmp.path(), || {
        let state = WorkspaceState {
            agent_id: Some("partial-agent".into()),
            server_url: Some("http://localhost:9999".into()),
            ..Default::default()
        };
        state.save().expect("save");

        // Read the raw JSON and verify no null keys
        let raw = std::fs::read_to_string(tmp.path().join(".agentcordon").join("state.json"))
            .expect("read file");

        assert!(
            !raw.contains("null"),
            "JSON should not contain null values, got:\n{}",
            raw
        );
        assert!(raw.contains("partial-agent"));
        assert!(raw.contains("localhost:9999"));
        // Fields that were None should not appear at all
        assert!(!raw.contains("jwt_expires_at"));
        assert!(!raw.contains("workspace_pk_hash"));
    });
}

// ===========================================================================
// Retry (1 test)
// ===========================================================================

/// 5. Saving twice: the second write wins.
#[test]
#[serial]
fn test_save_twice_second_wins() {
    let tmp = tempfile::tempdir().expect("tempdir");
    with_cwd(tmp.path(), || {
        let first = WorkspaceState {
            agent_id: Some("first".into()),
            ..Default::default()
        };
        first.save().expect("save first");

        let second = WorkspaceState {
            agent_id: Some("second".into()),
            ..Default::default()
        };
        second.save().expect("save second");

        let loaded = WorkspaceState::load();
        assert_eq!(
            loaded.agent_id.as_deref(),
            Some("second"),
            "second save should overwrite the first"
        );
    });
}

// ===========================================================================
// Error Handling (3 tests)
// ===========================================================================

/// 6. Corrupt JSON returns default state (no panic).
#[test]
#[serial]
fn test_load_corrupt_json_returns_default() {
    let tmp = tempfile::tempdir().expect("tempdir");
    with_cwd(tmp.path(), || {
        let dir = tmp.path().join(".agentcordon");
        std::fs::create_dir_all(&dir).expect("create dir");
        std::fs::write(dir.join("state.json"), "{{{broken").expect("write");

        let state = WorkspaceState::load();
        assert!(
            state.agent_id.is_none(),
            "corrupt JSON should yield default"
        );
    });
}

/// 7. Empty file returns default state (no panic).
#[test]
#[serial]
fn test_load_empty_file_returns_default() {
    let tmp = tempfile::tempdir().expect("tempdir");
    with_cwd(tmp.path(), || {
        let dir = tmp.path().join(".agentcordon");
        std::fs::create_dir_all(&dir).expect("create dir");
        std::fs::write(dir.join("state.json"), "").expect("write");

        let state = WorkspaceState::load();
        assert!(state.agent_id.is_none(), "empty file should yield default");
    });
}

/// 8. Valid JSON but wrong shape returns default (serde fails gracefully).
#[test]
#[serial]
fn test_load_wrong_shape_returns_default() {
    let tmp = tempfile::tempdir().expect("tempdir");
    with_cwd(tmp.path(), || {
        let dir = tmp.path().join(".agentcordon");
        std::fs::create_dir_all(&dir).expect("create dir");
        std::fs::write(dir.join("state.json"), r#"{"unexpected": 42}"#).expect("write");

        // This should NOT panic. All fields have `#[serde(default)]` so
        // unknown keys are ignored and missing fields get None.
        let state = WorkspaceState::load();
        assert!(
            state.agent_id.is_none(),
            "wrong-shape JSON should yield default for missing fields"
        );
    });
}

// ===========================================================================
// URL Resolution (6 tests)
// ===========================================================================

/// 9. Flag takes highest priority (flag > env > state > default).
#[test]
#[serial]
fn test_resolve_server_url_flag_wins() {
    std::env::set_var("AGENTCORDON_SERVER_URL", "http://from-env:3000");
    let state = WorkspaceState {
        server_url: Some("http://from-state:4000".into()),
        ..Default::default()
    };
    let flag = Some("http://from-flag:5000".to_string());

    let result = state.resolve_server_url(&flag);
    assert_eq!(result, "http://from-flag:5000");

    std::env::remove_var("AGENTCORDON_SERVER_URL");
}

/// 10. Env wins over state when no flag is provided.
#[test]
#[serial]
fn test_resolve_server_url_env_wins_over_state() {
    std::env::set_var("AGENTCORDON_SERVER_URL", "http://from-env:3000");
    let state = WorkspaceState {
        server_url: Some("http://from-state:4000".into()),
        ..Default::default()
    };

    let result = state.resolve_server_url(&None);
    assert_eq!(result, "http://from-env:3000");

    std::env::remove_var("AGENTCORDON_SERVER_URL");
}

/// 11. State wins over default when no flag or env.
#[test]
#[serial]
fn test_resolve_server_url_state_wins_over_default() {
    std::env::remove_var("AGENTCORDON_SERVER_URL");
    let state = WorkspaceState {
        server_url: Some("http://from-state:4000".into()),
        ..Default::default()
    };

    let result = state.resolve_server_url(&None);
    assert_eq!(result, "http://from-state:4000");
}

/// 12. Falls back to localhost:3140 when nothing is set.
#[test]
#[serial]
fn test_resolve_server_url_default() {
    std::env::remove_var("AGENTCORDON_SERVER_URL");
    let state = WorkspaceState::default();

    let result = state.resolve_server_url(&None);
    assert_eq!(result, "http://localhost:3140");
}

/// 13. Trailing slash is stripped at every priority level.
#[test]
#[serial]
fn test_resolve_server_url_strips_trailing_slash() {
    std::env::remove_var("AGENTCORDON_SERVER_URL");

    // Flag with trailing slash
    let state = WorkspaceState::default();
    let flag = Some("http://example.com/".to_string());
    assert_eq!(state.resolve_server_url(&flag), "http://example.com");

    // Env with trailing slash
    std::env::set_var("AGENTCORDON_SERVER_URL", "http://env.example.com/");
    assert_eq!(state.resolve_server_url(&None), "http://env.example.com");
    std::env::remove_var("AGENTCORDON_SERVER_URL");

    // State with trailing slash
    let state2 = WorkspaceState {
        server_url: Some("http://state.example.com/".into()),
        ..Default::default()
    };
    assert_eq!(state2.resolve_server_url(&None), "http://state.example.com");
}

/// 14. Empty env var is treated as unset (falls through to next priority).
#[test]
#[serial]
fn test_resolve_server_url_empty_env_skipped() {
    std::env::set_var("AGENTCORDON_SERVER_URL", "");
    let state = WorkspaceState {
        server_url: Some("http://from-state:4000".into()),
        ..Default::default()
    };

    let result = state.resolve_server_url(&None);
    assert_eq!(
        result, "http://from-state:4000",
        "empty env var should be skipped, falling through to state"
    );

    std::env::remove_var("AGENTCORDON_SERVER_URL");
}

// ===========================================================================
// JWT Validity (7 tests)
// ===========================================================================

/// Helper: current unix timestamp as i64.
fn now_ts() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

/// 15. JWT with future expiry is valid.
#[test]
fn test_jwt_valid_future_expiry() {
    let state = WorkspaceState {
        jwt: Some("valid.jwt.token".into()),
        jwt_expires_at: Some((now_ts() + 3600).to_string()),
        ..Default::default()
    };
    assert!(state.jwt_valid(), "JWT expiring in 1 hour should be valid");
}

/// 16. JWT with past expiry is invalid.
#[test]
fn test_jwt_expired() {
    let state = WorkspaceState {
        jwt: Some("expired.jwt.token".into()),
        jwt_expires_at: Some((now_ts() - 60).to_string()),
        ..Default::default()
    };
    assert!(
        !state.jwt_valid(),
        "JWT that expired 60s ago should be invalid"
    );
}

/// 17. JWT expiring within the 30s buffer is invalid.
#[test]
fn test_jwt_within_30s_buffer() {
    let state = WorkspaceState {
        jwt: Some("almost-expired.jwt.token".into()),
        jwt_expires_at: Some((now_ts() + 20).to_string()),
        ..Default::default()
    };
    assert!(
        !state.jwt_valid(),
        "JWT expiring in 20s should be invalid (inside 30s buffer)"
    );
}

/// 18. JWT at the exact 30s boundary is invalid (now < expires_at - 30
///     is false when expires_at - 30 == now).
#[test]
fn test_jwt_at_exact_boundary() {
    let state = WorkspaceState {
        jwt: Some("boundary.jwt.token".into()),
        jwt_expires_at: Some((now_ts() + 30).to_string()),
        ..Default::default()
    };
    assert!(
        !state.jwt_valid(),
        "JWT at exact 30s boundary should be invalid (not strictly less than)"
    );
}

/// 19. No JWT present means invalid.
#[test]
fn test_jwt_valid_no_jwt() {
    let state = WorkspaceState {
        jwt: None,
        jwt_expires_at: Some((now_ts() + 3600).to_string()),
        ..Default::default()
    };
    assert!(!state.jwt_valid(), "None jwt should be invalid");
}

/// 20. Empty JWT string means invalid.
#[test]
fn test_jwt_valid_empty_jwt() {
    let state = WorkspaceState {
        jwt: Some("".into()),
        jwt_expires_at: Some((now_ts() + 3600).to_string()),
        ..Default::default()
    };
    assert!(!state.jwt_valid(), "empty jwt should be invalid");
}

/// 21. Non-numeric expiry string means invalid (no panic).
#[test]
fn test_jwt_valid_non_numeric_expiry() {
    let state = WorkspaceState {
        jwt: Some("valid.jwt.token".into()),
        jwt_expires_at: Some("not-a-number".into()),
        ..Default::default()
    };
    assert!(
        !state.jwt_valid(),
        "non-numeric jwt_expires_at should yield invalid"
    );
}

// ===========================================================================
// Key Checks (2 tests)
// ===========================================================================

/// 22. `has_workspace_key` returns true when both files exist.
#[test]
#[serial]
fn test_has_workspace_key_both_present() {
    let tmp = tempfile::tempdir().expect("tempdir");
    with_cwd(tmp.path(), || {
        let dir = PathBuf::from(".agentcordon");
        std::fs::create_dir_all(&dir).expect("create dir");
        std::fs::write(dir.join("workspace.key"), b"dummy-private").expect("write key");
        std::fs::write(dir.join("workspace.pub"), b"dummy-public").expect("write pub");

        assert!(
            has_workspace_key(),
            "has_workspace_key should return true when both files exist"
        );
    });
}

/// 23. `has_workspace_key` returns false when only one file exists.
#[test]
#[serial]
fn test_has_workspace_key_missing_one() {
    let tmp = tempfile::tempdir().expect("tempdir");
    with_cwd(tmp.path(), || {
        let dir = PathBuf::from(".agentcordon");
        std::fs::create_dir_all(&dir).expect("create dir");

        // Only private key, no public
        std::fs::write(dir.join("workspace.key"), b"dummy-private").expect("write key");
        assert!(
            !has_workspace_key(),
            "should be false with only workspace.key"
        );

        // Now add public, remove private
        std::fs::write(dir.join("workspace.pub"), b"dummy-public").expect("write pub");
        std::fs::remove_file(dir.join("workspace.key")).expect("remove key");
        assert!(
            !has_workspace_key(),
            "should be false with only workspace.pub"
        );
    });
}
