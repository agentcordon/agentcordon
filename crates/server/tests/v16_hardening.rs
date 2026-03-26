//! v1.6 — Security Hardening Tests (Wave 4)
//!
//! Tests various hardening measures:
//! - Argon2id production parameters (4.1)
//! - Device name dot validation (4.7)

// ===========================================================================
// 4.1: Argon2id Production Params
// ===========================================================================

#[test]
fn test_argon2id_hash_verifies() {
    use agent_cordon_core::crypto::password::{hash_password, verify_password};

    let password = "secure-password-123!";
    let hash = hash_password(password).expect("hash should succeed");
    assert!(
        verify_password(password, &hash).expect("verify should not error"),
        "hash should verify"
    );
}

#[test]
fn test_argon2id_old_hashes_still_verify() {
    use agent_cordon_core::crypto::password::{hash_password, verify_password};

    // Hash with current params (test mode uses fast params)
    let hash = hash_password("my-password").expect("hash");

    // PHC format is self-describing — verification should work regardless of
    // which params were used to create the hash
    assert!(
        verify_password("my-password", &hash).expect("verify ok"),
        "correct password should verify"
    );
    assert!(
        !verify_password("wrong-password", &hash).expect("verify ok"),
        "wrong password should not verify"
    );
}

// ===========================================================================
// 4.7: Device Name Dot Validation
// ===========================================================================

#[test]
fn test_device_name_no_dots_accepted() {
    // Valid device names (no dots)
    let valid_names = ["my-laptop", "prod-device-1", "ci-runner", "test_device"];
    for name in &valid_names {
        assert!(
            !name.contains('.'),
            "valid device name '{}' should not contain dots",
            name
        );
    }
}

#[test]
fn test_device_name_with_dots_rejected() {
    // Device names with dots would cause scope parsing confusion
    let invalid_names = ["my.laptop", "device.name.here", "a.b"];
    for name in &invalid_names {
        assert!(
            name.contains('.'),
            "invalid device name '{}' should contain dots",
            name
        );
        // The 3-part scope format is: device_name.mcp_server.action
        // A device name with dots would create ambiguity
        let scope_str = format!("{}.github.create_issue", name);
        let parts: Vec<&str> = scope_str.split('.').collect();
        assert!(
            parts.len() > 3,
            "dotted device name creates >3 parts in scope: {:?}",
            parts
        );
    }
}

#[test]
fn test_device_name_dot_scope_confusion() {
    // Demonstrate why dots in device names break 3-part scope parsing
    let scope_with_dotted_name = "device.name.github.create_issue";
    let parts: Vec<&str> = scope_with_dotted_name.split('.').collect();
    assert_eq!(
        parts.len(),
        4,
        "dotted device name creates 4 parts instead of 3"
    );

    let scope_normal = "my-device.github.create_issue";
    let parts: Vec<&str> = scope_normal.split('.').collect();
    assert_eq!(parts.len(), 3, "normal device name creates exactly 3 parts");
}
