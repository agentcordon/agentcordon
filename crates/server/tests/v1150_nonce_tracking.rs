//! v1.15.0 — Feature 4: AES-GCM Nonce Collision Tracking
//!
//! Tests that encryption operations track a per-DEK counter,
//! nonces are unique, and thresholds are enforced.
//!
//! NOTE: These tests are written against the EXPECTED behavior from the
//! test design document. The nonce tracking feature is being implemented
//! in parallel — tests may not compile until the feature lands.

use axum::http::{Method, StatusCode};
use serde_json::json;

use agent_cordon_core::crypto::SecretEncryptor;
use agent_cordon_core::domain::user::UserRole;
use agent_cordon_server::test_helpers::TestAppBuilder;

use crate::common::*;

// ===========================================================================
// 4A. Happy Path
// ===========================================================================

/// Test #1: Encrypting a value increments the counter.
/// Encrypt once → counter=1. Encrypt again → counter=2.
#[tokio::test]
async fn test_encryption_increments_counter() {
    let ctx = TestAppBuilder::new().with_admin().build().await;

    let aad = b"test-aad";

    // The encryptor tracks encryption count via encryption_count()
    let initial_count = ctx.encryptor.encryption_count();

    let (_ciphertext1, _nonce1) = ctx
        .encryptor
        .encrypt(b"secret-value-1", aad)
        .expect("encrypt 1");
    assert_eq!(
        ctx.encryptor.encryption_count(),
        initial_count + 1,
        "counter should increment after first encryption"
    );

    let (_ciphertext2, _nonce2) = ctx
        .encryptor
        .encrypt(b"secret-value-2", aad)
        .expect("encrypt 2");
    assert_eq!(
        ctx.encryptor.encryption_count(),
        initial_count + 2,
        "counter should increment after second encryption"
    );
}

/// Test #2: Counter persists across operations with the same encryptor.
#[tokio::test]
async fn test_counter_persists_across_operations() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let aad = b"test-aad";

    let initial_count = ctx.encryptor.encryption_count();

    // Encrypt 5 values
    for i in 0..5 {
        let plaintext = format!("secret-{}", i);
        ctx.encryptor
            .encrypt(plaintext.as_bytes(), aad)
            .expect("encrypt");
    }
    assert_eq!(
        ctx.encryptor.encryption_count(),
        initial_count + 5,
        "counter should be initial+5 after 5 encryptions"
    );

    // Encrypt one more
    ctx.encryptor.encrypt(b"one-more", aad).expect("encrypt 6");
    assert_eq!(
        ctx.encryptor.encryption_count(),
        initial_count + 6,
        "counter should continue incrementing, not reset"
    );
}

/// Test #4: All nonces are unique across 1000 encryptions.
#[tokio::test]
async fn test_nonces_are_unique_across_encryptions() {
    let ctx = TestAppBuilder::new().build().await;
    let aad = b"nonce-uniqueness-test";

    let mut nonces = std::collections::HashSet::new();
    for i in 0..1000 {
        let plaintext = format!("value-{}", i);
        let (_ciphertext, nonce) = ctx
            .encryptor
            .encrypt(plaintext.as_bytes(), aad)
            .expect("encrypt");
        assert!(
            nonces.insert(nonce),
            "nonce collision detected at iteration {}",
            i
        );
    }
    assert_eq!(nonces.len(), 1000, "all 1000 nonces should be unique");
}

// ===========================================================================
// 4B. Retry/Idempotency
// ===========================================================================

// ===========================================================================
// 4D. Cross-Feature
// ===========================================================================

/// Test #8: Storing a credential via admin API increments the nonce counter.
#[tokio::test]
async fn test_credential_encryption_tracked() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let _admin = create_test_user(&*ctx.store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let (cookie, csrf) = login_user(&ctx.app, "admin", TEST_PASSWORD).await;
    let full_cookie = combined_cookie(&cookie, &csrf);

    let count_before = ctx.encryptor.encryption_count();

    let (status, body) = send_json(
        &ctx.app,
        Method::POST,
        "/api/v1/credentials",
        None,
        Some(&full_cookie),
        Some(&csrf),
        Some(json!({
            "name": "nonce-track-cred",
            "service": "test-service",
            "secret_value": "my-secret-value",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "create credential: {}", body);

    let count_after = ctx.encryptor.encryption_count();
    assert!(
        count_after > count_before,
        "encryption counter should increment when storing credential: before={}, after={}",
        count_before,
        count_after
    );
}

/// Test #9: Rotating a credential secret increments counter for both ops.
#[tokio::test]
async fn test_secret_history_encryption_tracked() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let _admin = create_test_user(&*ctx.store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let (cookie, csrf) = login_user(&ctx.app, "admin", TEST_PASSWORD).await;
    let full_cookie = combined_cookie(&cookie, &csrf);

    // Create a credential
    let (status, body) = send_json(
        &ctx.app,
        Method::POST,
        "/api/v1/credentials",
        None,
        Some(&full_cookie),
        Some(&csrf),
        Some(json!({
            "name": "nonce-rotate-cred",
            "service": "test-service",
            "secret_value": "original-secret",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "create credential: {}", body);
    let cred_id = body["data"]["id"].as_str().expect("credential id");

    let count_before_rotate = ctx.encryptor.encryption_count();

    // Rotate the secret
    let (status, _body) = send_json(
        &ctx.app,
        Method::PUT,
        &format!("/api/v1/credentials/{}", cred_id),
        None,
        Some(&full_cookie),
        Some(&csrf),
        Some(json!({
            "secret_value": "new-rotated-secret",
        })),
    )
    .await;
    assert!(
        status == StatusCode::OK || status == StatusCode::NO_CONTENT,
        "rotate secret: status={}",
        status
    );

    let count_after_rotate = ctx.encryptor.encryption_count();
    assert!(
        count_after_rotate > count_before_rotate,
        "counter should increment during rotation: before={}, after={}",
        count_before_rotate,
        count_after_rotate
    );
}

// ===========================================================================
// 4E. Security
// ===========================================================================

/// Test #10: Counter value is not exposed in any API endpoint.
#[tokio::test]
async fn test_counter_not_exposed_in_api() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let _admin = create_test_user(&*ctx.store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let (cookie, csrf) = login_user(&ctx.app, "admin", TEST_PASSWORD).await;
    let full_cookie = combined_cookie(&cookie, &csrf);

    // Create a credential (triggers encryption)
    let (status, body) = send_json(
        &ctx.app,
        Method::POST,
        "/api/v1/credentials",
        None,
        Some(&full_cookie),
        Some(&csrf),
        Some(json!({
            "name": "counter-leak-test",
            "service": "test-service",
            "secret_value": "secret-value",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "create credential: {}", body);
    let cred_id = body["data"]["id"].as_str().expect("credential id");

    // Check credential detail response for counter leakage
    let (status, detail) = send_json(
        &ctx.app,
        Method::GET,
        &format!("/api/v1/credentials/{}", cred_id),
        None,
        Some(&full_cookie),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let detail_str = serde_json::to_string(&detail).unwrap();
    assert!(
        !detail_str.contains("encryption_counter"),
        "credential response must not contain encryption counter"
    );
    assert!(
        !detail_str.contains("nonce_counter"),
        "credential response must not contain nonce counter"
    );
}
