//! v1.6.2 — SSRF Loopback Protection Tests
//!
//! Tests the `proxy_allow_loopback` config flag behavior in the server's
//! proxy endpoint (POST /api/v1/proxy/execute).
//!
//! NOTE: These tests verify the SSRF validation logic at the server proxy layer.
//! The device proxy has its own SSRF checks (in `crates/device/tests/ssrf_protection.rs`).
//! These tests focus on the server-side `validate_proxy_target` guard and
//! `proxy_allow_loopback` config flag.

use axum::http::{Method, StatusCode};
use serde_json::json;
use uuid::Uuid;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use agent_cordon_core::crypto::SecretEncryptor;
use agent_cordon_core::domain::credential::{CredentialId, StoredCredential};

use agent_cordon_server::test_helpers::{TestAppBuilder, TestContext};

use crate::common::*;

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

/// Store a credential and grant permissions to the admin agent.
/// The credential name is used as a placeholder in proxy URLs: `{{cred_name}}`.
async fn setup_credential(
    ctx: &TestContext,
    cred_name: &str,
    target_url_pattern: &str,
) -> CredentialId {
    let admin = ctx.admin_agent.as_ref().expect("admin agent");
    let now = chrono::Utc::now();
    let cred_id = CredentialId(Uuid::new_v4());
    let secret = "test-api-key-secret";
    let (encrypted, nonce) = ctx
        .encryptor
        .encrypt(secret.as_bytes(), cred_id.0.to_string().as_bytes())
        .expect("encrypt");
    let cred = StoredCredential {
        id: cred_id.clone(),
        name: cred_name.to_string(),
        service: "test-service".to_string(),
        encrypted_value: encrypted,
        nonce,
        scopes: vec!["read".to_string()],
        metadata: json!({}),
        created_by: Some(admin.id.clone()),
        created_by_user: None,
        created_at: now,
        updated_at: now,
        allowed_url_pattern: Some(target_url_pattern.to_string()),
        expires_at: None,
        transform_script: None,
        transform_name: None,
        vault: "default".to_string(),
        credential_type: "generic".to_string(),
        tags: vec![],
        description: None,
        target_identity: None,
        key_version: 1,
    };
    ctx.store
        .store_credential(&cred)
        .await
        .expect("store credential");

    for perm in &["read", "delegated_use"] {
        grant_cedar_permission(&ctx.state, &cred_id, &admin.id, perm).await;
    }

    cred_id
}

/// Send a proxy execute request using the admin agent.
/// Injects the credential placeholder in the Authorization header so the
/// proxy endpoint resolves the credential and proceeds to SSRF validation.
async fn proxy_request(
    ctx: &TestContext,
    cred_name: &str,
    target_url: &str,
) -> (StatusCode, serde_json::Value) {
    let admin = ctx.admin_agent.as_ref().expect("admin agent");
    let agent_jwt = issue_agent_jwt(&ctx.state, admin).await;
    let dev = ctx.admin_device.as_ref().expect("admin device");

    send_json_dual_auth(
        &ctx.app,
        Method::POST,
        "/api/v1/proxy/execute",
        &dev.signing_key,
        &dev.device_id,
        &agent_jwt,
        Some(json!({
            "method": "GET",
            "url": target_url,
            "headers": {"Authorization": format!("Bearer {{{{{}}}}}", cred_name)},
        })),
    )
    .await
}

// ===========================================================================
// 4A. Happy Path — loopback allowed
// ===========================================================================

#[tokio::test]
async fn test_proxy_localhost_with_allow_loopback() {
    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/test"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"ok": true})))
        .mount(&mock_server)
        .await;

    // test_default() sets proxy_allow_loopback=true
    let ctx = TestAppBuilder::new().with_admin().build().await;
    setup_credential(
        &ctx,
        "test-cred-localhost",
        &format!("{}/**", mock_server.uri()),
    )
    .await;

    let target_url = format!("{}/api/test", mock_server.uri());
    let (status, body) = proxy_request(&ctx, "test-cred-localhost", &target_url).await;

    assert_eq!(
        status,
        StatusCode::OK,
        "proxy to localhost should succeed with allow_loopback=true: {}",
        body
    );
}

#[tokio::test]
async fn test_proxy_127_0_0_1_with_allow_loopback() {
    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/test"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"ok": true})))
        .mount(&mock_server)
        .await;

    let uri_with_ip = mock_server.uri().replace("localhost", "127.0.0.1");
    let ctx = TestAppBuilder::new().with_admin().build().await;
    setup_credential(&ctx, "test-cred-ip", &format!("{}/**", uri_with_ip)).await;

    let target_url = format!("{}/api/test", uri_with_ip);
    let (status, body) = proxy_request(&ctx, "test-cred-ip", &target_url).await;

    assert_eq!(
        status,
        StatusCode::OK,
        "proxy to 127.0.0.1 should succeed with allow_loopback=true: {}",
        body
    );
}

// ===========================================================================
// 4C. Error Handling — loopback blocked
// ===========================================================================

#[tokio::test]
async fn test_proxy_localhost_without_allow_loopback_blocked() {
    let ctx = TestAppBuilder::new()
        .with_admin()
        .with_config(|c| c.proxy_allow_loopback = false)
        .build()
        .await;

    setup_credential(&ctx, "cred-blocked", "http://localhost:4001/**").await;
    let (status, body) =
        proxy_request(&ctx, "cred-blocked", "http://localhost:4001/api/test").await;

    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "proxy to localhost should be blocked with allow_loopback=false: {}",
        body
    );
}

#[tokio::test]
async fn test_proxy_private_ip_blocked() {
    let ctx = TestAppBuilder::new()
        .with_admin()
        .with_config(|c| c.proxy_allow_loopback = false)
        .build()
        .await;

    // Test 10.0.0.1
    setup_credential(&ctx, "cred-10net", "http://10.0.0.1/**").await;
    let (status, _) = proxy_request(&ctx, "cred-10net", "http://10.0.0.1/api").await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "proxy to 10.0.0.1 should be blocked"
    );

    // Test 192.168.1.1
    setup_credential(&ctx, "cred-192net", "http://192.168.1.1/**").await;
    let (status, _) = proxy_request(&ctx, "cred-192net", "http://192.168.1.1/api").await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "proxy to 192.168.1.1 should be blocked"
    );
}

#[tokio::test]
async fn test_ssrf_error_message_includes_guidance() {
    let ctx = TestAppBuilder::new()
        .with_admin()
        .with_config(|c| c.proxy_allow_loopback = false)
        .build()
        .await;

    setup_credential(&ctx, "cred-guidance", "http://localhost:4001/**").await;
    let (status, body) =
        proxy_request(&ctx, "cred-guidance", "http://localhost:4001/api/test").await;

    assert_eq!(status, StatusCode::FORBIDDEN);

    let error_msg = body.to_string().to_lowercase();
    assert!(
        error_msg.contains("not allowed") || error_msg.contains("localhost"),
        "SSRF error should indicate the target is blocked: {}",
        body
    );
}

// ===========================================================================
// 4D. Cross-Feature
// ===========================================================================

#[tokio::test]
async fn test_proxy_loopback_with_credential_injection() {
    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/protected"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": "secret"})))
        .mount(&mock_server)
        .await;

    let ctx = TestAppBuilder::new().with_admin().build().await;
    setup_credential(&ctx, "cred-inject", &format!("{}/**", mock_server.uri())).await;

    let target_url = format!("{}/api/protected", mock_server.uri());
    let (status, body) = proxy_request(&ctx, "cred-inject", &target_url).await;

    assert_eq!(
        status,
        StatusCode::OK,
        "full proxy flow with credential should succeed: {}",
        body
    );
}

// ===========================================================================
// 4E. Security
// ===========================================================================

#[tokio::test]
async fn test_ssrf_ipv6_loopback_blocked() {
    let ctx = TestAppBuilder::new()
        .with_admin()
        .with_config(|c| c.proxy_allow_loopback = false)
        .build()
        .await;

    setup_credential(&ctx, "cred-ipv6", "http://[::1]:4001/**").await;
    let (status, _) = proxy_request(&ctx, "cred-ipv6", "http://[::1]:4001/api/test").await;

    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "proxy to [::1] should be blocked when allow_loopback=false"
    );
}
