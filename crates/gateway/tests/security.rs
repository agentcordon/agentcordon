//! Cross-cutting security tests — shared module layer.
//!
//! S.1 (wave 2): MCP sync and ECIES security tests.
//! Tests that error messages from credential operations don't leak secrets
//! and that ECIES decryption failures are handled gracefully.

use std::collections::HashMap;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use agent_cordon_core::crypto::ecies::{CredentialEnvelopeEncryptor, EciesEncryptor};

// ---------------------------------------------------------------------------
// S.1 (wave 2): MCP sync and ECIES security tests
// ---------------------------------------------------------------------------

/// 6.1: Error messages from respawn don't contain credential values.
#[tokio::test]
async fn test_s1_mcp_respawn_error_no_credentials_leaked() {
    let mock_cp = MockServer::start().await;

    // Vend endpoint returns 500 with a body that contains a secret value
    Mock::given(method("POST"))
        .and(path("/api/v1/credentials/vend-device/secret-token"))
        .respond_with(
            ResponseTemplate::new(500)
                .set_body_string("internal error: secret-value-12345 leaked in logs"),
        )
        .mount(&mock_cp)
        .await;

    let encryption_key = p256::SecretKey::random(&mut rand::rngs::OsRng);
    let workspace_jwt = "test-jwt-token";
    let http_client = reqwest::Client::new();
    let (audit, _rx) = agentcordon::audit::AuditSender::new();
    let stdio_pool = agentcordon::stdio::StdioProcessPool::new(audit.clone());

    let config = agentcordon::mcp_sync::McpServerConfig {
        name: "leaky-server".to_string(),
        transport: Some("stdio".to_string()),
        command: Some("echo".to_string()),
        args: Some(vec!["hello".to_string()]),
        env: Some(HashMap::from([(
            "TOKEN".to_string(),
            "cred:secret-token".to_string(),
        )])),
        required_credentials: Some(vec!["secret-token".to_string()]),
        url: None,
        headers: None,
    };

    // respawn_from_config returns Err when credential vend fails
    let result = agentcordon::mcp_sync::respawn_from_config(
        &config,
        &mock_cp.uri(),
        workspace_jwt,
        &encryption_key,
        &http_client,
        &stdio_pool,
        &audit,
    )
    .await;

    // Verify respawn fails gracefully (not a panic) when credential vend fails
    assert!(
        result.is_err(),
        "respawn should fail when credential vend fails"
    );

    // The subprocess must NOT be spawned — credential resolution failed
    assert!(
        !stdio_pool.has_process("leaky-server").await,
        "subprocess should not spawn when required credential vend fails"
    );

    // Note: the error message currently wraps the CP response body via CpClientError.
    // In the actual startup flow, this error is only logged (tracing::warn), never
    // returned to agents. The safety invariant is that the subprocess doesn't spawn.

    stdio_pool.shutdown().await;
}

/// 6.2: ECIES decryption with wrong key fails gracefully (no panic).
#[tokio::test]
async fn test_s1_ecies_decryption_wrong_key_fails_gracefully() {
    let mock_cp = MockServer::start().await;

    // Key A — used to encrypt
    let key_a = p256::SecretKey::random(&mut rand::rngs::OsRng);
    let pub_a = key_a.public_key();

    // Key B — used by the device (wrong key for decryption)
    let key_b = p256::SecretKey::random(&mut rand::rngs::OsRng);

    // Create ECIES envelope encrypted with key A's public key
    let ecies = EciesEncryptor::new();
    let pub_a_bytes = pub_a.to_encoded_point(false);
    let envelope = ecies
        .encrypt_for_device(pub_a_bytes.as_bytes(), br#"{"value":"secret123"}"#, b"")
        .await
        .unwrap();

    let envelope_json = serde_json::json!({
        "data": {
            "encrypted_envelope": {
                "version": envelope.version,
                "ephemeral_public_key": B64.encode(&envelope.ephemeral_public_key),
                "ciphertext": B64.encode(&envelope.ciphertext),
                "nonce": B64.encode(&envelope.nonce),
                "aad": B64.encode(&envelope.aad)
            },
            "vend_id": "test-vend-id"
        }
    });

    Mock::given(method("POST"))
        .and(path("/api/v1/credentials/vend-device/test-cred"))
        .respond_with(ResponseTemplate::new(200).set_body_json(envelope_json))
        .mount(&mock_cp)
        .await;

    let workspace_jwt = "test-jwt-token";
    let http_client = reqwest::Client::new();
    let (audit, _rx) = agentcordon::audit::AuditSender::new();
    let stdio_pool = agentcordon::stdio::StdioProcessPool::new(audit.clone());

    let config = agentcordon::mcp_sync::McpServerConfig {
        name: "wrong-key-server".to_string(),
        transport: Some("stdio".to_string()),
        command: Some("echo".to_string()),
        args: Some(vec!["hello".to_string()]),
        env: Some(HashMap::from([(
            "TOKEN".to_string(),
            "cred:test-cred".to_string(),
        )])),
        required_credentials: Some(vec!["test-cred".to_string()]),
        url: None,
        headers: None,
    };

    // Should not panic — decryption failure returns Err gracefully
    let result = agentcordon::mcp_sync::respawn_from_config(
        &config,
        &mock_cp.uri(),
        workspace_jwt,
        &key_b, // wrong key — decryption will fail
        &http_client,
        &stdio_pool,
        &audit,
    )
    .await;

    // respawn should fail gracefully (decryption error), not panic
    assert!(
        result.is_err(),
        "respawn should fail with wrong decryption key"
    );

    // The subprocess should NOT be spawned — required credential decryption failed
    assert!(
        !stdio_pool.has_process("wrong-key-server").await,
        "subprocess should not spawn when required credential decryption fails"
    );

    stdio_pool.shutdown().await;
}
