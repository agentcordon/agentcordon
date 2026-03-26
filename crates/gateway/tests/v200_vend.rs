//! P3: Credential Vend + ECIES tests for the v2.0 workspace unification branch.
//!
//! Tests `vend_and_decrypt` from `crates/gateway/src/vend.rs`.
//! Uses wiremock to simulate the server's vend endpoint and real ECIES
//! encryption from `agent_cordon_core::crypto::ecies`.

use std::collections::HashMap;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use agent_cordon_core::crypto::ecies::{CredentialEnvelopeEncryptor, EciesEncryptor};
use agentcordon::vend::{vend_and_decrypt, VendError, VendResult, VendedCredential};

// ---------------------------------------------------------------------------
// Helper: create a wiremock response with a properly ECIES-encrypted envelope
// ---------------------------------------------------------------------------

async fn create_vend_response(
    encryption_pub_key: &p256::PublicKey,
    credential_json: &[u8],
    credential_type: &str,
    vend_id: &str,
) -> serde_json::Value {
    let ecies = EciesEncryptor::new();
    let pub_key_bytes = encryption_pub_key.to_encoded_point(false);
    let envelope = ecies
        .encrypt_for_device(pub_key_bytes.as_bytes(), credential_json, b"")
        .await
        .expect("ECIES encrypt should succeed");

    serde_json::json!({
        "data": {
            "credential_type": credential_type,
            "transform_name": null,
            "encrypted_envelope": {
                "version": envelope.version,
                "ephemeral_public_key": B64.encode(&envelope.ephemeral_public_key),
                "ciphertext": B64.encode(&envelope.ciphertext),
                "nonce": B64.encode(&envelope.nonce),
                "aad": B64.encode(&envelope.aad)
            },
            "vend_id": vend_id
        }
    })
}

// ---------------------------------------------------------------------------
// 1. test_vend_and_decrypt_bearer_credential
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_vend_and_decrypt_bearer_credential() {
    let mock_server = MockServer::start().await;
    let encryption_key = p256::SecretKey::random(&mut rand::rngs::OsRng);
    let pub_key = encryption_key.public_key();

    let cred_json = serde_json::json!({
        "type": "bearer",
        "value": "ghp_abc123def456",
        "metadata": {}
    });

    let response_body = create_vend_response(
        &pub_key,
        &serde_json::to_vec(&cred_json).unwrap(),
        "bearer",
        "vend-001",
    )
    .await;

    Mock::given(method("POST"))
        .and(path("/api/v1/credentials/cred-github/vend"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
        .mount(&mock_server)
        .await;

    let http = reqwest::Client::new();
    let result = vend_and_decrypt(
        &http,
        &mock_server.uri(),
        "test-jwt-token",
        &encryption_key,
        "cred-github",
    )
    .await
    .expect("vend_and_decrypt should succeed");

    assert_eq!(result.credential.value, "ghp_abc123def456");
    assert_eq!(result.credential.credential_type.as_deref(), Some("bearer"));
    assert_eq!(result.server_credential_type, "bearer");
    assert_eq!(result.vend_id, "vend-001");
}

// ---------------------------------------------------------------------------
// 2. test_vend_and_decrypt_api_key_with_metadata
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_vend_and_decrypt_api_key_with_metadata() {
    let mock_server = MockServer::start().await;
    let encryption_key = p256::SecretKey::random(&mut rand::rngs::OsRng);
    let pub_key = encryption_key.public_key();

    let cred_json = serde_json::json!({
        "type": "api_key_header",
        "value": "sk-proj-12345",
        "metadata": {
            "header_name": "X-API-Key"
        }
    });

    let response_body = create_vend_response(
        &pub_key,
        &serde_json::to_vec(&cred_json).unwrap(),
        "api_key_header",
        "vend-002",
    )
    .await;

    Mock::given(method("POST"))
        .and(path("/api/v1/credentials/cred-openai/vend"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
        .mount(&mock_server)
        .await;

    let http = reqwest::Client::new();
    let result = vend_and_decrypt(
        &http,
        &mock_server.uri(),
        "test-jwt-token",
        &encryption_key,
        "cred-openai",
    )
    .await
    .expect("vend should succeed");

    assert_eq!(result.credential.value, "sk-proj-12345");
    assert_eq!(
        result.credential.credential_type.as_deref(),
        Some("api_key_header")
    );
    assert_eq!(
        result
            .credential
            .metadata
            .get("header_name")
            .map(|s| s.as_str()),
        Some("X-API-Key")
    );
}

// ---------------------------------------------------------------------------
// 3-4. test_effective_credential_type
// ---------------------------------------------------------------------------

#[test]
fn test_effective_credential_type_prefers_material() {
    let result = VendResult {
        credential: VendedCredential {
            credential_type: Some("bearer".to_string()),
            value: "tok".to_string(),
            username: None,
            metadata: HashMap::new(),
        },
        server_credential_type: "generic".to_string(),
        transform_name: None,
        vend_id: "v1".to_string(),
    };
    assert_eq!(result.effective_credential_type(), "bearer");
}

#[test]
fn test_effective_credential_type_falls_back_to_server() {
    let result = VendResult {
        credential: VendedCredential {
            credential_type: None,
            value: "tok".to_string(),
            username: None,
            metadata: HashMap::new(),
        },
        server_credential_type: "api_key_header".to_string(),
        transform_name: None,
        vend_id: "v2".to_string(),
    };
    assert_eq!(result.effective_credential_type(), "api_key_header");
}

// ---------------------------------------------------------------------------
// 5. test_vend_twice_both_succeed
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_vend_twice_both_succeed() {
    let mock_server = MockServer::start().await;
    let encryption_key = p256::SecretKey::random(&mut rand::rngs::OsRng);
    let pub_key = encryption_key.public_key();

    let cred_json = serde_json::json!({
        "type": "bearer",
        "value": "token-value",
        "metadata": {}
    });

    let response_body = create_vend_response(
        &pub_key,
        &serde_json::to_vec(&cred_json).unwrap(),
        "bearer",
        "vend-a",
    )
    .await;

    Mock::given(method("POST"))
        .and(path("/api/v1/credentials/cred-repeat/vend"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
        .expect(2)
        .mount(&mock_server)
        .await;

    let http = reqwest::Client::new();
    let r1 = vend_and_decrypt(
        &http,
        &mock_server.uri(),
        "jwt1",
        &encryption_key,
        "cred-repeat",
    )
    .await
    .expect("first vend should succeed");

    let r2 = vend_and_decrypt(
        &http,
        &mock_server.uri(),
        "jwt2",
        &encryption_key,
        "cred-repeat",
    )
    .await
    .expect("second vend should succeed");

    assert_eq!(r1.credential.value, "token-value");
    assert_eq!(r2.credential.value, "token-value");
}

// ---------------------------------------------------------------------------
// 6. test_vend_404_returns_not_found
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_vend_404_returns_not_found() {
    let mock_server = MockServer::start().await;
    let encryption_key = p256::SecretKey::random(&mut rand::rngs::OsRng);

    Mock::given(method("POST"))
        .and(path("/api/v1/credentials/nonexistent/vend"))
        .respond_with(ResponseTemplate::new(404).set_body_string("not found"))
        .mount(&mock_server)
        .await;

    let http = reqwest::Client::new();
    let result = vend_and_decrypt(
        &http,
        &mock_server.uri(),
        "jwt",
        &encryption_key,
        "nonexistent",
    )
    .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        VendError::CredentialNotFound(id) => {
            assert_eq!(id, "nonexistent");
        }
        other => panic!("expected CredentialNotFound, got: {:?}", other),
    }
}

// ---------------------------------------------------------------------------
// 7. test_vend_403_returns_policy_denied
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_vend_403_returns_policy_denied() {
    let mock_server = MockServer::start().await;
    let encryption_key = p256::SecretKey::random(&mut rand::rngs::OsRng);

    Mock::given(method("POST"))
        .and(path("/api/v1/credentials/restricted/vend"))
        .respond_with(ResponseTemplate::new(403).set_body_string("forbidden"))
        .mount(&mock_server)
        .await;

    let http = reqwest::Client::new();
    let result = vend_and_decrypt(
        &http,
        &mock_server.uri(),
        "jwt",
        &encryption_key,
        "restricted",
    )
    .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        VendError::PolicyDenied => {} // expected
        other => panic!("expected PolicyDenied, got: {:?}", other),
    }
}

// ---------------------------------------------------------------------------
// 8. test_vend_500_returns_server_error
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_vend_500_returns_server_error() {
    let mock_server = MockServer::start().await;
    let encryption_key = p256::SecretKey::random(&mut rand::rngs::OsRng);

    Mock::given(method("POST"))
        .and(path("/api/v1/credentials/broken/vend"))
        .respond_with(ResponseTemplate::new(500).set_body_string("internal server error"))
        .mount(&mock_server)
        .await;

    let http = reqwest::Client::new();
    let result =
        vend_and_decrypt(&http, &mock_server.uri(), "jwt", &encryption_key, "broken").await;

    assert!(result.is_err());
    match result.unwrap_err() {
        VendError::ServerError { status, body } => {
            assert_eq!(status, 500);
            assert!(body.contains("internal server error"));
        }
        other => panic!("expected ServerError, got: {:?}", other),
    }
}

// ---------------------------------------------------------------------------
// 9. test_vend_invalid_json_response
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_vend_invalid_json_response() {
    let mock_server = MockServer::start().await;
    let encryption_key = p256::SecretKey::random(&mut rand::rngs::OsRng);

    Mock::given(method("POST"))
        .and(path("/api/v1/credentials/bad-json/vend"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string("this is not json")
                .insert_header("content-type", "application/json"),
        )
        .mount(&mock_server)
        .await;

    let http = reqwest::Client::new();
    let result = vend_and_decrypt(
        &http,
        &mock_server.uri(),
        "jwt",
        &encryption_key,
        "bad-json",
    )
    .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        VendError::InvalidResponse(_) => {} // expected
        other => panic!("expected InvalidResponse, got: {:?}", other),
    }
}

// ---------------------------------------------------------------------------
// 10. test_vend_wrong_key_decryption_fails
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_vend_wrong_key_decryption_fails() {
    let mock_server = MockServer::start().await;

    // Key A encrypts, Key B tries to decrypt
    let key_a = p256::SecretKey::random(&mut rand::rngs::OsRng);
    let key_b = p256::SecretKey::random(&mut rand::rngs::OsRng);
    let pub_a = key_a.public_key();

    let cred_json = serde_json::json!({
        "type": "bearer",
        "value": "secret-token",
        "metadata": {}
    });

    let response_body = create_vend_response(
        &pub_a,
        &serde_json::to_vec(&cred_json).unwrap(),
        "bearer",
        "vend-wrong-key",
    )
    .await;

    Mock::given(method("POST"))
        .and(path("/api/v1/credentials/wrong-key-cred/vend"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
        .mount(&mock_server)
        .await;

    let http = reqwest::Client::new();
    let result = vend_and_decrypt(
        &http,
        &mock_server.uri(),
        "jwt",
        &key_b, // wrong key
        "wrong-key-cred",
    )
    .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        VendError::DecryptionFailed(_) => {} // expected
        other => panic!("expected DecryptionFailed, got: {:?}", other),
    }
}

// ---------------------------------------------------------------------------
// 11. test_vend_corrupted_base64_envelope
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_vend_corrupted_base64_envelope() {
    let mock_server = MockServer::start().await;
    let encryption_key = p256::SecretKey::random(&mut rand::rngs::OsRng);

    // Response with invalid base64 in the envelope
    let response_body = serde_json::json!({
        "data": {
            "credential_type": "bearer",
            "transform_name": null,
            "encrypted_envelope": {
                "version": 1,
                "ephemeral_public_key": "not-valid-base64!!!",
                "ciphertext": B64.encode(b"garbage"),
                "nonce": B64.encode([0u8; 12]),
                "aad": B64.encode(b"")
            },
            "vend_id": "vend-corrupt"
        }
    });

    Mock::given(method("POST"))
        .and(path("/api/v1/credentials/corrupt-cred/vend"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
        .mount(&mock_server)
        .await;

    let http = reqwest::Client::new();
    let result = vend_and_decrypt(
        &http,
        &mock_server.uri(),
        "jwt",
        &encryption_key,
        "corrupt-cred",
    )
    .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        VendError::DecryptionFailed(msg) => {
            assert!(
                msg.contains("ephemeral") || msg.contains("base64") || msg.contains("invalid"),
                "error should mention the invalid field, got: {}",
                msg
            );
        }
        other => panic!("expected DecryptionFailed, got: {:?}", other),
    }
}

// ---------------------------------------------------------------------------
// 12. test_vend_empty_credential_value
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_vend_empty_credential_value_succeeds() {
    let mock_server = MockServer::start().await;
    let encryption_key = p256::SecretKey::random(&mut rand::rngs::OsRng);
    let pub_key = encryption_key.public_key();

    // Empty value is technically valid JSON — it's a business logic concern
    let cred_json = serde_json::json!({
        "type": "bearer",
        "value": "",
        "metadata": {}
    });

    let response_body = create_vend_response(
        &pub_key,
        &serde_json::to_vec(&cred_json).unwrap(),
        "bearer",
        "vend-empty",
    )
    .await;

    Mock::given(method("POST"))
        .and(path("/api/v1/credentials/empty-cred/vend"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
        .mount(&mock_server)
        .await;

    let http = reqwest::Client::new();
    let result = vend_and_decrypt(
        &http,
        &mock_server.uri(),
        "jwt",
        &encryption_key,
        "empty-cred",
    )
    .await
    .expect("vend with empty value should succeed at protocol level");

    assert_eq!(result.credential.value, "");
}

// ---------------------------------------------------------------------------
// 13. test_vend_sends_authorization_header
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_vend_sends_authorization_header() {
    let mock_server = MockServer::start().await;
    let encryption_key = p256::SecretKey::random(&mut rand::rngs::OsRng);
    let pub_key = encryption_key.public_key();

    let cred_json = serde_json::json!({
        "type": "bearer",
        "value": "token",
        "metadata": {}
    });

    let response_body = create_vend_response(
        &pub_key,
        &serde_json::to_vec(&cred_json).unwrap(),
        "bearer",
        "vend-auth-check",
    )
    .await;

    // This mock requires the Authorization header to be present
    Mock::given(method("POST"))
        .and(path("/api/v1/credentials/auth-check/vend"))
        .and(header("Authorization", "Bearer my-workspace-jwt"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
        .expect(1)
        .mount(&mock_server)
        .await;

    let http = reqwest::Client::new();
    let _result = vend_and_decrypt(
        &http,
        &mock_server.uri(),
        "my-workspace-jwt",
        &encryption_key,
        "auth-check",
    )
    .await
    .expect("vend should succeed with correct auth header");

    // If we reach here, the mock matched the header — verification passed.
}

// ---------------------------------------------------------------------------
// 14. test_vend_error_does_not_leak_credential
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_vend_error_does_not_leak_credential() {
    let mock_server = MockServer::start().await;
    let encryption_key = p256::SecretKey::random(&mut rand::rngs::OsRng);

    // Server returns 500 with a body that happens to contain a secret
    Mock::given(method("POST"))
        .and(path("/api/v1/credentials/leaky/vend"))
        .respond_with(ResponseTemplate::new(500).set_body_string("error processing credential"))
        .mount(&mock_server)
        .await;

    let http = reqwest::Client::new();
    let result = vend_and_decrypt(&http, &mock_server.uri(), "jwt", &encryption_key, "leaky").await;

    assert!(result.is_err());
    let err = result.unwrap_err();
    let err_str = format!("{}", err);

    // The error should include the server body for debugging but should NOT
    // contain the JWT or encryption key bytes
    assert!(
        !err_str.contains("jwt"),
        "error message should not contain the JWT"
    );
    // The encryption key raw bytes should never appear in any error message
    let key_hex = hex::encode(encryption_key.to_bytes());
    assert!(
        !err_str.contains(&key_hex),
        "error message should not contain encryption key"
    );
}
