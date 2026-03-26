//! Tests for local MCP config loading and StdioProcessPool operations.
//!
//! Tests 3.1–3.4: load_local_mcp_configs() and respawn_from_config() behavior
//! Tests 5.1–5.2: StdioProcessPool.remove()

use std::collections::HashMap;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use agent_cordon_core::crypto::ecies::{CredentialEnvelopeEncryptor, EciesEncryptor};
use agentcordon::audit::AuditSender;
use agentcordon::mcp_sync::{
    load_local_mcp_configs, respawn_from_config, McpServerConfig, McpSyncError,
};
use agentcordon::stdio::StdioProcessPool;

/// Create an ECIES envelope encrypted to the given public key, returned as JSON
/// in the format the CP vend-device endpoint returns.
async fn create_test_ecies_response(
    encryption_pub_key: &p256::PublicKey,
    plaintext: &[u8],
) -> serde_json::Value {
    let ecies = EciesEncryptor::new();
    let pub_key_bytes = encryption_pub_key.to_encoded_point(false);
    let envelope = ecies
        .encrypt_for_device(pub_key_bytes.as_bytes(), plaintext, b"")
        .await
        .unwrap();

    serde_json::json!({
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
    })
}

// ---------------------------------------------------------------------------
// 3.1: load_local_mcp_configs reads a JSON file and returns configs
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_load_local_mcp_configs_reads_json_file() {
    let config_path = std::env::temp_dir().join(format!("mcp-test-{}.json", uuid::Uuid::new_v4()));
    std::fs::write(
        &config_path,
        serde_json::to_string(&serde_json::json!([
            {
                "name": "test-echo",
                "transport": "stdio",
                "command": "bash",
                "args": ["-c", "cat"]
            },
            {
                "name": "http-server",
                "transport": "http"
            }
        ]))
        .unwrap(),
    )
    .unwrap();

    let configs = load_local_mcp_configs(&config_path).unwrap();
    let _ = std::fs::remove_file(&config_path);
    assert_eq!(configs.len(), 2);
    assert_eq!(configs[0].name, "test-echo");
    assert_eq!(configs[0].transport(), "stdio");
    assert_eq!(configs[0].command.as_deref(), Some("bash"));
    assert_eq!(configs[1].name, "http-server");
    assert_eq!(configs[1].transport(), "http");
    assert!(configs[1].command.is_none());
}

// ---------------------------------------------------------------------------
// 3.2: load_local_mcp_configs defaults transport to "stdio"
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_load_local_mcp_configs_default_transport() {
    let config_path = std::env::temp_dir().join(format!("mcp-test-{}.json", uuid::Uuid::new_v4()));
    std::fs::write(&config_path, r#"[{"name": "minimal", "command": "echo"}]"#).unwrap();

    let configs = load_local_mcp_configs(&config_path).unwrap();
    let _ = std::fs::remove_file(&config_path);
    assert_eq!(configs.len(), 1);
    assert_eq!(configs[0].transport(), "stdio");
}

// ---------------------------------------------------------------------------
// 3.3: load_local_mcp_configs returns error for missing file
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_load_local_mcp_configs_missing_file_returns_error() {
    let result = load_local_mcp_configs(std::path::Path::new("/nonexistent/mcp.json"));
    assert!(result.is_err());
    match result.unwrap_err() {
        McpSyncError::ConfigFileError(msg) => {
            assert!(
                msg.contains("/nonexistent/mcp.json"),
                "error should mention the path"
            );
        }
        other => panic!("expected ConfigFileError, got: {:?}", other),
    }
}

// ---------------------------------------------------------------------------
// 3.4: load_local_mcp_configs returns error for invalid JSON
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_load_local_mcp_configs_invalid_json_returns_error() {
    let config_path = std::env::temp_dir().join(format!("mcp-test-{}.json", uuid::Uuid::new_v4()));
    std::fs::write(&config_path, "not valid json {{{").unwrap();

    let result = load_local_mcp_configs(&config_path);
    let _ = std::fs::remove_file(&config_path);
    assert!(result.is_err());
    match result.unwrap_err() {
        McpSyncError::ConfigFileError(msg) => {
            assert!(
                msg.contains("invalid JSON"),
                "error should mention invalid JSON: {}",
                msg
            );
        }
        other => panic!("expected ConfigFileError, got: {:?}", other),
    }
}

// ---------------------------------------------------------------------------
// 3.5: respawn_from_config spawns subprocess and resolves credential placeholders
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_respawn_from_config_with_credentials() {
    let mock_cp = MockServer::start().await;

    let encryption_key = p256::SecretKey::random(&mut rand::rngs::OsRng);
    let encryption_pub = encryption_key.public_key();

    let envelope_response =
        create_test_ecies_response(&encryption_pub, br#"{"value":"secret123"}"#).await;

    Mock::given(method("POST"))
        .and(path("/api/v1/credentials/vend-device/test-cred"))
        .respond_with(ResponseTemplate::new(200).set_body_json(envelope_response))
        .expect(1)
        .mount(&mock_cp)
        .await;

    let workspace_jwt = "test-jwt-token";
    let http_client = reqwest::Client::new();
    let (audit, _rx) = AuditSender::new();
    let stdio_pool = StdioProcessPool::new(audit.clone());

    let config = McpServerConfig {
        name: "cred-server".to_string(),
        transport: Some("stdio".to_string()),
        command: Some("bash".to_string()),
        args: Some(vec![
            "-c".to_string(),
            r#"while IFS= read -r line; do echo '{"jsonrpc":"2.0","id":1,"result":{}}'; done"#
                .to_string(),
        ]),
        env: Some(HashMap::from([(
            "API_KEY".to_string(),
            "cred:test-cred".to_string(),
        )])),
        required_credentials: Some(vec!["test-cred".to_string()]),
        url: None,
        headers: None,
    };

    let result = respawn_from_config(
        &config,
        &mock_cp.uri(),
        workspace_jwt,
        &encryption_key,
        &http_client,
        &stdio_pool,
        &audit,
    )
    .await;

    assert!(
        result.is_ok(),
        "respawn_from_config should succeed: {:?}",
        result.err()
    );
    assert!(
        stdio_pool.has_process("cred-server").await,
        "subprocess should be spawned after credential resolution"
    );

    stdio_pool.shutdown().await;
}

// ---------------------------------------------------------------------------
// 3.6: respawn_from_config fails for missing command
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_respawn_from_config_missing_command() {
    let encryption_key = p256::SecretKey::random(&mut rand::rngs::OsRng);
    let workspace_jwt = "test-jwt-token";
    let http_client = reqwest::Client::new();
    let (audit, _rx) = AuditSender::new();
    let stdio_pool = StdioProcessPool::new(audit.clone());

    let config = McpServerConfig {
        name: "no-cmd".to_string(),
        transport: Some("stdio".to_string()),
        command: None,
        args: None,
        env: None,
        required_credentials: None,
        url: None,
        headers: None,
    };

    let result = respawn_from_config(
        &config,
        "http://localhost:9999",
        workspace_jwt,
        &encryption_key,
        &http_client,
        &stdio_pool,
        &audit,
    )
    .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        McpSyncError::MissingCommand => {}
        other => panic!("expected MissingCommand, got: {:?}", other),
    }
}

// ---------------------------------------------------------------------------
// 5.1: remove existing process returns true
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_stdio_pool_remove_existing_returns_true() {
    let (audit, _rx) = AuditSender::new();
    let pool = StdioProcessPool::new(audit);

    pool.spawn("test", "sleep", &["300".to_string()], HashMap::new())
        .await
        .expect("spawn should succeed");
    assert!(
        pool.has_process("test").await,
        "process should exist after spawn"
    );

    let removed = pool.remove("test").await;
    assert!(removed, "remove should return true for existing process");
    assert!(
        !pool.has_process("test").await,
        "process should not exist after remove"
    );
}

// ---------------------------------------------------------------------------
// 5.2: remove nonexistent process returns false
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_stdio_pool_remove_nonexistent_returns_false() {
    let (audit, _rx) = AuditSender::new();
    let pool = StdioProcessPool::new(audit);
    let removed = pool.remove("nonexistent").await;
    assert!(
        !removed,
        "remove should return false for nonexistent process"
    );
}
