//! MCP config sync integration tests: the workspace-facing sync endpoint and
//! its ECIES-encrypted credential envelopes.
//!
//! Broker-side behaviour (cache population, credential injection) is tested
//! in the broker crate's own integration harness (`crates/broker/tests`).

use crate::common;

use agent_cordon_core::crypto::SecretEncryptor;
use agent_cordon_core::domain::credential::{CredentialId, StoredCredential};
use agent_cordon_core::domain::mcp::{McpAuthMethod, McpServer, McpServerId, McpTransport};
use agent_cordon_core::domain::workspace::WorkspaceId;
use agent_cordon_core::storage::Store;
use agent_cordon_server::test_helpers::TestAppBuilder;
use axum::http::{Method, StatusCode};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Create an MCP server with required_credentials and auth_method.
async fn create_mcp_server_with_creds(
    store: &(dyn Store + Send + Sync),
    workspace_id: &WorkspaceId,
    name: &str,
    auth_method: McpAuthMethod,
    required_credentials: Option<Vec<CredentialId>>,
) -> McpServerId {
    let now = chrono::Utc::now();
    let server = McpServer {
        id: McpServerId(Uuid::new_v4()),
        workspace_id: Some(workspace_id.clone()),
        name: name.to_string(),
        upstream_url: format!("https://api.example.com/{}", name),
        transport: McpTransport::Sse,
        allowed_tools: Some(vec!["tool_a".to_string()]),
        enabled: true,
        created_by: None,
        created_at: now,
        updated_at: now,
        tags: vec![],
        required_credentials,
        auth_method,
        template_key: Some(name.to_string()),
        discovered_tools: None,
        created_by_user: None,
    };
    store
        .create_mcp_server(&server)
        .await
        .expect("create MCP server");
    store
        .add_mcp_server_workspace(&server.id, workspace_id, None)
        .await
        .expect("add MCP server workspace binding");
    server.id
}

/// Create a stored credential and return its ID.
async fn create_test_credential(
    ctx: &agent_cordon_server::test_helpers::TestContext,
    name: &str,
    secret: &str,
) -> CredentialId {
    let cred_id = CredentialId(Uuid::new_v4());
    // Production encrypts with the credential id as associated data
    // (credential_service::encrypt_secret); the sync path decrypts the same way.
    let (ciphertext, nonce) = ctx
        .encryptor
        .encrypt(secret.as_bytes(), cred_id.0.to_string().as_bytes())
        .expect("encrypt secret");
    let now = chrono::Utc::now();
    let cred = StoredCredential {
        id: cred_id.clone(),
        name: name.to_string(),
        service: "test-service".to_string(),
        encrypted_value: ciphertext,
        nonce,
        scopes: vec![],
        metadata: serde_json::json!({}),
        created_by: None,
        created_by_user: None,
        created_at: now,
        updated_at: now,
        allowed_url_pattern: None,
        expires_at: None,
        transform_script: None,
        transform_name: Some("bearer".to_string()),
        vault_id: agent_cordon_core::domain::vault::DEFAULT_VAULT_ID.to_string(),
        vault_name: "default".to_string(),
        credential_type: "generic".to_string(),
        tags: vec![],
        description: Some(format!("Test credential {}", name)),
        target_identity: None,
        key_version: 1,
    };
    ctx.store
        .store_credential(&cred)
        .await
        .expect("store credential");
    cred_id
}

/// Generate a P-256 keypair and return (secret_key, base64url-encoded uncompressed public key).
fn generate_broker_keypair() -> (p256::SecretKey, String) {
    use p256::elliptic_curve::rand_core::OsRng;
    let secret_key = p256::SecretKey::random(&mut OsRng);
    let public_key = secret_key.public_key();
    let point = public_key.to_encoded_point(false);
    let encoded = URL_SAFE_NO_PAD.encode(point.as_bytes());
    (secret_key, encoded)
}

// ===========================================================================
// Phase 4: Enhanced Config Sync with ECIES Credentials
// ===========================================================================

/// 4.1: GET /api/v1/workspaces/mcp-servers without query params returns backward-compatible format.
#[tokio::test]
async fn test_mcp_sync_without_credentials_unchanged() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let ws = ctx.admin_agent.as_ref().unwrap();

    let _server_id = create_mcp_server_with_creds(
        &*ctx.store,
        &ws.id,
        "github-sync",
        McpAuthMethod::ApiKey,
        None,
    )
    .await;

    let jwt = common::ctx_admin_jwt(&ctx).await;
    let (status, body) = common::send_json(
        &ctx.app,
        Method::GET,
        "/api/v1/workspaces/mcp-servers",
        Some(&jwt),
        None,
        None,
        None,
    )
    .await;

    assert_eq!(status, StatusCode::OK, "sync: {}", body);
    let servers = body["data"]["servers"].as_array().expect("servers array");
    assert!(!servers.is_empty(), "should have at least 1 server");

    // Backward compat: no credential_envelopes field when not requested
    for server in servers {
        assert!(
            server.get("credential_envelopes").is_none()
                || server["credential_envelopes"].is_null(),
            "credential_envelopes should not be present without include_credentials: {:?}",
            server
        );
    }
}

/// 4.2: GET with ?include_credentials=true&broker_public_key=<key> returns encrypted envelopes.
#[tokio::test]
async fn test_mcp_sync_with_credentials_returns_envelopes() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let ws = ctx.admin_agent.as_ref().unwrap();

    let cred_id = create_test_credential(&ctx, "github-pat", "ghp_test_envelope_123").await;
    let _server_id = create_mcp_server_with_creds(
        &*ctx.store,
        &ws.id,
        "github-env",
        McpAuthMethod::ApiKey,
        Some(vec![cred_id.clone()]),
    )
    .await;

    // Grant vend permission
    common::grant_cedar_permission(&ctx.state, &cred_id, &ws.id, "delegated_use").await;

    let (_secret_key, broker_pub) = generate_broker_keypair();
    let jwt = common::ctx_admin_jwt(&ctx).await;

    let uri = format!(
        "/api/v1/workspaces/mcp-servers?include_credentials=true&broker_public_key={}",
        broker_pub
    );
    let (status, body) =
        common::send_json(&ctx.app, Method::GET, &uri, Some(&jwt), None, None, None).await;

    assert_eq!(status, StatusCode::OK, "sync with creds: {}", body);
    let servers = body["data"]["servers"].as_array().expect("servers array");
    let github = servers
        .iter()
        .find(|s| s["name"].as_str() == Some("github-env"))
        .expect("github-env server");

    let envelopes = github["credential_envelopes"]
        .as_array()
        .expect("credential_envelopes should be an array");
    assert!(!envelopes.is_empty(), "should have at least one envelope");

    let envelope = &envelopes[0];
    assert!(
        envelope["credential_name"].is_string(),
        "envelope must have credential_name"
    );
    assert!(
        envelope["credential_type"].is_string(),
        "envelope must have credential_type"
    );

    let enc = &envelope["encrypted_envelope"];
    assert_eq!(enc["version"].as_u64(), Some(1), "version should be 1");
    assert!(
        enc["ephemeral_public_key"].is_string(),
        "must have ephemeral_public_key"
    );
    assert!(enc["ciphertext"].is_string(), "must have ciphertext");
    assert!(enc["nonce"].is_string(), "must have nonce");
    assert!(enc["aad"].is_string(), "must have aad");

    // Envelope fields are standard base64 (what the broker's vend.rs decodes);
    // only broker_public_key on the request is base64url.
    let epk_bytes = STANDARD
        .decode(enc["ephemeral_public_key"].as_str().unwrap())
        .expect("decode ephemeral_public_key");
    assert_eq!(
        epk_bytes.len(),
        65,
        "ephemeral_public_key should be 65 bytes (uncompressed P-256 point)"
    );
}

/// 4.3: ECIES envelope can be decrypted with the broker's private key.
#[tokio::test]
async fn test_mcp_sync_envelope_is_decryptable() {
    use agent_cordon_core::crypto::ecies::{
        CredentialEnvelopeDecryptor, EciesEncryptor, EncryptedEnvelope,
    };

    let ctx = TestAppBuilder::new().with_admin().build().await;
    let ws = ctx.admin_agent.as_ref().unwrap();

    let secret = "ghp_decrypt_test_secret_456";
    let cred_id = create_test_credential(&ctx, "github-decrypt", secret).await;
    let _server_id = create_mcp_server_with_creds(
        &*ctx.store,
        &ws.id,
        "github-dec",
        McpAuthMethod::ApiKey,
        Some(vec![cred_id.clone()]),
    )
    .await;

    common::grant_cedar_permission(&ctx.state, &cred_id, &ws.id, "delegated_use").await;

    let (secret_key, broker_pub) = generate_broker_keypair();
    let jwt = common::ctx_admin_jwt(&ctx).await;

    let uri = format!(
        "/api/v1/workspaces/mcp-servers?include_credentials=true&broker_public_key={}",
        broker_pub
    );
    let (status, body) =
        common::send_json(&ctx.app, Method::GET, &uri, Some(&jwt), None, None, None).await;
    assert_eq!(status, StatusCode::OK, "sync: {}", body);

    let servers = body["data"]["servers"].as_array().unwrap();
    let server = servers
        .iter()
        .find(|s| s["name"].as_str() == Some("github-dec"))
        .expect("github-dec server");
    let envelopes = server["credential_envelopes"].as_array().unwrap();
    let enc = &envelopes[0]["encrypted_envelope"];

    // Reconstruct the EncryptedEnvelope from the response
    let envelope = EncryptedEnvelope {
        version: enc["version"].as_u64().unwrap() as u8,
        ephemeral_public_key: STANDARD
            .decode(enc["ephemeral_public_key"].as_str().unwrap())
            .unwrap(),
        ciphertext: STANDARD
            .decode(enc["ciphertext"].as_str().unwrap())
            .unwrap(),
        nonce: STANDARD.decode(enc["nonce"].as_str().unwrap()).unwrap(),
        aad: STANDARD.decode(enc["aad"].as_str().unwrap()).unwrap(),
    };

    // Decrypt using broker's private key (raw 32-byte scalar)
    let sk_bytes = secret_key.to_bytes();
    let decryptor = EciesEncryptor;
    let plaintext = decryptor
        .decrypt_envelope(&sk_bytes, &envelope)
        .await
        .expect("ECIES decryption should succeed");

    let plaintext_str = String::from_utf8(plaintext).expect("plaintext should be valid UTF-8");
    let plaintext_json: serde_json::Value =
        serde_json::from_str(&plaintext_str).expect("plaintext should be valid JSON");

    assert_eq!(
        plaintext_json["value"].as_str(),
        Some(secret),
        "decrypted value should match the original secret"
    );
}

/// 4.4: Bad broker_public_key → 400.
#[tokio::test]
async fn test_mcp_sync_invalid_broker_key_rejected() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let jwt = common::ctx_admin_jwt(&ctx).await;

    let uri = "/api/v1/workspaces/mcp-servers?include_credentials=true&broker_public_key=AAAA";
    let (status, body) =
        common::send_json(&ctx.app, Method::GET, uri, Some(&jwt), None, None, None).await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "malformed key should be 400: {}",
        body
    );
    let err_msg = body.to_string().to_lowercase();
    assert!(
        err_msg.contains("broker_public_key") || err_msg.contains("public key"),
        "error should reference broker_public_key: {}",
        body
    );
}

/// 4.5: include_credentials=true without broker_public_key → 400.
#[tokio::test]
async fn test_mcp_sync_include_credentials_without_key_rejected() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let jwt = common::ctx_admin_jwt(&ctx).await;

    let uri = "/api/v1/workspaces/mcp-servers?include_credentials=true";
    let (status, body) =
        common::send_json(&ctx.app, Method::GET, uri, Some(&jwt), None, None, None).await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "missing key should be 400: {}",
        body
    );
}

/// 4.6: Servers with auth_method: none → no credential_envelopes.
#[tokio::test]
async fn test_mcp_sync_no_envelopes_for_no_auth_servers() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let ws = ctx.admin_agent.as_ref().unwrap();

    let _server_id = create_mcp_server_with_creds(
        &*ctx.store,
        &ws.id,
        "no-auth-server",
        McpAuthMethod::None,
        None,
    )
    .await;

    let (_sk, broker_pub) = generate_broker_keypair();
    let jwt = common::ctx_admin_jwt(&ctx).await;

    let uri = format!(
        "/api/v1/workspaces/mcp-servers?include_credentials=true&broker_public_key={}",
        broker_pub
    );
    let (status, body) =
        common::send_json(&ctx.app, Method::GET, &uri, Some(&jwt), None, None, None).await;
    assert_eq!(status, StatusCode::OK, "sync: {}", body);

    let servers = body["data"]["servers"].as_array().unwrap();
    let no_auth = servers
        .iter()
        .find(|s| s["name"].as_str() == Some("no-auth-server"))
        .expect("no-auth-server");

    let envelopes = &no_auth["credential_envelopes"];
    assert!(
        envelopes.is_null() || envelopes.as_array().is_none_or(|a| a.is_empty()),
        "no-auth server should have no credential_envelopes: {:?}",
        envelopes
    );
}

/// 4.7: Response body does not contain plaintext secret values.
#[tokio::test]
async fn test_mcp_sync_no_plaintext_secrets() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let ws = ctx.admin_agent.as_ref().unwrap();

    let secret = "ghp_phase4_leak_check_xyz789";
    let cred_id = create_test_credential(&ctx, "leak-check-cred", secret).await;
    let _server_id = create_mcp_server_with_creds(
        &*ctx.store,
        &ws.id,
        "leak-check-server",
        McpAuthMethod::ApiKey,
        Some(vec![cred_id.clone()]),
    )
    .await;

    common::grant_cedar_permission(&ctx.state, &cred_id, &ws.id, "delegated_use").await;

    let (_sk, broker_pub) = generate_broker_keypair();
    let jwt = common::ctx_admin_jwt(&ctx).await;

    let uri = format!(
        "/api/v1/workspaces/mcp-servers?include_credentials=true&broker_public_key={}",
        broker_pub
    );
    let (status, body) =
        common::send_json(&ctx.app, Method::GET, &uri, Some(&jwt), None, None, None).await;
    assert_eq!(status, StatusCode::OK);

    let body_str = serde_json::to_string(&body).unwrap();
    assert!(
        !body_str.contains(secret),
        "response body must not contain plaintext secret '{}'",
        secret
    );
}

// ===========================================================================
// ECIES unit test: encryption round-trip (does not require endpoint changes)
// ===========================================================================

/// Verify ECIES encrypt → decrypt round-trip works with P-256 keypair.
///
/// This test validates the crypto layer independently of the sync endpoint,
/// ensuring that when the Phase 4 endpoint lands, the envelope format will work.
#[tokio::test]
async fn test_ecies_roundtrip_with_p256_keypair() {
    use agent_cordon_core::crypto::ecies::{
        CredentialEnvelopeDecryptor, CredentialEnvelopeEncryptor, EciesEncryptor,
    };

    let (secret_key, _broker_pub) = generate_broker_keypair();

    // Get the uncompressed public key bytes (65 bytes)
    let public_key = secret_key.public_key();
    let point = public_key.to_encoded_point(false);
    let pub_bytes = point.as_bytes();
    assert_eq!(pub_bytes.len(), 65, "uncompressed P-256 point is 65 bytes");

    let plaintext = b"{\"value\": \"ghp_roundtrip_test\"}";
    let aad = b"test-workspace||test-credential||test-vend||2026-04-04T00:00:00Z";

    let encryptor = EciesEncryptor;

    // Encrypt
    let envelope = encryptor
        .encrypt_for_device(pub_bytes, plaintext, aad)
        .await
        .expect("ECIES encryption should succeed");

    assert_eq!(envelope.version, 1);
    assert_eq!(envelope.ephemeral_public_key.len(), 65);
    assert!(!envelope.ciphertext.is_empty());
    assert_eq!(envelope.nonce.len(), 12);

    // Decrypt
    let sk_bytes = secret_key.to_bytes();
    let decrypted = encryptor
        .decrypt_envelope(&sk_bytes, &envelope)
        .await
        .expect("ECIES decryption should succeed");

    assert_eq!(decrypted, plaintext, "round-trip plaintext must match");
}
