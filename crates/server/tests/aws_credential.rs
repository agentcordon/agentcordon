//! Integration tests for F-006: AWS Credential Type & SigV4 Transform.
//!
//! Tests cover:
//! 1. Credential creation with `credential_type = "aws"` (valid/invalid JSON, missing fields)
//! 2. Auto-default of `transform_name` to `"aws-sigv4"` for AWS credentials
//! 3. Generic credential type backward compatibility
//! 4. `credential_type` field in list/get API responses
//! 5. Proxy with AWS SigV4 signing (Authorization header + extra headers)
//! 6. Backward compatibility: generic credential proxy still works

use axum::http::{Method, StatusCode};
use serde_json::{json, Value};
use uuid::Uuid;
use wiremock::matchers::{method as wm_method, path as wm_path};
use wiremock::{Mock, MockServer, Request as WiremockRequest, ResponseTemplate};

use agent_cordon_core::crypto::SecretEncryptor;
use agent_cordon_core::domain::agent::Agent;
use agent_cordon_core::domain::credential::{CredentialId, StoredCredential};

use agent_cordon_server::test_helpers::{TestAppBuilder, TestContext};

use crate::common::grant_cedar_permission;

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

async fn setup_test_app() -> TestContext {
    TestAppBuilder::new().with_admin().build().await
}

/// Get a device-bound JWT for the admin agent via direct issuance.
async fn get_jwt(ctx: &TestContext) -> String {
    crate::common::ctx_admin_jwt(ctx).await
}

/// Send a JSON request with dual auth (device + agent JWT).
async fn send_json(
    ctx: &TestContext,
    method: Method,
    uri: &str,
    agent_jwt: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let dev = ctx.admin_device.as_ref().expect("admin device");
    crate::common::send_json_dual_auth(
        &ctx.app,
        method,
        uri,
        &dev.signing_key,
        &dev.device_id,
        agent_jwt,
        body,
    )
    .await
}

/// Helper: a valid AWS credential JSON string.
fn valid_aws_secret() -> String {
    json!({
        "access_key_id": "AKIAIOSFODNN7EXAMPLE",
        "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "region": "us-east-1",
        "service": "s3"
    })
    .to_string()
}

/// Helper: store an AWS credential directly in the store (bypassing API).
async fn store_aws_credential(
    state: &agent_cordon_server::state::AppState,
    owner: &Agent,
    name: &str,
) -> CredentialId {
    let secret = valid_aws_secret();
    let now = chrono::Utc::now();
    let cred_id = CredentialId(Uuid::new_v4());
    let (encrypted, nonce) = state
        .encryptor
        .encrypt(secret.as_bytes(), cred_id.0.to_string().as_bytes())
        .expect("encrypt");
    let cred = StoredCredential {
        id: cred_id.clone(),
        name: name.to_string(),
        service: "aws".to_string(),
        encrypted_value: encrypted,
        nonce,
        scopes: vec!["s3:GetObject".to_string()],
        metadata: json!({}),
        created_by: Some(owner.id.clone()),
        created_by_user: None,
        created_at: now,
        updated_at: now,
        allowed_url_pattern: None,
        expires_at: None,
        transform_script: None,
        transform_name: Some("aws-sigv4".to_string()),
        vault: "default".to_string(),
        credential_type: "aws".to_string(),
        tags: vec![],
        key_version: 1,
    };
    state
        .store
        .store_credential(&cred)
        .await
        .expect("store credential");

    for perm in &["read", "write", "delete", "delegated_use"] {
        grant_cedar_permission(state, &cred_id, &owner.id, perm).await;
    }

    cred_id
}

/// Helper: store a generic credential (no transform).
async fn store_generic_credential(
    state: &agent_cordon_server::state::AppState,
    owner: &Agent,
    name: &str,
    secret: &str,
) -> CredentialId {
    let now = chrono::Utc::now();
    let cred_id = CredentialId(Uuid::new_v4());
    let (encrypted, nonce) = state
        .encryptor
        .encrypt(secret.as_bytes(), cred_id.0.to_string().as_bytes())
        .expect("encrypt");
    let cred = StoredCredential {
        id: cred_id.clone(),
        name: name.to_string(),
        service: "test".to_string(),
        encrypted_value: encrypted,
        nonce,
        scopes: vec!["read".to_string()],
        metadata: json!({}),
        created_by: Some(owner.id.clone()),
        created_by_user: None,
        created_at: now,
        updated_at: now,
        allowed_url_pattern: None,
        expires_at: None,
        transform_script: None,
        transform_name: None,
        vault: "default".to_string(),
        credential_type: "generic".to_string(),
        tags: vec![],
        key_version: 1,
    };
    state
        .store
        .store_credential(&cred)
        .await
        .expect("store credential");

    for perm in &["read", "write", "delete", "delegated_use"] {
        grant_cedar_permission(state, &cred_id, &owner.id, perm).await;
    }

    cred_id
}

// ===========================================================================
// 1. Create AWS credential with valid JSON → succeeds, credential_type is "aws"
// ===========================================================================

#[tokio::test]
async fn create_aws_credential_valid_json_succeeds() {
    let ctx = setup_test_app().await;
    let jwt = get_jwt(&ctx).await;

    let (status, body) = send_json(
        &ctx,
        Method::POST,
        "/api/v1/credentials",
        &jwt,
        Some(json!({
            "name": "my-aws-cred",
            "service": "aws",
            "credential_type": "aws",
            "secret_value": valid_aws_secret(),
            "scopes": ["s3:GetObject"],
            "allowed_url_pattern": "https://*.s3.amazonaws.com/*"
        })),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "response: {}", body);
    let data = &body["data"];
    assert_eq!(data["name"], "my-aws-cred");
    assert_eq!(data["credential_type"], "aws");
    assert_eq!(data["service"], "aws");
}

// ===========================================================================
// 2. Create AWS credential with invalid JSON → 400
// ===========================================================================

#[tokio::test]
async fn create_aws_credential_invalid_json_returns_400() {
    let ctx = setup_test_app().await;
    let jwt = get_jwt(&ctx).await;

    let (status, body) = send_json(
        &ctx,
        Method::POST,
        "/api/v1/credentials",
        &jwt,
        Some(json!({
            "name": "bad-aws-cred",
            "service": "aws",
            "credential_type": "aws",
            "secret_value": "this-is-not-json"
        })),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "response: {}", body);
    let error_msg = body["error"]["message"].as_str().unwrap();
    assert!(
        error_msg.contains("credential_type 'aws'"),
        "error should mention aws credential_type: {}",
        error_msg
    );
    // Security: error message must NOT contain the secret_value
    assert!(
        !error_msg.contains("this-is-not-json"),
        "error must not leak secret_value: {}",
        error_msg
    );
}

// ===========================================================================
// 3. Create AWS credential with missing region/service → succeeds (optional, inferred at proxy time)
// ===========================================================================

#[tokio::test]
async fn create_aws_credential_without_region_succeeds() {
    let ctx = setup_test_app().await;
    let jwt = get_jwt(&ctx).await;

    let partial_secret = json!({
        "access_key_id": "AKIAIOSFODNN7EXAMPLE",
        "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        // region and service omitted — inferred from target URL at proxy time
    })
    .to_string();

    let (status, body) = send_json(
        &ctx,
        Method::POST,
        "/api/v1/credentials",
        &jwt,
        Some(json!({
            "name": "partial-aws-cred",
            "service": "aws",
            "credential_type": "aws",
            "secret_value": partial_secret
        })),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "response: {}", body);
    assert_eq!(body["data"]["credential_type"], "aws");
    assert_eq!(body["data"]["transform_name"], "aws-sigv4");
    // Auto-defaulted URL pattern
    assert_eq!(
        body["data"]["allowed_url_pattern"],
        "https://*.amazonaws.com/*"
    );
}

#[tokio::test]
async fn create_aws_credential_missing_access_key_returns_400() {
    let ctx = setup_test_app().await;
    let jwt = get_jwt(&ctx).await;

    let incomplete_secret = json!({
        "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "region": "us-east-1",
        "service": "s3"
        // missing "access_key_id"
    })
    .to_string();

    let (status, body) = send_json(
        &ctx,
        Method::POST,
        "/api/v1/credentials",
        &jwt,
        Some(json!({
            "name": "no-access-key-cred",
            "service": "aws",
            "credential_type": "aws",
            "secret_value": incomplete_secret
        })),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "response: {}", body);
    let error_msg = body["error"]["message"].as_str().unwrap();
    assert!(
        error_msg.contains("access_key_id"),
        "error should mention missing field 'access_key_id': {}",
        error_msg
    );
}

#[tokio::test]
async fn create_aws_credential_empty_field_returns_400() {
    let ctx = setup_test_app().await;
    let jwt = get_jwt(&ctx).await;

    let secret_with_empty = json!({
        "access_key_id": "",
        "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "region": "us-east-1",
        "service": "s3"
    })
    .to_string();

    let (status, body) = send_json(
        &ctx,
        Method::POST,
        "/api/v1/credentials",
        &jwt,
        Some(json!({
            "name": "empty-field-cred",
            "service": "aws",
            "credential_type": "aws",
            "secret_value": secret_with_empty
        })),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "response: {}", body);
    let error_msg = body["error"]["message"].as_str().unwrap();
    assert!(
        error_msg.contains("access_key_id"),
        "error should mention empty field: {}",
        error_msg
    );
}

// ===========================================================================
// 4. Create AWS credential auto-defaults transform_name to "aws-sigv4"
// ===========================================================================

#[tokio::test]
async fn create_aws_credential_auto_defaults_transform_name() {
    let ctx = setup_test_app().await;
    let jwt = get_jwt(&ctx).await;

    // Don't set transform_name — should auto-default to "aws-sigv4"
    let (status, body) = send_json(
        &ctx,
        Method::POST,
        "/api/v1/credentials",
        &jwt,
        Some(json!({
            "name": "auto-transform-aws-cred",
            "service": "aws",
            "credential_type": "aws",
            "secret_value": valid_aws_secret()
        })),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "response: {}", body);
    let data = &body["data"];
    assert_eq!(data["credential_type"], "aws");
    assert_eq!(
        data["transform_name"], "aws-sigv4",
        "transform_name should be auto-defaulted to aws-sigv4"
    );
}

#[tokio::test]
async fn create_aws_credential_explicit_transform_name_preserved() {
    let ctx = setup_test_app().await;
    let jwt = get_jwt(&ctx).await;

    // Explicitly set a different transform_name — should be preserved
    let (status, body) = send_json(
        &ctx,
        Method::POST,
        "/api/v1/credentials",
        &jwt,
        Some(json!({
            "name": "explicit-transform-aws-cred",
            "service": "aws",
            "credential_type": "aws",
            "secret_value": valid_aws_secret(),
            "transform_name": "identity"
        })),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "response: {}", body);
    let data = &body["data"];
    assert_eq!(data["credential_type"], "aws");
    assert_eq!(
        data["transform_name"], "identity",
        "explicit transform_name should not be overridden"
    );
}

// ===========================================================================
// 5. Create generic credential → credential_type is "generic"
// ===========================================================================

#[tokio::test]
async fn create_generic_credential_default_type() {
    let ctx = setup_test_app().await;
    let jwt = get_jwt(&ctx).await;

    // No credential_type specified — should default to "generic"
    let (status, body) = send_json(
        &ctx,
        Method::POST,
        "/api/v1/credentials",
        &jwt,
        Some(json!({
            "name": "generic-cred",
            "service": "test",
            "secret_value": "some-secret-token"
        })),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "response: {}", body);
    let data = &body["data"];
    assert_eq!(data["credential_type"], "generic");
}

#[tokio::test]
async fn create_generic_credential_explicit_type() {
    let ctx = setup_test_app().await;
    let jwt = get_jwt(&ctx).await;

    let (status, body) = send_json(
        &ctx,
        Method::POST,
        "/api/v1/credentials",
        &jwt,
        Some(json!({
            "name": "explicit-generic-cred",
            "service": "test",
            "credential_type": "generic",
            "secret_value": "another-secret"
        })),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "response: {}", body);
    assert_eq!(body["data"]["credential_type"], "generic");
}

// ===========================================================================
// 6. Credential type appears in list/get credential responses
// ===========================================================================

#[tokio::test]
async fn credential_type_in_list_response() {
    let ctx = setup_test_app().await;
    let jwt = get_jwt(&ctx).await;

    // Create an AWS credential
    let (status, _) = send_json(
        &ctx,
        Method::POST,
        "/api/v1/credentials",
        &jwt,
        Some(json!({
            "name": "list-aws-cred",
            "service": "aws",
            "credential_type": "aws",
            "secret_value": valid_aws_secret()
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Create a generic credential
    let (status, _) = send_json(
        &ctx,
        Method::POST,
        "/api/v1/credentials",
        &jwt,
        Some(json!({
            "name": "list-generic-cred",
            "service": "test",
            "secret_value": "secret"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // List credentials and check credential_type in each
    let (status, body) = send_json(&ctx, Method::GET, "/api/v1/credentials", &jwt, None).await;
    assert_eq!(status, StatusCode::OK, "response: {}", body);

    let creds = body["data"].as_array().expect("data should be an array");
    assert!(creds.len() >= 2, "should have at least 2 credentials");

    let aws_cred = creds
        .iter()
        .find(|c| c["name"] == "list-aws-cred")
        .expect("should find AWS credential in list");
    assert_eq!(aws_cred["credential_type"], "aws");

    let generic_cred = creds
        .iter()
        .find(|c| c["name"] == "list-generic-cred")
        .expect("should find generic credential in list");
    assert_eq!(generic_cred["credential_type"], "generic");
}

#[tokio::test]
async fn credential_type_in_get_response() {
    let ctx = setup_test_app().await;
    let jwt = get_jwt(&ctx).await;

    // Create an AWS credential
    let (status, create_body) = send_json(
        &ctx,
        Method::POST,
        "/api/v1/credentials",
        &jwt,
        Some(json!({
            "name": "get-aws-cred",
            "service": "aws",
            "credential_type": "aws",
            "secret_value": valid_aws_secret()
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "create failed: {}", create_body);
    let cred_id = create_body["data"]["id"].as_str().unwrap();

    // Get the credential by ID
    let (status, body) = send_json(
        &ctx,
        Method::GET,
        &format!("/api/v1/credentials/{}", cred_id),
        &jwt,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "response: {}", body);
    assert_eq!(body["data"]["credential_type"], "aws");
    assert_eq!(body["data"]["transform_name"], "aws-sigv4");
}

// ===========================================================================
// 7. Proxy with AWS credential produces correct SigV4 Authorization header
// ===========================================================================

#[tokio::test]
async fn proxy_aws_sigv4_authorization_header() {
    let ctx = setup_test_app().await;
    let admin = ctx.admin_agent.as_ref().expect("admin");
    let mock_server = MockServer::start().await;

    // Create a mock that captures the request so we can inspect headers
    Mock::given(wm_method("GET"))
        .and(wm_path("/api/data"))
        .respond_with(ResponseTemplate::new(200).set_body_string("aws-ok"))
        .mount(&mock_server)
        .await;

    // Store an AWS credential with aws-sigv4 transform
    let _cred_id = store_aws_credential(&ctx.state, admin, "aws-cred").await;

    let jwt = get_jwt(&ctx).await;

    let upstream_url = format!("{}/api/data", mock_server.uri());
    let (status, body) = send_json(
        &ctx,
        Method::POST,
        "/api/v1/proxy/execute",
        &jwt,
        Some(json!({
            "method": "GET",
            "url": upstream_url,
            "headers": {"Authorization": "{{aws-cred}}"}
        })),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "response: {}", body);
    assert_eq!(body["data"]["status_code"], 200);
    assert_eq!(body["data"]["body"], "aws-ok");

    // Verify the mock received the request with the correct headers
    let received = mock_server.received_requests().await.unwrap();
    assert_eq!(
        received.len(),
        1,
        "should have received exactly one request"
    );
    let req = &received[0];

    // Authorization header should start with AWS4-HMAC-SHA256
    let auth_header = get_header(req, "authorization");
    assert!(
        auth_header.starts_with("AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/"),
        "Authorization header should start with AWS4-HMAC-SHA256 and contain access_key_id. Got: {}",
        auth_header
    );
    assert!(
        auth_header.contains("SignedHeaders="),
        "Authorization header should contain SignedHeaders"
    );
    assert!(
        auth_header.contains("Signature="),
        "Authorization header should contain Signature"
    );
}

// ===========================================================================
// 8. Proxy with AWS credential includes extra headers
// ===========================================================================

#[tokio::test]
async fn proxy_aws_sigv4_extra_headers() {
    let ctx = setup_test_app().await;
    let admin = ctx.admin_agent.as_ref().expect("admin");
    let mock_server = MockServer::start().await;

    Mock::given(wm_method("POST"))
        .and(wm_path("/api/upload"))
        .respond_with(ResponseTemplate::new(200).set_body_string("uploaded"))
        .mount(&mock_server)
        .await;

    let _cred_id = store_aws_credential(&ctx.state, admin, "aws-cred-headers").await;

    let jwt = get_jwt(&ctx).await;

    let upstream_url = format!("{}/api/upload", mock_server.uri());
    let (status, body) = send_json(
        &ctx,
        Method::POST,
        "/api/v1/proxy/execute",
        &jwt,
        Some(json!({
            "method": "POST",
            "url": upstream_url,
            "headers": {"Authorization": "{{aws-cred-headers}}"},
            "body": "{\"key\":\"value\"}"
        })),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "response: {}", body);
    assert_eq!(body["data"]["status_code"], 200);

    // Verify extra headers were sent to the upstream
    let received = mock_server.received_requests().await.unwrap();
    assert_eq!(received.len(), 1);
    let req = &received[0];

    // x-amz-date header should be present and in YYYYMMDDTHHMMSSZ format
    let amz_date = get_header(req, "x-amz-date");
    assert!(!amz_date.is_empty(), "x-amz-date header should be present");
    // Validate format: 16 chars, YYYYMMDDTHHMMSSZ
    assert_eq!(
        amz_date.len(),
        16,
        "x-amz-date should be 16 chars (YYYYMMDDTHHMMSSZ). Got: {}",
        amz_date
    );
    assert!(
        amz_date.ends_with('Z'),
        "x-amz-date should end with 'Z'. Got: {}",
        amz_date
    );
    assert!(
        amz_date.chars().nth(8) == Some('T'),
        "x-amz-date should have 'T' at position 8. Got: {}",
        amz_date
    );

    // x-amz-content-sha256 should be present (64 hex chars = SHA-256 hash)
    let content_sha = get_header(req, "x-amz-content-sha256");
    assert!(
        !content_sha.is_empty(),
        "x-amz-content-sha256 header should be present"
    );
    assert_eq!(
        content_sha.len(),
        64,
        "x-amz-content-sha256 should be 64 hex chars. Got: {}",
        content_sha
    );
    assert!(
        content_sha.chars().all(|c| c.is_ascii_hexdigit()),
        "x-amz-content-sha256 should be hex. Got: {}",
        content_sha
    );

    // host header should be present
    let host = get_header(req, "host");
    assert!(!host.is_empty(), "host header should be present");
}

// ===========================================================================
// 9. Existing generic credential proxy still works unchanged
// ===========================================================================

#[tokio::test]
async fn proxy_generic_credential_still_works() {
    let ctx = setup_test_app().await;
    let admin = ctx.admin_agent.as_ref().expect("admin");
    let mock_server = MockServer::start().await;

    let secret = "generic_token_abc123";

    Mock::given(wm_method("GET"))
        .and(wm_path("/api/generic-test"))
        .and(wiremock::matchers::header(
            "Authorization",
            format!("token {}", secret).as_str(),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_string("generic-ok"))
        .mount(&mock_server)
        .await;

    let _cred_id = store_generic_credential(&ctx.state, admin, "my-generic-cred", secret).await;

    let jwt = get_jwt(&ctx).await;
    let upstream_url = format!("{}/api/generic-test", mock_server.uri());

    let (status, body) = send_json(
        &ctx,
        Method::POST,
        "/api/v1/proxy/execute",
        &jwt,
        Some(json!({
            "method": "GET",
            "url": upstream_url,
            "headers": {"Authorization": "token {{my-generic-cred}}"}
        })),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "response: {}", body);
    assert_eq!(body["data"]["status_code"], 200);
    assert_eq!(body["data"]["body"], "generic-ok");
}

// ===========================================================================
// 10. AWS SigV4 proxy with GET (no body) — extra headers correct
// ===========================================================================

#[tokio::test]
async fn proxy_aws_sigv4_get_no_body() {
    let ctx = setup_test_app().await;
    let admin = ctx.admin_agent.as_ref().expect("admin");
    let mock_server = MockServer::start().await;

    Mock::given(wm_method("GET"))
        .and(wm_path("/bucket/key.txt"))
        .respond_with(ResponseTemplate::new(200).set_body_string("file-contents"))
        .mount(&mock_server)
        .await;

    let _cred_id = store_aws_credential(&ctx.state, admin, "aws-get-cred").await;

    let jwt = get_jwt(&ctx).await;
    let upstream_url = format!("{}/bucket/key.txt", mock_server.uri());

    let (status, body) = send_json(
        &ctx,
        Method::POST,
        "/api/v1/proxy/execute",
        &jwt,
        Some(json!({
            "method": "GET",
            "url": upstream_url,
            "headers": {"Authorization": "{{aws-get-cred}}"}
        })),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "response: {}", body);
    assert_eq!(body["data"]["status_code"], 200);

    // Verify SigV4 headers are present even for GET with no body
    let received = mock_server.received_requests().await.unwrap();
    assert_eq!(received.len(), 1);
    let req = &received[0];

    let auth = get_header(req, "authorization");
    assert!(auth.starts_with("AWS4-HMAC-SHA256"));

    // For empty body, content hash should be SHA-256 of empty string
    let content_sha = get_header(req, "x-amz-content-sha256");
    let empty_sha = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    assert_eq!(
        content_sha, empty_sha,
        "content hash for empty body should be SHA-256 of empty string"
    );
}

// ===========================================================================
// 11. AWS credential via API, then proxy — full end-to-end flow
// ===========================================================================

#[tokio::test]
async fn aws_credential_api_create_then_proxy_e2e() {
    let ctx = setup_test_app().await;
    let mock_server = MockServer::start().await;
    let jwt = get_jwt(&ctx).await;

    Mock::given(wm_method("GET"))
        .and(wm_path("/api/e2e"))
        .respond_with(ResponseTemplate::new(200).set_body_string("e2e-ok"))
        .mount(&mock_server)
        .await;

    // Create AWS credential via API — must set allowed_url_pattern for mock server
    let (status, create_body) = send_json(
        &ctx,
        Method::POST,
        "/api/v1/credentials",
        &jwt,
        Some(json!({
            "name": "e2e-aws-cred",
            "service": "aws",
            "credential_type": "aws",
            "secret_value": valid_aws_secret(),
            "allowed_url_pattern": format!("{}/*", mock_server.uri())
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "create failed: {}", create_body);
    assert_eq!(create_body["data"]["credential_type"], "aws");
    assert_eq!(create_body["data"]["transform_name"], "aws-sigv4");

    // Use it in a proxy request
    let upstream_url = format!("{}/api/e2e", mock_server.uri());
    let (status, body) = send_json(
        &ctx,
        Method::POST,
        "/api/v1/proxy/execute",
        &jwt,
        Some(json!({
            "method": "GET",
            "url": upstream_url,
            "headers": {"Authorization": "{{e2e-aws-cred}}"}
        })),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "proxy failed: {}", body);
    assert_eq!(body["data"]["status_code"], 200);
    assert_eq!(body["data"]["body"], "e2e-ok");

    // Verify SigV4 headers
    let received = mock_server.received_requests().await.unwrap();
    assert_eq!(received.len(), 1);
    let req = &received[0];

    let auth = get_header(req, "authorization");
    assert!(auth.starts_with("AWS4-HMAC-SHA256"), "auth: {}", auth);
}

// ===========================================================================
// 12. AWS credential with structured fields
// ===========================================================================

#[tokio::test]
async fn create_aws_credential_with_structured_fields() {
    let ctx = setup_test_app().await;
    let jwt = get_jwt(&ctx).await;

    let (status, body) = send_json(
        &ctx,
        Method::POST,
        "/api/v1/credentials",
        &jwt,
        Some(json!({
            "name": "struct-aws-cred",
            "service": "aws",
            "credential_type": "aws",
            "aws_access_key_id": "AKIAIOSFODNN7EXAMPLE",
            "aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "aws_region": "us-west-2",
            "aws_service": "dynamodb"
        })),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "response: {}", body);
    assert_eq!(body["data"]["credential_type"], "aws");
    assert_eq!(body["data"]["transform_name"], "aws-sigv4");
}

#[tokio::test]
async fn create_aws_credential_structured_fields_missing_secret_key() {
    let ctx = setup_test_app().await;
    let jwt = get_jwt(&ctx).await;

    let (status, body) = send_json(
        &ctx,
        Method::POST,
        "/api/v1/credentials",
        &jwt,
        Some(json!({
            "name": "no-secret-key-cred",
            "service": "aws",
            "credential_type": "aws",
            "aws_access_key_id": "AKIAIOSFODNN7EXAMPLE"
            // missing aws_secret_access_key
        })),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "response: {}", body);
}

#[tokio::test]
async fn create_aws_credential_structured_fields_empty_access_key() {
    let ctx = setup_test_app().await;
    let jwt = get_jwt(&ctx).await;

    let (status, body) = send_json(
        &ctx,
        Method::POST,
        "/api/v1/credentials",
        &jwt,
        Some(json!({
            "name": "empty-ak-cred",
            "service": "aws",
            "credential_type": "aws",
            "aws_access_key_id": "",
            "aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        })),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "response: {}", body);
}

#[tokio::test]
async fn create_aws_credential_structured_fields_empty_secret_key() {
    let ctx = setup_test_app().await;
    let jwt = get_jwt(&ctx).await;

    let (status, body) = send_json(
        &ctx,
        Method::POST,
        "/api/v1/credentials",
        &jwt,
        Some(json!({
            "name": "empty-sk-cred",
            "service": "aws",
            "credential_type": "aws",
            "aws_access_key_id": "AKIAIOSFODNN7EXAMPLE",
            "aws_secret_access_key": ""
        })),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "response: {}", body);
}

#[tokio::test]
async fn create_aws_credential_no_secret_at_all_returns_400() {
    let ctx = setup_test_app().await;
    let jwt = get_jwt(&ctx).await;

    let (status, _body) = send_json(
        &ctx,
        Method::POST,
        "/api/v1/credentials",
        &jwt,
        Some(json!({
            "name": "no-secret-cred",
            "service": "aws",
            "credential_type": "aws"
            // no secret_value, no aws_* fields
        })),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
}

// ===========================================================================
// 13. Default URL pattern for AWS credentials
// ===========================================================================

#[tokio::test]
async fn create_aws_credential_default_url_pattern() {
    let ctx = setup_test_app().await;
    let jwt = get_jwt(&ctx).await;

    // Create without allowed_url_pattern — should default to https://*.amazonaws.com/*
    let (status, body) = send_json(
        &ctx,
        Method::POST,
        "/api/v1/credentials",
        &jwt,
        Some(json!({
            "name": "default-url-aws-cred",
            "service": "aws",
            "credential_type": "aws",
            "secret_value": valid_aws_secret()
        })),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "response: {}", body);
    assert_eq!(
        body["data"]["allowed_url_pattern"], "https://*.amazonaws.com/*",
        "AWS credential should default to *.amazonaws.com"
    );
}

#[tokio::test]
async fn create_aws_credential_explicit_url_pattern_preserved() {
    let ctx = setup_test_app().await;
    let jwt = get_jwt(&ctx).await;

    let (status, body) = send_json(
        &ctx,
        Method::POST,
        "/api/v1/credentials",
        &jwt,
        Some(json!({
            "name": "explicit-url-aws-cred",
            "service": "aws",
            "credential_type": "aws",
            "secret_value": valid_aws_secret(),
            "allowed_url_pattern": "https://my-vpc.internal/*"
        })),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "response: {}", body);
    assert_eq!(
        body["data"]["allowed_url_pattern"], "https://my-vpc.internal/*",
        "explicit URL pattern should be preserved"
    );
}

// ===========================================================================
// 14. Unknown credential types
// ===========================================================================

#[tokio::test]
async fn create_credential_unknown_type_rejected() {
    let ctx = setup_test_app().await;
    let jwt = get_jwt(&ctx).await;

    let (status, _body) = send_json(
        &ctx,
        Method::POST,
        "/api/v1/credentials",
        &jwt,
        Some(json!({
            "name": "unknown-type-cred",
            "service": "test",
            "credential_type": "gcp",
            "secret_value": "some-secret"
        })),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn create_credential_unknown_type_azure_rejected() {
    let ctx = setup_test_app().await;
    let jwt = get_jwt(&ctx).await;

    let (status, _body) = send_json(
        &ctx,
        Method::POST,
        "/api/v1/credentials",
        &jwt,
        Some(json!({
            "name": "azure-type-cred",
            "service": "azure",
            "credential_type": "azure",
            "secret_value": "some-secret"
        })),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
}

// ===========================================================================
// 15. AWS proxy with stored region/service
// ===========================================================================

#[tokio::test]
async fn proxy_aws_sigv4_with_stored_region_service_works() {
    let ctx = setup_test_app().await;
    let admin = ctx.admin_agent.as_ref().expect("admin");
    let mock_server = MockServer::start().await;

    Mock::given(wm_method("GET"))
        .and(wm_path("/data"))
        .respond_with(ResponseTemplate::new(200).set_body_string("stored-region-ok"))
        .mount(&mock_server)
        .await;

    let _cred_id = store_aws_credential(&ctx.state, admin, "stored-region-cred").await;

    let jwt = get_jwt(&ctx).await;
    let upstream_url = format!("{}/data", mock_server.uri());

    let (status, body) = send_json(
        &ctx,
        Method::POST,
        "/api/v1/proxy/execute",
        &jwt,
        Some(json!({
            "method": "GET",
            "url": upstream_url,
            "headers": {"Authorization": "{{stored-region-cred}}"}
        })),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "response: {}", body);
    assert_eq!(body["data"]["status_code"], 200);
}

// ===========================================================================
// 16. AWS SigV4 proxy: no region, non-AWS URL → fails
// ===========================================================================

#[tokio::test]
async fn proxy_aws_sigv4_no_region_non_aws_url_fails() {
    let ctx = setup_test_app().await;
    let admin = ctx.admin_agent.as_ref().expect("admin");
    let mock_server = MockServer::start().await;

    Mock::given(wm_method("GET"))
        .and(wm_path("/api/no-region"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&mock_server)
        .await;

    // Store a credential WITHOUT region/service in the secret
    let secret_no_region = json!({
        "access_key_id": "AKIAIOSFODNN7EXAMPLE",
        "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    })
    .to_string();

    let now = chrono::Utc::now();
    let cred_id = CredentialId(Uuid::new_v4());
    let (encrypted, nonce) = ctx
        .encryptor
        .encrypt(
            secret_no_region.as_bytes(),
            cred_id.0.to_string().as_bytes(),
        )
        .expect("encrypt");

    let cred = StoredCredential {
        id: cred_id.clone(),
        name: "no-region-cred".to_string(),
        service: "aws".to_string(),
        encrypted_value: encrypted,
        nonce,
        scopes: vec![],
        metadata: json!({}),
        created_by: Some(admin.id.clone()),
        created_by_user: None,
        created_at: now,
        updated_at: now,
        allowed_url_pattern: None,
        expires_at: None,
        transform_script: None,
        transform_name: Some("aws-sigv4".to_string()),
        vault: "default".to_string(),
        credential_type: "aws".to_string(),
        tags: vec![],
        key_version: 1,
    };
    ctx.store.store_credential(&cred).await.expect("store");
    for perm in &["read", "write", "delete", "delegated_use"] {
        grant_cedar_permission(&ctx.state, &cred_id, &admin.id, perm).await;
    }

    let jwt = get_jwt(&ctx).await;

    // Proxy to a non-AWS URL without region → should fail
    let upstream_url = format!("{}/api/no-region", mock_server.uri());
    let (status, body) = send_json(
        &ctx,
        Method::POST,
        "/api/v1/proxy/execute",
        &jwt,
        Some(json!({
            "method": "GET",
            "url": upstream_url,
            "headers": {"Authorization": "{{no-region-cred}}"}
        })),
    )
    .await;

    // Should fail because we can't infer region from a localhost URL
    assert_ne!(
        status,
        StatusCode::OK,
        "should fail for non-AWS URL without region"
    );
    // The error should be in the response
    assert!(
        body.to_string().contains("region")
            || body["data"]["status_code"] != 200
            || status != StatusCode::OK,
        "response should indicate region issue: {}",
        body
    );
}

// ===========================================================================
// 17. Structured fields proxy flow
// ===========================================================================

#[tokio::test]
async fn aws_credential_structured_fields_then_proxy_e2e() {
    let ctx = setup_test_app().await;
    let mock_server = MockServer::start().await;
    let jwt = get_jwt(&ctx).await;

    Mock::given(wm_method("PUT"))
        .and(wm_path("/items/42"))
        .respond_with(ResponseTemplate::new(200).set_body_string("struct-proxy-ok"))
        .mount(&mock_server)
        .await;

    // Create via structured fields with allowed_url_pattern for mock server
    let (status, create_body) = send_json(
        &ctx,
        Method::POST,
        "/api/v1/credentials",
        &jwt,
        Some(json!({
            "name": "struct-proxy-cred",
            "service": "aws",
            "credential_type": "aws",
            "aws_access_key_id": "AKIAIOSFODNN7EXAMPLE",
            "aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "aws_region": "us-east-1",
            "aws_service": "execute-api",
            "allowed_url_pattern": format!("{}/*", mock_server.uri())
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "create: {}", create_body);

    // Use in proxy
    let upstream_url = format!("{}/items/42", mock_server.uri());
    let (status, body) = send_json(
        &ctx,
        Method::POST,
        "/api/v1/proxy/execute",
        &jwt,
        Some(json!({
            "method": "PUT",
            "url": upstream_url,
            "headers": {"Authorization": "{{struct-proxy-cred}}"},
            "body": "{\"name\":\"updated\"}"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "proxy: {}", body);
    assert_eq!(body["data"]["status_code"], 200);
    assert_eq!(body["data"]["body"], "struct-proxy-ok");

    let received = mock_server.received_requests().await.unwrap();
    assert_eq!(received.len(), 1);
    let req = &received[0];
    let auth = get_header(req, "authorization");
    assert!(auth.starts_with("AWS4-HMAC-SHA256"), "auth: {}", auth);
}

// ===========================================================================
// 18. Generic credential with AWS key pattern rejected
// ===========================================================================

#[tokio::test]
async fn generic_credential_with_akia_pattern_rejected() {
    let ctx = setup_test_app().await;
    let jwt = get_jwt(&ctx).await;

    let (status, body) = send_json(
        &ctx,
        Method::POST,
        "/api/v1/credentials",
        &jwt,
        Some(json!({
            "name": "misplaced-aws-key",
            "service": "test",
            "secret_value": "AKIAIOSFODNN7EXAMPLE"
        })),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "response: {}", body);
    let error_msg = body["error"]["message"].as_str().unwrap();
    assert!(
        error_msg.contains("AWS Access Key ID pattern"),
        "error should mention AWS key detection: {}",
        error_msg
    );
    assert!(
        error_msg.contains("credential_type 'aws'"),
        "error should suggest using aws type: {}",
        error_msg
    );
}

#[tokio::test]
async fn generic_credential_with_akia_in_multiline_paste_rejected() {
    let ctx = setup_test_app().await;
    let jwt = get_jwt(&ctx).await;

    // Simulate pasting both access key and secret key into one field
    let pasted = "AKIAIOSFODNN7EXAMPLE\nwJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
    let (status, body) = send_json(
        &ctx,
        Method::POST,
        "/api/v1/credentials",
        &jwt,
        Some(json!({
            "name": "multiline-aws-paste",
            "service": "test",
            "secret_value": pasted
        })),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "response: {}", body);
    let error_msg = body["error"]["message"].as_str().unwrap();
    assert!(
        error_msg.contains("AWS Access Key ID pattern"),
        "error should detect AKIA in multiline paste: {}",
        error_msg
    );
}

#[tokio::test]
async fn generic_credential_with_normal_secret_succeeds() {
    let ctx = setup_test_app().await;
    let jwt = get_jwt(&ctx).await;

    let (status, body) = send_json(
        &ctx,
        Method::POST,
        "/api/v1/credentials",
        &jwt,
        Some(json!({
            "name": "normal-api-key",
            "service": "test",
            "secret_value": "sk-1234567890abcdef"
        })),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "response: {}", body);
    assert_eq!(body["data"]["credential_type"], "generic");
}

#[tokio::test]
async fn generic_credential_with_short_akia_prefix_succeeds() {
    let ctx = setup_test_app().await;
    let jwt = get_jwt(&ctx).await;

    // "AKIA" followed by fewer than 16 alphanumeric chars should not trigger
    let (status, body) = send_json(
        &ctx,
        Method::POST,
        "/api/v1/credentials",
        &jwt,
        Some(json!({
            "name": "short-akia",
            "service": "test",
            "secret_value": "AKIA12345"
        })),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "response: {}", body);
    assert_eq!(body["data"]["credential_type"], "generic");
}

// ===========================================================================
// Helper: extract header from wiremock request
// ===========================================================================

fn get_header(req: &WiremockRequest, name: &str) -> String {
    req.headers
        .iter()
        .find(|(n, _)| n.as_str().eq_ignore_ascii_case(name))
        .map(|(_, v)| v.to_str().unwrap_or("").to_string())
        .unwrap_or_default()
}
