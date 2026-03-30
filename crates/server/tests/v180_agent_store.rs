//! v1.8.0 — Agent Store Credential Tests
//!
//! Tests for `POST /api/v1/credentials/agent-store` which allows devices
//! to store credentials on behalf of agents. This endpoint auto-adds the
//! `llm_exposed` tag and records the agent identity.
//!
//! The endpoint requires dual auth: device JWT (Authorization header) plus
//! agent JWT (X-Agent-JWT header). Agent identity is derived from the JWT.

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::json;
use tower::ServiceExt;

use agent_cordon_server::test_helpers::TestAppBuilder;

use crate::common::*;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Send a request with workspace JWT auth (Authorization: Bearer).
///
/// In v2.0, device+agent dual auth is replaced by single workspace JWT auth.
/// The `agent_jwt` (workspace identity JWT) is sent as the Bearer token.
/// device_key and device_id params are kept for backward compat but ignored.
async fn send_device_and_agent_auth(
    app: &axum::Router,
    method: Method,
    uri: &str,
    _device_key: &p256::ecdsa::SigningKey,
    _device_id: &str,
    agent_jwt: &str,
    body: Option<serde_json::Value>,
) -> (StatusCode, serde_json::Value) {
    let mut builder = Request::builder().method(method).uri(uri);
    builder = builder.header(header::AUTHORIZATION, format!("Bearer {}", agent_jwt));

    let body = match body {
        Some(v) => {
            builder = builder.header(header::CONTENT_TYPE, "application/json");
            Body::from(serde_json::to_vec(&v).unwrap())
        }
        None => Body::empty(),
    };

    let request = builder.body(body).unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or(json!(null));
    (status, json)
}

// ===========================================================================
// Happy Path
// ===========================================================================

/// Test: Dual auth (device JWT + agent JWT) creates credential successfully via agent-store.
#[tokio::test]
async fn test_agent_store_creates_credential() {
    let ctx = TestAppBuilder::new().with_admin().build().await;

    let agent = ctx.admin_agent.as_ref().expect("admin agent");
    let agent_jwt = issue_agent_jwt(&ctx.state, agent).await;

    let (status, body) = send_device_and_agent_auth(
        &ctx.app,
        Method::POST,
        "/api/v1/credentials/agent-store",
        ctx.admin_signing_key(),
        ctx.admin_device_id(),
        &agent_jwt,
        Some(json!({
            "name": "agent-stored-cred",
            "service": "github",
            "secret_value": "ghp_test_secret_value_123",
            "agent_id": agent.id.0.to_string(),
            "agent_name": agent.name,
        })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "agent-store should succeed: {}",
        body
    );

    let data = &body["data"];
    assert!(data["id"].is_string(), "should return credential id");
    assert_eq!(data["name"].as_str(), Some("agent-stored-cred"));
    assert_eq!(data["service"].as_str(), Some("github"));
}

/// Test: Agent-store auto-adds llm_exposed tag.
#[tokio::test]
async fn test_agent_store_auto_adds_llm_exposed_tag() {
    let ctx = TestAppBuilder::new().with_admin().build().await;

    let agent = ctx.admin_agent.as_ref().expect("admin agent");
    let agent_jwt = issue_agent_jwt(&ctx.state, agent).await;

    let (status, body) = send_device_and_agent_auth(
        &ctx.app,
        Method::POST,
        "/api/v1/credentials/agent-store",
        ctx.admin_signing_key(),
        ctx.admin_device_id(),
        &agent_jwt,
        Some(json!({
            "name": "agent-llm-cred",
            "service": "openai",
            "secret_value": "sk-test-secret",
            "agent_id": agent.id.0.to_string(),
            "agent_name": agent.name,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "agent-store: {}", body);

    let tags = body["data"]["tags"]
        .as_array()
        .expect("tags should be array");
    let tag_strs: Vec<&str> = tags.iter().filter_map(|t| t.as_str()).collect();
    assert!(
        tag_strs.contains(&"llm_exposed"),
        "should auto-add llm_exposed tag, got: {:?}",
        tag_strs
    );
}

/// Test: Agent-store with extra tags merges llm_exposed.
#[tokio::test]
async fn test_agent_store_merges_tags_with_llm_exposed() {
    let ctx = TestAppBuilder::new().with_admin().build().await;

    let agent = ctx.admin_agent.as_ref().expect("admin agent");
    let agent_jwt = issue_agent_jwt(&ctx.state, agent).await;

    let (status, body) = send_device_and_agent_auth(
        &ctx.app,
        Method::POST,
        "/api/v1/credentials/agent-store",
        ctx.admin_signing_key(),
        ctx.admin_device_id(),
        &agent_jwt,
        Some(json!({
            "name": "agent-tagged-cred",
            "service": "slack",
            "secret_value": "xoxb-test-token",
            "tags": ["production", "ci"],
            "agent_id": agent.id.0.to_string(),
            "agent_name": agent.name,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "agent-store: {}", body);

    let tags = body["data"]["tags"].as_array().expect("tags");
    let tag_strs: Vec<&str> = tags.iter().filter_map(|t| t.as_str()).collect();
    assert!(
        tag_strs.contains(&"llm_exposed"),
        "should include llm_exposed"
    );
    assert!(
        tag_strs.contains(&"production"),
        "should preserve production tag"
    );
    assert!(tag_strs.contains(&"ci"), "should preserve ci tag");
}

/// Test: Agent-store does not duplicate llm_exposed if already present.
#[tokio::test]
async fn test_agent_store_no_duplicate_llm_exposed() {
    let ctx = TestAppBuilder::new().with_admin().build().await;

    let agent = ctx.admin_agent.as_ref().expect("admin agent");
    let agent_jwt = issue_agent_jwt(&ctx.state, agent).await;

    let (status, body) = send_device_and_agent_auth(
        &ctx.app,
        Method::POST,
        "/api/v1/credentials/agent-store",
        ctx.admin_signing_key(),
        ctx.admin_device_id(),
        &agent_jwt,
        Some(json!({
            "name": "agent-dedup-cred",
            "service": "test",
            "secret_value": "secret",
            "tags": ["llm_exposed", "other"],
            "agent_id": agent.id.0.to_string(),
            "agent_name": agent.name,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "agent-store: {}", body);

    let tags = body["data"]["tags"].as_array().expect("tags");
    let llm_count = tags
        .iter()
        .filter(|t| t.as_str() == Some("llm_exposed"))
        .count();
    assert_eq!(
        llm_count, 1,
        "llm_exposed should appear exactly once, got {}",
        llm_count
    );
}

/// Test: Agent identity (agent_id) stored correctly via created_by.
#[tokio::test]
async fn test_agent_store_records_agent_identity() {
    let ctx = TestAppBuilder::new().with_admin().build().await;

    let agent = ctx.admin_agent.as_ref().expect("admin agent");
    let agent_jwt = issue_agent_jwt(&ctx.state, agent).await;

    let (status, body) = send_device_and_agent_auth(
        &ctx.app,
        Method::POST,
        "/api/v1/credentials/agent-store",
        ctx.admin_signing_key(),
        ctx.admin_device_id(),
        &agent_jwt,
        Some(json!({
            "name": "agent-identity-cred",
            "service": "test",
            "secret_value": "secret",
            "agent_id": agent.id.0.to_string(),
            "agent_name": agent.name,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "agent-store: {}", body);

    // The created_by field should contain the agent's ID
    let created_by = body["data"]["created_by"].as_str();
    assert!(
        created_by.is_some(),
        "created_by should be set to agent ID, got: {:?}",
        body["data"]
    );
    assert_eq!(
        created_by.unwrap(),
        agent.id.0.to_string(),
        "created_by should match agent ID"
    );
}

// ===========================================================================
// Error Handling
// ===========================================================================

/// Test: Agent-store without device JWT returns 401.
#[tokio::test]
async fn test_agent_store_requires_device_jwt() {
    let ctx = TestAppBuilder::new().with_admin().build().await;

    let agent = ctx.admin_agent.as_ref().expect("admin agent");

    // Send without any auth header
    let (status, _body) = send_json(
        &ctx.app,
        Method::POST,
        "/api/v1/credentials/agent-store",
        None,
        None,
        None,
        Some(json!({
            "name": "no-auth-cred",
            "service": "test",
            "secret_value": "secret",
            "agent_id": agent.id.0.to_string(),
            "agent_name": agent.name,
        })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "should reject without device auth"
    );
}

/// Test: Agent-store without required name field returns 400/422.
#[tokio::test]
async fn test_agent_store_missing_name_returns_error() {
    let ctx = TestAppBuilder::new().with_admin().build().await;

    let agent = ctx.admin_agent.as_ref().expect("admin agent");
    let agent_jwt = issue_agent_jwt(&ctx.state, agent).await;

    let (status, body) = send_device_and_agent_auth(
        &ctx.app,
        Method::POST,
        "/api/v1/credentials/agent-store",
        ctx.admin_signing_key(),
        ctx.admin_device_id(),
        &agent_jwt,
        Some(json!({
            "service": "test",
            "secret_value": "secret",
            "agent_id": agent.id.0.to_string(),
            "agent_name": agent.name,
        })),
    )
    .await;
    assert!(
        status == StatusCode::BAD_REQUEST || status == StatusCode::UNPROCESSABLE_ENTITY,
        "missing name should return 400/422, got {}: {}",
        status,
        body
    );
}

/// Test: Agent-store without required service field returns 400/422.
#[tokio::test]
async fn test_agent_store_missing_service_returns_error() {
    let ctx = TestAppBuilder::new().with_admin().build().await;

    let agent = ctx.admin_agent.as_ref().expect("admin agent");
    let agent_jwt = issue_agent_jwt(&ctx.state, agent).await;

    let (status, body) = send_device_and_agent_auth(
        &ctx.app,
        Method::POST,
        "/api/v1/credentials/agent-store",
        ctx.admin_signing_key(),
        ctx.admin_device_id(),
        &agent_jwt,
        Some(json!({
            "name": "no-service-cred",
            "secret_value": "secret",
            "agent_id": agent.id.0.to_string(),
            "agent_name": agent.name,
        })),
    )
    .await;
    assert!(
        status == StatusCode::BAD_REQUEST || status == StatusCode::UNPROCESSABLE_ENTITY,
        "missing service should return 400/422, got {}: {}",
        status,
        body
    );
}

/// Test: Agent-store without required secret_value returns 400/422.
#[tokio::test]
async fn test_agent_store_missing_secret_returns_error() {
    let ctx = TestAppBuilder::new().with_admin().build().await;

    let agent = ctx.admin_agent.as_ref().expect("admin agent");
    let agent_jwt = issue_agent_jwt(&ctx.state, agent).await;

    let (status, body) = send_device_and_agent_auth(
        &ctx.app,
        Method::POST,
        "/api/v1/credentials/agent-store",
        ctx.admin_signing_key(),
        ctx.admin_device_id(),
        &agent_jwt,
        Some(json!({
            "name": "no-secret-cred",
            "service": "test",
            "agent_id": agent.id.0.to_string(),
            "agent_name": agent.name,
        })),
    )
    .await;
    assert!(
        status == StatusCode::BAD_REQUEST || status == StatusCode::UNPROCESSABLE_ENTITY,
        "missing secret should return 400/422, got {}: {}",
        status,
        body
    );
}

// ===========================================================================
// Security
// ===========================================================================

/// Test: Response does NOT contain raw secret_value or encrypted_value.
#[tokio::test]
async fn test_agent_store_secret_not_in_response() {
    let ctx = TestAppBuilder::new().with_admin().build().await;

    let agent = ctx.admin_agent.as_ref().expect("admin agent");
    let agent_jwt = issue_agent_jwt(&ctx.state, agent).await;

    let secret = "ghp_super_secret_test_value_12345";
    let (status, body) = send_device_and_agent_auth(
        &ctx.app,
        Method::POST,
        "/api/v1/credentials/agent-store",
        ctx.admin_signing_key(),
        ctx.admin_device_id(),
        &agent_jwt,
        Some(json!({
            "name": "secret-check-cred",
            "service": "github",
            "secret_value": secret,
            "agent_id": agent.id.0.to_string(),
            "agent_name": agent.name,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "agent-store: {}", body);

    let body_str = body.to_string();
    assert!(
        !body_str.contains(secret),
        "response should NOT contain the raw secret value"
    );
    assert!(
        body_str.find("encrypted_value").is_none(),
        "response should NOT contain encrypted_value field"
    );
}

// ===========================================================================
// Audit
// ===========================================================================

/// Test: Agent-store emits an audit event.
#[tokio::test]
async fn test_agent_store_emits_audit_event() {
    let ctx = TestAppBuilder::new().with_admin().build().await;

    let agent = ctx.admin_agent.as_ref().expect("admin agent");
    let agent_jwt = issue_agent_jwt(&ctx.state, agent).await;

    let (status, _body) = send_device_and_agent_auth(
        &ctx.app,
        Method::POST,
        "/api/v1/credentials/agent-store",
        ctx.admin_signing_key(),
        ctx.admin_device_id(),
        &agent_jwt,
        Some(json!({
            "name": "audit-test-cred",
            "service": "test",
            "secret_value": "secret",
            "agent_id": agent.id.0.to_string(),
            "agent_name": agent.name,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "agent-store should succeed");

    // Verify audit event was recorded
    let events = ctx
        .store
        .list_audit_events(10, 0)
        .await
        .expect("list audit events");
    let cred_event = events.iter().find(|e| {
        e.resource_type == "credential"
            && e.metadata.get("credential_name").and_then(|v| v.as_str()) == Some("audit-test-cred")
    });
    assert!(
        cred_event.is_some(),
        "should find audit event for agent-stored credential"
    );

    // Verify audit metadata includes source indicator
    let event = cred_event.unwrap();
    assert_eq!(
        event.workspace_name.as_deref(),
        Some(&agent.name[..]),
        "audit should include workspace name"
    );
}
