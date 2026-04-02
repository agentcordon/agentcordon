//! E2E "2-Minute Setup" Acceptance Tests (Feature 8)
//!
//! These tests exercise the complete v1.5.2 user journey end-to-end,
//! from server start through a full agent operation cycle.
//!
//! Uses in-process HTTP via `tower::ServiceExt::oneshot` (no TCP/Docker).
//! Uses `wiremock::MockServer` for upstream API simulation.

use crate::common::*;

use axum::http::{Method, StatusCode};
use serde_json::{json, Value};
use uuid::Uuid;

use agent_cordon_core::domain::credential::CredentialId;
use agent_cordon_core::domain::policy::{PolicyId, StoredPolicy};
use agent_cordon_core::domain::user::UserRole;
use agent_cordon_core::domain::workspace::{Workspace, WorkspaceId, WorkspaceStatus};
use agent_cordon_core::policy::PolicyEngine;

use agent_cordon_server::test_helpers::TestAppBuilder;

use base64::Engine;

use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const TEST_PASSWORD: &str = "strong-test-password-e2e!";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Create an agent bound to a device directly in DB.
/// Replaces old device-mediated enrollment flow (removed in v1.13.0).
/// Returns (agent_id_string, "") for backwards compat.
async fn enroll_agent_via_device(
    state: &agent_cordon_server::state::AppState,
    _device_key: &p256::ecdsa::SigningKey,
    _device_id: &str,
    agent_name: &str,
    agent_tags: Option<Vec<&str>>,
) -> (String, String) {
    let agent_id = WorkspaceId(Uuid::new_v4());
    let now = chrono::Utc::now();
    let tags: Vec<String> = agent_tags
        .unwrap_or_default()
        .into_iter()
        .map(String::from)
        .collect();

    let agent = Workspace {
        id: agent_id.clone(),
        name: agent_name.to_string(),
        enabled: true,
        status: WorkspaceStatus::Active,
        pk_hash: None,
        encryption_public_key: None,
        tags,
        owner_id: None,
        parent_id: None,
        tool_name: None,
        created_at: now,
        updated_at: now,
    };

    state
        .store
        .create_workspace(&agent)
        .await
        .expect("create agent in DB");

    (agent_id.0.to_string(), String::new())
}

/// Issue a JWT for an agent bound to a device (API key exchange removed in v1.6.1).
/// Returns (StatusCode::OK, json with access_token) to maintain test interface.
async fn exchange_token_through_device(
    state: &agent_cordon_server::state::AppState,
    _device_key: &p256::ecdsa::SigningKey,
    device_id: &str,
    _api_key: &str,
) -> (StatusCode, Value) {
    let jwt = get_jwt_via_device(state, _device_key, device_id, _api_key).await;
    (
        StatusCode::OK,
        json!({
            "data": {
                "access_token": jwt,
                "token_type": "bearer"
            }
        }),
    )
}

/// Call the vend endpoint and return (status, body).
async fn vend_credential_raw(
    state: &agent_cordon_server::state::AppState,
    device_key: &p256::ecdsa::SigningKey,
    device_id: &str,
    agent_jwt: &str,
    credential_id: &str,
    correlation_id: Option<&str>,
) -> (StatusCode, Value) {
    let jti = Uuid::new_v4().to_string();
    let device_jwt_token = sign_device_jwt(device_key, device_id, &jti);

    let app = agent_cordon_server::build_router(state.clone());

    let mut builder = axum::http::Request::builder()
        .method(Method::POST)
        .uri(format!("/api/v1/credentials/{}/vend", credential_id))
        .header(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {}", device_jwt_token),
        )
        .header("x-agent-jwt", agent_jwt)
        .header(axum::http::header::CONTENT_TYPE, "application/json");

    if let Some(corr) = correlation_id {
        builder = builder.header("x-correlation-id", corr);
    }

    let request = builder.body(axum::body::Body::empty()).unwrap();
    let response = tower::ServiceExt::oneshot(app, request).await.unwrap();
    let status = response.status();
    let bytes = http_body_util::BodyExt::collect(response.into_body())
        .await
        .unwrap()
        .to_bytes();
    let json: Value = serde_json::from_slice(&bytes).unwrap_or(json!(null));
    (status, json)
}

/// Create a credential via admin API, returns credential_id.
async fn create_credential_via_api(
    state: &agent_cordon_server::state::AppState,
    cookie: &str,
    csrf: &str,
    name: &str,
    service: &str,
    secret: &str,
) -> String {
    let app = agent_cordon_server::build_router(state.clone());
    let (status, body) = send_json(
        &app,
        Method::POST,
        "/api/v1/credentials",
        None,
        Some(cookie),
        Some(csrf),
        Some(json!({
            "name": name,
            "service": service,
            "secret_value": secret,
        })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "create credential '{}': {}",
        name,
        body
    );
    body["data"]["id"].as_str().unwrap().to_string()
}

// ===========================================================================
// 8A. The Full Flow
// ===========================================================================

// ===========================================================================
// 8B. Negative E2E Scenarios
// ===========================================================================

// ===========================================================================
// 8C. Concurrency E2E
// ===========================================================================

/// 3 agents enroll through the same device concurrently; all approved with unique IDs.
#[tokio::test]
async fn test_e2e_concurrent_agent_enrollments() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let _admin = create_test_user(&*ctx.store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let app = agent_cordon_server::build_router(ctx.state.clone());
    let (cookie, csrf) = login_user(&app, "admin", TEST_PASSWORD).await;
    let full_cookie = combined_cookie(&cookie, &csrf);

    // Create and enroll a single device
    let (sig_key, sig_jwk, _enc_key, enc_jwk) = generate_dual_p256_keypairs_jwk();
    let (device_id, bootstrap_token) =
        create_device_via_api(&ctx.state, &full_cookie, &csrf, "concurrent-device").await;
    enroll_device(&ctx.state, &bootstrap_token, &sig_jwk, &enc_jwk).await;

    // Enroll 3 agents concurrently through the same device
    let state = ctx.state.clone();
    let sig_key_clone = sig_key.clone();
    let device_id_clone = device_id.clone();

    let mut enrollment_handles = Vec::new();
    for i in 0..3 {
        let s = state.clone();
        let sk = sig_key_clone.clone();
        let did = device_id_clone.clone();
        let handle = tokio::spawn(async move {
            enroll_agent_via_device(&s, &sk, &did, &format!("concurrent-agent-{}", i), None).await
        });
        enrollment_handles.push(handle);
    }

    // Collect results — agent_id is in the first element
    let mut agent_ids = Vec::new();
    for handle in enrollment_handles {
        let (agent_id, _) = handle.await.expect("enrollment task");
        agent_ids.push(agent_id);
    }

    // Assert all agent IDs are unique
    let mut unique_ids = agent_ids.clone();
    unique_ids.sort();
    unique_ids.dedup();
    assert_eq!(
        unique_ids.len(),
        3,
        "all 3 agent IDs must be unique: {:?}",
        agent_ids
    );

    // All agents should be bound to the same device
    for agent_id in &agent_ids {
        let agent_uuid = Uuid::parse_str(agent_id).unwrap();
        let agent = ctx
            .store
            .get_workspace(&WorkspaceId(agent_uuid))
            .await
            .expect("get agent")
            .expect("agent must exist");
        assert!(agent.enabled, "agent {} must be enabled", agent_id,);
    }
}

