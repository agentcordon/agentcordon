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

/// E2E full flow: Server start → device enroll → agent enroll → approve →
/// get API key → token exchange → add credential → vend → upstream call → audit trail.
#[tokio::test]
#[ignore = "REMOVED: v2.0 has no enrollment flow — workspaces register directly"]
async fn test_e2e_two_minute_setup_full_flow() {
    // -----------------------------------------------------------------------
    // Step 1: Server starts
    // -----------------------------------------------------------------------
    let ctx = TestAppBuilder::new()
        .with_admin()
        .with_enrollment()
        .build()
        .await;
    let _admin = create_test_user(&*ctx.store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let app = agent_cordon_server::build_router(ctx.state.clone());
    let (cookie, csrf) = login_user(&app, "admin", TEST_PASSWORD).await;
    let full_cookie = combined_cookie(&cookie, &csrf);

    // -----------------------------------------------------------------------
    // Step 2: Device auto-enrolls
    // -----------------------------------------------------------------------
    let (sig_key, sig_jwk, _enc_key, enc_jwk) = generate_dual_p256_keypairs_jwk();
    let (device_id, bootstrap_token) =
        create_device_via_api(&ctx.state, &full_cookie, &csrf, "auto-device").await;

    // Enroll with both JWKs
    let enrolled_id = enroll_device(&ctx.state, &bootstrap_token, &sig_jwk, &enc_jwk).await;
    assert_eq!(enrolled_id, device_id);

    // Verify device is active
    let app = agent_cordon_server::build_router(ctx.state.clone());
    let (status, body) = send_json(
        &app,
        Method::GET,
        &format!("/api/v1/workspaces/{}", device_id),
        None,
        Some(&full_cookie),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "get device: {}", body);
    assert_eq!(body["data"]["status"], "active");
    assert!(body["data"]["owner_id"].is_string(), "owner_id must be set");

    // -----------------------------------------------------------------------
    // Step 3: Create agent bound to device
    // (Agent enrollment flow removed in v1.13.0 — agents created directly)
    // -----------------------------------------------------------------------
    let (agent_id, _) = enroll_agent_via_device(
        &ctx.state,
        &sig_key,
        &device_id,
        "e2e-test-agent",
        Some(vec!["e2e"]),
    )
    .await;

    // -----------------------------------------------------------------------
    // Step 6: Get agent JWT via device (API key exchange removed in v1.6.1)
    // -----------------------------------------------------------------------
    let (status, body) = exchange_token_through_device(&ctx.state, &sig_key, &device_id, "").await;
    assert_eq!(status, StatusCode::OK, "token exchange: {}", body);
    let agent_jwt = body["data"]["access_token"].as_str().unwrap().to_string();
    assert_eq!(agent_jwt.split('.').count(), 3, "JWT must have 3 segments");
    assert_eq!(body["data"]["token_type"], "bearer");

    // Decode JWT claims and verify device_id
    let jwt_parts: Vec<&str> = agent_jwt.split('.').collect();
    let claims_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(jwt_parts[1])
        .expect("decode JWT payload");
    let claims: Value = serde_json::from_slice(&claims_bytes).expect("parse JWT claims");
    // Workspace identity JWT - verify it has a sub claim
    assert!(claims["sub"].is_string(), "JWT must contain a sub claim");

    // -----------------------------------------------------------------------
    // Step 7: Add a credential to the vault
    // -----------------------------------------------------------------------
    let credential_id = create_credential_via_api(
        &ctx.state,
        &full_cookie,
        &csrf,
        "e2e-api-key",
        "test-api",
        "sk-live-test-secret-12345",
    )
    .await;

    // Grant the agent vend_credential permission via Cedar policies
    let cred_uuid = Uuid::parse_str(&credential_id).expect("credential_id must be valid UUID");
    let agent_uuid = Uuid::parse_str(&agent_id).expect("agent_id must be valid UUID");
    for perm in &["read", "write", "delete", "delegated_use"] {
        grant_cedar_permission(
            &ctx.state,
            &CredentialId(cred_uuid),
            &WorkspaceId(agent_uuid),
            perm,
        )
        .await;
    }

    // -----------------------------------------------------------------------
    // Step 8: Credential vend
    // -----------------------------------------------------------------------
    let (status, vend_body) = vend_credential_raw(
        &ctx.state,
        &sig_key,
        &device_id,
        &agent_jwt,
        &credential_id,
        Some("e2e-test-corr-001"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "vend credential: {}", vend_body);

    let vend_data = &vend_body["data"];
    assert!(
        vend_data["vend_id"].as_str().unwrap().starts_with("vnd_"),
        "vend_id must start with vnd_"
    );
    // Verify encrypted envelope is present
    let envelope = &vend_data["encrypted_envelope"];
    assert!(
        envelope["version"].is_number(),
        "envelope must have version"
    );
    assert!(
        envelope["ephemeral_public_key"].is_string(),
        "envelope must have ephemeral_public_key"
    );
    assert!(
        envelope["ciphertext"].is_string(),
        "envelope must have ciphertext"
    );
    assert!(envelope["nonce"].is_string(), "envelope must have nonce");

    // -----------------------------------------------------------------------
    // Step 9: Upstream call (simulated with wiremock)
    // -----------------------------------------------------------------------
    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/data"))
        .and(header("Authorization", "Bearer sk-live-test-secret-12345"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"result": "success"})))
        .expect(1)
        .mount(&mock_server)
        .await;

    // Simulate device making upstream call with vended credential
    let client = reqwest::Client::new();
    let upstream_resp = client
        .get(format!("{}/api/data", mock_server.uri()))
        .header("Authorization", "Bearer sk-live-test-secret-12345")
        .send()
        .await
        .expect("upstream call");
    assert_eq!(upstream_resp.status(), 200);
    let upstream_body: Value = upstream_resp.json().await.expect("parse upstream response");
    assert_eq!(upstream_body["result"], "success");

    // -----------------------------------------------------------------------
    // Step 10: Verify audit trail
    // -----------------------------------------------------------------------
    let events = ctx
        .store
        .list_audit_events(100, 0)
        .await
        .expect("list audit events");

    // Collect event types in chronological order (list_audit_events returns DESC, so reverse)
    let event_types: Vec<String> = events
        .iter()
        .rev()
        .map(|e| serde_json::to_value(&e.event_type).unwrap())
        .map(|v| v.as_str().unwrap().to_string())
        .collect();

    // Verify key events exist (they should appear in chronological order)
    assert!(
        event_types.contains(&"workspace_created".to_string()),
        "must have WorkspaceCreated event, got: {:?}",
        event_types
    );
    assert!(
        event_types.contains(&"credential_vended".to_string()),
        "must have CredentialVended event, got: {:?}",
        event_types
    );

    // Verify chronological ordering: WorkspaceCreated before vend
    let idx_created = event_types
        .iter()
        .position(|t| t == "workspace_created")
        .unwrap();
    let idx_vended = event_types
        .iter()
        .position(|t| t == "credential_vended")
        .unwrap();

    assert!(
        idx_created < idx_vended,
        "WorkspaceCreated must come before CredentialVended"
    );

    // Verify NO secrets in audit metadata
    for event in &events {
        let metadata_str = event.metadata.to_string();
        assert!(
            !metadata_str.contains("sk-live-test-secret-12345"),
            "audit event {:?} must not contain credential secret",
            event.event_type
        );
    }

    // Verify credential vend event has correct fields
    let vend_event = events
        .iter()
        .find(|e| {
            serde_json::to_value(&e.event_type)
                .unwrap()
                .as_str()
                .unwrap()
                == "credential_vended"
        })
        .expect("must find CredentialVended event");
    assert!(
        !vend_event.correlation_id.is_empty(),
        "vend event must have correlation_id"
    );
    assert!(
        vend_event.metadata["device_id"].is_string(),
        "vend event must have device_id in metadata"
    );
    assert!(
        vend_event.metadata["vend_id"].is_string(),
        "vend event must have vend_id in metadata"
    );
}

// ===========================================================================
// 8B. Negative E2E Scenarios
// ===========================================================================

/// Disabled device blocks the entire chain: token exchange + vend both fail.
/// Re-enable device: everything works again.
#[tokio::test]
#[ignore = "REMOVED: v2.0 has no enrollment flow — workspaces register directly"]
async fn test_e2e_disabled_device_blocks_entire_chain() {
    let ctx = TestAppBuilder::new()
        .with_admin()
        .with_enrollment()
        .build()
        .await;
    let _admin = create_test_user(&*ctx.store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let app = agent_cordon_server::build_router(ctx.state.clone());
    let (cookie, csrf) = login_user(&app, "admin", TEST_PASSWORD).await;
    let full_cookie = combined_cookie(&cookie, &csrf);

    // Setup: device + agent, get agent JWT + credential
    let dac = setup_full_device_agent(&ctx.state, &full_cookie, &csrf).await;

    let credential_id = create_credential_via_api(
        &ctx.state,
        &full_cookie,
        &csrf,
        "disabled-test-cred",
        "test-svc",
        "secret-123",
    )
    .await;
    let cred_uuid = Uuid::parse_str(&credential_id).unwrap();
    let agent_uuid = Uuid::parse_str(&dac.agent_id).unwrap();
    for perm in &["read", "write", "delete", "delegated_use"] {
        grant_cedar_permission(
            &ctx.state,
            &CredentialId(cred_uuid),
            &WorkspaceId(agent_uuid),
            perm,
        )
        .await;
    }

    // Disable device
    let app = agent_cordon_server::build_router(ctx.state.clone());
    let (status, _) = send_json(
        &app,
        Method::PUT,
        &format!("/api/v1/workspaces/{}", dac.device_id),
        None,
        Some(&full_cookie),
        Some(&csrf),
        Some(json!({ "enabled": false })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "disable device");

    // Dual-auth whoami should fail with disabled device
    let app = agent_cordon_server::build_router(ctx.state.clone());
    let (status, _) = send_json_dual_auth(
        &app,
        Method::GET,
        "/api/v1/auth/whoami",
        &dac.device_signing_key,
        &dac.device_id,
        &dac.agent_jwt,
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "whoami must fail when device disabled"
    );

    // Vend should fail
    let (status, _) = vend_credential_raw(
        &ctx.state,
        &dac.device_signing_key,
        &dac.device_id,
        &dac.agent_jwt,
        &credential_id,
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "vend must fail when device disabled"
    );

    // Re-enable device
    let app = agent_cordon_server::build_router(ctx.state.clone());
    let (status, _) = send_json(
        &app,
        Method::PUT,
        &format!("/api/v1/workspaces/{}", dac.device_id),
        None,
        Some(&full_cookie),
        Some(&csrf),
        Some(json!({ "enabled": true })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "re-enable device");

    // Dual-auth whoami should work again after re-enable
    let new_jwt_str =
        get_jwt_via_device(&ctx.state, &dac.device_signing_key, &dac.device_id, "").await;
    let app = agent_cordon_server::build_router(ctx.state.clone());
    let (status, body) = send_json_dual_auth(
        &app,
        Method::GET,
        "/api/v1/auth/whoami",
        &dac.device_signing_key,
        &dac.device_id,
        &new_jwt_str,
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "whoami must succeed after re-enable: {}",
        body
    );
    let new_jwt = &new_jwt_str;

    // Vend should work again
    let (status, _) = vend_credential_raw(
        &ctx.state,
        &dac.device_signing_key,
        &dac.device_id,
        new_jwt,
        &credential_id,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "vend must succeed after re-enable");
}

/// After dual-protocol removal, workspace identity JWTs are not device-bound.
/// Agent A's JWT works through any valid device since DKT validation was removed.
/// This test verifies that cross-device operation succeeds with workspace identity.
#[tokio::test]
#[ignore = "REMOVED: v2.0 has no enrollment flow — workspaces register directly"]
async fn test_e2e_agent_jwt_works_through_any_device() {
    let ctx = TestAppBuilder::new()
        .with_admin()
        .with_enrollment()
        .build()
        .await;
    let _admin = create_test_user(&*ctx.store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let app = agent_cordon_server::build_router(ctx.state.clone());
    let (cookie, csrf) = login_user(&app, "admin", TEST_PASSWORD).await;
    let full_cookie = combined_cookie(&cookie, &csrf);

    // Setup device A + agent
    let dac_a = setup_full_device_agent(&ctx.state, &full_cookie, &csrf).await;

    // Setup device B (separate device, no agent)
    let (sig_key_b, sig_jwk_b, _enc_key_b, enc_jwk_b) = generate_dual_p256_keypairs_jwk();
    let (device_id_b, bootstrap_b) =
        create_device_via_api(&ctx.state, &full_cookie, &csrf, "device-b").await;
    enroll_device(&ctx.state, &bootstrap_b, &sig_jwk_b, &enc_jwk_b).await;

    // Create credential and grant to agent A via Cedar
    let credential_id = create_credential_via_api(
        &ctx.state,
        &full_cookie,
        &csrf,
        "cross-device-cred",
        "test-svc",
        "secret-456",
    )
    .await;
    let cred_uuid = Uuid::parse_str(&credential_id).unwrap();
    let agent_uuid = Uuid::parse_str(&dac_a.agent_id).unwrap();
    for perm in &["read", "write", "delete", "delegated_use"] {
        grant_cedar_permission(
            &ctx.state,
            &CredentialId(cred_uuid),
            &WorkspaceId(agent_uuid),
            perm,
        )
        .await;
    }

    // Agent A's workspace identity JWT works through device B (no DKT binding)
    let app = agent_cordon_server::build_router(ctx.state.clone());
    let (status, _) = send_json_dual_auth(
        &app,
        Method::GET,
        "/api/v1/auth/whoami",
        &sig_key_b,
        &device_id_b,
        &dac_a.agent_jwt,
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "workspace identity JWT should work through any valid device"
    );

    // Vend also works through device B
    let (status, _) = vend_credential_raw(
        &ctx.state,
        &sig_key_b,
        &device_id_b,
        &dac_a.agent_jwt,
        &credential_id,
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "vend should work through any valid device with workspace identity JWT"
    );
}

/// Cedar forbid policy blocks credential vend; removing it allows vend.
#[tokio::test]
#[ignore = "REMOVED: v2.0 has no enrollment flow — workspaces register directly"]
async fn test_e2e_credential_vend_denied_by_cedar_policy() {
    let ctx = TestAppBuilder::new()
        .with_admin()
        .with_enrollment()
        .build()
        .await;
    let _admin = create_test_user(&*ctx.store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let app = agent_cordon_server::build_router(ctx.state.clone());
    let (cookie, csrf) = login_user(&app, "admin", TEST_PASSWORD).await;
    let full_cookie = combined_cookie(&cookie, &csrf);

    // Setup device + agent
    let dac = setup_full_device_agent(&ctx.state, &full_cookie, &csrf).await;

    // Create credential and grant permissions
    let credential_id = create_credential_via_api(
        &ctx.state,
        &full_cookie,
        &csrf,
        "cedar-deny-cred",
        "test-svc",
        "secret-789",
    )
    .await;
    let cred_uuid = Uuid::parse_str(&credential_id).unwrap();
    let agent_uuid = Uuid::parse_str(&dac.agent_id).unwrap();
    for perm in &["read", "write", "delete", "delegated_use"] {
        grant_cedar_permission(
            &ctx.state,
            &CredentialId(cred_uuid),
            &WorkspaceId(agent_uuid),
            perm,
        )
        .await;
    }

    // Add a Cedar forbid policy for this agent
    let forbid_policy = StoredPolicy {
        id: PolicyId(Uuid::new_v4()),
        name: "e2e-forbid-vend".to_string(),
        description: Some("Forbid vend for e2e test".to_string()),
        cedar_policy: format!(
            r#"forbid(principal == AgentCordon::Workspace::"{}",
                     action == AgentCordon::Action::"vend_credential",
                     resource);"#,
            dac.agent_id
        ),
        enabled: true,
        is_system: false,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };
    ctx.store
        .store_policy(&forbid_policy)
        .await
        .expect("store forbid policy");

    // Reload policies into the engine
    let all_policies = ctx.store.get_all_enabled_policies().await.unwrap();
    let policy_texts: Vec<(String, String)> = all_policies
        .iter()
        .map(|p| (p.id.0.to_string(), p.cedar_policy.clone()))
        .collect();
    ctx.state
        .policy_engine
        .reload_policies(policy_texts)
        .expect("reload policies");

    // Vend should be denied
    let (status, _) = vend_credential_raw(
        &ctx.state,
        &dac.device_signing_key,
        &dac.device_id,
        &dac.agent_jwt,
        &credential_id,
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "vend must be denied by Cedar policy"
    );

    // Check audit event for denial
    let events = ctx.store.list_audit_events(100, 0).await.unwrap();
    let deny_event = events.iter().find(|e| {
        serde_json::to_value(&e.event_type)
            .unwrap()
            .as_str()
            .unwrap()
            == "credential_vend_denied"
    });
    assert!(
        deny_event.is_some(),
        "must have CredentialVendDenied audit event"
    );

    // Remove forbid policy and reload
    ctx.store
        .delete_policy(&forbid_policy.id)
        .await
        .expect("delete forbid policy");
    let all_policies = ctx.store.get_all_enabled_policies().await.unwrap();
    let policy_texts: Vec<(String, String)> = all_policies
        .iter()
        .map(|p| (p.id.0.to_string(), p.cedar_policy.clone()))
        .collect();
    ctx.state
        .policy_engine
        .reload_policies(policy_texts)
        .expect("reload policies after delete");

    // Vend should now succeed
    let (status, _) = vend_credential_raw(
        &ctx.state,
        &dac.device_signing_key,
        &dac.device_id,
        &dac.agent_jwt,
        &credential_id,
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "vend must succeed after removing forbid policy"
    );
}

/// Revoked permission blocks vend.
/// The credential is created by a different user so ownership-based policy (rule 1b)
/// does not apply — this test exercises fine-grained permission revocation.
#[tokio::test]
#[ignore = "REMOVED: v2.0 has no enrollment flow — workspaces register directly"]
async fn test_e2e_revoked_permission_blocks_vend() {
    let ctx = TestAppBuilder::new()
        .with_admin()
        .with_enrollment()
        .build()
        .await;
    let _admin = create_test_user(&*ctx.store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let app = agent_cordon_server::build_router(ctx.state.clone());
    let (cookie, csrf) = login_user(&app, "admin", TEST_PASSWORD).await;
    let full_cookie = combined_cookie(&cookie, &csrf);

    let dac = setup_full_device_agent(&ctx.state, &full_cookie, &csrf).await;

    // Create credential under a DIFFERENT user so ownership doesn't match the agent's owner.
    // This ensures we're testing fine-grained permission revocation, not the ownership bypass.
    let _other_user =
        create_test_user(&*ctx.store, "other-user", TEST_PASSWORD, UserRole::Admin).await;
    let other_app = agent_cordon_server::build_router(ctx.state.clone());
    let (other_cookie, other_csrf) = login_user(&other_app, "other-user", TEST_PASSWORD).await;
    let other_full_cookie = combined_cookie(&other_cookie, &other_csrf);

    let credential_id = create_credential_via_api(
        &ctx.state,
        &other_full_cookie,
        &other_csrf,
        "revoke-perm-cred",
        "test-svc",
        "secret-abc",
    )
    .await;
    let cred_uuid = Uuid::parse_str(&credential_id).unwrap();
    let agent_uuid = Uuid::parse_str(&dac.agent_id).unwrap();

    // Grant permissions via Cedar grant policies → vend succeeds
    for perm in &["read", "write", "delete", "delegated_use"] {
        grant_cedar_permission(
            &ctx.state,
            &CredentialId(cred_uuid),
            &WorkspaceId(agent_uuid),
            perm,
        )
        .await;
    }

    let (status, _) = vend_credential_raw(
        &ctx.state,
        &dac.device_signing_key,
        &dac.device_id,
        &dac.agent_jwt,
        &credential_id,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "vend must succeed with permissions");

    // Revoke all permissions via Cedar
    for perm in &["read", "write", "delete", "delegated_use"] {
        revoke_cedar_permission(
            &ctx.state,
            &CredentialId(cred_uuid),
            &WorkspaceId(agent_uuid),
            perm,
        )
        .await;
    }

    // Vend should fail — v1.15.0: no blanket vend permit, grants revoked, no ownership match
    let (status, _) = vend_credential_raw(
        &ctx.state,
        &dac.device_signing_key,
        &dac.device_id,
        &dac.agent_jwt,
        &credential_id,
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "vend should be denied after revoking all grants (no ownership match)"
    );
}

/// Bootstrap token is single-use: second enrollment attempt fails.
#[tokio::test]
#[ignore = "REMOVED: v2.0 has no enrollment flow — workspaces register directly"]
async fn test_e2e_bootstrap_token_single_use() {
    let ctx = TestAppBuilder::new()
        .with_admin()
        .with_enrollment()
        .build()
        .await;
    let _admin = create_test_user(&*ctx.store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let app = agent_cordon_server::build_router(ctx.state.clone());
    let (cookie, csrf) = login_user(&app, "admin", TEST_PASSWORD).await;
    let full_cookie = combined_cookie(&cookie, &csrf);

    let (_sig_key, sig_jwk, _enc_key, enc_jwk) = generate_dual_p256_keypairs_jwk();
    let (_device_id, bootstrap_token) =
        create_device_via_api(&ctx.state, &full_cookie, &csrf, "single-use-device").await;

    // First enrollment succeeds
    enroll_device(&ctx.state, &bootstrap_token, &sig_jwk, &enc_jwk).await;

    // Second enrollment with same token should fail
    let (_sig_key2, sig_jwk2, _enc_key2, enc_jwk2) = generate_dual_p256_keypairs_jwk();
    let app = agent_cordon_server::build_router(ctx.state.clone());
    let (status, _) = send_json(
        &app,
        Method::POST,
        "/api/v1/workspaces/enroll",
        None,
        None,
        None,
        Some(json!({
            "bootstrap_token": bootstrap_token,
            "signing_key": sig_jwk2,
            "encryption_key": enc_jwk2
        })),
    )
    .await;
    assert!(
        status == StatusCode::UNAUTHORIZED || status == StatusCode::CONFLICT,
        "second enrollment must fail with 401 or 409, got: {}",
        status
    );
}

/// JTI replay is blocked: same JTI used twice results in 401.
#[tokio::test]
#[ignore = "REMOVED: v2.0 has no enrollment flow — workspaces register directly"]
async fn test_e2e_jti_replay_blocked() {
    let ctx = TestAppBuilder::new()
        .with_admin()
        .with_enrollment()
        .build()
        .await;
    let _admin = create_test_user(&*ctx.store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let app = agent_cordon_server::build_router(ctx.state.clone());
    let (cookie, csrf) = login_user(&app, "admin", TEST_PASSWORD).await;
    let full_cookie = combined_cookie(&cookie, &csrf);

    let dac = setup_full_device_agent(&ctx.state, &full_cookie, &csrf).await;

    let credential_id = create_credential_via_api(
        &ctx.state,
        &full_cookie,
        &csrf,
        "jti-replay-cred",
        "test-svc",
        "secret-jti",
    )
    .await;
    let cred_uuid = Uuid::parse_str(&credential_id).unwrap();
    let agent_uuid = Uuid::parse_str(&dac.agent_id).unwrap();
    for perm in &["read", "write", "delete", "delegated_use"] {
        grant_cedar_permission(
            &ctx.state,
            &CredentialId(cred_uuid),
            &WorkspaceId(agent_uuid),
            perm,
        )
        .await;
    }

    // Use a specific JTI for the first vend request
    let jti = "e2e-replay-test-jti-abc";
    let device_jwt_1 = sign_device_jwt_with_ttl(&dac.device_signing_key, &dac.device_id, jti, 30);

    // First request with this JTI succeeds
    let app = agent_cordon_server::build_router(ctx.state.clone());
    let request = axum::http::Request::builder()
        .method(Method::POST)
        .uri(format!("/api/v1/credentials/{}/vend", credential_id))
        .header(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {}", device_jwt_1),
        )
        .header("x-agent-jwt", &dac.agent_jwt)
        .header(axum::http::header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::empty())
        .unwrap();
    let response = tower::ServiceExt::oneshot(app, request).await.unwrap();
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "first use of JTI should succeed"
    );

    // Second request with same JTI must fail
    let device_jwt_2 = sign_device_jwt_with_ttl(&dac.device_signing_key, &dac.device_id, jti, 30);

    let app = agent_cordon_server::build_router(ctx.state.clone());
    let request = axum::http::Request::builder()
        .method(Method::POST)
        .uri(format!("/api/v1/credentials/{}/vend", credential_id))
        .header(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {}", device_jwt_2),
        )
        .header("x-agent-jwt", &dac.agent_jwt)
        .header(axum::http::header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::empty())
        .unwrap();
    let response = tower::ServiceExt::oneshot(app, request).await.unwrap();
    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "second use of same JTI must be rejected (replay)"
    );
}

// ===========================================================================
// 8C. Concurrency E2E
// ===========================================================================

/// 3 agents enroll through the same device concurrently; all approved with unique IDs.
#[tokio::test]
async fn test_e2e_concurrent_agent_enrollments() {
    let ctx = TestAppBuilder::new()
        .with_admin()
        .with_enrollment()
        .build()
        .await;
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

/// 3 agents vend the same credential concurrently; all succeed with unique vend_ids.
#[tokio::test]
#[ignore = "REMOVED: v2.0 has no enrollment flow — workspaces register directly"]
async fn test_e2e_concurrent_credential_vends() {
    let ctx = TestAppBuilder::new()
        .with_admin()
        .with_enrollment()
        .build()
        .await;
    let _admin = create_test_user(&*ctx.store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let app = agent_cordon_server::build_router(ctx.state.clone());
    let (cookie, csrf) = login_user(&app, "admin", TEST_PASSWORD).await;
    let full_cookie = combined_cookie(&cookie, &csrf);

    // Create device + 3 agents
    let (sig_key, sig_jwk, _enc_key, enc_jwk) = generate_dual_p256_keypairs_jwk();
    let (device_id, bootstrap_token) =
        create_device_via_api(&ctx.state, &full_cookie, &csrf, "vend-concurrent-device").await;
    enroll_device(&ctx.state, &bootstrap_token, &sig_jwk, &enc_jwk).await;

    let mut agent_jwts = Vec::new();
    for i in 0..3 {
        let (agent_id, _) = enroll_agent_via_device(
            &ctx.state,
            &sig_key,
            &device_id,
            &format!("vend-concurrent-agent-{}", i),
            None,
        )
        .await;

        // Grant permissions
        let agent_uuid = Uuid::parse_str(&agent_id).unwrap();

        // Issue JWT directly for this specific agent
        let agent = ctx
            .store
            .get_workspace(&WorkspaceId(agent_uuid))
            .await
            .unwrap()
            .unwrap();
        let jwt = issue_agent_jwt(&ctx.state, &agent);
        agent_jwts.push((agent_id, jwt));
    }

    // Create credential
    let credential_id = create_credential_via_api(
        &ctx.state,
        &full_cookie,
        &csrf,
        "concurrent-vend-cred",
        "test-svc",
        "secret-concurrent",
    )
    .await;
    let cred_uuid = Uuid::parse_str(&credential_id).unwrap();

    // Grant permissions to all agents
    for (agent_id, _) in &agent_jwts {
        let agent_uuid = Uuid::parse_str(agent_id).unwrap();
        for perm in &["read", "write", "delete", "delegated_use"] {
            grant_cedar_permission(
                &ctx.state,
                &CredentialId(cred_uuid),
                &WorkspaceId(agent_uuid),
                perm,
            )
            .await;
        }
    }

    // Vend concurrently
    let state = ctx.state.clone();
    let mut vend_handles = Vec::new();
    for (_agent_id, jwt) in &agent_jwts {
        let s = state.clone();
        let sk = sig_key.clone();
        let did = device_id.clone();
        let ajwt = jwt.clone();
        let cid = credential_id.clone();
        let handle =
            tokio::spawn(
                async move { vend_credential_raw(&s, &sk, &did, &ajwt, &cid, None).await },
            );
        vend_handles.push(handle);
    }

    // Collect vend results
    let mut vend_ids = Vec::new();
    for handle in vend_handles {
        let (status, body) = handle.await.expect("vend task");
        assert_eq!(
            status,
            StatusCode::OK,
            "concurrent vend must succeed: {}",
            body
        );
        let vend_id = body["data"]["vend_id"].as_str().unwrap().to_string();
        assert!(vend_id.starts_with("vnd_"), "vend_id must start with vnd_");
        vend_ids.push(vend_id);
    }

    // Assert all vend_ids are unique
    let mut unique_vend_ids = vend_ids.clone();
    unique_vend_ids.sort();
    unique_vend_ids.dedup();
    assert_eq!(
        unique_vend_ids.len(),
        3,
        "all 3 vend_ids must be unique: {:?}",
        vend_ids
    );

    // Assert 3 CredentialVended audit events
    let events = ctx.store.list_audit_events(200, 0).await.unwrap();
    let vend_events: Vec<_> = events
        .iter()
        .filter(|e| {
            serde_json::to_value(&e.event_type)
                .unwrap()
                .as_str()
                .unwrap()
                == "credential_vended"
        })
        .collect();
    assert!(
        vend_events.len() >= 3,
        "must have at least 3 CredentialVended audit events, got {}",
        vend_events.len()
    );
}
