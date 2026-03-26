//! v1.15.0 — Feature 10: Agent Justification for Credential Use
//!
//! Tests that credential vending works without justification (optional field).

use axum::http::{Method, StatusCode};
use serde_json::json;

use agent_cordon_core::domain::user::UserRole;
use agent_cordon_server::test_helpers::TestAppBuilder;

use crate::common::*;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Set up a complete test scenario: admin, credential, agent with permission.
/// Returns (full_cookie, csrf, cred_id, agent_id, device_ctx).
async fn setup_justification_scenario(
    ctx: &agent_cordon_server::test_helpers::TestContext,
) -> (String, String, String, String, QuickDeviceAgent) {
    let _admin = create_test_user(&*ctx.store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let (cookie, csrf) = login_user(&ctx.app, "admin", TEST_PASSWORD).await;
    let full_cookie = combined_cookie(&cookie, &csrf);

    // Create credential
    let (status, cred_body) = send_json(
        &ctx.app,
        Method::POST,
        "/api/v1/credentials",
        None,
        Some(&full_cookie),
        Some(&csrf),
        Some(json!({
            "name": "justification-test-cred",
            "service": "test-service",
            "secret_value": "test-secret-for-justification",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "create credential: {}", cred_body);
    let cred_id_str = cred_body["data"]["id"]
        .as_str()
        .expect("cred id")
        .to_string();

    // Register agent
    let ws = register_workspace_full_context(&ctx.app, &full_cookie, &csrf).await;
    let agent_id =
        agent_cordon_core::domain::agent::AgentId(ws.agent_id.parse().expect("parse agent_id"));
    let cred_id = agent_cordon_core::domain::credential::CredentialId(
        cred_id_str.parse().expect("parse cred_id"),
    );

    // Grant permission
    grant_cedar_permission(&ctx.state, &cred_id, &agent_id, "delegated_use").await;

    // Set encryption key on workspace (required for vend_credential)
    let (_enc_key, enc_jwk) = generate_p256_keypair_jwk();
    let enc_jwk_str = serde_json::to_string(&enc_jwk).unwrap();
    {
        let mut workspace = ctx.store.get_workspace(&agent_id).await.unwrap().unwrap();
        workspace.encryption_public_key = Some(enc_jwk_str);
        ctx.store.update_workspace(&workspace).await.unwrap();
    }

    // Setup device
    let agent = ctx.store.get_workspace(&agent_id).await.unwrap().unwrap();
    let device_ctx = quick_device_setup(&ctx.state, &agent, "").await;

    (full_cookie, csrf, cred_id_str, ws.agent_id, device_ctx)
}

/// Test: Proxy request without justification still succeeds (optional field).
#[tokio::test]
async fn test_proxy_without_justification_succeeds() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let (_full_cookie, _csrf, cred_id, _agent_id, device_ctx) =
        setup_justification_scenario(&ctx).await;

    // Vend without justification
    let (status, body) = send_json_dual_auth(
        &ctx.app,
        Method::POST,
        &format!("/api/v1/credentials/{}/vend", cred_id),
        &device_ctx.device_signing_key,
        &device_ctx.device_id,
        &device_ctx.agent_jwt,
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "vend without justification: {}",
        body
    );
}
