//! Cross-feature E2E integration tests for v1.5.4.
//!
//! These tests exercise multiple v1.5.4 features together in realistic
//! end-to-end scenarios: tags + policy + ownership.

use crate::common::*;

use axum::http::{Method, StatusCode};
use serde_json::json;

use agent_cordon_core::domain::user::UserRole;
use agent_cordon_server::test_helpers::TestAppBuilder;

// ===========================================================================
// E2E Test 2: Tag management affects policy evaluation
// ===========================================================================

#[tokio::test]
async fn test_e2e_tag_management_affects_policy_evaluation() {
    let ctx = TestAppBuilder::new().build().await;

    // (a) Admin creates agent A1 with no tags
    let _admin_user = create_test_user(
        &*ctx.store,
        "admin-e2e-tags",
        TEST_PASSWORD,
        UserRole::Admin,
    )
    .await;
    let (cookie, csrf) = login_user(&ctx.app, "admin-e2e-tags", TEST_PASSWORD).await;
    let full_cookie = combined_cookie(&cookie, &csrf);

    let (agent, api_key) =
        create_agent_in_db(&*ctx.store, "e2e-notag-agent", vec![], true, None).await;
    let (dev_id, dev_key) = create_device_and_bind_agent(&ctx.state, &agent).await;
    let jwt = get_jwt_via_device(&ctx.state, &dev_key, &dev_id, &api_key).await;

    // Set encryption key on workspace (required for vend_credential when permitted)
    {
        let (_enc_key, enc_jwk) = generate_p256_keypair_jwk();
        let enc_jwk_str = serde_json::to_string(&enc_jwk).unwrap();
        let mut ws = ctx.store.get_workspace(&agent.id).await.unwrap().unwrap();
        ws.encryption_public_key = Some(enc_jwk_str);
        ctx.store.update_workspace(&ws).await.unwrap();
    }

    // Create a credential owned by a different user
    let _other_user =
        create_test_user(&*ctx.store, "other-e2e", TEST_PASSWORD, UserRole::Admin).await;
    let (other_cookie, other_csrf) = login_user(&ctx.app, "other-e2e", TEST_PASSWORD).await;
    let other_full = combined_cookie(&other_cookie, &other_csrf);
    let (status, body) = send_json(
        &ctx.app,
        Method::POST,
        "/api/v1/credentials",
        None,
        Some(&other_full),
        Some(&other_csrf),
        Some(json!({
            "name": "e2e-tag-cred",
            "service": "svc",
            "secret_value": "secret"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let cred_id = body["data"]["id"].as_str().unwrap().to_string();

    // (b) A1 attempts to access credential — denied (no admin tag, no ownership, no grants)
    let (status, _body) = send_json_dual_auth(
        &ctx.app,
        Method::POST,
        &format!("/api/v1/credentials/{}/vend", cred_id),
        &dev_key,
        &dev_id,
        &jwt,
        None,
    )
    .await;
    // v1.15.0: vend_credential requires explicit grants or ownership match.
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "vend without grants or ownership should be denied"
    );

    // (c) Admin adds tag "admin" to A1
    let (status, body) = send_json(
        &ctx.app,
        Method::POST,
        &format!("/api/v1/workspaces/{}/tags", agent.id.0),
        None,
        Some(&full_cookie),
        Some(&csrf),
        Some(json!({ "tag": "admin" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "add admin tag: {}", body);

    // Need fresh JWT since agent tags changed
    let jwt2 = get_jwt_via_device(&ctx.state, &dev_key, &dev_id, &api_key).await;

    // (d) A1 attempts to access the same credential — succeeds (admin wildcard)
    let (status, body) = send_json_dual_auth(
        &ctx.app,
        Method::POST,
        &format!("/api/v1/credentials/{}/vend", cred_id),
        &dev_key,
        &dev_id,
        &jwt2,
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "admin-tagged agent should access any credential: {}",
        body
    );
}

// ===========================================================================
// E2E Test 4: Policy test endpoint validates ownership rule
// ===========================================================================

#[tokio::test]
async fn test_e2e_policy_test_endpoint_validates_ownership_rule() {
    let ctx = TestAppBuilder::new().build().await;
    let admin = create_test_user(
        &*ctx.store,
        "admin-e2e-policy",
        TEST_PASSWORD,
        UserRole::Admin,
    )
    .await;
    let (cookie, csrf) = login_user(&ctx.app, "admin-e2e-policy", TEST_PASSWORD).await;
    let full_cookie = combined_cookie(&cookie, &csrf);

    let user_id = admin.id.0.to_string();

    // (b) Ownership-match request → permit
    let (status, body) = send_json(
        &ctx.app,
        Method::POST,
        "/api/v1/policies/test",
        None,
        Some(&full_cookie),
        Some(&csrf),
        Some(json!({
            "principal": {
                "type": "Agent",
                "id": "owner-match-agent",
                "attributes": { "name": "a", "enabled": true, "tags": [], "owner": &user_id }
            },
            "action": "vend_credential",
            "resource": {
                "type": "Credential",
                "id": "owned-cred",
                "attributes": { "name": "c", "service": "s", "scopes": [], "owner": &user_id, "tags": [] }
            }
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["data"]["decision"], "permit",
        "ownership match should permit"
    );

    // (d) Ownership-mismatch request → deny
    let (status, body) = send_json(
        &ctx.app,
        Method::POST,
        "/api/v1/policies/test",
        None,
        Some(&full_cookie),
        Some(&csrf),
        Some(json!({
            "principal": {
                "type": "Agent",
                "id": "mismatch-agent",
                "attributes": { "name": "a", "enabled": true, "tags": [], "owner": "user-x" }
            },
            "action": "vend_credential",
            "resource": {
                "type": "Credential",
                "id": "other-cred",
                "attributes": { "name": "c", "service": "s", "scopes": [], "owner": "user-y", "tags": [] }
            }
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    // v1.15.0: vend_credential requires explicit grants or ownership match.
    // Ownership mismatch with no grants → deny.
    assert_eq!(
        body["data"]["decision"], "deny",
        "vend with ownership mismatch and no grants should deny"
    );
}
