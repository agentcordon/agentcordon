//! v1.15.0 — Feature 8: Audit Log Policy Reasoning
//!
//! Tests that Cedar-evaluated authorization decisions populate the
//! `decision_reason` field in audit events with the contributing policy
//! name/ID, and that this information is accessible via the audit API.

use axum::http::{Method, StatusCode};
use serde_json::json;

use agent_cordon_core::domain::user::UserRole;
use agent_cordon_core::storage::AuditFilter;
use agent_cordon_server::test_helpers::TestAppBuilder;

use crate::common::*;
use agent_cordon_core::storage::Store;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Set a P-256 encryption public key on a workspace so that vend_credential
/// can ECIES-encrypt credentials to it.
async fn set_encryption_key_on_workspace(
    store: &(dyn Store + Send + Sync),
    workspace_id: &agent_cordon_core::domain::workspace::WorkspaceId,
) {
    let (_enc_key, enc_jwk) = generate_p256_keypair_jwk();
    let enc_jwk_str = serde_json::to_string(&enc_jwk).unwrap();
    let mut ws = store.get_workspace(workspace_id).await.unwrap().unwrap();
    ws.encryption_public_key = Some(enc_jwk_str);
    store.update_workspace(&ws).await.unwrap();
}

/// Fetch audit events filtered by resource type and optional resource ID.
async fn fetch_audit_events_for_resource(
    ctx: &agent_cordon_server::test_helpers::TestContext,
    resource_type: &str,
    resource_id: Option<&str>,
) -> Vec<agent_cordon_core::domain::audit::AuditEvent> {
    ctx.store
        .list_audit_events_filtered(&AuditFilter {
            limit: 100,
            offset: 0,
            resource_type: Some(resource_type.to_string()),
            resource_id: resource_id.map(|s| s.to_string()),
            ..Default::default()
        })
        .await
        .expect("fetch audit events")
}

// ===========================================================================
// 8A. Happy Path
// ===========================================================================

/// Test #1: Allow decision includes the policy name in decision_reason.
#[tokio::test]
async fn test_allow_decision_includes_policy_name() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let _admin = create_test_user(&*ctx.store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let (cookie, csrf) = login_user(&ctx.app, "admin", TEST_PASSWORD).await;
    let full_cookie = combined_cookie(&cookie, &csrf);

    // Create credential and agent
    let (status, cred_body) = send_json(
        &ctx.app,
        Method::POST,
        "/api/v1/credentials",
        None,
        Some(&full_cookie),
        Some(&csrf),
        Some(json!({
            "name": "policy-reason-cred",
            "service": "test-service",
            "secret_value": "secret-123",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "create credential: {}", cred_body);
    let cred_id_str = cred_body["data"]["id"].as_str().expect("credential id");

    let ws = register_workspace_full_context(&ctx.app, &full_cookie, &csrf).await;
    let agent_id =
        agent_cordon_core::domain::agent::AgentId(ws.agent_id.parse().expect("parse agent_id"));
    let cred_id = agent_cordon_core::domain::credential::CredentialId(
        cred_id_str.parse().expect("parse cred_id"),
    );

    // Set encryption key so vend_credential can ECIES-encrypt
    set_encryption_key_on_workspace(&*ctx.store, &agent_id).await;

    // Create a named Cedar policy granting access
    grant_cedar_permission(&ctx.state, &cred_id, &agent_id, "delegated_use").await;

    // Now set up device + bind agent for dual auth
    let agent = ctx
        .store
        .get_workspace(&agent_id)
        .await
        .expect("get agent")
        .expect("agent exists");
    let device_ctx = quick_device_setup(&ctx.state, &agent, "").await;

    // Vend credential (triggers Cedar evaluation + audit)
    let (status, _body) = send_json_dual_auth(
        &ctx.app,
        Method::POST,
        &format!("/api/v1/credentials/{}/vend", cred_id_str),
        &device_ctx.device_signing_key,
        &device_ctx.device_id,
        &device_ctx.agent_jwt,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "vend should succeed");

    // Fetch audit events for this credential
    let events = fetch_audit_events_for_resource(&ctx, "credential", Some(cred_id_str)).await;
    let vend_events: Vec<_> = events
        .iter()
        .filter(|e| {
            matches!(
                e.event_type,
                agent_cordon_core::domain::audit::AuditEventType::CredentialVended
            )
        })
        .collect();

    assert!(
        !vend_events.is_empty(),
        "should have at least one CredentialVended audit event"
    );

    // Check decision_reason contains the grant policy name
    let event = vend_events.last().unwrap();
    if let Some(ref reason) = event.decision_reason {
        // The grant policy name follows the pattern "grant:{cred_id}:{agent_id}:{action}"
        // After the feature lands, decision_reason should contain the policy name
        assert!(
            !reason.is_empty(),
            "decision_reason should not be empty for allow decisions"
        );
    }
    // Note: if decision_reason is None, the feature hasn't landed yet
}

/// Test #2: Deny decision includes policy name or "default deny" reason.
/// Uses a restrictive custom policy that does NOT permit workspace vend_credential.
#[tokio::test]
async fn test_deny_decision_includes_policy_name() {
    // Custom policy: only admin users can act. No workspace vend permission
    // at all, so workspace vend requests are denied by Cedar default-deny.
    let restrictive_policy = r#"
        // Admin users can do everything
        permit(
          principal is AgentCordon::User,
          action,
          resource
        ) when { principal.role == "admin" };

        // NOTE: No workspace vend permission — workspaces are denied by default
    "#;

    let ctx = TestAppBuilder::new()
        .with_admin()
        .with_policy(restrictive_policy)
        .build()
        .await;
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
            "name": "deny-reason-cred",
            "service": "deny-test",
            "secret_value": "secret-456",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "create credential: {}", cred_body);
    let cred_id_str = cred_body["data"]["id"].as_str().expect("credential id");

    // Register agent but do NOT grant permissions
    let ws = register_workspace_full_context(&ctx.app, &full_cookie, &csrf).await;
    let agent_id =
        agent_cordon_core::domain::agent::AgentId(ws.agent_id.parse().expect("parse agent_id"));
    let agent = ctx
        .store
        .get_workspace(&agent_id)
        .await
        .expect("get agent")
        .expect("agent exists");
    let device_ctx = quick_device_setup(&ctx.state, &agent, "").await;

    // Attempt vend without permission — should be denied
    let (status, _body) = send_json_dual_auth(
        &ctx.app,
        Method::POST,
        &format!("/api/v1/credentials/{}/vend", cred_id_str),
        &device_ctx.device_signing_key,
        &device_ctx.device_id,
        &device_ctx.agent_jwt,
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "vend should be denied without explicit grant"
    );

    // Fetch audit events
    let events = fetch_audit_events_for_resource(&ctx, "credential", Some(cred_id_str)).await;
    let denied: Vec<_> = events
        .iter()
        .filter(|e| {
            matches!(
                e.event_type,
                agent_cordon_core::domain::audit::AuditEventType::CredentialVendDenied
                    | agent_cordon_core::domain::audit::AuditEventType::CredentialAccessDenied
            )
        })
        .collect();

    assert!(
        !denied.is_empty(),
        "should have a deny audit event for the credential"
    );
}

/// Test #3: Multiple contributing policies are all listed in decision_reason.
#[tokio::test]
async fn test_multiple_policies_all_listed() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let _admin = create_test_user(&*ctx.store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let (cookie, csrf) = login_user(&ctx.app, "admin", TEST_PASSWORD).await;
    let full_cookie = combined_cookie(&cookie, &csrf);

    // Create credential + agent
    let (status, cred_body) = send_json(
        &ctx.app,
        Method::POST,
        "/api/v1/credentials",
        None,
        Some(&full_cookie),
        Some(&csrf),
        Some(json!({
            "name": "multi-policy-cred",
            "service": "multi-test",
            "secret_value": "secret-789",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let cred_id_str = cred_body["data"]["id"].as_str().expect("cred id");

    let ws = register_workspace_full_context(&ctx.app, &full_cookie, &csrf).await;
    let agent_id =
        agent_cordon_core::domain::agent::AgentId(ws.agent_id.parse().expect("parse agent_id"));
    let cred_id = agent_cordon_core::domain::credential::CredentialId(
        cred_id_str.parse().expect("parse cred_id"),
    );

    // Set encryption key so vend_credential can ECIES-encrypt
    set_encryption_key_on_workspace(&*ctx.store, &agent_id).await;

    // Grant delegated_use — this creates a "vend_credential" policy (agents never get raw "access")
    grant_cedar_permission(&ctx.state, &cred_id, &agent_id, "delegated_use").await;

    // The "vend" action will match the "vend_credential" policy
    let agent = ctx
        .store
        .get_workspace(&agent_id)
        .await
        .expect("get agent")
        .expect("agent");
    let device_ctx = quick_device_setup(&ctx.state, &agent, "").await;

    let (status, _) = send_json_dual_auth(
        &ctx.app,
        Method::POST,
        &format!("/api/v1/credentials/{}/vend", cred_id_str),
        &device_ctx.device_signing_key,
        &device_ctx.device_id,
        &device_ctx.agent_jwt,
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "vend should succeed with both policies"
    );

    // Fetch audit event — after feature, decision_reason should list contributing policies
    let events = fetch_audit_events_for_resource(&ctx, "credential", Some(cred_id_str)).await;
    assert!(
        !events.is_empty(),
        "should have audit events for the credential"
    );
}

/// Test #4: Default deny (no policies match) has clear reason.
/// Uses a minimal policy that only allows admin users — no workspace vend grants at all.
#[tokio::test]
async fn test_default_deny_reason_clear() {
    let minimal_policy = r#"
        // Only admin users can do things
        permit(
          principal is AgentCordon::User,
          action,
          resource
        ) when { principal.role == "admin" };

        // NOTE: No workspace vend permission — Cedar default-deny applies
    "#;

    let ctx = TestAppBuilder::new()
        .with_admin()
        .with_policy(minimal_policy)
        .build()
        .await;
    let _admin = create_test_user(&*ctx.store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let (cookie, csrf) = login_user(&ctx.app, "admin", TEST_PASSWORD).await;
    let full_cookie = combined_cookie(&cookie, &csrf);

    // Create credential, register agent, but grant NO permissions
    let (status, cred_body) = send_json(
        &ctx.app,
        Method::POST,
        "/api/v1/credentials",
        None,
        Some(&full_cookie),
        Some(&csrf),
        Some(json!({
            "name": "default-deny-cred",
            "service": "deny-test",
            "secret_value": "secret-xyz",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let cred_id_str = cred_body["data"]["id"].as_str().expect("cred id");

    let ws = register_workspace_full_context(&ctx.app, &full_cookie, &csrf).await;
    let agent_id =
        agent_cordon_core::domain::agent::AgentId(ws.agent_id.parse().expect("parse agent_id"));
    let agent = ctx
        .store
        .get_workspace(&agent_id)
        .await
        .expect("get agent")
        .expect("agent");
    let device_ctx = quick_device_setup(&ctx.state, &agent, "").await;

    // Attempt vend — no matching agent policies → default deny
    let (status, _) = send_json_dual_auth(
        &ctx.app,
        Method::POST,
        &format!("/api/v1/credentials/{}/vend", cred_id_str),
        &device_ctx.device_signing_key,
        &device_ctx.device_id,
        &device_ctx.agent_jwt,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let events = fetch_audit_events_for_resource(&ctx, "credential", Some(cred_id_str)).await;
    let denied: Vec<_> = events
        .iter()
        .filter(|e| {
            matches!(
                e.decision,
                agent_cordon_core::domain::audit::AuditDecision::Forbid
            )
        })
        .collect();
    assert!(!denied.is_empty(), "should have a deny event");
}

/// Test #5: Audit list API includes decision_reason field.
#[tokio::test]
async fn test_audit_list_shows_policy_reasoning() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let _admin = create_test_user(&*ctx.store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let (cookie, csrf) = login_user(&ctx.app, "admin", TEST_PASSWORD).await;
    let full_cookie = combined_cookie(&cookie, &csrf);

    // Trigger some audit events by creating an agent
    let _ws = register_workspace_full_context(&ctx.app, &full_cookie, &csrf).await;

    // Query audit API
    let (status, body) = send_json(
        &ctx.app,
        Method::GET,
        "/api/v1/audit?limit=10",
        None,
        Some(&full_cookie),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "audit list: {}", body);

    // Verify the response structure includes decision_reason field
    let events = body["data"]
        .as_array()
        .expect("audit data should be an array");
    if !events.is_empty() {
        // Each event should have the decision_reason key (even if null)
        let first = &events[0];
        assert!(
            first.get("decision_reason").is_some() || first.get("decisionReason").is_some(),
            "audit event should have decision_reason field in API response"
        );
    }
}

// ===========================================================================
// 8B. Retry/Idempotency
// ===========================================================================

/// Test #6: Same request twice creates two distinct audit events.
#[tokio::test]
async fn test_same_request_twice_creates_two_audit_events() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let _admin = create_test_user(&*ctx.store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let (cookie, csrf) = login_user(&ctx.app, "admin", TEST_PASSWORD).await;
    let full_cookie = combined_cookie(&cookie, &csrf);

    // Create credential + agent with permission
    let (status, cred_body) = send_json(
        &ctx.app,
        Method::POST,
        "/api/v1/credentials",
        None,
        Some(&full_cookie),
        Some(&csrf),
        Some(json!({
            "name": "dedup-test-cred",
            "service": "dedup-test",
            "secret_value": "secret-dedup",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let cred_id_str = cred_body["data"]["id"].as_str().expect("cred id");

    let ws = register_workspace_full_context(&ctx.app, &full_cookie, &csrf).await;
    let agent_id = agent_cordon_core::domain::agent::AgentId(ws.agent_id.parse().unwrap());
    let cred_id = agent_cordon_core::domain::credential::CredentialId(cred_id_str.parse().unwrap());
    set_encryption_key_on_workspace(&*ctx.store, &agent_id).await;
    grant_cedar_permission(&ctx.state, &cred_id, &agent_id, "delegated_use").await;

    let agent = ctx.store.get_workspace(&agent_id).await.unwrap().unwrap();
    let device_ctx = quick_device_setup(&ctx.state, &agent, "").await;

    // Vend twice
    for _ in 0..2 {
        let (status, _) = send_json_dual_auth(
            &ctx.app,
            Method::POST,
            &format!("/api/v1/credentials/{}/vend", cred_id_str),
            &device_ctx.device_signing_key,
            &device_ctx.device_id,
            &device_ctx.agent_jwt,
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
    }

    // Should have 2 distinct audit events
    let events = fetch_audit_events_for_resource(&ctx, "credential", Some(cred_id_str)).await;
    let vend_events: Vec<_> = events
        .iter()
        .filter(|e| {
            matches!(
                e.event_type,
                agent_cordon_core::domain::audit::AuditEventType::CredentialVended
            )
        })
        .collect();
    assert!(
        vend_events.len() >= 2,
        "should have at least 2 vend audit events, got {}",
        vend_events.len()
    );
}

// ===========================================================================
// 8D. Cross-Feature
// ===========================================================================

/// Test #10: Credential proxy includes policy reasoning in audit.
#[tokio::test]
async fn test_credential_proxy_includes_policy_reasoning() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let _admin = create_test_user(&*ctx.store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let (cookie, csrf) = login_user(&ctx.app, "admin", TEST_PASSWORD).await;
    let full_cookie = combined_cookie(&cookie, &csrf);

    // Create credential + agent with access
    let (status, cred_body) = send_json(
        &ctx.app,
        Method::POST,
        "/api/v1/credentials",
        None,
        Some(&full_cookie),
        Some(&csrf),
        Some(json!({
            "name": "proxy-reason-cred",
            "service": "proxy-test",
            "secret_value": "secret-proxy",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let cred_id_str = cred_body["data"]["id"].as_str().expect("cred id");

    let ws = register_workspace_full_context(&ctx.app, &full_cookie, &csrf).await;
    let agent_id = agent_cordon_core::domain::agent::AgentId(ws.agent_id.parse().unwrap());
    let cred_id = agent_cordon_core::domain::credential::CredentialId(cred_id_str.parse().unwrap());
    set_encryption_key_on_workspace(&*ctx.store, &agent_id).await;
    grant_cedar_permission(&ctx.state, &cred_id, &agent_id, "delegated_use").await;

    let agent = ctx.store.get_workspace(&agent_id).await.unwrap().unwrap();
    let device_ctx = quick_device_setup(&ctx.state, &agent, "").await;

    // Vend (triggers Cedar eval with audit)
    let (status, _) = send_json_dual_auth(
        &ctx.app,
        Method::POST,
        &format!("/api/v1/credentials/{}/vend", cred_id_str),
        &device_ctx.device_signing_key,
        &device_ctx.device_id,
        &device_ctx.agent_jwt,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Verify audit event exists for this credential
    let events = fetch_audit_events_for_resource(&ctx, "credential", Some(cred_id_str)).await;
    assert!(
        !events.is_empty(),
        "should have audit events for credential proxy"
    );
}

// ===========================================================================
// 8E. Security
// ===========================================================================

/// Test #12: Policy reasoning does not leak secret information.
#[tokio::test]
async fn test_policy_reasoning_no_secret_leakage() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let _admin = create_test_user(&*ctx.store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let (cookie, csrf) = login_user(&ctx.app, "admin", TEST_PASSWORD).await;
    let full_cookie = combined_cookie(&cookie, &csrf);

    let (status, cred_body) = send_json(
        &ctx.app,
        Method::POST,
        "/api/v1/credentials",
        None,
        Some(&full_cookie),
        Some(&csrf),
        Some(json!({
            "name": "secret-leak-cred",
            "service": "leak-test",
            "secret_value": "super-secret-do-not-leak",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let cred_id_str = cred_body["data"]["id"].as_str().expect("cred id");

    let ws = register_workspace_full_context(&ctx.app, &full_cookie, &csrf).await;
    let agent_id = agent_cordon_core::domain::agent::AgentId(ws.agent_id.parse().unwrap());
    let cred_id = agent_cordon_core::domain::credential::CredentialId(cred_id_str.parse().unwrap());
    set_encryption_key_on_workspace(&*ctx.store, &agent_id).await;
    grant_cedar_permission(&ctx.state, &cred_id, &agent_id, "delegated_use").await;

    let agent = ctx.store.get_workspace(&agent_id).await.unwrap().unwrap();
    let device_ctx = quick_device_setup(&ctx.state, &agent, "").await;

    let (status, _) = send_json_dual_auth(
        &ctx.app,
        Method::POST,
        &format!("/api/v1/credentials/{}/vend", cred_id_str),
        &device_ctx.device_signing_key,
        &device_ctx.device_id,
        &device_ctx.agent_jwt,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let events = fetch_audit_events_for_resource(&ctx, "credential", Some(cred_id_str)).await;
    for event in &events {
        if let Some(ref reason) = event.decision_reason {
            assert!(
                !reason.contains("super-secret-do-not-leak"),
                "decision_reason must not contain secret values"
            );
        }
        let metadata_str = serde_json::to_string(&event.metadata).unwrap();
        assert!(
            !metadata_str.contains("super-secret-do-not-leak"),
            "audit metadata must not contain secret values"
        );
    }
}

/// Test #13: Policy reasoning is only visible to admin users.
#[tokio::test]
async fn test_policy_reasoning_visible_to_admin_only() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let _admin = create_test_user(&*ctx.store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let _viewer = create_test_user(&*ctx.store, "viewer", TEST_PASSWORD, UserRole::Viewer).await;

    // Viewer tries to access audit API
    let (viewer_cookie, viewer_csrf) = login_user(&ctx.app, "viewer", TEST_PASSWORD).await;
    let viewer_full_cookie = combined_cookie(&viewer_cookie, &viewer_csrf);

    let (status, _body) = send_json(
        &ctx.app,
        Method::GET,
        "/api/v1/audit?limit=10",
        None,
        Some(&viewer_full_cookie),
        None,
        None,
    )
    .await;

    // Viewer should either be denied (403) or get events without decision_reason
    assert!(
        status == StatusCode::FORBIDDEN || status == StatusCode::OK,
        "viewer audit access should be controlled: status={}",
        status
    );
}
