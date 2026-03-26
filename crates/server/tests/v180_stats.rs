//! v1.8.0 — Dashboard Stats Endpoint Tests
//!
//! Tests for `GET /api/v1/stats` which provides aggregate counts for
//! agents, credentials, devices, and recent audit events. Used by the
//! dashboard UI.

use axum::http::{Method, StatusCode};
use serde_json::json;

use agent_cordon_core::domain::user::UserRole;
use agent_cordon_core::storage::Store;
use agent_cordon_server::test_helpers::TestAppBuilder;

use crate::common::*;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async fn setup_admin(app: &axum::Router, store: &(dyn Store + Send + Sync)) -> (String, String) {
    create_user_in_db(
        store,
        "stats-admin",
        TEST_PASSWORD,
        UserRole::Admin,
        false,
        true,
    )
    .await;
    let cookie = login_user_combined(app, "stats-admin", TEST_PASSWORD).await;
    let csrf = extract_csrf_from_cookie(&cookie).unwrap();
    (cookie, csrf)
}

async fn setup_viewer(app: &axum::Router, store: &(dyn Store + Send + Sync)) -> (String, String) {
    create_user_in_db(
        store,
        "stats-viewer",
        TEST_PASSWORD,
        UserRole::Viewer,
        false,
        true,
    )
    .await;
    let cookie = login_user_combined(app, "stats-viewer", TEST_PASSWORD).await;
    let csrf = extract_csrf_from_cookie(&cookie).unwrap();
    (cookie, csrf)
}

// ===========================================================================
// Happy Path
// ===========================================================================

/// Test: Empty state returns zero counts.
#[tokio::test]
async fn test_stats_empty_state_returns_zeros() {
    let ctx = TestAppBuilder::new().build().await;
    let (cookie, csrf) = setup_admin(&ctx.app, &*ctx.store).await;

    let (status, body) = send_json(
        &ctx.app,
        Method::GET,
        "/api/v1/stats",
        None,
        Some(&cookie),
        Some(&csrf),
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "stats endpoint should return 200: {}",
        body
    );

    let data = &body["data"];
    // Workspaces: TestAppBuilder creates no workspaces by default (unless with_admin)
    assert!(
        data["workspaces"]["total"].is_number(),
        "workspaces.total should be a number"
    );
    assert!(
        data["credentials"]["total"].is_number(),
        "credentials.total should be a number"
    );
    assert!(
        data["recent_events"].is_array(),
        "recent_events should be an array"
    );
}

/// Test: Stats returns correct agent count.
#[tokio::test]
async fn test_stats_returns_correct_agent_count() {
    let ctx = TestAppBuilder::new()
        .with_admin()
        .with_agent("stats-agent-1", &["viewer"])
        .with_agent("stats-agent-2", &["viewer"])
        .build()
        .await;
    let (cookie, csrf) = setup_admin(&ctx.app, &*ctx.store).await;

    let (status, body) = send_json(
        &ctx.app,
        Method::GET,
        "/api/v1/stats",
        None,
        Some(&cookie),
        Some(&csrf),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "stats: {}", body);

    let workspaces_total = body["data"]["workspaces"]["total"]
        .as_u64()
        .expect("workspaces.total");
    // TestAppBuilder creates admin + 2 agents = 3 workspaces
    assert!(
        workspaces_total >= 3,
        "expected at least 3 workspaces, got {}",
        workspaces_total
    );
}

/// Test: Stats returns correct credential count.
#[tokio::test]
async fn test_stats_returns_correct_credential_count() {
    let ctx = TestAppBuilder::new().build().await;
    let (cookie, csrf) = setup_admin(&ctx.app, &*ctx.store).await;

    // Create 2 credentials
    for i in 0..2 {
        let (status, _) = send_json(
            &ctx.app,
            Method::POST,
            "/api/v1/credentials",
            None,
            Some(&cookie),
            Some(&csrf),
            Some(json!({
                "name": format!("stats-cred-{}", i),
                "service": "test-service",
                "secret_value": "test-secret-value",
            })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "create credential {}", i);
    }

    let (status, body) = send_json(
        &ctx.app,
        Method::GET,
        "/api/v1/stats",
        None,
        Some(&cookie),
        Some(&csrf),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "stats: {}", body);

    let creds_total = body["data"]["credentials"]["total"]
        .as_u64()
        .expect("credentials.total");
    assert_eq!(
        creds_total, 2,
        "expected 2 credentials, got {}",
        creds_total
    );
}

/// Test: Stats returns correct device count.
#[tokio::test]
async fn test_stats_returns_correct_device_count() {
    let ctx = TestAppBuilder::new()
        .with_admin()
        .with_agent("stats-dev-agent", &["viewer"])
        .build()
        .await;
    let (cookie, csrf) = setup_admin(&ctx.app, &*ctx.store).await;

    let (status, body) = send_json(
        &ctx.app,
        Method::GET,
        "/api/v1/stats",
        None,
        Some(&cookie),
        Some(&csrf),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "stats: {}", body);

    let workspaces_total = body["data"]["workspaces"]["total"]
        .as_u64()
        .expect("workspaces.total");
    // TestAppBuilder creates a workspace per agent (admin + stats-dev-agent = 2)
    assert!(
        workspaces_total >= 2,
        "expected at least 2 workspaces, got {}",
        workspaces_total
    );
}

/// Test: Stats returns llm_exposed credential count.
#[tokio::test]
async fn test_stats_returns_llm_exposed_count() {
    let ctx = TestAppBuilder::new().build().await;
    let (cookie, csrf) = setup_admin(&ctx.app, &*ctx.store).await;

    // Create a credential with llm_exposed tag
    let (status, _) = send_json(
        &ctx.app,
        Method::POST,
        "/api/v1/credentials",
        None,
        Some(&cookie),
        Some(&csrf),
        Some(json!({
            "name": "llm-cred-stats",
            "service": "test",
            "secret_value": "secret",
            "tags": ["llm_exposed"],
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "create llm_exposed credential");

    // Create a normal credential
    let (status, _) = send_json(
        &ctx.app,
        Method::POST,
        "/api/v1/credentials",
        None,
        Some(&cookie),
        Some(&csrf),
        Some(json!({
            "name": "normal-cred-stats",
            "service": "test",
            "secret_value": "secret",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "create normal credential");

    let (status, body) = send_json(
        &ctx.app,
        Method::GET,
        "/api/v1/stats",
        None,
        Some(&cookie),
        Some(&csrf),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "stats: {}", body);

    let llm_exposed = body["data"]["credentials"]["llm_exposed"]
        .as_u64()
        .expect("credentials.llm_exposed");
    assert_eq!(
        llm_exposed, 1,
        "expected 1 llm_exposed credential, got {}",
        llm_exposed
    );

    let total = body["data"]["credentials"]["total"]
        .as_u64()
        .expect("credentials.total");
    assert_eq!(total, 2, "expected 2 total credentials, got {}", total);
}

/// Test: Stats returns recent audit events (capped at 10).
#[tokio::test]
async fn test_stats_returns_recent_audit_events() {
    let ctx = TestAppBuilder::new().build().await;
    let (cookie, csrf) = setup_admin(&ctx.app, &*ctx.store).await;

    // Create a credential to generate an audit event
    let (status, _) = send_json(
        &ctx.app,
        Method::POST,
        "/api/v1/credentials",
        None,
        Some(&cookie),
        Some(&csrf),
        Some(json!({
            "name": "audit-gen-cred",
            "service": "test",
            "secret_value": "secret",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "create credential");

    let (status, body) = send_json(
        &ctx.app,
        Method::GET,
        "/api/v1/stats",
        None,
        Some(&cookie),
        Some(&csrf),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "stats: {}", body);

    let events = body["data"]["recent_events"]
        .as_array()
        .expect("recent_events array");
    assert!(!events.is_empty(), "should have at least one audit event");
    assert!(
        events.len() <= 10,
        "should cap at 10 events, got {}",
        events.len()
    );

    // Verify event structure
    let event = &events[0];
    assert!(event["id"].is_string(), "event should have id");
    assert!(
        event["event_type"].is_string(),
        "event should have event_type"
    );
    assert!(
        event["timestamp"].is_string(),
        "event should have timestamp"
    );
    assert!(event["decision"].is_string(), "event should have decision");
}

// ===========================================================================
// Security
// ===========================================================================

/// Test: Stats with a Cedar policy that denies view_audit returns 403.
///
/// The default Cedar policy permits viewers to view audit (and stats uses
/// the `view_audit` action). This test uses a restrictive policy to verify
/// the endpoint enforces policy correctly.
#[tokio::test]
async fn test_stats_denied_by_policy() {
    // Use a custom Cedar policy that only allows admin role to view_audit
    let restrictive_policy = r#"
permit(
  principal is AgentCordon::User,
  action == AgentCordon::Action::"view_audit",
  resource
) when {
  principal.role == "admin"
};
permit(
  principal is AgentCordon::User,
  action == AgentCordon::Action::"login",
  resource
);
"#;
    let ctx = TestAppBuilder::new()
        .with_policy(restrictive_policy)
        .build()
        .await;
    let (cookie, csrf) = setup_viewer(&ctx.app, &*ctx.store).await;

    let (status, body) = send_json(
        &ctx.app,
        Method::GET,
        "/api/v1/stats",
        None,
        Some(&cookie),
        Some(&csrf),
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "viewer should get 403 with restrictive policy: {}",
        body
    );
}

/// Test: Stats without auth returns 401.
#[tokio::test]
async fn test_stats_requires_authentication() {
    let ctx = TestAppBuilder::new().build().await;

    let (status, _body) = send_json(
        &ctx.app,
        Method::GET,
        "/api/v1/stats",
        None,
        None,
        None,
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "unauthenticated should get 401"
    );
}
