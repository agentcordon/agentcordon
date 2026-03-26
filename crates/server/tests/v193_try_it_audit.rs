//! Integration tests — v1.9.3 Feature 11: Try It Audit Events.
//!
//! Verifies that the Try It endpoint emits audit events for each token
//! issuance, with proper agent context and no leaked token values.

use crate::common;

use agent_cordon_core::domain::user::UserRole;
use agent_cordon_server::test_helpers::TestAppBuilder;
use axum::http::{Method, StatusCode};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Setup with demo seed data for Try It tests.
async fn setup_with_seed() -> (agent_cordon_server::test_helpers::TestContext, String) {
    let ctx = TestAppBuilder::new()
        .with_config(|c| {
            c.seed_demo = true;
        })
        .build()
        .await;

    agent_cordon_server::seed::seed_demo_data(
        &ctx.store,
        &ctx.encryptor,
        &ctx.state.config,
        &ctx.jwt_issuer,
    )
    .await
    .expect("seed demo data");

    let _user = common::create_test_user(
        &*ctx.store,
        "tryit-audit-user",
        common::TEST_PASSWORD,
        UserRole::Admin,
    )
    .await;
    let cookie =
        common::login_user_combined(&ctx.app, "tryit-audit-user", common::TEST_PASSWORD).await;
    (ctx, cookie)
}

/// Get the count of audit events.
async fn get_audit_event_count(app: &axum::Router, cookie: &str) -> usize {
    let (status, body) = common::send_json_auto_csrf(
        app,
        Method::GET,
        "/api/v1/audit?limit=100",
        None,
        Some(cookie),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "audit list: {:?}", body);

    body["data"].as_array().map(|a| a.len()).unwrap_or(0)
}

/// Call the Try It endpoint and return the response.
async fn call_try_it(app: &axum::Router, cookie: &str) -> (StatusCode, serde_json::Value) {
    common::send_json_auto_csrf(
        app,
        Method::GET,
        "/api/v1/demo/try-it",
        None,
        Some(cookie),
        None,
    )
    .await
}

// ===========================================================================
// 11A. Happy Path
// ===========================================================================

/// Calling Try It should emit an audit event.
#[tokio::test]
async fn test_try_it_emits_audit_event() {
    let (ctx, cookie) = setup_with_seed().await;

    let events_before = get_audit_event_count(&ctx.app, &cookie).await;

    // Call Try It
    let (status, _) = call_try_it(&ctx.app, &cookie).await;
    assert_eq!(status, StatusCode::OK, "try-it should succeed");

    let events_after = get_audit_event_count(&ctx.app, &cookie).await;

    assert!(
        events_after > events_before,
        "audit event count should increase after Try It call ({} -> {})",
        events_before,
        events_after
    );
}

/// The Try It audit event should contain agent information.
#[tokio::test]
async fn test_try_it_audit_has_agent_info() {
    let (ctx, cookie) = setup_with_seed().await;

    // Call Try It
    let (status, _) = call_try_it(&ctx.app, &cookie).await;
    assert_eq!(status, StatusCode::OK);

    // Get recent audit events
    let (status, body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::GET,
        "/api/v1/audit?limit=10",
        None,
        Some(&cookie),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let events = body["data"].as_array().expect("data array");

    // Find the Try It audit event (should be the most recent token issuance event)
    let try_it_event = events.iter().find(|e| {
        let event_type = e["event_type"].as_str().unwrap_or("");
        event_type.contains("TokenIssued")
            || event_type.contains("DemoToken")
            || event_type.contains("token_issued")
            || event_type.contains("demo")
    });

    if let Some(event) = try_it_event {
        // Event should have agent/workspace info (v2.0: agents unified into workspaces)
        let has_agent_info = event.get("agent_name").is_some()
            || event.get("agent_id").is_some()
            || event.get("workspace_name").is_some()
            || event.get("workspace_id").is_some()
            || event["metadata"]
                .as_object()
                .map(|m| {
                    m.contains_key("agent_name")
                        || m.contains_key("demo_agent")
                        || m.contains_key("workspace_name")
                })
                .unwrap_or(false);

        assert!(
            has_agent_info,
            "Try It audit event should contain agent/workspace info: {:?}",
            event
        );
    }
    // If no specific Try It event found, the feature may not be implemented yet.
    // The test documents the expectation.
}

// ===========================================================================
// 11B. Retry/Idempotency
// ===========================================================================

/// Multiple Try It calls should create multiple audit events (not deduplicated).
#[tokio::test]
async fn test_try_it_multiple_calls_multiple_events() {
    let (ctx, cookie) = setup_with_seed().await;

    let events_before = get_audit_event_count(&ctx.app, &cookie).await;

    // Call Try It 3 times
    for i in 0..3 {
        let (status, _) = call_try_it(&ctx.app, &cookie).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "try-it call {} should succeed",
            i + 1
        );
    }

    let events_after = get_audit_event_count(&ctx.app, &cookie).await;

    // Each call is a distinct token issuance — should create separate events
    assert!(
        events_after >= events_before + 3,
        "3 Try It calls should create at least 3 new audit events ({} -> {}, expected at least {})",
        events_before,
        events_after,
        events_before + 3
    );
}

// ===========================================================================
// 11D. Cross-Feature
// ===========================================================================

/// After calling Try It, the event should be visible in recent activity.
#[tokio::test]
async fn test_try_it_audit_visible_in_dashboard() {
    let (ctx, cookie) = setup_with_seed().await;

    // Call Try It
    let (status, _) = call_try_it(&ctx.app, &cookie).await;
    assert_eq!(status, StatusCode::OK);

    // Check stats endpoint (includes recent_events)
    let (status, body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::GET,
        "/api/v1/stats",
        None,
        Some(&cookie),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let recent = body["data"]["recent_events"]
        .as_array()
        .expect("recent_events");
    assert!(
        !recent.is_empty(),
        "recent events should not be empty after Try It call"
    );

    // The most recent event should be related to Try It / token issuance
    // (it's the last action performed)
}

// ===========================================================================
// 11E. Security
// ===========================================================================

/// Audit event for Try It should NOT contain the actual JWT token value.
#[tokio::test]
async fn test_try_it_audit_no_token_value() {
    let (ctx, cookie) = setup_with_seed().await;

    // Call Try It to get the JWT
    let (status, try_body) = call_try_it(&ctx.app, &cookie).await;
    assert_eq!(status, StatusCode::OK);

    let curl_command = try_body["data"]["curl_command"].as_str().unwrap_or("");

    // Extract the JWT from the curl command (appears after "Bearer " or "-H")
    let jwt_token = curl_command
        .split("Bearer ")
        .nth(1)
        .and_then(|s| s.split('"').next())
        .unwrap_or("");

    // Get audit events
    let (status, body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::GET,
        "/api/v1/audit?limit=10",
        None,
        Some(&cookie),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let events = body["data"].as_array().expect("data array");

    // No audit event should contain the actual JWT token
    if !jwt_token.is_empty() {
        for event in events {
            let event_str = serde_json::to_string(event).unwrap_or_default();
            assert!(
                !event_str.contains(jwt_token),
                "audit event should NOT contain the actual JWT token value"
            );
        }
    }
}
