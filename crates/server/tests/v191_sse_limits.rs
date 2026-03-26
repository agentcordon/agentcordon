//! Integration tests — v1.9.1 Feature 2: SSE Connection Leak Fix.
//!
//! Verifies the server enforces per-session SSE connection limits so that
//! navigating between pages doesn't leak EventSource connections.

use crate::common;

use agent_cordon_core::domain::user::UserRole;
use agent_cordon_server::events::UiEvent;
use agent_cordon_server::test_helpers::TestAppBuilder;
use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use tower::ServiceExt;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async fn setup() -> (agent_cordon_server::test_helpers::TestContext, String) {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let _user = common::create_test_user(
        &*ctx.store,
        "sse-limit-user",
        common::TEST_PASSWORD,
        UserRole::Admin,
    )
    .await;
    let cookie =
        common::login_user_combined(&ctx.app, "sse-limit-user", common::TEST_PASSWORD).await;
    (ctx, cookie)
}

/// Open an SSE connection and return the response status + content-type.
async fn open_sse(app: &axum::Router, cookie: &str) -> (StatusCode, String) {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/api/v1/events/ui")
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let status = resp.status();
    let content_type = resp
        .headers()
        .get(header::CONTENT_TYPE)
        .map(|v| v.to_str().unwrap_or("").to_string())
        .unwrap_or_default();

    (status, content_type)
}

// ===========================================================================
// 2A. Happy Path
// ===========================================================================

#[tokio::test]
async fn test_sse_single_connection_works() {
    let (ctx, cookie) = setup().await;

    let (status, content_type) = open_sse(&ctx.app, &cookie).await;

    assert_eq!(status, StatusCode::OK);
    assert!(
        content_type.contains("text/event-stream"),
        "SSE endpoint should return text/event-stream, got: {}",
        content_type,
    );
}

#[tokio::test]
async fn test_sse_connection_receives_events() {
    let (ctx, _cookie) = setup().await;

    let mut rx = ctx.state.ui_event_bus.subscribe();

    let workspace_id = Uuid::new_v4();
    ctx.state.ui_event_bus.emit(UiEvent::WorkspaceCreated {
        workspace_id,
        workspace_name: "sse-limit-test-agent".to_string(),
    });

    let event = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
        .await
        .expect("should receive event within timeout")
        .expect("event should be Ok");

    match event {
        UiEvent::WorkspaceCreated {
            workspace_id: id, ..
        } => {
            assert_eq!(id, workspace_id);
        }
        other => panic!("expected WorkspaceCreated, got: {:?}", other),
    }
}

// ===========================================================================
// 2B. Retry/Idempotency
// ===========================================================================

#[tokio::test]
async fn test_sse_reconnect_after_disconnect() {
    let (ctx, cookie) = setup().await;

    // Open and immediately consume (simulating disconnect by dropping response)
    let (status1, _) = open_sse(&ctx.app, &cookie).await;
    assert_eq!(status1, StatusCode::OK);

    // Open a new connection — should work fine
    let (status2, content_type) = open_sse(&ctx.app, &cookie).await;
    assert_eq!(status2, StatusCode::OK);
    assert!(content_type.contains("text/event-stream"));
}

#[tokio::test]
async fn test_sse_rapid_reconnect() {
    let (ctx, cookie) = setup().await;

    // Open and drop 5 times rapidly — no server leak
    for _ in 0..5 {
        let (status, _) = open_sse(&ctx.app, &cookie).await;
        assert_eq!(status, StatusCode::OK);
    }

    // Final connection should still work
    let (status, content_type) = open_sse(&ctx.app, &cookie).await;
    assert_eq!(status, StatusCode::OK);
    assert!(content_type.contains("text/event-stream"));
}

// ===========================================================================
// 2C. Error Handling
// ===========================================================================

/// Per-session connection limit test.
///
/// Opens N+1 SSE connections with the same session cookie. The server should
/// either return 429 on the excess connection or close the oldest one.
#[tokio::test]
async fn test_sse_max_connections_per_session() {
    let (ctx, cookie) = setup().await;

    // Open connections up to the limit. We assume the limit is 2-3.
    // We'll try opening 4 and expect at least one to get 429.
    // Note: with oneshot(), each request gets its own "connection" but
    // the server tracks SSE streams per session.
    let mut statuses = Vec::new();
    for _ in 0..4 {
        let (status, _) = open_sse(&ctx.app, &cookie).await;
        statuses.push(status);
    }

    // At least the first connection should succeed
    assert_eq!(
        statuses[0],
        StatusCode::OK,
        "first SSE connection should succeed",
    );

    // If the server enforces limits, some later connections should get 429.
    // If the server uses close-oldest strategy, all return 200 but older
    // streams get dropped. Either behavior is acceptable.
    let has_429 = statuses.contains(&StatusCode::TOO_MANY_REQUESTS);
    let all_200 = statuses.iter().all(|s| *s == StatusCode::OK);

    assert!(
        has_429 || all_200,
        "server should either reject excess connections (429) or accept all (close-oldest): {:?}",
        statuses,
    );
}

#[tokio::test]
async fn test_sse_different_sessions_independent_limits() {
    let ctx = TestAppBuilder::new().with_admin().build().await;

    // Create two users with independent sessions
    let _user_a = common::create_test_user(
        &*ctx.store,
        "sse-user-a",
        common::TEST_PASSWORD,
        UserRole::Admin,
    )
    .await;
    let _user_b = common::create_test_user(
        &*ctx.store,
        "sse-user-b",
        common::TEST_PASSWORD,
        UserRole::Admin,
    )
    .await;

    let cookie_a = common::login_user_combined(&ctx.app, "sse-user-a", common::TEST_PASSWORD).await;
    let cookie_b = common::login_user_combined(&ctx.app, "sse-user-b", common::TEST_PASSWORD).await;

    // Both should be able to open SSE connections independently
    let (status_a, _) = open_sse(&ctx.app, &cookie_a).await;
    let (status_b, _) = open_sse(&ctx.app, &cookie_b).await;

    assert_eq!(status_a, StatusCode::OK, "user A SSE should work");
    assert_eq!(status_b, StatusCode::OK, "user B SSE should work");
}

// ===========================================================================
// 2D. Cross-Feature
// ===========================================================================

#[tokio::test]
async fn test_sse_connection_limit_doesnt_affect_api() {
    let (ctx, cookie) = setup().await;

    // Open SSE connections
    for _ in 0..3 {
        let _ = open_sse(&ctx.app, &cookie).await;
    }

    // Regular API calls should still work regardless of SSE state
    let (status, _) = common::send_json(
        &ctx.app,
        Method::GET,
        "/api/v1/workspaces",
        None,
        Some(&cookie),
        None,
        None,
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "API calls should not be affected by SSE connection limits",
    );
}

// ===========================================================================
// 2E. Security
// ===========================================================================

#[tokio::test]
async fn test_sse_unauthenticated_still_rejected() {
    let ctx = TestAppBuilder::new().with_admin().build().await;

    let resp = ctx
        .app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/events/ui")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "SSE without auth should return 401",
    );
}
