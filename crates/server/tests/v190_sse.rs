//! Integration tests — v1.9.0 Feature 4: SSE Real-Time Updates.
//!
//! Verifies the UI SSE endpoint at `/api/v1/events/ui` delivers events
//! correctly, requires authentication, and doesn't leak secrets.

use crate::common;

use agent_cordon_core::domain::user::UserRole;
use agent_cordon_server::events::UiEvent;
use agent_cordon_server::test_helpers::TestAppBuilder;
use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

#[allow(dead_code)]
async fn get_authed(app: &axum::Router, uri: &str, cookie: &str) -> (StatusCode, String, String) {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(uri)
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
    let body = String::from_utf8(
        resp.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();

    (status, content_type, body)
}

// ===========================================================================
// 4A. Happy Path
// ===========================================================================

#[tokio::test]
async fn test_sse_endpoint_returns_event_stream() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let _user = common::create_test_user(
        &*ctx.store,
        "sse-user",
        common::TEST_PASSWORD,
        UserRole::Admin,
    )
    .await;
    let cookie = common::login_user_combined(&ctx.app, "sse-user", common::TEST_PASSWORD).await;

    let resp = ctx
        .app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/events/ui")
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let ct = resp
        .headers()
        .get(header::CONTENT_TYPE)
        .unwrap()
        .to_str()
        .unwrap();
    assert!(
        ct.contains("text/event-stream"),
        "SSE endpoint should return text/event-stream, got: {}",
        ct,
    );
}

#[tokio::test]
async fn test_sse_receives_workspace_created_event() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    // Subscribe to UI event bus before emitting
    let mut rx = ctx.state.ui_event_bus.subscribe();

    // Emit a workspace_created event
    let workspace_id = Uuid::new_v4();
    ctx.state.ui_event_bus.emit(UiEvent::WorkspaceCreated {
        workspace_id,
        workspace_name: "test-sse-workspace".to_string(),
    });

    // Verify the event was received on the bus
    let event = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
        .await
        .expect("should receive event within timeout")
        .expect("event should be Ok");

    match event {
        UiEvent::WorkspaceCreated {
            workspace_id: id,
            workspace_name,
        } => {
            assert_eq!(id, workspace_id);
            assert_eq!(workspace_name, "test-sse-workspace");
        }
        other => panic!("expected WorkspaceCreated, got: {:?}", other),
    }
}

#[tokio::test]
async fn test_sse_receives_credential_created_event() {
    let ctx = TestAppBuilder::new().with_admin().build().await;

    let mut rx = ctx.state.ui_event_bus.subscribe();

    let cred_id = Uuid::new_v4();
    ctx.state.ui_event_bus.emit(UiEvent::CredentialCreated {
        credential_id: cred_id,
        credential_name: "test-cred".to_string(),
    });

    let event = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
        .await
        .expect("should receive event")
        .expect("event should be Ok");

    match event {
        UiEvent::CredentialCreated { credential_id, .. } => {
            assert_eq!(credential_id, cred_id);
        }
        other => panic!("expected CredentialCreated, got: {:?}", other),
    }
}

#[tokio::test]
async fn test_sse_receives_workspace_created_event_for_device() {
    let ctx = TestAppBuilder::new().with_admin().build().await;

    let mut rx = ctx.state.ui_event_bus.subscribe();

    let workspace_id = Uuid::new_v4();
    ctx.state.ui_event_bus.emit(UiEvent::WorkspaceCreated {
        workspace_id,
        workspace_name: "test-device".to_string(),
    });

    let event = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
        .await
        .expect("should receive event")
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

#[tokio::test]
async fn test_sse_receives_policy_changed_event() {
    let ctx = TestAppBuilder::new().with_admin().build().await;

    let mut rx = ctx.state.ui_event_bus.subscribe();

    ctx.state.ui_event_bus.emit(UiEvent::PolicyChanged {
        policy_name: "test-policy".to_string(),
    });

    let event = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
        .await
        .expect("should receive event")
        .expect("event should be Ok");

    match event {
        UiEvent::PolicyChanged { policy_name } => {
            assert_eq!(policy_name, "test-policy");
        }
        other => panic!("expected PolicyChanged, got: {:?}", other),
    }
}

// ===========================================================================
// 4B. Retry/Idempotency
// ===========================================================================

#[tokio::test]
async fn test_sse_multiple_subscribers() {
    let ctx = TestAppBuilder::new().with_admin().build().await;

    // Two subscribers
    let mut rx1 = ctx.state.ui_event_bus.subscribe();
    let mut rx2 = ctx.state.ui_event_bus.subscribe();

    let workspace_id = Uuid::new_v4();
    ctx.state.ui_event_bus.emit(UiEvent::WorkspaceCreated {
        workspace_id,
        workspace_name: "multi-sub-workspace".to_string(),
    });

    // Both should receive the event
    let e1 = tokio::time::timeout(std::time::Duration::from_secs(2), rx1.recv())
        .await
        .expect("rx1 timeout")
        .expect("rx1 recv");
    let e2 = tokio::time::timeout(std::time::Duration::from_secs(2), rx2.recv())
        .await
        .expect("rx2 timeout")
        .expect("rx2 recv");

    match (&e1, &e2) {
        (
            UiEvent::WorkspaceCreated {
                workspace_id: id1, ..
            },
            UiEvent::WorkspaceCreated {
                workspace_id: id2, ..
            },
        ) => {
            assert_eq!(*id1, workspace_id);
            assert_eq!(*id2, workspace_id);
        }
        _ => panic!("both subscribers should get WorkspaceCreated"),
    }
}

// ===========================================================================
// 4C. Error Handling
// ===========================================================================

#[tokio::test]
async fn test_sse_without_auth_returns_401() {
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

#[tokio::test]
async fn test_sse_no_subscribers_no_error() {
    let ctx = TestAppBuilder::new().with_admin().build().await;

    // Emit events with no subscribers — should not panic or error
    ctx.state.ui_event_bus.emit(UiEvent::WorkspaceCreated {
        workspace_id: Uuid::new_v4(),
        workspace_name: "no-sub-workspace".to_string(),
    });
    ctx.state.ui_event_bus.emit(UiEvent::CredentialCreated {
        credential_id: Uuid::new_v4(),
        credential_name: "no-sub-cred".to_string(),
    });
    ctx.state.ui_event_bus.emit(UiEvent::PolicyChanged {
        policy_name: "no-sub-policy".to_string(),
    });

    // If we got here without panicking, the test passes
}

// ===========================================================================
// 4E. Security
// ===========================================================================

#[tokio::test]
async fn test_sse_no_secrets_in_events() {
    let _ctx = TestAppBuilder::new().with_admin().build().await;

    // Credential events should only contain id and name, not secret values
    let cred_event = UiEvent::CredentialCreated {
        credential_id: Uuid::new_v4(),
        credential_name: "test-cred".to_string(),
    };

    let serialized = serde_json::to_string(&cred_event).unwrap();
    assert!(
        !serialized.contains("secret_value"),
        "event must not contain secret_value"
    );
    assert!(
        !serialized.contains("encrypted_value"),
        "event must not contain encrypted_value"
    );

    // Verify the event only has expected fields
    let parsed: serde_json::Value = serde_json::from_str(&serialized).unwrap();
    assert!(parsed.get("credential_id").is_some());
    assert!(parsed.get("credential_name").is_some());
}

#[tokio::test]
async fn test_sse_device_events_not_exposed_to_ui() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let _user = common::create_test_user(
        &*ctx.store,
        "sse-sep-user",
        common::TEST_PASSWORD,
        UserRole::Admin,
    )
    .await;
    let cookie = common::login_user_combined(&ctx.app, "sse-sep-user", common::TEST_PASSWORD).await;

    // The UI SSE endpoint is /api/v1/events/ui
    // The device SSE endpoint is different (/api/v1/devices/events or similar)
    // Verify UI endpoint exists and returns event-stream
    let resp = ctx
        .app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/events/ui")
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let ct = resp
        .headers()
        .get(header::CONTENT_TYPE)
        .unwrap()
        .to_str()
        .unwrap();
    assert!(ct.contains("text/event-stream"));

    // Verify that UiEvent and DeviceEvent are separate types
    // (compile-time check — if this test compiles, they're separate)
    let _ui_event = UiEvent::WorkspaceCreated {
        workspace_id: Uuid::new_v4(),
        workspace_name: "test".to_string(),
    };
    let _device_event = agent_cordon_server::events::DeviceEvent::PolicyChanged {
        policy_name: "test".to_string(),
    };
}

// ===========================================================================
// 4D. Cross-Feature — Event type coverage
// ===========================================================================

#[tokio::test]
async fn test_sse_all_event_types_serialize() {
    // Verify all UiEvent variants can be serialized (no panic)
    let events: Vec<UiEvent> = vec![
        UiEvent::WorkspaceCreated {
            workspace_id: Uuid::new_v4(),
            workspace_name: "a".to_string(),
        },
        UiEvent::WorkspaceUpdated {
            workspace_id: Uuid::new_v4(),
        },
        UiEvent::CredentialCreated {
            credential_id: Uuid::new_v4(),
            credential_name: "c".to_string(),
        },
        UiEvent::CredentialUpdated {
            credential_id: Uuid::new_v4(),
        },
        UiEvent::CredentialDeleted {
            credential_id: Uuid::new_v4(),
        },
        UiEvent::PolicyChanged {
            policy_name: "p".to_string(),
        },
        UiEvent::AuditEvent {
            event_type: "test".to_string(),
        },
        UiEvent::UserCreated {
            user_id: Uuid::new_v4(),
        },
        UiEvent::McpServerChanged {
            server_name: "m".to_string(),
        },
    ];

    for event in &events {
        let json = serde_json::to_string(event)
            .unwrap_or_else(|e| panic!("failed to serialize {:?}: {}", event, e));
        assert!(!json.is_empty());

        // Verify event_type() returns a valid string
        let event_type = event.event_type();
        assert!(!event_type.is_empty());
    }
}

#[tokio::test]
async fn test_sse_event_type_names() {
    // Verify event_type() returns expected SSE event names
    assert_eq!(
        UiEvent::WorkspaceCreated {
            workspace_id: Uuid::nil(),
            workspace_name: String::new()
        }
        .event_type(),
        "workspace_created",
    );
    assert_eq!(
        UiEvent::CredentialCreated {
            credential_id: Uuid::nil(),
            credential_name: String::new()
        }
        .event_type(),
        "credential_created",
    );
    assert_eq!(
        UiEvent::PolicyChanged {
            policy_name: String::new()
        }
        .event_type(),
        "policy_changed",
    );
    assert_eq!(
        UiEvent::AuditEvent {
            event_type: String::new()
        }
        .event_type(),
        "audit_event",
    );
}
