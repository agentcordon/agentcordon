//! v1.5.7 — End-to-end flow tests (category 6)
//!
//! Tests the full audit lifecycle: device sends events over WebSocket ->
//! server persists -> events visible in admin audit API. Also tests
//! dedup across device reconnects.

use common::*;
use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use tokio_tungstenite::tungstenite::{client::IntoClientRequest, http::HeaderValue, Message};
use uuid::Uuid;

use agent_cordon_server::test_helpers::TestAppBuilder;

use crate::common;

// ---------------------------------------------------------------------------
// Helpers (reuse patterns from v157_audit_sync)
// ---------------------------------------------------------------------------

async fn start_test_server(
    ctx: &agent_cordon_server::test_helpers::TestContext,
) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let app = agent_cordon_server::build_router(ctx.state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind test listener");
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (addr, handle)
}

async fn ws_connect_device(
    addr: std::net::SocketAddr,
    device_jwt: &str,
) -> tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>> {
    let url = format!("ws://{}/api/v1/devices/audit-stream", addr);
    let mut request = url.into_client_request().expect("build WS request");
    request.headers_mut().insert(
        "Authorization",
        HeaderValue::from_str(&format!("Bearer {}", device_jwt)).unwrap(),
    );
    let (ws, _) = tokio_tungstenite::connect_async(request)
        .await
        .expect("WS connect");
    ws
}

fn make_audit_event_with_id(
    event_id: &str,
    event_type: &str,
    session_id: &str,
    seq: u64,
    details: Value,
) -> Value {
    json!({
        "events": [{
            "event_id": event_id,
            "session_id": session_id,
            "seq": seq,
            "event_type": event_type,
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "details": details
        }]
    })
}

async fn read_ws_msg(
    ws: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
) -> Option<Value> {
    let timeout = tokio::time::timeout(std::time::Duration::from_secs(5), ws.next()).await;
    match timeout {
        Ok(Some(Ok(Message::Text(text)))) => serde_json::from_str(&text).ok(),
        _ => None,
    }
}

// ===========================================================================
// Category 6: E2E Tests
// ===========================================================================

#[tokio::test]
#[ignore = "REMOVED: v2.0 has no device endpoints — devices unified into workspaces"]
async fn test_e2e_mcp_tool_call_audit_lifecycle() {
    // Full lifecycle:
    // 1. Admin creates device + agent
    // 2. Device connects WS audit stream
    // 3. Simulated MCP tool call event sent via WS
    // 4. Server persists with device attribution
    // 5. Event visible via admin audit API with correct metadata

    let ctx = TestAppBuilder::new()
        .with_admin()
        .build()
        .await;
    let (addr, _handle) = start_test_server(&ctx).await;

    // Create admin session for API calls
    use agent_cordon_core::domain::user::UserRole;
    let _admin_user = create_user_in_db(
        &*ctx.store,
        "e2e-admin",
        "password123!",
        UserRole::Admin,
        true,
        true,
    )
    .await;
    let cookie = login_user_combined(&ctx.app, "e2e-admin", "password123!").await;
    let csrf = extract_csrf_from_cookie(&cookie).unwrap();

    // Create and enroll a device via API
    let (sig_key, sig_jwk, _enc_key, enc_jwk) = generate_dual_p256_keypairs_jwk();
    let (device_id, bootstrap_token) =
        create_device_via_api(&ctx.state, &cookie, &csrf, "e2e-test-device").await;
    enroll_device(&ctx.state, &bootstrap_token, &sig_jwk, &enc_jwk).await;

    // Connect device WS audit stream
    let jti = Uuid::new_v4().to_string();
    let device_jwt = sign_device_jwt(&sig_key, &device_id, &jti);
    let mut ws = ws_connect_device(addr, &device_jwt).await;

    // Simulate an MCP tool call event from the device
    let event_id = Uuid::new_v4().to_string();
    let tool_call_time = chrono::Utc::now();
    let event = make_audit_event_with_id(
        &event_id,
        "mcp_tool_call",
        &jti,
        0,
        json!({
            "agent_name": "my-copilot",
            "mcp_server": "github",
            "tool": "create_issue",
            "allowed": true
        }),
    );
    ws.send(Message::Text(event.to_string())).await.unwrap();

    // Wait for ack
    let response = read_ws_msg(&mut ws).await.expect("should receive ack");
    assert_eq!(response["ack"].as_str().unwrap(), event_id);
    ws.close(None).await.ok();

    // Query audit log via admin API
    let admin_jwt = ctx_admin_jwt(&ctx).await;
    let (status, body) = ctx_admin_send(
        &ctx,
        axum::http::Method::GET,
        "/api/v1/audit?limit=10",
        &admin_jwt,
        None,
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK);

    let events = body["data"].as_array().expect("data should be array");
    let our_event = events
        .iter()
        .find(|e| e["id"].as_str() == Some(&event_id))
        .expect("our event should appear in audit log");

    // Verify all fields
    assert_eq!(our_event["device_id"].as_str().unwrap(), device_id);
    assert_eq!(
        our_event["device_name"].as_str().unwrap(),
        "e2e-test-device"
    );
    assert_eq!(our_event["metadata"]["agent_name"], "my-copilot");
    assert_eq!(our_event["metadata"]["mcp_server"], "github");
    assert_eq!(our_event["metadata"]["tool"], "create_issue");
    assert_eq!(our_event["metadata"]["allowed"], true);

    // Timestamp should be within a reasonable range (60s to account for test timing)
    let event_ts = our_event["timestamp"].as_str().unwrap();
    let parsed_ts = chrono::DateTime::parse_from_rfc3339(event_ts).unwrap();
    let diff = (parsed_ts.timestamp() - tool_call_time.timestamp()).abs();
    assert!(
        diff < 60,
        "event timestamp should be within 60s of tool call time (diff={}s)",
        diff
    );
}

#[tokio::test]
#[ignore = "REMOVED: v2.0 has no device endpoints — devices unified into workspaces"]
async fn test_e2e_device_restart_no_duplicate_events() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let (addr, _handle) = start_test_server(&ctx).await;

    // Generate 5 event IDs upfront
    let event_ids: Vec<String> = (0..5).map(|_| Uuid::new_v4().to_string()).collect();

    // Session 1: send all 5 events
    let jti1 = Uuid::new_v4().to_string();
    let device_jwt1 = sign_device_jwt(ctx.admin_signing_key(), ctx.admin_device_id(), &jti1);
    let mut ws1 = ws_connect_device(addr, &device_jwt1).await;

    for (seq, eid) in event_ids.iter().enumerate() {
        let event =
            make_audit_event_with_id(eid, "mcp_tool_call", &jti1, seq as u64, json!({"seq": seq}));
        ws1.send(Message::Text(event.to_string())).await.unwrap();
        let response = read_ws_msg(&mut ws1).await.expect("should receive ack");
        assert_eq!(response["ack"].as_str().unwrap(), eid.as_str());
    }

    // Disconnect (simulate device restart)
    ws1.close(None).await.ok();
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Session 2: reconnect and resend events 3-4 (simulating uncertain ack state)
    let jti2 = Uuid::new_v4().to_string();
    let device_jwt2 = sign_device_jwt(ctx.admin_signing_key(), ctx.admin_device_id(), &jti2);
    let mut ws2 = ws_connect_device(addr, &device_jwt2).await;

    for (seq, eid) in event_ids[3..5].iter().enumerate() {
        let event = make_audit_event_with_id(
            eid,
            "mcp_tool_call",
            &jti2,
            seq as u64,
            json!({"seq": seq + 3}),
        );
        ws2.send(Message::Text(event.to_string())).await.unwrap();
        let response = read_ws_msg(&mut ws2)
            .await
            .expect("should receive ack on resend");
        assert_eq!(
            response["ack"].as_str().unwrap(),
            eid.as_str(),
            "duplicate should still be acked"
        );
    }

    ws2.close(None).await.ok();

    // Verify store has exactly 5 events (not 7)
    let stored = ctx
        .store
        .list_audit_events_filtered(&agent_cordon_core::storage::AuditFilter {
            limit: 100,
            ..Default::default()
        })
        .await
        .unwrap();

    let matching: Vec<_> = stored
        .iter()
        .filter(|e| event_ids.contains(&e.id.to_string()))
        .collect();
    assert_eq!(
        matching.len(),
        5,
        "should have exactly 5 events, not 7 (dedup should prevent duplicates)"
    );
}
