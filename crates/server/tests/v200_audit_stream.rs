//! v2.0 — Workspace audit-stream WebSocket endpoint tests.
//!
//! Tests the `GET /api/v1/workspaces/audit-stream` WebSocket endpoint
//! using workspace identity JWTs (server-signed).

use common::*;
use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use tokio_tungstenite::tungstenite::{client::IntoClientRequest, http::HeaderValue, Message};
use uuid::Uuid;

use agent_cordon_server::test_helpers::TestAppBuilder;

use crate::common;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Start a TCP listener with the test app and return (addr, join_handle).
async fn start_ws_server(
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

/// Connect a WebSocket client to the audit-stream endpoint with a workspace JWT.
async fn ws_connect(
    addr: std::net::SocketAddr,
    workspace_jwt: &str,
) -> tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>> {
    let url = format!("ws://{}/api/v1/workspaces/audit-stream", addr);
    let mut request = url.into_client_request().expect("build WS request");
    request.headers_mut().insert(
        "Authorization",
        HeaderValue::from_str(&format!("Bearer {}", workspace_jwt)).unwrap(),
    );
    let (ws, _response) = tokio_tungstenite::connect_async(request)
        .await
        .expect("WS connect");
    ws
}

/// Extract session ID from a token for session binding.
///
/// For JWTs: extracts the `jti` claim.
/// For opaque OAuth tokens: derives a deterministic UUID from the token hash
/// (must match server-side `extract_jti_from_jwt` logic).
fn extract_jti(token: &str) -> String {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() == 3 {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        if let Ok(bytes) = URL_SAFE_NO_PAD.decode(parts[1]) {
            if let Ok(payload) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                if let Some(jti) = payload.get("jti").and_then(|v| v.as_str()) {
                    return jti.to_string();
                }
            }
        }
    }
    // For opaque tokens, derive deterministic session ID from token hash
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(token.as_bytes());
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&hash[..16]);
    Uuid::from_bytes(bytes).to_string()
}

/// Create a test audit event JSON envelope.
fn make_event(event_type: &str, session_id: &str, seq: u64, details: Value) -> Value {
    json!({
        "events": [{
            "event_id": Uuid::new_v4().to_string(),
            "session_id": session_id,
            "seq": seq,
            "event_type": event_type,
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "details": details
        }]
    })
}

/// Create a test audit event with a specific event_id.
fn make_event_with_id(
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

/// Read a text message from the WebSocket with a timeout.
async fn read_ws(
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
// Tests: connection and auth
// ===========================================================================

#[tokio::test]
async fn test_audit_stream_accepts_workspace_jwt() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let (addr, _handle) = start_ws_server(&ctx).await;

    let workspace_jwt = ctx_admin_jwt(&ctx).await;
    let jti = extract_jti(&workspace_jwt);

    let mut ws = ws_connect(addr, &workspace_jwt).await;

    // Verify connection is alive by sending an event and receiving ack
    let event = make_event("mcp_tool_call", &jti, 0, json!({"tool": "test"}));
    ws.send(Message::Text(event.to_string())).await.unwrap();

    let response = read_ws(&mut ws).await;
    assert!(response.is_some(), "should receive ack");
    assert!(
        response.unwrap().get("ack").is_some(),
        "response should be an ack"
    );

    ws.close(None).await.ok();
}

#[tokio::test]
async fn test_audit_stream_rejects_invalid_jwt() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let (addr, _handle) = start_ws_server(&ctx).await;

    let url = format!("ws://{}/api/v1/workspaces/audit-stream", addr);
    let mut request = url.into_client_request().expect("build WS request");
    request.headers_mut().insert(
        "Authorization",
        HeaderValue::from_str("Bearer invalid-jwt-token").unwrap(),
    );

    // Connection should fail — server returns HTTP 401 before upgrade
    let result = tokio_tungstenite::connect_async(request).await;
    assert!(result.is_err(), "invalid JWT should fail WebSocket upgrade");
}

#[tokio::test]
async fn test_audit_stream_rejects_no_auth() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let (addr, _handle) = start_ws_server(&ctx).await;

    let url = format!("ws://{}/api/v1/workspaces/audit-stream", addr);
    let request = url.into_client_request().expect("build WS request");

    // Connection should fail — no auth header
    let result = tokio_tungstenite::connect_async(request).await;
    assert!(result.is_err(), "no auth should fail WebSocket upgrade");
}

// ===========================================================================
// Tests: event ingestion and persistence
// ===========================================================================

#[tokio::test]
async fn test_audit_event_ingestion_and_persistence() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let (addr, _handle) = start_ws_server(&ctx).await;

    let workspace_jwt = ctx_admin_jwt(&ctx).await;
    let jti = extract_jti(&workspace_jwt);
    let mut ws = ws_connect(addr, &workspace_jwt).await;

    let event_id = Uuid::new_v4().to_string();
    let event = make_event_with_id(
        &event_id,
        "mcp_tool_call",
        &jti,
        0,
        json!({"tool": "create_issue", "mcp_server": "github", "allowed": true}),
    );
    ws.send(Message::Text(event.to_string())).await.unwrap();

    // Should receive ack
    let response = read_ws(&mut ws).await.expect("should receive ack");
    assert_eq!(response["ack"].as_str().unwrap(), event_id);

    // Verify persistence
    let event_uuid = Uuid::parse_str(&event_id).unwrap();
    let stored = ctx
        .store
        .get_audit_event(&event_uuid)
        .await
        .unwrap()
        .expect("event should be persisted");

    // Server-side attribution: workspace_id comes from JWT
    assert!(stored.workspace_id.is_some(), "workspace_id should be set");
    assert!(
        stored.workspace_name.is_some(),
        "workspace_name should be set"
    );
    assert_eq!(stored.action, "mcp_tool_call");
    assert_eq!(stored.metadata["tool"], "create_issue");

    ws.close(None).await.ok();
}

#[tokio::test]
async fn test_audit_event_workspace_id_from_jwt_not_details() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let (addr, _handle) = start_ws_server(&ctx).await;

    let workspace_jwt = ctx_admin_jwt(&ctx).await;
    let jti = extract_jti(&workspace_jwt);
    let mut ws = ws_connect(addr, &workspace_jwt).await;

    let fake_workspace_id = Uuid::new_v4().to_string();
    let event_id = Uuid::new_v4().to_string();
    let event = make_event_with_id(
        &event_id,
        "mcp_tool_call",
        &jti,
        0,
        json!({
            "tool": "test",
            "workspace_id": fake_workspace_id,
        }),
    );
    ws.send(Message::Text(event.to_string())).await.unwrap();
    let _ = read_ws(&mut ws).await;

    // The stored event should have the REAL workspace_id from the JWT
    let event_uuid = Uuid::parse_str(&event_id).unwrap();
    let stored = ctx
        .store
        .get_audit_event(&event_uuid)
        .await
        .unwrap()
        .expect("event should be persisted");

    let admin_agent = ctx.admin_agent.as_ref().unwrap();
    assert_eq!(
        stored.workspace_id.as_ref().unwrap().0,
        admin_agent.id.0,
        "workspace_id should match the JWT subject, not the client-supplied value"
    );

    ws.close(None).await.ok();
}

// ===========================================================================
// Tests: dedup and session binding
// ===========================================================================

#[tokio::test]
async fn test_audit_event_dedup() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let (addr, _handle) = start_ws_server(&ctx).await;

    let workspace_jwt = ctx_admin_jwt(&ctx).await;
    let jti = extract_jti(&workspace_jwt);
    let mut ws = ws_connect(addr, &workspace_jwt).await;

    let event_id = Uuid::new_v4().to_string();

    // Send same event twice
    for seq in 0..2 {
        let event = make_event_with_id(
            &event_id,
            "mcp_tool_call",
            &jti,
            seq,
            json!({"tool": "test"}),
        );
        ws.send(Message::Text(event.to_string())).await.unwrap();
        let response = read_ws(&mut ws).await.expect("should receive ack");
        assert_eq!(response["ack"].as_str().unwrap(), event_id);
    }

    // Only 1 event should be in the store
    let events = ctx
        .store
        .list_audit_events_filtered(&agent_cordon_core::storage::AuditFilter {
            limit: 50,
            ..Default::default()
        })
        .await
        .unwrap();
    let matching: Vec<_> = events
        .iter()
        .filter(|e| e.id.to_string() == event_id)
        .collect();
    assert_eq!(
        matching.len(),
        1,
        "duplicate event_id should not create duplicate records"
    );

    ws.close(None).await.ok();
}

#[tokio::test]
async fn test_audit_session_id_must_match_jwt() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let (addr, _handle) = start_ws_server(&ctx).await;

    let workspace_jwt = ctx_admin_jwt(&ctx).await;
    let jti = extract_jti(&workspace_jwt);
    let mut ws = ws_connect(addr, &workspace_jwt).await;

    // Send event with wrong session_id
    let event_id = Uuid::new_v4().to_string();
    let event = make_event_with_id(
        &event_id,
        "mcp_tool_call",
        "wrong-session-id",
        0,
        json!({"tool": "test"}),
    );
    ws.send(Message::Text(event.to_string())).await.unwrap();

    let response = read_ws(&mut ws).await.expect("should receive error");
    assert_eq!(
        response["error"].as_str().unwrap(),
        "session_mismatch",
        "wrong session_id should produce session_mismatch error"
    );

    // Event should NOT be persisted
    let event_uuid = Uuid::parse_str(&event_id).unwrap();
    let stored = ctx.store.get_audit_event(&event_uuid).await.unwrap();
    assert!(
        stored.is_none(),
        "event with wrong session_id should not be persisted"
    );

    // Connection should still be open — send a valid event
    let good_event = make_event("mcp_tool_call", &jti, 0, json!({"tool": "test"}));
    ws.send(Message::Text(good_event.to_string()))
        .await
        .unwrap();
    let response = read_ws(&mut ws)
        .await
        .expect("connection should still work");
    assert!(response.get("ack").is_some());

    ws.close(None).await.ok();
}

// ===========================================================================
// Tests: malformed events
// ===========================================================================

#[tokio::test]
async fn test_audit_malformed_event_returns_error() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let (addr, _handle) = start_ws_server(&ctx).await;

    let workspace_jwt = ctx_admin_jwt(&ctx).await;
    let jti = extract_jti(&workspace_jwt);
    let mut ws = ws_connect(addr, &workspace_jwt).await;

    // Send malformed event
    let bad = json!({"events": [{"bad_field": true}]});
    ws.send(Message::Text(bad.to_string())).await.unwrap();

    let response = read_ws(&mut ws).await.expect("should receive error");
    assert!(
        response.get("error").is_some(),
        "malformed event should return error"
    );

    // Connection should still be open — send a valid event
    let good = make_event("mcp_tool_call", &jti, 0, json!({"tool": "test"}));
    ws.send(Message::Text(good.to_string())).await.unwrap();
    let response = read_ws(&mut ws)
        .await
        .expect("should receive ack for valid event");
    assert!(response.get("ack").is_some());

    ws.close(None).await.ok();
}

// ===========================================================================
// Tests: audit events filterable by workspace_id (History tab)
// ===========================================================================

#[tokio::test]
async fn test_audit_events_filterable_by_workspace_id() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let (addr, _handle) = start_ws_server(&ctx).await;

    let workspace_jwt = ctx_admin_jwt(&ctx).await;
    let jti = extract_jti(&workspace_jwt);
    let mut ws = ws_connect(addr, &workspace_jwt).await;

    // Send a few events
    for seq in 0..3 {
        let event = make_event(
            "mcp_tool_call",
            &jti,
            seq,
            json!({"tool": format!("tool_{}", seq)}),
        );
        ws.send(Message::Text(event.to_string())).await.unwrap();
        let _ = read_ws(&mut ws).await;
    }
    ws.close(None).await.ok();

    // Filter audit events by workspace_id
    let admin_agent = ctx.admin_agent.as_ref().unwrap();
    let ws_id = admin_agent.id.0.to_string();

    let events = ctx
        .store
        .list_audit_events_filtered(&agent_cordon_core::storage::AuditFilter {
            limit: 50,
            workspace_id: Some(ws_id.clone()),
            ..Default::default()
        })
        .await
        .unwrap();

    assert_eq!(
        events.len(),
        3,
        "should find all 3 events by workspace_id filter"
    );
    for event in &events {
        assert_eq!(
            event.workspace_id.as_ref().unwrap().0.to_string(),
            ws_id,
            "all events should have the correct workspace_id"
        );
    }
}

// ===========================================================================
// Tests: decision mapping from details
// ===========================================================================

#[tokio::test]
async fn test_audit_event_decision_from_allowed_field() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let (addr, _handle) = start_ws_server(&ctx).await;

    let workspace_jwt = ctx_admin_jwt(&ctx).await;
    let jti = extract_jti(&workspace_jwt);
    let mut ws = ws_connect(addr, &workspace_jwt).await;

    // Allowed event
    let allowed_id = Uuid::new_v4().to_string();
    let event = make_event_with_id(
        &allowed_id,
        "mcp_tool_call",
        &jti,
        0,
        json!({"tool": "test", "allowed": true}),
    );
    ws.send(Message::Text(event.to_string())).await.unwrap();
    let _ = read_ws(&mut ws).await;

    // Denied event
    let denied_id = Uuid::new_v4().to_string();
    let event = make_event_with_id(
        &denied_id,
        "mcp_tool_denied",
        &jti,
        1,
        json!({"tool": "test", "allowed": false}),
    );
    ws.send(Message::Text(event.to_string())).await.unwrap();
    let _ = read_ws(&mut ws).await;
    ws.close(None).await.ok();

    // Check the allowed event
    let stored = ctx
        .store
        .get_audit_event(&Uuid::parse_str(&allowed_id).unwrap())
        .await
        .unwrap()
        .expect("allowed event should exist");
    assert!(
        matches!(
            stored.decision,
            agent_cordon_core::domain::audit::AuditDecision::Permit
        ),
        "allowed=true should map to Allow decision"
    );

    // Check the denied event
    let stored = ctx
        .store
        .get_audit_event(&Uuid::parse_str(&denied_id).unwrap())
        .await
        .unwrap()
        .expect("denied event should exist");
    assert!(
        matches!(
            stored.decision,
            agent_cordon_core::domain::audit::AuditDecision::Forbid
        ),
        "allowed=false should map to Deny decision"
    );
}
