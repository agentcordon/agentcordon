//! WebSocket endpoint for device audit event ingestion.
//!
//! `GET /api/v1/workspaces/audit-stream` — accepts a WebSocket upgrade from
//! an authenticated workspace (device). The device sends audit events as JSON
//! envelopes; the server stores them and acks each one.
//!
//! Wire format (device -> server):
//! ```json
//! { "events": [{ "event_id": "...", "session_id": "...", "seq": 0, "event_type": "...", "timestamp": "...", "details": {...} }] }
//! ```
//!
//! Wire format (server -> device):
//! ```json
//! { "ack": "<event_id>" }
//! ```

use std::collections::{HashSet, VecDeque};
use std::time::Instant;

use axum::{
    extract::{ws, State, WebSocketUpgrade},
    http::HeaderMap,
    response::IntoResponse,
};
use serde::Deserialize;
use uuid::Uuid;

use agent_cordon_core::domain::audit::{AuditDecision, AuditEvent, AuditEventType};
use agent_cordon_core::domain::workspace::Workspace;

use crate::events::UiEvent;
use crate::extractors::AuthenticatedWorkspace;
use crate::response::ApiError;
use crate::state::{AppState, SharedStore};

/// Wire format: a batch of events from the device.
#[derive(Debug, Deserialize)]
pub(super) struct WireEnvelope {
    pub(super) events: Vec<WireEvent>,
}

/// A single event in the wire format.
#[derive(Debug, Deserialize)]
pub(super) struct WireEvent {
    pub(super) event_id: String,
    #[allow(dead_code)]
    pub(super) session_id: String,
    #[allow(dead_code)]
    pub(super) seq: u64,
    pub(super) event_type: String,
    pub(super) timestamp: String,
    pub(super) details: serde_json::Value,
}

/// Bounded dedup set that evicts the oldest entries when capacity is reached.
/// Prevents unbounded memory growth on long-lived WebSocket connections.
const MAX_SEEN_IDS: usize = 10_000;

struct BoundedIdSet {
    ids: HashSet<String>,
    order: VecDeque<String>,
}

impl BoundedIdSet {
    fn new() -> Self {
        Self {
            ids: HashSet::with_capacity(MAX_SEEN_IDS),
            order: VecDeque::with_capacity(MAX_SEEN_IDS),
        }
    }

    fn contains(&self, id: &str) -> bool {
        self.ids.contains(id)
    }

    fn insert(&mut self, id: String) {
        if self.ids.len() >= MAX_SEEN_IDS {
            // Evict the oldest entry
            if let Some(oldest) = self.order.pop_front() {
                self.ids.remove(&oldest);
            }
        }
        self.ids.insert(id.clone());
        self.order.push_back(id);
    }
}

/// Rate limiter state per connection.
struct RateLimit {
    count: u32,
    window_start: Instant,
}

impl RateLimit {
    fn new() -> Self {
        Self {
            count: 0,
            window_start: Instant::now(),
        }
    }

    /// Check if a new event is within the rate limit (100/sec).
    /// Returns true if allowed, false if rate-limited.
    fn check(&mut self) -> bool {
        let now = Instant::now();
        if now.duration_since(self.window_start).as_secs() >= 1 {
            self.count = 0;
            self.window_start = now;
        }
        self.count += 1;
        self.count <= 100
    }
}

/// GET /api/v1/workspaces/audit-stream — WebSocket upgrade for audit event ingestion.
///
/// Authenticates the workspace via the `Authorization: Bearer` header before
/// upgrading to WebSocket. After upgrade, the device streams audit events and
/// the server persists them.
pub(super) async fn audit_stream_ws(
    State(state): State<AppState>,
    auth_ws: AuthenticatedWorkspace,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Result<impl IntoResponse, ApiError> {
    let workspace = auth_ws.workspace;

    // Extract the JTI from the JWT for session binding.
    let token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .unwrap_or("");
    let jti = extract_jti_from_jwt(token);

    tracing::info!(
        workspace_id = %workspace.id.0,
        workspace_name = %workspace.name,
        "audit-stream WebSocket upgrade accepted"
    );

    Ok(ws.on_upgrade(move |socket| handle_audit_socket(socket, state, workspace, jti)))
}

/// Handle the WebSocket connection after upgrade.
async fn handle_audit_socket(
    mut socket: ws::WebSocket,
    state: AppState,
    workspace: Workspace,
    expected_session_id: String,
) {
    let mut rate_limit = RateLimit::new();
    let mut expected_seq: u64 = 0;
    let mut seen_ids = BoundedIdSet::new();

    loop {
        let msg = match socket.recv().await {
            Some(Ok(msg)) => msg,
            Some(Err(e)) => {
                tracing::debug!(error = %e, "audit WS read error");
                break;
            }
            None => break, // Client closed
        };

        let text = match msg {
            ws::Message::Text(t) => t,
            ws::Message::Close(_) => break,
            _ => continue, // Ignore ping/pong/binary
        };

        let envelope: WireEnvelope = match serde_json::from_str(&text) {
            Ok(e) => e,
            Err(_) => {
                send_error(&mut socket, "invalid_format", "malformed JSON envelope").await;
                continue;
            }
        };

        for wire_event in envelope.events {
            if let Err(msg) = process_wire_event(
                &wire_event,
                &state,
                &workspace,
                &expected_session_id,
                &mut rate_limit,
                &mut expected_seq,
                &mut seen_ids,
            )
            .await
            {
                send_error(&mut socket, &msg.0, &msg.1).await;
                continue;
            }

            // Ack the event.
            let ack = serde_json::json!({ "ack": wire_event.event_id });
            if send_text(&mut socket, &ack.to_string()).await.is_err() {
                return;
            }
        }
    }

    tracing::debug!(
        workspace_id = %workspace.id.0,
        "audit-stream WebSocket closed"
    );
}

/// Process a single wire event: validate, convert, store, emit UI event.
///
/// Returns `Ok(())` on success, or `Err((code, message))` on validation failure.
async fn process_wire_event(
    wire: &WireEvent,
    state: &AppState,
    workspace: &Workspace,
    expected_session_id: &str,
    rate_limit: &mut RateLimit,
    expected_seq: &mut u64,
    seen_ids: &mut BoundedIdSet,
) -> Result<(), (String, String)> {
    // Validate required fields.
    if wire.event_id.is_empty() || wire.event_type.is_empty() || wire.timestamp.is_empty() {
        return Err(("invalid_event".into(), "missing required fields".into()));
    }

    // Session binding: session_id must match JWT jti.
    if wire.session_id != expected_session_id {
        return Err((
            "session_mismatch".into(),
            "session_id does not match JWT jti".into(),
        ));
    }

    // Rate limit check.
    if !rate_limit.check() {
        return Err(("rate_limited".into(), "too many events per second".into()));
    }

    // Sequence gap detection (warn only, don't reject).
    if wire.seq != *expected_seq {
        tracing::warn!(
            expected = *expected_seq,
            actual = wire.seq,
            "audit event sequence gap detected"
        );
    }
    *expected_seq = wire.seq + 1;

    // Dedup: skip if we've already processed this event_id in this session.
    if seen_ids.contains(&wire.event_id) {
        // Still ack it (idempotent), but don't store again.
        return Ok(());
    }
    seen_ids.insert(wire.event_id.clone());

    // Convert wire event to domain AuditEvent.
    let mut event = wire_to_audit_event(wire, workspace);

    // Resolve MCP server name -> UUID for consistent resource_id filtering.
    resolve_mcp_resource_id(&mut event, &state.store, workspace).await;

    // Store in database (ignore duplicate key errors for cross-session dedup).
    match state.store.append_audit_event(&event).await {
        Ok(()) => {}
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("UNIQUE constraint") || msg.contains("duplicate key") {
                tracing::debug!(event_id = %wire.event_id, "duplicate audit event, skipping");
            } else {
                tracing::error!(error = %e, "failed to store audit event");
                return Err(("store_error".into(), "failed to persist event".into()));
            }
        }
    }

    // Emit UI event for real-time dashboard updates.
    state.ui_event_bus.emit(UiEvent::AuditEvent {
        event_type: wire.event_type.clone(),
    });

    Ok(())
}

/// Convert a wire event into a domain AuditEvent.
///
/// Server-side attribution: workspace_id and workspace_name come from the
/// authenticated JWT, NOT from the client-supplied data. This prevents a
/// device from claiming to be a different workspace.
fn wire_to_audit_event(wire: &WireEvent, workspace: &Workspace) -> AuditEvent {
    let event_id = Uuid::parse_str(&wire.event_id).unwrap_or_else(|_| Uuid::new_v4());

    let timestamp = chrono::DateTime::parse_from_rfc3339(&wire.timestamp)
        .map(|t| t.with_timezone(&chrono::Utc))
        .unwrap_or_else(|_| chrono::Utc::now());

    let event_type = map_wire_event_type(&wire.event_type);

    // Extract workspace_id from details if present (for filtering),
    // but always override with the authenticated workspace.
    let workspace_id = Some(workspace.id.clone());
    let workspace_name = Some(workspace.name.clone());

    AuditEvent {
        id: event_id,
        timestamp,
        correlation_id: Uuid::new_v4().to_string(),
        event_type,
        workspace_id,
        workspace_name,
        user_id: None,
        user_name: None,
        action: wire.event_type.clone(),
        resource_type: resource_type_from_event(&wire.event_type),
        resource_id: extract_resource_id(&wire.details),
        decision: decision_from_details(&wire.details),
        decision_reason: None,
        metadata: wire.details.clone(),
    }
}

/// Map wire event type strings to the AuditEventType enum.
fn map_wire_event_type(s: &str) -> AuditEventType {
    match s {
        "mcp_tool_call" => AuditEventType::McpToolCall,
        "mcp_tool_denied" => AuditEventType::McpToolDenied,
        "credential_proxy_auth" => AuditEventType::CredentialProxyAuth,
        "credential_stored" => AuditEventType::CredentialStored,
        "credential_scope_check" => AuditEventType::CredentialScopeCheck,
        "subprocess_spawned" => AuditEventType::SubprocessSpawned,
        "subprocess_crashed" => AuditEventType::SubprocessCrashed,
        "subprocess_respawned" => AuditEventType::SubprocessRespawned,
        "sse_connected" => AuditEventType::SseConnected,
        "sse_disconnected" => AuditEventType::SseDisconnected,
        _ => AuditEventType::McpToolCall, // Fallback for unknown types
    }
}

/// Derive resource_type from the event_type string.
fn resource_type_from_event(event_type: &str) -> String {
    if event_type.starts_with("mcp_") {
        "mcp_server".to_string()
    } else if event_type.starts_with("credential_") {
        "credential".to_string()
    } else if event_type.starts_with("subprocess_") {
        "subprocess".to_string()
    } else if event_type.starts_with("sse_") {
        "sse".to_string()
    } else {
        "workspace".to_string()
    }
}

/// Extract a resource_id from the event details (if present).
fn extract_resource_id(details: &serde_json::Value) -> Option<String> {
    // Try common fields: mcp_server, credential_name
    details
        .get("mcp_server")
        .or_else(|| details.get("credential_name"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

/// Resolve MCP server name to UUID for audit events.
///
/// The CLI emits audit events with `mcp_server: "<name>"` in details, but the
/// History tab queries by MCP server UUID. This function looks up the UUID from
/// the (workspace, name) pair and updates `resource_id` so that filtering by
/// UUID works correctly.
async fn resolve_mcp_resource_id(
    event: &mut AuditEvent,
    store: &SharedStore,
    workspace: &Workspace,
) {
    // Only resolve for MCP events that have a name-based resource_id.
    if event.resource_type != "mcp_server" {
        return;
    }

    let server_name = match &event.resource_id {
        Some(name) => name.clone(),
        None => return,
    };

    // If resource_id is already a valid UUID, no resolution needed.
    if Uuid::parse_str(&server_name).is_ok() {
        return;
    }

    // Look up the MCP server by workspace + name to get its UUID.
    match store
        .get_mcp_server_by_workspace_and_name(&workspace.id, &server_name)
        .await
    {
        Ok(Some(mcp_server)) => {
            event.resource_id = Some(mcp_server.id.0.to_string());
        }
        Ok(None) => {
            tracing::warn!(
                server_name = %server_name,
                "Could not resolve MCP server '{}' by name — skipping enrichment",
                server_name
            );
        }
        Err(e) => {
            tracing::debug!(
                server_name = %server_name,
                error = %e,
                "failed to resolve MCP server name to UUID for audit event"
            );
        }
    }
}

/// Derive the audit decision from the event details.
fn decision_from_details(details: &serde_json::Value) -> AuditDecision {
    match details.get("allowed").and_then(|v| v.as_bool()) {
        Some(true) => AuditDecision::Permit,
        Some(false) => AuditDecision::Forbid,
        None => AuditDecision::NotApplicable,
    }
}

/// Extract a session identifier from a token.
///
/// For JWTs: extracts the `jti` claim.
/// For opaque OAuth tokens: derives a deterministic UUID from the token hash.
fn extract_jti_from_jwt(token: &str) -> String {
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
    // For opaque tokens (OAuth), derive a deterministic session ID from the token hash.
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(token.as_bytes());
    // Use first 16 bytes as a UUID v4-like identifier
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&hash[..16]);
    Uuid::from_bytes(bytes).to_string()
}

/// Send a JSON text message over the WebSocket.
async fn send_text(socket: &mut ws::WebSocket, text: &str) -> Result<(), ()> {
    socket
        .send(ws::Message::Text(text.to_string().into()))
        .await
        .map_err(|_| ())
}

/// Send an error message over the WebSocket.
async fn send_error(socket: &mut ws::WebSocket, code: &str, message: &str) {
    let msg = serde_json::json!({ "error": code, "message": message });
    let _ = send_text(socket, &msg.to_string()).await;
}

/// POST /api/v1/workspaces/audit-events — batch audit event ingestion via REST.
pub(super) async fn audit_ingest_post(
    State(state): State<AppState>,
    auth_ws: AuthenticatedWorkspace,
    axum::Json(envelope): axum::Json<WireEnvelope>,
) -> Result<impl IntoResponse, ApiError> {
    let workspace = auth_ws.workspace;

    let mut accepted = 0u32;
    for wire_event in &envelope.events {
        if wire_event.event_id.is_empty()
            || wire_event.event_type.is_empty()
            || wire_event.timestamp.is_empty()
        {
            continue; // skip malformed
        }
        let mut event = wire_to_audit_event(wire_event, &workspace);

        // Resolve MCP server name -> UUID for consistent resource_id filtering.
        resolve_mcp_resource_id(&mut event, &state.store, &workspace).await;

        match state.store.append_audit_event(&event).await {
            Ok(()) => {
                state.ui_event_bus.emit(UiEvent::AuditEvent {
                    event_type: wire_event.event_type.clone(),
                });
                accepted += 1;
            }
            Err(e) => {
                let msg = e.to_string();
                if msg.contains("UNIQUE constraint") || msg.contains("duplicate key") {
                    accepted += 1; // idempotent
                } else {
                    tracing::error!(error = %e, "failed to store audit event");
                }
            }
        }
    }

    Ok(axum::Json(serde_json::json!({ "accepted": accepted })))
}
