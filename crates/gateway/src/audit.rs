//! Minimal audit event infrastructure for CLI subprocess management.

use std::time::Duration;

use chrono::Utc;
use serde::Serialize;
use tokio::sync::mpsc;
use tokio::time;
use uuid::Uuid;

/// A CLI-side audit event.
#[derive(Debug, Clone, Serialize)]
pub struct AuditEvent {
    pub event_id: Uuid,
    pub event_type: String,
    pub timestamp: chrono::DateTime<Utc>,
    pub details: serde_json::Value,
}

/// Cloneable handle for emitting audit events.
#[derive(Clone)]
pub struct AuditSender {
    tx: mpsc::Sender<AuditEvent>,
}

impl AuditSender {
    /// Create a new audit channel with capacity 1000.
    /// Returns the sender handle and the receiver.
    pub fn new() -> (Self, mpsc::Receiver<AuditEvent>) {
        let (tx, rx) = mpsc::channel(1000);
        (Self { tx }, rx)
    }

    /// Emit an audit event (best-effort, drops if channel full).
    pub fn emit(&self, event_type: &str, details: serde_json::Value) {
        let event = AuditEvent {
            event_id: Uuid::new_v4(),
            event_type: event_type.to_string(),
            timestamp: Utc::now(),
            details,
        };
        if self.tx.try_send(event).is_err() {
            tracing::warn!(
                event_type = event_type,
                "audit channel full, dropping event"
            );
        }
    }
}

/// Forward audit events from the local channel to the server via REST POST.
/// Batches up to 50 events or 5s wait, fire-and-forget.
pub async fn run_audit_forwarder(
    mut rx: mpsc::Receiver<AuditEvent>,
    server_url: String,
    jwt: String,
) {
    const MAX_BATCH: usize = 50;
    let client = reqwest::Client::new();
    let url = format!("{}/api/v1/workspaces/audit-events", server_url);
    let mut batch: Vec<serde_json::Value> = Vec::with_capacity(MAX_BATCH);
    let mut seq: u64 = 0;
    let mut interval = time::interval(Duration::from_secs(5));
    // First tick fires immediately — consume it.
    interval.tick().await;

    loop {
        tokio::select! {
            event = rx.recv() => {
                match event {
                    Some(ev) => {
                        batch.push(serde_json::json!({
                            "event_id": ev.event_id.to_string(),
                            "session_id": "forwarder",
                            "seq": seq,
                            "event_type": ev.event_type,
                            "timestamp": ev.timestamp.to_rfc3339(),
                            "details": ev.details,
                        }));
                        seq += 1;
                        if batch.len() >= MAX_BATCH {
                            flush_batch(&client, &url, &jwt, &mut batch).await;
                        }
                    }
                    None => {
                        // Channel closed — flush remaining and exit.
                        flush_batch(&client, &url, &jwt, &mut batch).await;
                        return;
                    }
                }
            }
            _ = interval.tick() => {
                flush_batch(&client, &url, &jwt, &mut batch).await;
            }
        }
    }
}

/// POST a batch of audit events to the server. Fire-and-forget on failure.
async fn flush_batch(
    client: &reqwest::Client,
    url: &str,
    jwt: &str,
    batch: &mut Vec<serde_json::Value>,
) {
    if batch.is_empty() {
        return;
    }
    let payload = serde_json::json!({ "events": batch });
    match client
        .post(url)
        .header("Authorization", format!("Bearer {}", jwt))
        .json(&payload)
        .send()
        .await
    {
        Ok(resp) if !resp.status().is_success() => {
            tracing::warn!(
                status = %resp.status(),
                "audit forwarder: server rejected batch"
            );
        }
        Err(e) => {
            tracing::warn!(error = %e, "audit forwarder: failed to send batch");
        }
        _ => {}
    }
    batch.clear();
}
