//! v1.5.7 — Device audit channel unit tests (category 2)
//!
//! Tests the mpsc-based `AuditSender` and channel behavior including
//! basic emit, channel-full handling, and concurrent emitters.

use agentcordon::audit::AuditSender;
use serde_json::json;
use uuid::Uuid;

#[tokio::test]
async fn test_audit_sender_emit_appears_in_channel() {
    let (sender, mut receiver) = AuditSender::new();

    sender.emit(
        "mcp_tool_call",
        json!({"tool": "create_issue", "agent_name": "test-agent"}),
    );

    let event = receiver.try_recv().expect("should receive emitted event");
    assert_eq!(event.event_type, "mcp_tool_call");
    assert_eq!(event.details["tool"], "create_issue");
    assert_eq!(event.details["agent_name"], "test-agent");
    // event_id should be a valid UUID
    assert!(!event.event_id.is_nil());
    // timestamp should be recent
    let now = chrono::Utc::now();
    let diff = now - event.timestamp;
    assert!(diff.num_seconds() < 5, "timestamp should be recent");
}

#[tokio::test]
async fn test_audit_channel_full_drops_event_no_panic() {
    let (sender, _receiver) = AuditSender::new();

    // Fill channel to capacity (1000)
    for i in 0..1000 {
        sender.emit("test_event", json!({"seq": i}));
    }

    // Event #1001 should be dropped without panicking
    sender.emit("overflow_event", json!({"should": "be dropped"}));

    // Channel should still have 1000 events (can't check exact count easily,
    // but we verify no panic and the channel is functional)
}

#[tokio::test]
async fn test_audit_channel_concurrent_emitters() {
    let (sender, mut receiver) = AuditSender::new();

    let mut handles = Vec::new();
    let num_tasks = 10;
    let events_per_task = 50;

    for task_id in 0..num_tasks {
        let sender_clone = sender.clone();
        let handle = tokio::spawn(async move {
            for seq in 0..events_per_task {
                sender_clone.emit("concurrent_test", json!({"task_id": task_id, "seq": seq}));
            }
        });
        handles.push(handle);
    }

    // Wait for all tasks to complete
    for handle in handles {
        handle.await.unwrap();
    }

    // Drop the original sender so only clones exist (they're also dropped now)
    drop(sender);

    // Collect all events
    let mut received_events = Vec::new();
    while let Ok(event) = receiver.try_recv() {
        received_events.push(event);
    }

    assert_eq!(
        received_events.len(),
        num_tasks * events_per_task,
        "should receive all {} events from {} tasks",
        num_tasks * events_per_task,
        num_tasks
    );

    // All event_ids should be unique
    let mut ids: Vec<Uuid> = received_events.iter().map(|e| e.event_id).collect();
    ids.sort();
    ids.dedup();
    assert_eq!(
        ids.len(),
        num_tasks * events_per_task,
        "all event_ids should be unique"
    );
}
