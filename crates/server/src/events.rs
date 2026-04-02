//! In-process event bus for server-to-device push notifications.
//!
//! Uses `tokio::sync::broadcast` to fan out events to all connected
//! SSE clients (device SSE endpoints).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use serde::Serialize;
use tokio::sync::broadcast;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// UI Events (browser SSE — parallel to DeviceEvent)
// ---------------------------------------------------------------------------

/// Events pushed to browser clients via the `/api/v1/events/ui` SSE endpoint.
///
/// These are separate from `DeviceEvent` (which targets device daemons).
/// UI events notify the browser of entity changes so pages can auto-refresh.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum UiEvent {
    WorkspaceCreated {
        workspace_id: Uuid,
        workspace_name: String,
    },
    WorkspaceUpdated {
        workspace_id: Uuid,
    },
    CredentialCreated {
        credential_id: Uuid,
        credential_name: String,
    },
    CredentialUpdated {
        credential_id: Uuid,
    },
    CredentialDeleted {
        credential_id: Uuid,
    },
    PolicyChanged {
        policy_name: String,
    },
    AuditEvent {
        event_type: String,
    },
    UserCreated {
        user_id: Uuid,
    },
    McpServerChanged {
        server_name: String,
    },
    UserUpdated {
        user_id: Uuid,
    },
    UserDeleted {
        user_id: Uuid,
    },
    VaultChanged {
        vault_name: String,
    },
    WorkspaceDeleted {
        workspace_id: Uuid,
    },
}

impl UiEvent {
    /// SSE event type name for the `event:` field.
    pub fn event_type(&self) -> &'static str {
        match self {
            UiEvent::WorkspaceCreated { .. } => "workspace_created",
            UiEvent::WorkspaceUpdated { .. } => "workspace_updated",
            UiEvent::CredentialCreated { .. } => "credential_created",
            UiEvent::CredentialUpdated { .. } => "credential_updated",
            UiEvent::CredentialDeleted { .. } => "credential_deleted",
            UiEvent::PolicyChanged { .. } => "policy_changed",
            UiEvent::AuditEvent { .. } => "audit_event",
            UiEvent::UserCreated { .. } => "user_created",
            UiEvent::McpServerChanged { .. } => "mcp_server_changed",
            UiEvent::UserUpdated { .. } => "user_updated",
            UiEvent::UserDeleted { .. } => "user_deleted",
            UiEvent::VaultChanged { .. } => "vault_changed",
            UiEvent::WorkspaceDeleted { .. } => "workspace_deleted",
        }
    }
}

/// In-process broadcast event bus for UI (browser) events.
#[derive(Clone)]
pub struct UiEventBus {
    sender: broadcast::Sender<UiEvent>,
}

impl UiEventBus {
    /// Create a new UI event bus with the given channel capacity.
    pub fn new(capacity: usize) -> Self {
        let (sender, _) = broadcast::channel(capacity);
        Self { sender }
    }

    /// Subscribe to the UI event stream.
    pub fn subscribe(&self) -> broadcast::Receiver<UiEvent> {
        self.sender.subscribe()
    }

    /// Emit a UI event to all subscribers (browser SSE connections).
    pub fn emit(&self, event: UiEvent) {
        let _ = self.sender.send(event);
    }
}

/// Events that can be pushed to workspaces via SSE.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DeviceEvent {
    /// A workspace's status changed (e.g., enabled/disabled).
    WorkspaceStatusChanged { workspace_id: Uuid },
    /// A credential's secret was rotated.
    CredentialRotated { credential_name: String },
    /// A workspace was revoked.
    WorkspaceRevoked { workspace_id: Uuid, pk_hash: String },
    /// A Cedar policy was created, updated, or deleted.
    /// Also covers permission changes — grants ARE Cedar policies.
    PolicyChanged { policy_name: String },
}

impl DeviceEvent {
    /// SSE event type name for the `event:` field.
    pub fn event_type(&self) -> &'static str {
        match self {
            DeviceEvent::WorkspaceStatusChanged { .. } => "workspace_status_changed",
            DeviceEvent::CredentialRotated { .. } => "credential_rotated",
            DeviceEvent::WorkspaceRevoked { .. } => "workspace_revoked",
            DeviceEvent::PolicyChanged { .. } => "policy_changed",
        }
    }
}

/// In-process broadcast event bus.
#[derive(Clone)]
pub struct EventBus {
    sender: broadcast::Sender<DeviceEvent>,
}

impl EventBus {
    /// Create a new event bus with the given channel capacity.
    pub fn new(capacity: usize) -> Self {
        let (sender, _) = broadcast::channel(capacity);
        Self { sender }
    }

    /// Subscribe to the event stream. Returns a receiver that will get
    /// all events emitted after this call.
    pub fn subscribe(&self) -> broadcast::Receiver<DeviceEvent> {
        self.sender.subscribe()
    }

    /// Emit an event to all subscribers. If there are no subscribers,
    /// the event is silently dropped.
    pub fn emit(&self, event: DeviceEvent) {
        // send() returns Err only when there are no active receivers,
        // which is fine — just means no SSE clients are connected.
        let _ = self.sender.send(event);
    }
}

// ---------------------------------------------------------------------------
// SSE Connection Tracker (per-user connection limiting)
// ---------------------------------------------------------------------------

/// Tracks active SSE connections per user to prevent connection leaks.
///
/// Each user is limited to `max_per_user` concurrent SSE connections.
/// When a connection is acquired, an [`SseConnectionGuard`] is returned
/// that automatically decrements the count when dropped.
#[derive(Clone)]
pub struct SseConnectionTracker {
    connections: Arc<Mutex<HashMap<Uuid, usize>>>,
    max_per_user: usize,
}

impl SseConnectionTracker {
    /// Create a new tracker with the given per-user connection limit.
    pub fn new(max_per_user: usize) -> Self {
        Self {
            connections: Arc::new(Mutex::new(HashMap::new())),
            max_per_user,
        }
    }

    /// Try to acquire an SSE connection slot for the given user.
    ///
    /// Returns `Ok(SseConnectionGuard)` if under the limit, or `Err(())` if
    /// the user already has `max_per_user` active connections.
    #[allow(clippy::result_unit_err)]
    pub fn try_acquire(&self, user_id: Uuid) -> Result<SseConnectionGuard, ()> {
        let mut conns = self.connections.lock().unwrap_or_else(|e| e.into_inner());
        let count = conns.entry(user_id).or_insert(0);
        if *count >= self.max_per_user {
            return Err(());
        }
        *count += 1;
        tracing::debug!(%user_id, count = *count, "SSE connection acquired");
        Ok(SseConnectionGuard {
            user_id,
            connections: Arc::clone(&self.connections),
        })
    }
}

/// RAII guard that decrements the SSE connection count when dropped.
pub struct SseConnectionGuard {
    user_id: Uuid,
    connections: Arc<Mutex<HashMap<Uuid, usize>>>,
}

impl Drop for SseConnectionGuard {
    fn drop(&mut self) {
        let mut conns = self.connections.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(count) = conns.get_mut(&self.user_id) {
            *count = count.saturating_sub(1);
            tracing::debug!(user_id = %self.user_id, count = *count, "SSE connection released");
            if *count == 0 {
                conns.remove(&self.user_id);
            }
        }
    }
}
