use async_trait::async_trait;

use crate::domain::audit::AuditEvent;
use crate::error::StoreError;

/// Structured filter for audit event queries.
///
/// Replaces positional parameters so new filters can be added without breaking
/// every callsite.
#[derive(Debug, Default, Clone)]
pub struct AuditFilter {
    pub limit: u32,
    pub offset: u32,
    pub resource_type: Option<String>,
    pub resource_id: Option<String>,
    pub source: Option<String>,
    pub action: Option<String>,
    pub decision: Option<String>,
    pub event_type: Option<String>,
    /// Unified workspace identity filter (replaces agent_id + device_id).
    pub workspace_id: Option<String>,
    pub workspace_name: Option<String>,
    pub user_id: Option<String>,
    /// Event types to exclude from results (e.g. `["policy_evaluated"]`).
    pub exclude_event_types: Vec<String>,
}

#[async_trait]
pub trait AuditStore: Send + Sync {
    async fn append_audit_event(&self, event: &AuditEvent) -> Result<(), StoreError>;
    async fn list_audit_events(
        &self,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<AuditEvent>, StoreError>;
    async fn get_audit_event(&self, id: &uuid::Uuid) -> Result<Option<AuditEvent>, StoreError>;
    async fn list_audit_events_filtered(
        &self,
        filter: &AuditFilter,
    ) -> Result<Vec<AuditEvent>, StoreError>;
}
