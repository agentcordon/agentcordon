use std::sync::Arc;

use crate::domain::audit::AuditEvent;
use crate::error::ServiceError;
use crate::storage::traits::{AuditFilter, AuditStore};

/// Service layer for audit event queries.
///
/// Provides read access to the audit log. Write access (appending events)
/// will be added as route handlers migrate to using services.
pub struct AuditService<S: AuditStore> {
    store: Arc<S>,
}

impl<S: AuditStore> AuditService<S> {
    pub fn new(store: Arc<S>) -> Self {
        Self { store }
    }

    pub async fn list(&self, limit: u32, offset: u32) -> Result<Vec<AuditEvent>, ServiceError> {
        Ok(self.store.list_audit_events(limit, offset).await?)
    }

    pub async fn list_filtered(
        &self,
        filter: &AuditFilter,
    ) -> Result<Vec<AuditEvent>, ServiceError> {
        Ok(self.store.list_audit_events_filtered(filter).await?)
    }

    pub async fn get(&self, id: &uuid::Uuid) -> Result<AuditEvent, ServiceError> {
        self.store
            .get_audit_event(id)
            .await?
            .ok_or_else(|| ServiceError::NotFound {
                resource: "audit_event".into(),
                id: id.to_string(),
            })
    }

    pub async fn append(&self, event: &AuditEvent) -> Result<(), ServiceError> {
        self.store.append_audit_event(event).await?;
        Ok(())
    }
}
