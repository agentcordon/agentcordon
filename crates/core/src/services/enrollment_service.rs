use std::sync::Arc;

use crate::domain::enrollment::EnrollmentSession;
use crate::error::ServiceError;
use crate::storage::traits::{AuditStore, EnrollmentStore};

/// Service layer for enrollment session operations.
///
/// Manages the enrollment lifecycle (create, approve, deny, claim).
/// Token generation and crypto remain in route handlers.
pub struct EnrollmentService<S: EnrollmentStore + AuditStore> {
    store: Arc<S>,
}

impl<S: EnrollmentStore + AuditStore> EnrollmentService<S> {
    pub fn new(store: Arc<S>) -> Self {
        Self { store }
    }

    pub async fn create_session(&self, session: &EnrollmentSession) -> Result<(), ServiceError> {
        if session.agent_name.trim().is_empty() {
            return Err(ServiceError::Validation {
                field: "agent_name".into(),
                message: "agent name must not be empty".into(),
            });
        }
        self.store.create_enrollment_session(session).await?;
        Ok(())
    }

    pub async fn list_pending(&self) -> Result<Vec<EnrollmentSession>, ServiceError> {
        Ok(self.store.list_pending_enrollment_sessions().await?)
    }

    pub async fn get_by_ref(&self, approval_ref: &str) -> Result<EnrollmentSession, ServiceError> {
        self.store
            .get_enrollment_session_by_ref(approval_ref)
            .await?
            .ok_or_else(|| ServiceError::NotFound {
                resource: "enrollment_session".into(),
                id: approval_ref.to_string(),
            })
    }

    pub async fn approve(&self, session_id: &str, approved_by: &str) -> Result<(), ServiceError> {
        let approved = self
            .store
            .approve_enrollment_session(session_id, approved_by)
            .await?;
        if !approved {
            return Err(ServiceError::NotFound {
                resource: "enrollment_session".into(),
                id: session_id.to_string(),
            });
        }
        Ok(())
    }

    pub async fn reject(&self, session_id: &str) -> Result<(), ServiceError> {
        let denied = self.store.deny_enrollment_session(session_id).await?;
        if !denied {
            return Err(ServiceError::NotFound {
                resource: "enrollment_session".into(),
                id: session_id.to_string(),
            });
        }
        Ok(())
    }

    pub async fn complete(&self, session_id: &str) -> Result<Option<String>, ServiceError> {
        let auth_code = self.store.claim_enrollment_session(session_id).await?;
        Ok(auth_code)
    }
}
