use async_trait::async_trait;

use crate::domain::enrollment::EnrollmentSession;
use crate::error::StoreError;

#[async_trait]
pub trait EnrollmentStore: Send + Sync {
    async fn create_enrollment_session(
        &self,
        session: &EnrollmentSession,
    ) -> Result<(), StoreError>;
    async fn get_enrollment_session_by_token_hash(
        &self,
        token_hash: &str,
    ) -> Result<Option<EnrollmentSession>, StoreError>;
    async fn get_enrollment_session_by_ref(
        &self,
        approval_ref: &str,
    ) -> Result<Option<EnrollmentSession>, StoreError>;
    async fn list_pending_enrollment_sessions(&self) -> Result<Vec<EnrollmentSession>, StoreError>;
    async fn count_pending_enrollment_sessions(&self) -> Result<u32, StoreError>;
    async fn count_recent_enrollment_sessions_by_ip(
        &self,
        client_ip: &str,
        window_seconds: u64,
    ) -> Result<u32, StoreError>;
    async fn approve_enrollment_session(
        &self,
        id: &str,
        approved_by: &str,
    ) -> Result<bool, StoreError>;
    async fn deny_enrollment_session(&self, id: &str) -> Result<bool, StoreError>;
    async fn claim_enrollment_session(&self, id: &str) -> Result<Option<String>, StoreError>;
    async fn expire_enrollment_sessions(&self) -> Result<u32, StoreError>;
}
