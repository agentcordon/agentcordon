use async_trait::async_trait;

use crate::domain::credential::{CredentialId, SecretHistoryEntry};
use crate::error::StoreError;

#[async_trait]
pub trait SecretHistoryStore: Send + Sync {
    async fn store_secret_history(
        &self,
        credential_id: &CredentialId,
        encrypted_value: &[u8],
        nonce: &[u8],
        changed_by_user: Option<&str>,
        changed_by_agent: Option<&str>,
    ) -> Result<(), StoreError>;
    async fn list_secret_history(
        &self,
        credential_id: &CredentialId,
    ) -> Result<Vec<SecretHistoryEntry>, StoreError>;
    /// Returns (encrypted_value, nonce) for a specific history entry, if found.
    async fn get_secret_history_value(
        &self,
        history_id: &str,
    ) -> Result<Option<(Vec<u8>, Vec<u8>)>, StoreError>;
}
