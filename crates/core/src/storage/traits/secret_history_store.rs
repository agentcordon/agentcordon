use async_trait::async_trait;

use crate::domain::credential::{CredentialId, SecretHistoryEntry};
use crate::error::StoreError;

/// The sealed material of one history row: what a restore copies back onto
/// the credential and what `rotate-key` re-seals.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretHistoryCiphertext {
    pub id: String,
    pub credential_id: CredentialId,
    pub encrypted_value: Vec<u8>,
    pub nonce: Vec<u8>,
    /// Master-key version the row was sealed under.
    pub key_version: i64,
}

#[async_trait]
pub trait SecretHistoryStore: Send + Sync {
    /// Archive a credential's current ciphertext. `key_version` is the
    /// master-key version that ciphertext was sealed under (the
    /// credential's own `key_version` at the time).
    async fn store_secret_history(
        &self,
        credential_id: &CredentialId,
        encrypted_value: &[u8],
        nonce: &[u8],
        key_version: i64,
        changed_by_user: Option<&str>,
        changed_by_agent: Option<&str>,
    ) -> Result<(), StoreError>;
    async fn list_secret_history(
        &self,
        credential_id: &CredentialId,
    ) -> Result<Vec<SecretHistoryEntry>, StoreError>;
    /// Returns the sealed material for one of `credential_id`'s history
    /// entries. An entry that exists but belongs to another credential is
    /// `None`: its ciphertext was sealed under that credential's associated
    /// data and can never be restored here.
    async fn get_secret_history_value(
        &self,
        credential_id: &CredentialId,
        history_id: &str,
    ) -> Result<Option<SecretHistoryCiphertext>, StoreError>;
    /// Every history row's sealed material, for re-sealing under a new
    /// master key.
    async fn list_all_secret_history_ciphertexts(
        &self,
    ) -> Result<Vec<SecretHistoryCiphertext>, StoreError>;
    /// Replace one history row's sealed material. Returns `false` when no
    /// row has that id.
    async fn update_secret_history_ciphertext(
        &self,
        history_id: &str,
        encrypted_value: &[u8],
        nonce: &[u8],
        key_version: i64,
    ) -> Result<bool, StoreError>;
}
