use async_trait::async_trait;

use crate::domain::agent::AgentId;
use crate::domain::credential::{
    CredentialId, CredentialSummary, CredentialUpdate, StoredCredential,
};
use crate::domain::user::UserId;
use crate::domain::workspace::WorkspaceId;
use crate::error::StoreError;

#[async_trait]
pub trait CredentialStore: Send + Sync {
    async fn store_credential(&self, cred: &StoredCredential) -> Result<(), StoreError>;
    async fn get_credential(
        &self,
        id: &CredentialId,
    ) -> Result<Option<StoredCredential>, StoreError>;
    async fn get_credential_by_name(
        &self,
        name: &str,
    ) -> Result<Option<StoredCredential>, StoreError>;
    /// Look up a credential by name scoped to a specific workspace (created_by).
    async fn get_credential_by_workspace_and_name(
        &self,
        workspace_id: &WorkspaceId,
        name: &str,
    ) -> Result<Option<StoredCredential>, StoreError>;
    async fn list_credentials(&self) -> Result<Vec<CredentialSummary>, StoreError>;
    async fn delete_credential(&self, id: &CredentialId) -> Result<bool, StoreError>;
    /// Every credential in the vault with this id.
    async fn list_credentials_by_vault(
        &self,
        vault_id: &str,
    ) -> Result<Vec<CredentialSummary>, StoreError>;
    /// List credentials in a vault, enforcing that the user either created the
    /// credential or has been granted a vault share. Returns only accessible credentials.
    async fn list_credentials_by_vault_for_user(
        &self,
        vault_id: &str,
        user_id: &UserId,
    ) -> Result<Vec<CredentialSummary>, StoreError>;
    async fn update_credential(
        &self,
        id: &CredentialId,
        updates: &CredentialUpdate,
    ) -> Result<bool, StoreError>;
    /// Rotate the sealed secret: archive the ciphertext the row holds now
    /// (under its own `key_version`) to the secret history, then apply
    /// `updates`, in one immediate transaction. `updates` must carry the new
    /// `encrypted_value` and `nonce`. `Ok(false)` when the credential does
    /// not exist, in which case nothing is archived; when the write fails
    /// the history row is not kept either.
    async fn rotate_credential_secret(
        &self,
        id: &CredentialId,
        updates: &CredentialUpdate,
        changed_by_user: Option<&str>,
        changed_by_agent: Option<&str>,
    ) -> Result<bool, StoreError>;
    async fn list_credentials_for_agent(
        &self,
        agent_id: &AgentId,
    ) -> Result<Vec<CredentialSummary>, StoreError>;
    /// Load all full credentials in a single query.
    async fn list_all_stored_credentials(&self) -> Result<Vec<StoredCredential>, StoreError>;
    /// Load all full credentials matching a given name. Used by vend-by-name
    /// to avoid loading the entire credential table.
    async fn list_stored_credentials_by_name(
        &self,
        name: &str,
    ) -> Result<Vec<StoredCredential>, StoreError>;
}
