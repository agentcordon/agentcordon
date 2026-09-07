use async_trait::async_trait;

use crate::domain::user::UserId;
use crate::domain::vault::{Vault, VaultShare};
use crate::error::StoreError;

#[async_trait]
pub trait VaultStore: Send + Sync {
    async fn create_vault(&self, vault: &Vault) -> Result<(), StoreError>;
    async fn get_vault(&self, id: &str) -> Result<Option<Vault>, StoreError>;
    /// Every vault on the install, ordered by name.
    async fn list_vaults(&self) -> Result<Vec<Vault>, StoreError>;
    /// The vaults this user owns. The system default vault has no owner, so
    /// it is never in this list.
    async fn list_vaults_owned_by(&self, user_id: &UserId) -> Result<Vec<Vault>, StoreError>;
    async fn rename_vault(&self, id: &str, name: &str) -> Result<bool, StoreError>;
    /// Delete the vault row. Callers check first that it holds no
    /// credentials — the schema would refuse the delete anyway, since
    /// `credentials.vault_id` references it.
    async fn delete_vault(&self, id: &str) -> Result<bool, StoreError>;
    async fn count_credentials_in_vault(&self, id: &str) -> Result<i64, StoreError>;
    async fn share_vault(&self, share: &VaultShare) -> Result<(), StoreError>;
    async fn unshare_vault(&self, vault_id: &str, user_id: &UserId) -> Result<bool, StoreError>;
    async fn list_vault_shares(&self, vault_id: &str) -> Result<Vec<VaultShare>, StoreError>;
    /// Every share granted *to* this user, whichever vault it is on.
    async fn get_vault_shares_for_user(
        &self,
        user_id: &UserId,
    ) -> Result<Vec<VaultShare>, StoreError>;
}
