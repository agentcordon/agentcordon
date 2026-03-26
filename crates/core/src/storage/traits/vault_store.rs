use async_trait::async_trait;

use crate::domain::user::UserId;
use crate::domain::vault::VaultShare;
use crate::error::StoreError;

#[async_trait]
pub trait VaultStore: Send + Sync {
    async fn share_vault(&self, share: &VaultShare) -> Result<(), StoreError>;
    async fn unshare_vault(&self, vault_name: &str, user_id: &UserId) -> Result<bool, StoreError>;
    async fn list_vault_shares(&self, vault_name: &str) -> Result<Vec<VaultShare>, StoreError>;
    async fn get_vault_shares_for_user(
        &self,
        user_id: &UserId,
    ) -> Result<Vec<VaultShare>, StoreError>;
}
