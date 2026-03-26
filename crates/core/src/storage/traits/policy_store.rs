use async_trait::async_trait;

use crate::domain::policy::{PolicyId, StoredPolicy};
use crate::error::StoreError;

#[async_trait]
pub trait PolicyStore: Send + Sync {
    async fn store_policy(&self, policy: &StoredPolicy) -> Result<(), StoreError>;
    async fn get_policy(&self, id: &PolicyId) -> Result<Option<StoredPolicy>, StoreError>;
    async fn list_policies(&self) -> Result<Vec<StoredPolicy>, StoreError>;
    async fn update_policy(&self, policy: &StoredPolicy) -> Result<(), StoreError>;
    async fn delete_policy(&self, id: &PolicyId) -> Result<bool, StoreError>;
    async fn get_all_enabled_policies(&self) -> Result<Vec<StoredPolicy>, StoreError>;
    /// Delete all policies whose name starts with the given prefix.
    async fn delete_policies_by_name_prefix(&self, prefix: &str) -> Result<u64, StoreError>;
    /// Delete a single policy by its exact name.
    async fn delete_policy_by_name(&self, name: &str) -> Result<bool, StoreError>;
}
