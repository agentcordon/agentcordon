use std::sync::Arc;

use crate::domain::policy::{PolicyId, StoredPolicy};
use crate::error::ServiceError;
use crate::storage::traits::{AuditStore, PolicyStore};

/// Service layer for policy (Cedar) operations.
///
/// Handles policy CRUD. Policy evaluation itself remains in the
/// policy engine — this service manages the stored policy lifecycle.
pub struct PolicyService<S: PolicyStore + AuditStore> {
    store: Arc<S>,
}

impl<S: PolicyStore + AuditStore> PolicyService<S> {
    pub fn new(store: Arc<S>) -> Self {
        Self { store }
    }

    pub async fn create(&self, policy: &StoredPolicy) -> Result<(), ServiceError> {
        if policy.name.trim().is_empty() {
            return Err(ServiceError::Validation {
                field: "name".into(),
                message: "policy name must not be empty".into(),
            });
        }
        if policy.cedar_policy.trim().is_empty() {
            return Err(ServiceError::Validation {
                field: "cedar_policy".into(),
                message: "cedar policy body must not be empty".into(),
            });
        }
        self.store.store_policy(policy).await?;
        Ok(())
    }

    pub async fn get(&self, id: &PolicyId) -> Result<StoredPolicy, ServiceError> {
        self.store
            .get_policy(id)
            .await?
            .ok_or_else(|| ServiceError::NotFound {
                resource: "policy".into(),
                id: id.0.to_string(),
            })
    }

    pub async fn list(&self) -> Result<Vec<StoredPolicy>, ServiceError> {
        Ok(self.store.list_policies().await?)
    }

    pub async fn list_enabled(&self) -> Result<Vec<StoredPolicy>, ServiceError> {
        Ok(self.store.get_all_enabled_policies().await?)
    }

    pub async fn update(&self, policy: &StoredPolicy) -> Result<(), ServiceError> {
        if policy.name.trim().is_empty() {
            return Err(ServiceError::Validation {
                field: "name".into(),
                message: "policy name must not be empty".into(),
            });
        }
        if policy.cedar_policy.trim().is_empty() {
            return Err(ServiceError::Validation {
                field: "cedar_policy".into(),
                message: "cedar policy body must not be empty".into(),
            });
        }
        // Ensure the policy exists
        self.store
            .get_policy(&policy.id)
            .await?
            .ok_or_else(|| ServiceError::NotFound {
                resource: "policy".into(),
                id: policy.id.0.to_string(),
            })?;
        self.store.update_policy(policy).await?;
        Ok(())
    }

    pub async fn delete(&self, id: &PolicyId) -> Result<(), ServiceError> {
        let deleted = self.store.delete_policy(id).await?;
        if !deleted {
            return Err(ServiceError::NotFound {
                resource: "policy".into(),
                id: id.0.to_string(),
            });
        }
        Ok(())
    }

    pub async fn enable(&self, id: &PolicyId) -> Result<(), ServiceError> {
        let mut policy = self.get(id).await?;
        policy.enabled = true;
        self.store.update_policy(&policy).await?;
        Ok(())
    }

    pub async fn disable(&self, id: &PolicyId) -> Result<(), ServiceError> {
        let mut policy = self.get(id).await?;
        policy.enabled = false;
        self.store.update_policy(&policy).await?;
        Ok(())
    }
}
