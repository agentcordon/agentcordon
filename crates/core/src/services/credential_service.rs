use std::sync::Arc;

use crate::domain::agent::AgentId;
use crate::domain::credential::{
    CredentialId, CredentialSummary, CredentialUpdate, StoredCredential,
};
use crate::domain::workspace::WorkspaceId;
use crate::error::ServiceError;
use crate::storage::traits::{AuditStore, CredentialStore};

/// Service layer for credential operations.
///
/// Handles credential CRUD. Crypto operations (encryption/decryption) remain
/// in route handlers for now — this service operates on already-encrypted
/// `StoredCredential` values. Permission grants are now Cedar policies,
/// managed via PolicyStore.
pub struct CredentialService<S: CredentialStore + AuditStore> {
    store: Arc<S>,
}

impl<S: CredentialStore + AuditStore> CredentialService<S> {
    pub fn new(store: Arc<S>) -> Self {
        Self { store }
    }

    pub async fn create(&self, credential: &StoredCredential) -> Result<(), ServiceError> {
        if credential.name.trim().is_empty() {
            return Err(ServiceError::Validation {
                field: "name".into(),
                message: "credential name must not be empty".into(),
            });
        }
        // Names are not unique — multiple credentials can share the same name.
        // Cedar policies control access; names are human-friendly labels.
        self.store.store_credential(credential).await?;
        Ok(())
    }

    pub async fn get(&self, id: &CredentialId) -> Result<StoredCredential, ServiceError> {
        self.store
            .get_credential(id)
            .await?
            .ok_or_else(|| ServiceError::NotFound {
                resource: "credential".into(),
                id: id.0.to_string(),
            })
    }

    pub async fn get_by_name(&self, name: &str) -> Result<StoredCredential, ServiceError> {
        self.store
            .get_credential_by_name(name)
            .await?
            .ok_or_else(|| ServiceError::NotFound {
                resource: "credential".into(),
                id: name.to_string(),
            })
    }

    pub async fn get_by_workspace_and_name(
        &self,
        workspace_id: &WorkspaceId,
        name: &str,
    ) -> Result<StoredCredential, ServiceError> {
        self.store
            .get_credential_by_workspace_and_name(workspace_id, name)
            .await?
            .ok_or_else(|| ServiceError::NotFound {
                resource: "credential".into(),
                id: name.to_string(),
            })
    }

    pub async fn list(&self) -> Result<Vec<CredentialSummary>, ServiceError> {
        Ok(self.store.list_credentials().await?)
    }

    pub async fn list_by_vault(&self, vault: &str) -> Result<Vec<CredentialSummary>, ServiceError> {
        Ok(self.store.list_credentials_by_vault(vault).await?)
    }

    pub async fn list_for_agent(
        &self,
        agent_id: &AgentId,
    ) -> Result<Vec<CredentialSummary>, ServiceError> {
        Ok(self.store.list_credentials_for_agent(agent_id).await?)
    }

    pub async fn update(
        &self,
        id: &CredentialId,
        updates: &CredentialUpdate,
    ) -> Result<(), ServiceError> {
        let updated = self.store.update_credential(id, updates).await?;
        if !updated {
            return Err(ServiceError::NotFound {
                resource: "credential".into(),
                id: id.0.to_string(),
            });
        }
        Ok(())
    }

    pub async fn delete(&self, id: &CredentialId) -> Result<(), ServiceError> {
        let deleted = self.store.delete_credential(id).await?;
        if !deleted {
            return Err(ServiceError::NotFound {
                resource: "credential".into(),
                id: id.0.to_string(),
            });
        }
        Ok(())
    }
}
