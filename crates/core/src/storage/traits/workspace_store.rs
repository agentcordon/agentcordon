use async_trait::async_trait;

use crate::domain::user::UserId;
use crate::domain::workspace::{ProvisioningToken, Workspace, WorkspaceId, WorkspaceRegistration};
use crate::error::StoreError;

/// Unified workspace storage trait.
///
/// Replaces the former AgentStore, DeviceStore, and the old WorkspaceStore
/// (workspace identity + registration). All autonomous entities are now
/// Workspaces stored in the `workspaces` table.
#[async_trait]
pub trait WorkspaceStore: Send + Sync {
    // ---- CRUD ----

    async fn create_workspace(&self, workspace: &Workspace) -> Result<(), StoreError>;
    async fn get_workspace(&self, id: &WorkspaceId) -> Result<Option<Workspace>, StoreError>;
    async fn get_workspace_by_name(&self, name: &str) -> Result<Option<Workspace>, StoreError>;
    async fn get_workspace_by_pk_hash(
        &self,
        pk_hash: &str,
    ) -> Result<Option<Workspace>, StoreError>;
    async fn list_workspaces(&self) -> Result<Vec<Workspace>, StoreError>;
    async fn get_workspaces_by_owner(
        &self,
        owner_id: &UserId,
    ) -> Result<Vec<Workspace>, StoreError>;
    async fn update_workspace(&self, workspace: &Workspace) -> Result<(), StoreError>;
    async fn delete_workspace(&self, id: &WorkspaceId) -> Result<bool, StoreError>;

    // ---- JTI tracking (replay prevention) ----

    async fn check_workspace_jti(&self, jti: &str) -> Result<bool, StoreError>;
    /// Atomically store a JTI. Returns true if the JTI was newly inserted,
    /// false if it already existed (replay detected).
    async fn store_workspace_jti(
        &self,
        jti: &str,
        workspace_id: &WorkspaceId,
        expires_at: &chrono::DateTime<chrono::Utc>,
    ) -> Result<bool, StoreError>;
    async fn cleanup_expired_workspace_jtis(&self) -> Result<u32, StoreError>;

    // ---- Authentication tracking ----

    /// Update only the `last_authenticated_at` and `updated_at` timestamps.
    async fn touch_workspace_authenticated(
        &self,
        id: &WorkspaceId,
        now: &chrono::DateTime<chrono::Utc>,
    ) -> Result<(), StoreError>;

    // ---- Registration flow (PKCE-based workspace registration) ----

    async fn create_workspace_registration(
        &self,
        reg: &WorkspaceRegistration,
    ) -> Result<(), StoreError>;
    async fn get_workspace_registration(
        &self,
        pk_hash: &str,
    ) -> Result<Option<WorkspaceRegistration>, StoreError>;
    async fn increment_registration_attempts(&self, pk_hash: &str) -> Result<(), StoreError>;
    async fn delete_workspace_registration(&self, pk_hash: &str) -> Result<bool, StoreError>;
    /// Null out the approval_code field after it has been read (one-time use).
    async fn null_registration_approval_code(&self, pk_hash: &str) -> Result<(), StoreError>;

    // ---- Provisioning tokens (CI/CD registration) ----

    async fn create_provisioning_token(&self, token: &ProvisioningToken) -> Result<(), StoreError>;
    async fn get_provisioning_token(
        &self,
        token_hash: &str,
    ) -> Result<Option<ProvisioningToken>, StoreError>;
    /// Atomically mark a provisioning token as used. Returns true if updated (was unused).
    async fn mark_provisioning_token_used(&self, token_hash: &str) -> Result<bool, StoreError>;
}
