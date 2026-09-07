use async_trait::async_trait;

use crate::domain::user::UserId;
use crate::domain::workspace::{Workspace, WorkspaceId};
use crate::error::StoreError;

/// Unified workspace storage trait.
///
/// Replaces the former AgentStore and DeviceStore. All autonomous entities
/// are Workspaces stored in the `workspaces` table.
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
    /// Revoke a workspace and everything that authenticates as it, in one
    /// transaction: status to revoked, its OAuth clients revoked, and every
    /// access and refresh token bound to it revoked. `false` when no such
    /// workspace exists. The caller decides whether the transition is allowed
    /// (see `Workspace::revoke`); this applies it.
    async fn revoke_workspace(&self, id: &WorkspaceId) -> Result<bool, StoreError>;

    // ---- Authentication tracking ----

    /// Update only the `last_authenticated_at` and `updated_at` timestamps.
    async fn touch_workspace_authenticated(
        &self,
        id: &WorkspaceId,
        now: &chrono::DateTime<chrono::Utc>,
    ) -> Result<(), StoreError>;
}
