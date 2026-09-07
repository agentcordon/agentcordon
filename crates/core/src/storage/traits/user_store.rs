use async_trait::async_trait;

use crate::domain::oidc::OidcProviderId;
use crate::domain::user::{User, UserId};
use crate::error::StoreError;

#[async_trait]
pub trait UserStore: Send + Sync {
    async fn create_user(&self, user: &User) -> Result<(), StoreError>;
    async fn get_user(&self, id: &UserId) -> Result<Option<User>, StoreError>;
    async fn get_user_by_username(&self, username: &str) -> Result<Option<User>, StoreError>;
    async fn list_users(&self) -> Result<Vec<User>, StoreError>;
    async fn update_user(&self, user: &User) -> Result<(), StoreError>;
    async fn delete_user(&self, id: &UserId) -> Result<bool, StoreError>;

    /// The user bound to an identity provider's stable subject, if any.
    ///
    /// This is the only way an OIDC login resolves an existing account.
    async fn get_user_by_oidc_identity(
        &self,
        provider_id: &OidcProviderId,
        subject: &str,
    ) -> Result<Option<User>, StoreError>;

    /// Record that `subject` at `provider_id` is `user_id`. Idempotent for
    /// the same triple; a different user for the same (provider, subject)
    /// is a conflict.
    async fn link_oidc_identity(
        &self,
        user_id: &UserId,
        provider_id: &OidcProviderId,
        subject: &str,
    ) -> Result<(), StoreError>;
}
