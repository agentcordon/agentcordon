pub mod shared;

#[cfg(feature = "sqlite")]
pub mod migrations;
#[cfg(feature = "postgres")]
pub mod postgres;
#[cfg(feature = "sqlite")]
pub mod sqlite;

pub mod traits;
pub use traits::*;

use async_trait::async_trait;

use crate::error::StoreError;

/// Composite Store trait — existing code using `dyn Store` continues to work.
/// All domain-specific methods are inherited from the sub-traits.
#[async_trait]
pub trait Store:
    UserStore
    + SessionStore
    + CredentialStore
    + SecretHistoryStore
    + PolicyStore
    + AuditStore
    + VaultStore
    + McpStore
    + McpOAuthStore
    + OAuthProviderClientStore
    + OAuthStore
    + OidcStore
    + WorkspaceStore
{
    // Lifecycle
    async fn run_migrations(&self) -> Result<(), StoreError>;
}
