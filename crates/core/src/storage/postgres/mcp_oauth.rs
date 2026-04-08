use async_trait::async_trait;

use super::PostgresStore;
use crate::domain::mcp_oauth::McpOAuthState;
use crate::error::StoreError;
use crate::storage::McpOAuthStore;

/// Postgres McpOAuthStore implementation stub.
/// Returns `StoreError::Database("not yet implemented")` until the Postgres
/// migration for `mcp_oauth_states` is added.
#[async_trait]
impl McpOAuthStore for PostgresStore {
    async fn create_mcp_oauth_state(&self, _state: &McpOAuthState) -> Result<(), StoreError> {
        Err(StoreError::Database(
            "mcp_oauth: postgres not yet implemented".into(),
        ))
    }
    async fn consume_mcp_oauth_state(
        &self,
        _state: &str,
    ) -> Result<Option<McpOAuthState>, StoreError> {
        Err(StoreError::Database(
            "mcp_oauth: postgres not yet implemented".into(),
        ))
    }
    async fn cleanup_expired_mcp_oauth_states(&self) -> Result<u32, StoreError> {
        Err(StoreError::Database(
            "mcp_oauth: postgres not yet implemented".into(),
        ))
    }
}
