use async_trait::async_trait;

use crate::domain::mcp_oauth::McpOAuthState;
use crate::error::StoreError;

/// Storage operations for MCP OAuth2 authorization state.
#[async_trait]
pub trait McpOAuthStore: Send + Sync {
    /// Insert a new OAuth state record.
    async fn create_mcp_oauth_state(&self, state: &McpOAuthState) -> Result<(), StoreError>;

    /// Retrieve and delete an OAuth state record in one atomic operation (single-use).
    /// Returns `None` if the state does not exist.
    async fn consume_mcp_oauth_state(
        &self,
        state: &str,
    ) -> Result<Option<McpOAuthState>, StoreError>;

    /// Delete all expired OAuth state records. Returns the count of deleted rows.
    async fn cleanup_expired_mcp_oauth_states(&self) -> Result<u32, StoreError>;
}
