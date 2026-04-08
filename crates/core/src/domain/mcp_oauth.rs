use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::user::UserId;
use super::workspace::WorkspaceId;

/// OAuth2 authorization state for MCP server provisioning.
///
/// Stored server-side during the OAuth2 authorization code flow.
/// Each state is single-use and expires after a configurable TTL.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpOAuthState {
    /// Cryptographically random state parameter (CSRF protection).
    pub state: String,
    /// Which MCP template this flow is for.
    pub template_key: String,
    /// Target workspace for the new MCP server.
    pub workspace_id: WorkspaceId,
    /// Authenticated user who initiated the flow.
    pub user_id: UserId,
    /// The redirect_uri used in the authorization request.
    pub redirect_uri: String,
    /// PKCE S256 code verifier (stored server-side, sent at token exchange).
    pub code_verifier: Option<String>,
    /// Authorization server URL (origin) for AS-keyed provider client lookup.
    pub authorization_server_url: Option<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}
