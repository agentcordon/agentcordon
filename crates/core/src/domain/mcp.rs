use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::credential::CredentialId;
use super::workspace::WorkspaceId;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct McpServerId(pub Uuid);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpServer {
    pub id: McpServerId,
    /// The workspace this MCP server belongs to. Required — every MCP server is workspace-scoped.
    pub workspace_id: WorkspaceId,
    pub name: String,
    pub upstream_url: String,
    pub transport: String,
    pub allowed_tools: Option<Vec<String>>,
    pub enabled: bool,
    /// The workspace that registered/created this MCP server.
    pub created_by: Option<WorkspaceId>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    /// User-defined tags for categorization and policy matching.
    pub tags: Vec<String>,
    /// Credential IDs needed by this MCP server.
    pub required_credentials: Option<Vec<CredentialId>>,
}

/// A tool discovered from an MCP server via JSON-RPC `tools/list`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpTool {
    pub name: String,
    pub description: Option<String>,
    pub input_schema: Option<serde_json::Value>,
}
