use std::fmt;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::credential::CredentialId;
use super::user::UserId;
use super::workspace::WorkspaceId;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct McpServerId(pub Uuid);

/// Authentication method required by an MCP server.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "lowercase")]
pub enum McpAuthMethod {
    #[default]
    None,
    #[serde(rename = "api_key")]
    ApiKey,
    #[serde(rename = "oauth2")]
    OAuth2,
}

impl fmt::Display for McpAuthMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => write!(f, "none"),
            Self::ApiKey => write!(f, "api_key"),
            Self::OAuth2 => write!(f, "oauth2"),
        }
    }
}

impl McpAuthMethod {
    /// Parse an auth method string from the database. Returns `None` for unknown values.
    pub fn from_str_opt(s: &str) -> Option<Self> {
        match s {
            "none" => Some(Self::None),
            "api_key" => Some(Self::ApiKey),
            "oauth2" => Some(Self::OAuth2),
            _ => None,
        }
    }
}

/// Supported MCP server transport types.
/// STDIO has been removed — all MCP servers are HTTP or SSE.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum McpTransport {
    #[default]
    Http,
    Sse,
}

impl fmt::Display for McpTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Http => write!(f, "http"),
            Self::Sse => write!(f, "sse"),
        }
    }
}

impl McpTransport {
    /// Parse a transport string from the database. Returns `None` for unknown values.
    pub fn from_str_opt(s: &str) -> Option<Self> {
        match s {
            "http" => Some(Self::Http),
            "sse" => Some(Self::Sse),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpServer {
    pub id: McpServerId,
    /// The workspace this MCP server belongs to. Required — every MCP server is workspace-scoped.
    pub workspace_id: WorkspaceId,
    pub name: String,
    pub upstream_url: String,
    pub transport: McpTransport,
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
    /// Authentication method required by this server (none, api_key, oauth2).
    pub auth_method: McpAuthMethod,
    /// Template key if this server was provisioned from the catalog.
    pub template_key: Option<String>,
    /// Full tool metadata from MCP discovery (name, description, input_schema).
    pub discovered_tools: Option<Vec<McpTool>>,
    /// The user who created/owns this MCP server.
    pub created_by_user: Option<UserId>,
}

/// A tool discovered from an MCP server via JSON-RPC `tools/list`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpTool {
    pub name: String,
    pub description: Option<String>,
    pub input_schema: Option<serde_json::Value>,
}
