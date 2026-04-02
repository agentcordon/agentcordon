pub mod actions;
pub mod cedar;
pub mod entities;
pub mod schema;
pub mod templates;

use crate::domain::credential::StoredCredential;
use crate::domain::policy::{PolicyDecision, PolicyValidationError};
use crate::domain::user::User;
use crate::domain::workspace::Workspace;
use crate::error::PolicyError;

/// Lightweight server (OAuth client) representation for policy evaluation.
#[derive(Debug, Clone)]
pub struct PolicyServer {
    /// Unique identifier for the server (used as Cedar entity ID).
    pub id: String,
    /// Human-readable name of the server.
    pub name: String,
    /// Whether the server is enabled. Disabled servers are denied all actions.
    pub enabled: bool,
    /// Tags for fine-grained policy control.
    pub tags: Vec<String>,
    /// The OAuth client_id for this server.
    pub client_id: String,
}

/// The principal requesting an action. A human User, an autonomous Workspace,
/// or a Server (OAuth client).
pub enum PolicyPrincipal<'a> {
    User(&'a User),
    Workspace(&'a Workspace),
    Server(&'a PolicyServer),
}

/// Resource variants for policy evaluation.
#[allow(clippy::large_enum_variant)]
pub enum PolicyResource {
    /// A specific credential being accessed.
    Credential { credential: StoredCredential },
    /// System-level resource (e.g., listing all credentials, creating credentials).
    System,
    /// Policy management resource.
    PolicyAdmin,
    /// A workspace being managed by a user (view, enable/disable, configure).
    WorkspaceResource { workspace: Workspace },
    /// An MCP server resource for tool-call and tool-listing authorization.
    McpServer {
        /// Unique identifier for the MCP server (used as Cedar entity ID).
        id: String,
        /// Human-readable name of the MCP server.
        name: String,
        /// Whether the MCP server is enabled.
        enabled: bool,
        /// Tags for fine-grained policy control.
        tags: Vec<String>,
    },
}

/// Additional context for policy evaluation.
#[derive(Default)]
pub struct PolicyContext {
    /// Scopes the workspace is requesting for this access.
    pub requested_scopes: Vec<String>,
    /// Target URL for vend_credential requests.
    pub target_url: Option<String>,
    /// Tool name for mcp_tool_call actions.
    pub tool_name: Option<String>,
    /// Credential name for mcp_tool_call actions.
    pub credential_name: Option<String>,
    /// Tag value for manage_tags actions.
    pub tag_value: Option<String>,
    /// Optional justification string provided by the workspace for audit/compliance.
    /// Max 1024 characters. Passed into Cedar context so policies can require it.
    pub justification: Option<String>,
    /// Correlation ID from the HTTP request, threaded into audit events.
    pub correlation_id: Option<String>,
    /// OAuth token claims for audit enrichment. Included in policy audit metadata
    /// so every access decision log contains the full token context.
    pub oauth_claims: Option<serde_json::Value>,
}

/// Trait for policy engines that evaluate authorization decisions.
///
/// Implementations must be thread-safe (`Send + Sync`).
/// The default behavior is deny-all; policies must explicitly permit access.
pub trait PolicyEngine: Send + Sync {
    /// Evaluate whether the given principal may perform `action` on `resource`
    /// with the supplied context.
    ///
    /// **Root bypass**: If the principal is a `User` with `is_root = true`,
    /// this returns `Allow` immediately without Cedar evaluation.
    fn evaluate(
        &self,
        principal: &PolicyPrincipal,
        action: &str,
        resource: &PolicyResource,
        context: &PolicyContext,
    ) -> Result<PolicyDecision, PolicyError>;

    /// Reload the engine's policy set from a list of `(id, cedar_source)` pairs.
    fn reload_policies(&self, policies: Vec<(String, String)>) -> Result<(), PolicyError>;

    /// Validate a Cedar policy text against the schema.
    fn validate_policy_text(&self, cedar_source: &str) -> Result<(), PolicyError>;

    /// Validate a Cedar policy text and return structured errors.
    fn validate_policy_text_detailed(
        &self,
        cedar_source: &str,
    ) -> Result<(), Vec<PolicyValidationError>>;
}
