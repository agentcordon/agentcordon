pub mod actions;
pub mod cedar;
pub mod entities;
pub mod schema;
pub mod templates;

use crate::domain::credential::StoredCredential;
use crate::domain::policy::{PolicyDecision, PolicyValidationError};
use crate::domain::user::{User, UserId};
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

/// Ergonomic conversions for resources passed to `Authz` builders.
impl From<&StoredCredential> for PolicyResource {
    fn from(c: &StoredCredential) -> Self {
        PolicyResource::Credential {
            credential: c.clone(),
        }
    }
}

impl From<&Workspace> for PolicyResource {
    fn from(w: &Workspace) -> Self {
        PolicyResource::WorkspaceResource {
            workspace: w.clone(),
        }
    }
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
        /// Owning user (the user who provisioned the MCP server). Workspaces
        /// inherit access to MCP servers their owner provisioned.
        owner: Option<UserId>,
    },
}

/// Additional context for policy evaluation.
///
/// AWS-style open property bag. Per-action context (tool name, target URL,
/// requested scopes, etc.) is carried in the [`claims`] HashMap; new
/// conditional-access knobs (region, MFA age, source IP, device posture,
/// ...) can be added by handlers without changing this struct.
///
/// Cedar templates referencing the legacy field names by string key
/// (`context.tool_name`, `context.target_url`, `context.requested_scopes`,
/// `context.credential_name`, `context.tag_value`, `context.justification`)
/// continue to evaluate correctly — `build_context` reads them out of the
/// bag using the same keys. Use [`ClaimKey`] constants to avoid typos.
#[derive(Default, Debug, Clone)]
pub struct PolicyContext {
    /// Correlation ID from the HTTP request, threaded into audit events.
    pub correlation_id: Option<String>,
    /// OAuth token claims for audit enrichment. Included in policy audit
    /// metadata so every access decision log contains the full token context.
    pub oauth_claims: Option<serde_json::Value>,
    /// Open claim bag. Keys are the names Cedar policies reference via
    /// `context.<key>`. Values are JSON; primitives are converted into the
    /// appropriate Cedar `RestrictedExpression` shape by `build_context`.
    pub claims: std::collections::HashMap<String, serde_json::Value>,
}

impl PolicyContext {
    /// Insert a single claim by key/value, returning self for builder chaining.
    pub fn with_claim<K, V>(mut self, key: K, value: V) -> Self
    where
        K: Into<String>,
        V: Into<serde_json::Value>,
    {
        self.claims.insert(key.into(), value.into());
        self
    }

    /// Look up a claim value by key.
    pub fn claim(&self, key: &str) -> Option<&serde_json::Value> {
        self.claims.get(key)
    }

    /// Read a string-typed claim, returning empty string when absent or
    /// non-string. Convenience for Cedar string-context construction.
    pub fn string_claim(&self, key: &str) -> String {
        self.claims
            .get(key)
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .unwrap_or_default()
    }

    /// Read a string-array claim, returning empty Vec when absent or
    /// non-array. Convenience for Cedar set-context construction.
    pub fn string_array_claim(&self, key: &str) -> Vec<String> {
        self.claims
            .get(key)
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|s| s.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default()
    }
}

/// Canonical keys used in the claim bag. These mirror the Cedar context
/// fields referenced by existing policy templates so that
/// `context.<key>` continues to resolve.
pub mod claim_keys {
    /// Scopes (Vec<String>) the workspace is requesting for this access.
    pub const REQUESTED_SCOPES: &str = "requested_scopes";
    /// Target URL (String) for `vend_credential` requests.
    pub const TARGET_URL: &str = "target_url";
    /// Tool name (String) for `mcp_tool_call` actions.
    pub const TOOL_NAME: &str = "tool_name";
    /// Credential name (String) for `mcp_tool_call` actions.
    pub const CREDENTIAL_NAME: &str = "credential_name";
    /// Tag value (String) for `manage_tags` actions.
    pub const TAG_VALUE: &str = "tag_value";
    /// Optional justification (String) provided by the workspace for
    /// audit/compliance.
    pub const JUSTIFICATION: &str = "justification";
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
