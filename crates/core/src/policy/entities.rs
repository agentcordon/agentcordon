//! Cedar entity type constants (fully qualified with namespace).
//!
//! Single source of truth — never use bare entity type strings elsewhere.
//! Derived from `policies/schema.cedarschema.json`.

/// The Cedar namespace for all AgentCordon entity types.
pub const NS: &str = "AgentCordon";

pub const WORKSPACE: &str = "AgentCordon::Workspace";
pub const USER: &str = "AgentCordon::User";
pub const SERVER: &str = "AgentCordon::Server";
pub const CREDENTIAL: &str = "AgentCordon::Credential";
pub const SYSTEM: &str = "AgentCordon::System";
pub const POLICY_RESOURCE: &str = "AgentCordon::PolicyResource";
pub const MCP_SERVER: &str = "AgentCordon::McpServer";
pub const WORKSPACE_RESOURCE: &str = "AgentCordon::WorkspaceResource";
pub const ACTION: &str = "AgentCordon::Action";

// Backward-compat aliases (removed in later phases)
pub const AGENT: &str = WORKSPACE;
pub const DEVICE: &str = WORKSPACE;
pub const AGENT_RESOURCE: &str = WORKSPACE_RESOURCE;
