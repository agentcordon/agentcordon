//! Cedar action name constants.
//!
//! Single source of truth — never use bare action name strings elsewhere.
//! Derived from `policies/schema.cedarschema.json`.

pub const ACCESS: &str = "access";
pub const LIST: &str = "list";
pub const CREATE: &str = "create";
pub const UPDATE: &str = "update";
pub const UNPROTECT: &str = "unprotect";
pub const DELETE: &str = "delete";
pub const MANAGE_POLICIES: &str = "manage_policies";
pub const MANAGE_PERMISSIONS: &str = "manage_permissions";
pub const VEND_CREDENTIAL: &str = "vend_credential";
pub const MANAGE_USERS: &str = "manage_users";
pub const MANAGE_WORKSPACES: &str = "manage_workspaces";
pub const VIEW_AUDIT: &str = "view_audit";
pub const ROTATE_KEY: &str = "rotate_key";
pub const MANAGE_OIDC_PROVIDERS: &str = "manage_oidc_providers";
pub const MANAGE_VAULTS: &str = "manage_vaults";
pub const ROTATE_ENCRYPTION_KEY: &str = "rotate_encryption_key";
pub const MANAGE_MCP_SERVERS: &str = "manage_mcp_servers";
pub const MCP_TOOL_CALL: &str = "mcp_tool_call";
pub const MCP_LIST_TOOLS: &str = "mcp_list_tools";
pub const REGISTER_WORKSPACE: &str = "register_workspace";
pub const MANAGE_TAGS: &str = "manage_tags";

// Backward-compat aliases (removed in later phases)
pub const MANAGE_AGENTS: &str = MANAGE_WORKSPACES;
pub const MANAGE_DEVICES: &str = MANAGE_WORKSPACES;
