// =============================================================================
// AgentCordon Default Cedar Policies
// =============================================================================
//
// Cedar denies by default when no permit policy matches. Every permit below
// checks `principal.enabled`, so disabled principals are implicitly denied
// without needing explicit forbid rules.
//
// Root users bypass Cedar entirely (handled in code before evaluation).
//
// PRINCIPAL TYPES:
//   Workspace — autonomous entities (agents, devices, CLI tools)
//   User      — human operators (admin, operator, viewer roles)
//
// ACTION REFERENCE:
//   access              - Direct credential access via API (workspaces only)
//   vend_credential     - Credential vending through proxy (workspaces only)
//   list                - List/view resources
//   create              - Create a new resource
//   update              - Update a credential
//   delete              - Delete a resource
//   unprotect           - Reveal raw credential secret (users only)
//   manage_permissions  - Manage per-credential permission grants
//   manage_policies     - CRUD Cedar policies
//   manage_users        - CRUD user accounts
//   manage_workspaces   - View/enable/disable/configure workspaces
//   view_audit          - View audit log entries
//   rotate_key          - Rotate a workspace's API key
//   manage_oidc_providers - CRUD OIDC identity providers
//   manage_vaults       - Share/unshare credential vaults
//   rotate_encryption_key - Rotate the server encryption key
//   manage_mcp_servers  - CRUD MCP server registrations
//   mcp_tool_call       - Call a tool on an MCP server
//   mcp_list_tools      - List available tools on an MCP server
//   register_workspace  - Register a new workspace
//   manage_tags         - Add/remove tags on workspaces, system
//
// =============================================================================


// ---------------------------------------------------------------------------
// SECTION 1: WORKSPACE POLICIES
// ---------------------------------------------------------------------------

// 1a. Enabled admin workspaces can do everything.
permit(
  principal is AgentCordon::Workspace,
  action,
  resource
) when {
  principal.enabled && principal.tags.contains("admin")
};

// 1b. Enabled workspaces can list, vend, update, and delete their owner's
// credentials. `access` is intentionally excluded — workspaces must never see
// raw credential secrets. They use `vend_credential` to proxy requests.
// `manage_permissions` is excluded — credential sharing is a human-only operation.
permit(
  principal is AgentCordon::Workspace,
  action in [
    AgentCordon::Action::"list",
    AgentCordon::Action::"vend_credential",
    AgentCordon::Action::"update",
    AgentCordon::Action::"delete"
  ],
  resource is AgentCordon::Credential
) when {
  principal.enabled && principal has owner && resource.owner == principal.owner
};

// 1c. Enabled workspaces can create resources.
permit(
  principal is AgentCordon::Workspace,
  action == AgentCordon::Action::"create",
  resource is AgentCordon::System
) when {
  principal.enabled
};

// 1d. Enabled workspaces can list system-level resources (MCP servers, etc.).
permit(
  principal is AgentCordon::Workspace,
  action == AgentCordon::Action::"list",
  resource is AgentCordon::System
) when {
  principal.enabled
};


// ---------------------------------------------------------------------------
// SECTION 2: USER POLICIES
// ---------------------------------------------------------------------------

// --- Admin ---

// 2a. Enabled admin users have full access to system, workspace, MCP, and
// policy resources. Credential access is scoped to own credentials (2b).
permit(
  principal is AgentCordon::User,
  action,
  resource is AgentCordon::System
) when {
  principal.enabled && principal.role == "admin"
};

permit(
  principal is AgentCordon::User,
  action,
  resource is AgentCordon::WorkspaceResource
) when {
  principal.enabled && principal.role == "admin"
};

permit(
  principal is AgentCordon::User,
  action,
  resource is AgentCordon::McpServer
) when {
  principal.enabled && principal.role == "admin"
};

permit(
  principal is AgentCordon::User,
  action,
  resource is AgentCordon::PolicyResource
) when {
  principal.enabled && principal.role == "admin"
};

// 2b. Enabled admin users can manage their own credentials.
// Scoped by ownership — admins only see/modify their own.
// Root users bypass Cedar entirely, so root can see all.
permit(
  principal is AgentCordon::User,
  action,
  resource is AgentCordon::Credential
) when {
  principal.enabled && principal.role == "admin" && resource.owner == principal
};

// --- Operator ---

// 2c. Enabled operators can manage their own credentials.
permit(
  principal is AgentCordon::User,
  action in [
    AgentCordon::Action::"list",
    AgentCordon::Action::"update",
    AgentCordon::Action::"delete",
    AgentCordon::Action::"unprotect"
  ],
  resource is AgentCordon::Credential
) when {
  principal.enabled && principal.role == "operator" && resource.owner == principal
};

// 2d. Enabled operators can create, list, view audit, and manage MCP servers.
permit(
  principal is AgentCordon::User,
  action in [
    AgentCordon::Action::"create",
    AgentCordon::Action::"list",
    AgentCordon::Action::"view_audit",
    AgentCordon::Action::"manage_mcp_servers"
  ],
  resource is AgentCordon::System
) when {
  principal.enabled && principal.role == "operator"
};

// 2e. Enabled operators can manage workspaces.
permit(
  principal is AgentCordon::User,
  action == AgentCordon::Action::"manage_workspaces",
  resource
) when {
  principal.enabled && principal.role == "operator"
};

// --- Viewer ---

// 2f. Enabled viewers can list system resources and view audit.
permit(
  principal is AgentCordon::User,
  action in [
    AgentCordon::Action::"list",
    AgentCordon::Action::"view_audit"
  ],
  resource is AgentCordon::System
) when {
  principal.enabled && principal.role == "viewer"
};

// 2g. Enabled viewers can list their own credentials.
permit(
  principal is AgentCordon::User,
  action == AgentCordon::Action::"list",
  resource is AgentCordon::Credential
) when {
  principal.enabled && principal.role == "viewer" && resource.owner == principal
};


// ---------------------------------------------------------------------------
// SECTION 3: MCP POLICIES
// ---------------------------------------------------------------------------

// 3a. Enabled workspaces can discover tools on enabled MCP servers.
permit(
  principal is AgentCordon::Workspace,
  action == AgentCordon::Action::"mcp_list_tools",
  resource is AgentCordon::McpServer
) when {
  principal.enabled && resource.enabled
};

// 3b. Enabled workspaces can call tools on enabled MCP servers.
permit(
  principal is AgentCordon::Workspace,
  action == AgentCordon::Action::"mcp_tool_call",
  resource is AgentCordon::McpServer
) when {
  principal.enabled && resource.enabled
};


// ---------------------------------------------------------------------------
// SECTION 4: SECURITY BOUNDARIES
// ---------------------------------------------------------------------------

// 4a. Workspaces must NEVER see raw credential secrets. Agents use
// vend_credential to proxy requests; credentials are injected server-side.
// Without this, an admin workspace (1a) could reveal raw secrets.
forbid(
  principal is AgentCordon::Workspace,
  action == AgentCordon::Action::"unprotect",
  resource
);

// 4b. Disabled MCP servers must not be callable or discoverable.
// Without these, admin workspaces (1a) could bypass the enabled check.
forbid(
  principal,
  action == AgentCordon::Action::"mcp_tool_call",
  resource is AgentCordon::McpServer
) when {
  !resource.enabled
};

forbid(
  principal,
  action == AgentCordon::Action::"mcp_list_tools",
  resource is AgentCordon::McpServer
) when {
  !resource.enabled
};
