// =============================================================================
// AgentCordon Default Cedar Policies (v2.0 — Unified Workspace Model)
// =============================================================================
//
// Cedar denies by default when no permit policy matches.
// No explicit forbid is needed -- the absence of a matching permit is sufficient.
//
// Root users bypass Cedar entirely (handled in code before evaluation).
// This file contains policies for TWO principal types:
//   1. Workspaces -- autonomous entities (agents, devices, CLI tools)
//   2. Users      -- human operators authenticating via username/password + session
//
// TAG / ROLE REFERENCE:
//   Workspace tags: "admin" (full access), custom tags (policy-driven)
//   User roles:     "admin" (full access), "operator" (manage day-to-day),
//                   "viewer" (read-only)
//
// ACTION REFERENCE:
//   access              - Direct credential access via API (workspaces only)
//   vend_credential     - Credential vending through proxy (workspaces only)
//   list                - List/view resources (workspaces + users)
//   create              - Create a new resource (workspaces + users)
//   update              - Update a credential (workspaces + users)
//   delete              - Delete a resource (workspaces + users)
//   unprotect           - Reveal raw credential secret (users only; workspaces forbidden)
//   manage_permissions  - Manage per-credential permission grants
//   manage_policies     - CRUD Cedar policies
//   manage_users        - CRUD user accounts (users only)
//   manage_workspaces   - View/enable/disable/configure workspaces
//   manage_enrollments  - Approve/deny enrollment requests
//   view_audit          - View audit log entries
//   rotate_key          - Rotate a workspace's API key (users only)
//   manage_oidc_providers - CRUD OIDC identity providers (users only)
//   manage_vaults       - Share/unshare credential vaults (users only)
//   rotate_encryption_key - Rotate the server encryption key (users only)
//   manage_mcp_servers  - CRUD MCP server registrations (users only)
//   mcp_tool_call       - Call a tool on an MCP server (workspaces)
//   mcp_list_tools      - List available tools on an MCP server (workspaces)
//   register_workspace  - Register a new workspace (workspaces)
//   manage_tags         - Add/remove tags on workspaces, system (users only)
//
// =============================================================================


// ---------------------------------------------------------------------------
// SECTION 1: WORKSPACE POLICIES
// ---------------------------------------------------------------------------

// 1a. Admin workspaces can do everything.
permit(
  principal is AgentCordon::Workspace,
  action,
  resource
) when {
  principal.tags.contains("admin")
};

// 1b. Credential owners can list/vend/update/delete their own credentials.
// Note: `access` is intentionally excluded — workspaces must NEVER see raw
// credential secrets. They use `vend_credential` to proxy requests (credentials
// injected automatically) and `list` to discover what's available.
// Note: `manage_permissions` is intentionally excluded — credential sharing
// (granting other workspaces access) is a human-only operation via the admin UI.
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
  principal has owner && resource.owner == principal.owner
};

// 1c. Workspaces can create credentials.
permit(
  principal is AgentCordon::Workspace,
  action == AgentCordon::Action::"create",
  resource is AgentCordon::System
);

// 1e. Enabled workspaces can list system-level resources (MCP servers, etc.).
// This grants access to discovery endpoints like /api/v1/mcp-servers.
// Listing only exposes metadata — never raw secrets.
permit(
  principal is AgentCordon::Workspace,
  action == AgentCordon::Action::"list",
  resource is AgentCordon::System
) when {
  principal.enabled
};

// 1d. Enabled workspaces can vend their owner's credentials through the proxy.
// Agents never see raw secrets — vend_credential injects credentials into
// upstream requests automatically. Scoped by ownership: a workspace can only
// vend credentials belonging to its owner. Operators can tighten this further
// by removing this policy and using per-credential grants or tag-based access.
permit(
  principal is AgentCordon::Workspace,
  action == AgentCordon::Action::"vend_credential",
  resource is AgentCordon::Credential
) when {
  principal.enabled && principal has owner && resource.owner == principal.owner
};


// ---------------------------------------------------------------------------
// SECTION 2: USER POLICIES
// ---------------------------------------------------------------------------

// 2a. Admin users can perform any action on System resources.
permit(
  principal is AgentCordon::User,
  action,
  resource is AgentCordon::System
) when {
  principal.role == "admin"
};

// 2a-ws. Admin users can perform any action on workspace resources.
permit(
  principal is AgentCordon::User,
  action,
  resource is AgentCordon::WorkspaceResource
) when {
  principal.role == "admin"
};

// 2a-mcp. Admin users can perform any action on MCP server resources.
permit(
  principal is AgentCordon::User,
  action,
  resource is AgentCordon::McpServer
) when {
  principal.role == "admin"
};

// 2a-policy. Admin users can manage policies.
permit(
  principal is AgentCordon::User,
  action,
  resource is AgentCordon::PolicyResource
) when {
  principal.role == "admin"
};

// 2a-cred. Admin users can manage their OWN credentials.
// Credentials are scoped by ownership — admins only see/modify their own.
// Root users bypass Cedar entirely (handled in code), so root can see all.
permit(
  principal is AgentCordon::User,
  action,
  resource is AgentCordon::Credential
) when {
  principal.role == "admin" && resource.owner == principal
};

// 2b. Operators can list their OWN credentials.
permit(
  principal is AgentCordon::User,
  action == AgentCordon::Action::"list",
  resource is AgentCordon::Credential
) when {
  principal.role == "operator" && resource.owner == principal
};

permit(
  principal is AgentCordon::User,
  action == AgentCordon::Action::"create",
  resource is AgentCordon::System
) when {
  principal.role == "operator"
};

permit(
  principal is AgentCordon::User,
  action == AgentCordon::Action::"delete",
  resource is AgentCordon::Credential
) when {
  principal.role == "operator" && resource.owner == principal
};

// manage_permissions is admin-only (granted via 2a-cred).
// Credential sharing controls who else can access secrets — too sensitive for operators.

// 2b-update. Operators can update their OWN credentials.
permit(
  principal is AgentCordon::User,
  action == AgentCordon::Action::"update",
  resource is AgentCordon::Credential
) when {
  principal.role == "operator" && resource.owner == principal
};

// 2c. Operators can list credentials at the system level.
permit(
  principal is AgentCordon::User,
  action == AgentCordon::Action::"list",
  resource is AgentCordon::System
) when {
  principal.role == "operator"
};

// 2d. Operators can manage workspaces (view, enable/disable, configure).
permit(
  principal is AgentCordon::User,
  action == AgentCordon::Action::"manage_workspaces",
  resource
) when {
  principal.role == "operator"
};

// 2e. Operators can manage enrollments (approve/deny requests).
permit(
  principal is AgentCordon::User,
  action == AgentCordon::Action::"manage_enrollments",
  resource is AgentCordon::System
) when {
  principal.role == "operator"
};

// 2e-vaults. Admins can manage vaults (share/unshare).
permit(
  principal is AgentCordon::User,
  action == AgentCordon::Action::"manage_vaults",
  resource is AgentCordon::System
) when {
  principal.role == "admin"
};

// 2f. Operators can view the audit log.
permit(
  principal is AgentCordon::User,
  action == AgentCordon::Action::"view_audit",
  resource is AgentCordon::System
) when {
  principal.role == "operator"
};

// 2g. Viewers can list system resources (read-only).
permit(
  principal is AgentCordon::User,
  action == AgentCordon::Action::"list",
  resource is AgentCordon::System
) when {
  principal.role == "viewer"
};

// 2g-cred. Viewers can list their OWN credentials (read-only).
permit(
  principal is AgentCordon::User,
  action == AgentCordon::Action::"list",
  resource is AgentCordon::Credential
) when {
  principal.role == "viewer" && resource.owner == principal
};

// 2h. Viewers can view the audit log (read-only access).
permit(
  principal is AgentCordon::User,
  action == AgentCordon::Action::"view_audit",
  resource is AgentCordon::System
) when {
  principal.role == "viewer"
};

// 2i. Admin users can rotate workspace API keys.
permit(
  principal is AgentCordon::User,
  action == AgentCordon::Action::"rotate_key",
  resource is AgentCordon::WorkspaceResource
) when {
  principal.role == "admin"
};

// 2k. Operators can reveal secrets for their OWN credentials (unprotect action).
permit(
  principal is AgentCordon::User,
  action == AgentCordon::Action::"unprotect",
  resource is AgentCordon::Credential
) when {
  principal.role == "operator" && resource.owner == principal
};

// 2l. Admin users can manage tags on workspaces and system resources.
permit(
  principal is AgentCordon::User,
  action == AgentCordon::Action::"manage_tags",
  resource
) when {
  principal.role == "admin"
};


// ---------------------------------------------------------------------------
// SECTION 3: DEFENSE-IN-DEPTH FORBID RULES
// ---------------------------------------------------------------------------

// 3a. Disabled workspaces cannot perform any action.
// WHY: Permit 1a grants admin workspaces ALL actions without checking enabled.
// Without this forbid, a disabled admin workspace would still have full access.
forbid(
  principal is AgentCordon::Workspace,
  action,
  resource
) when {
  !principal.enabled
};

// 3b. Disabled users cannot perform any action.
// WHY: Permits 2a-* grant admin/operator users broad access without checking enabled.
// Without this forbid, a disabled admin user would still have full access.
forbid(
  principal is AgentCordon::User,
  action,
  resource
) when {
  !principal.enabled
};

// 3c. REMOVED — non-admin workspaces have no permit for manage_policies,
// so Cedar's implicit deny handles this. No explicit forbid needed.

// 3d. Workspaces cannot reveal credential secrets (unprotect action).
// WHY: CRITICAL secrets boundary — agents must NEVER see raw secret values.
// Without this forbid, an admin workspace (permit 1a) could read raw secrets.
// Agents use vend_credential to proxy requests; credentials are injected automatically.
forbid(
  principal is AgentCordon::Workspace,
  action == AgentCordon::Action::"unprotect",
  resource
);

// 3e. Users cannot list credentials owned by other users.
// WHY: Tenant isolation — without this, admin users (permit 2a-cred) could see
// all credentials. This enforces per-user scoping. Root bypasses Cedar in code.
forbid(
  principal is AgentCordon::User,
  action == AgentCordon::Action::"list",
  resource is AgentCordon::Credential
) when {
  resource.owner != principal
};

// 3f. REMOVED — was a blanket forbid preventing cross-owner credential vending.
// This blocked explicit Cedar grant policies (e.g., `grant:{cred}:{workspace}:vend_credential`)
// from enabling cross-workspace credential sharing, because Cedar forbid always overrides permit.
// Security is preserved by deny-by-default: without an explicit grant policy, cross-owner
// vending is denied (no matching permit). Policy 1d only permits same-owner vending.
// Cross-owner access requires an explicit per-credential Cedar grant policy.


// ---------------------------------------------------------------------------
// SECTION 4: MCP POLICIES
// ---------------------------------------------------------------------------

// 4a. Enabled workspaces can discover tools on enabled MCP servers.
permit(
  principal is AgentCordon::Workspace,
  action == AgentCordon::Action::"mcp_list_tools",
  resource is AgentCordon::McpServer
) when {
  principal.enabled && resource.enabled
};

// 4b. All workspaces can call tools on enabled MCP servers.
permit(
  principal is AgentCordon::Workspace,
  action == AgentCordon::Action::"mcp_tool_call",
  resource is AgentCordon::McpServer
) when {
  resource.enabled
};

// 4c. Defense-in-depth — forbid tool calls on disabled MCP servers.
// WHY: Permits 4b checks resource.enabled, but this forbid is belt-and-suspenders
// to ensure disabled MCP servers are never callable even if new permits are added.
forbid(
  principal,
  action == AgentCordon::Action::"mcp_tool_call",
  resource is AgentCordon::McpServer
) when {
  !resource.enabled
};

// 4d. Defense-in-depth — forbid tool listing on disabled MCP servers.
// WHY: Permits 4a checks resource.enabled, but this forbid is belt-and-suspenders
// to ensure disabled MCP servers can't even be discovered via tool listing.
forbid(
  principal,
  action == AgentCordon::Action::"mcp_list_tools",
  resource is AgentCordon::McpServer
) when {
  !resource.enabled
};


// ---------------------------------------------------------------------------
// SECTION 5: CREDENTIAL ACCESS POLICIES
// ---------------------------------------------------------------------------

// 5b. REMOVED — was a blanket permit allowing any enabled workspace to list
// ALL credentials regardless of ownership. Credential listing is now scoped
// by ownership (policy 1b) and per-credential Cedar grants. This prevents
// User A's workspaces from seeing User B's credentials.

// 5c. REMOVED — was a blanket permit allowing any enabled workspace to directly
// access any credential. Same security concern as 5b. Credential access is now
// controlled by fine-grained Cedar grant policies and tag-based access.

// 5d. REMOVED — was a forbid preventing disabled workspaces from vending credentials.
// This is a strict subset of rule 3a which already forbids ALL actions for disabled
// workspaces. Removed to reduce policy surface area without changing behavior.
