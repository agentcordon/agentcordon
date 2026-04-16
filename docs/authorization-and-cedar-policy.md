> [Home](index.md) > Authorization & Cedar Policy

# Authorization and Cedar Policy

All authorization decisions in AgentCordon are modeled as **Cedar policies**. Cedar is the **single source of truth** -- there are no DB-based permission grants or secondary authorization tables.

> [!IMPORTANT]
> **Deny-by-default** is enforced at three independent layers: Cedar semantics (no permit = deny), code-level mapping (`PolicyDecisionResult::Forbid`), and middleware error handling (`ApiError::Forbidden`). If no `permit()` matches, access is denied.

---

**On this page:**
[Cedar Integration](#cedar-integration) | [Entity Types](#entity-types) | [Actions](#actions) | [Policy Evaluation](#policy-evaluation) | [Default Policy](#default-policy) | [Policy Storage](#policy-storage-and-loading) | [Policy Templates](#policy-templates) | [Writing Custom Policies](#writing-custom-policies) | [Audit Logging](#audit-logging) | [Security Invariants](#security-invariants)

---

## Cedar Integration

| Component | Details |
|-----------|---------|
| **Library** | `cedar-policy` v4 (`crates/core/Cargo.toml`) |
| **Engine** | `CedarPolicyEngine` (`crates/core/src/policy/cedar/mod.rs`) |
| **Auditing wrapper** | `AuditingPolicyEngine` (`crates/server/src/auditing_policy_engine.rs`) |
| **Schema** | `policies/schema.cedarschema.json` |
| **Default policy** | `policies/default.cedar` |

---

## Entity Types

The Cedar schema defines these entity types in the `AgentCordon` namespace:

| Entity Type | Key Attributes | Purpose |
|-------------|---------------|---------|
| `Workspace` | `name`, `enabled`, `tags`, `owner` (User, optional), `parent` (Workspace, optional) | Autonomous agents and devices |
| `User` | `name`, `role` (admin/operator/viewer), `enabled`, `is_root` | Human operators |
| `Credential` | `name`, `service`, `scopes`, `owner` (User), `tags` | API credentials and secrets |
| `System` | -- (no attributes) | System-level resource (creating credentials, listing, etc.) |
| `McpServer` | `name`, `enabled`, `tags`, `workspace` (Workspace, optional), `owner` (User, optional) | MCP server resource |
| `PolicyResource` | -- (no attributes) | Policy management resource |
| `WorkspaceResource` | `name`, `enabled`, `owner` (User, optional) | Workspace management by users |

> [!NOTE]
> The `Server` entity type (`AgentCordon::Server`) is used in code for OAuth client principals (`PolicyPrincipal::Server`) but is **not** in the Cedar schema. Server entities are built by `build_server_entity()` with attributes `name`, `enabled`, `tags`, and `client_id`.

### Entity UID Formats

```
AgentCordon::Workspace::"{workspace_uuid}"
AgentCordon::User::"{user_uuid}"
AgentCordon::Credential::"{credential_uuid}"
AgentCordon::McpServer::"{server_id}"
AgentCordon::System::"system"
AgentCordon::PolicyResource::"policies"
```

---

## Actions

| Category | Actions |
|----------|---------|
| **Credential** | `access`, `list`, `create`, `update`, `delete`, `unprotect`, `vend_credential`, `manage_permissions` |
| **MCP** | `mcp_tool_call`, `mcp_list_tools` |
| **Policy** | `manage_policies` |
| **User** | `manage_users` |
| **Workspace** | `manage_workspaces`, `view_audit`, `rotate_key`, `manage_mcp_servers`, `manage_tags`, `manage_oidc_providers`, `manage_vaults`, `rotate_encryption_key` |
| **Registration** | `register_workspace` |

---

## Policy Evaluation

Policy evaluation is a pure function (`crates/core/src/policy/cedar/mod.rs`):

```
evaluate(principal, action, resource, context) -> PolicyDecision
```

### Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| **Principal** | `PolicyPrincipal` | `User`, `Workspace`, or `Server` (OAuth client) |
| **Action** | `&str` | One of the actions listed above |
| **Resource** | `PolicyResource` | `Credential`, `System`, `PolicyAdmin`, `WorkspaceResource`, `McpServer` |
| **Context** | `PolicyContext` | Additional fields depending on the action (see below) |

### Context Fields by Action

| Action | Context Fields |
|--------|---------------|
| `access` | `requested_scopes`, `timestamp` |
| `vend_credential` | `requested_scopes`, `target_url`, `justification`, `timestamp` |
| `mcp_tool_call` | `tool_name`, `credential_name`, `justification`, `timestamp` |
| `mcp_list_tools` | `timestamp` |
| `manage_tags` | `tag_value`, `timestamp` |
| Others | `timestamp` |

### Root Bypass

> [!WARNING]
> Users with `is_root: true` bypass Cedar evaluation entirely. This is handled in code before the policy engine is called -- the root bypass is **not** a Cedar policy. It returns `Permit` with reason `"root_bypass"`.

### Decision Flow

```
1. Build Cedar entities (principal, resource) from domain objects
2. Build Cedar context with action-specific fields
3. Call cedar_policy::Authorizer::is_authorized()
4. Cedar::Allow  -> PolicyDecisionResult::Permit  (emit metric)
5. Cedar::Deny   -> PolicyDecisionResult::Forbid  (emit metric)
6. Return PolicyDecision { decision, reasons, errors }
```

Metrics are emitted as `policy_evaluations_total` with `decision="permit"` or `decision="forbid"`.

---

## Default Policy

The default policy (`policies/default.cedar`, ~255 lines) is seeded at first startup. It covers four sections:

### Section 1: Workspace Policies

```cedar
// 1a: Enabled admin workspaces (tagged "admin") can do everything
permit(
  principal is AgentCordon::Workspace,
  action,
  resource
) when {
  principal.enabled && principal.tags.contains("admin")
};

// 1b: Enabled workspaces can list, vend, update, and delete their
// owner's credentials. `access` and `manage_permissions` are excluded.
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

// 1c: Enabled workspaces can create resources
permit(
  principal is AgentCordon::Workspace,
  action == AgentCordon::Action::"create",
  resource is AgentCordon::System
) when { principal.enabled };

// 1d: Enabled workspaces can list system resources
permit(
  principal is AgentCordon::Workspace,
  action == AgentCordon::Action::"list",
  resource is AgentCordon::System
) when { principal.enabled };
```

### Section 2: User Policies

| Policy | Role | Permissions |
|--------|------|-------------|
| 2a (4 rules) | Admin | All actions on System, WorkspaceResource, McpServer, and PolicyResource |
| 2b | Admin | All actions on own credentials only (`resource.owner == principal`) |
| 2c | Operator | `list`, `update`, `delete`, `unprotect` on own credentials |
| 2d | Operator | `create`, `list`, `view_audit`, `manage_mcp_servers` on System |
| 2e | Operator | `manage_workspaces` on any resource |
| 2f | Viewer | `list`, `view_audit` on System |
| 2g | Viewer | `list` on own credentials only |

> [!NOTE]
> Actions not explicitly granted to a role are implicitly denied. For example, operators cannot `manage_policies`, `manage_users`, `rotate_key`, or `manage_tags`. Viewers can only read. Admin credential access is owner-scoped -- root users (who bypass Cedar) are the only principals that can see all credentials.

### Section 3: MCP Policies

```cedar
// 3a: Enabled workspaces can use MCP servers owned by the same user.
// Both mcp_list_tools and mcp_tool_call are granted in a single rule
// with an owner-match condition.
permit(
  principal is AgentCordon::Workspace,
  action in [
    AgentCordon::Action::"mcp_list_tools",
    AgentCordon::Action::"mcp_tool_call"
  ],
  resource is AgentCordon::McpServer
) when {
  principal.enabled && resource.enabled
  && principal has owner && resource has owner
  && resource.owner == principal.owner
};
```

### Section 4: Security Boundaries (Forbid Rules)

> [!CAUTION]
> These `forbid()` rules **override any `permit()`** that might match. They are the hard security boundaries.

```cedar
// 4a: Workspaces can NEVER see raw secrets
forbid(
  principal is AgentCordon::Workspace,
  action == AgentCordon::Action::"unprotect",
  resource
);

// 4b: Disabled MCP servers cannot be called
forbid(
  principal,
  action == AgentCordon::Action::"mcp_tool_call",
  resource is AgentCordon::McpServer
) when { !resource.enabled };

// 4c: Disabled MCP servers cannot be discovered
forbid(
  principal,
  action == AgentCordon::Action::"mcp_list_tools",
  resource is AgentCordon::McpServer
) when { !resource.enabled };
```

> [!NOTE]
> There are no explicit `forbid()` rules for disabled workspaces or disabled users. Instead, every `permit()` rule includes a `principal.enabled` condition, so disabled principals are implicitly denied by Cedar's deny-by-default semantics.

---

## Policy Storage and Loading

Policies are stored in the database (`policies` table) and loaded at startup:

1. **Seed** -- if no enabled policies exist, `policies/default.cedar` is inserted as a system policy
2. **Load** -- all enabled policies are compiled into a `PolicySet` via `CedarPolicyEngine::new()`
3. **Reload** -- `reload_policies()` atomically replaces the policy set (parse-then-swap via `RwLock`)

> [!NOTE]
> If any policy fails to parse during reload, the current set remains unchanged. This prevents a broken policy from locking you out.

### Policy Management API

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/policies` | Create policy |
| GET | `/api/v1/policies` | List all policies |
| GET | `/api/v1/policies/{id}` | Get policy |
| PUT | `/api/v1/policies/{id}` | Update policy |
| DELETE | `/api/v1/policies/{id}` | Delete policy |
| POST | `/api/v1/policies/validate` | Validate Cedar syntax (structured errors) |
| POST | `/api/v1/policies/test` | Test a policy decision |
| GET | `/api/v1/policies/schema` | Get Cedar schema |
| GET | `/api/v1/policies/schema/reference` | Get Cedar schema reference |

---

## Policy Templates

Pre-built templates are available in `data/policy-templates/`:

| Template | Use Case |
|----------|----------|
| **Permit All** (`permit-all.json`) | Development/testing -- allows all actions |
| **Deny All** (`deny-all.json`) | Baseline restrictive -- denies everything |
| **Workspace Access** (`workspace-access.json`) | Production starting point -- workspaces can vend credentials |

### Tag-Based Access Example

`policies/shared-tag-access.cedar` demonstrates tag-based credential sharing:

```cedar
// Workspaces can vend credentials that share a tag
permit(
  principal is AgentCordon::Workspace,
  action == AgentCordon::Action::"vend_credential",
  resource is AgentCordon::Credential
) when {
  principal.tags.containsAny(resource.tags)
};
```

This file also grants `access` and `list` for tag-matched credentials.

---

## Writing Custom Policies

### Granting a Workspace Access to a Specific Credential

```cedar
permit(
  principal == AgentCordon::Workspace::"workspace-uuid-here",
  action == AgentCordon::Action::"vend_credential",
  resource == AgentCordon::Credential::"credential-uuid-here"
);
```

### Granting Tag-Based MCP Access

```cedar
permit(
  principal is AgentCordon::Workspace,
  action == AgentCordon::Action::"mcp_tool_call",
  resource is AgentCordon::McpServer
) when {
  principal.tags.containsAny(resource.tags)
  && resource.enabled
};
```

### Restricting a Workspace to Specific Tools

```cedar
permit(
  principal == AgentCordon::Workspace::"workspace-uuid",
  action == AgentCordon::Action::"mcp_tool_call",
  resource == AgentCordon::McpServer::"server-id"
) when {
  context.tool_name == "allowed_tool_name"
};
```

---

## Audit Logging

Every policy decision is automatically logged by `AuditingPolicyEngine` (`crates/server/src/auditing_policy_engine.rs`), a decorator around `CedarPolicyEngine`. Individual route handlers do not need to emit `PolicyEvaluated` events -- the wrapper handles this centrally.

The audit event (`AuditEvent`, defined in `crates/core/src/domain/audit.rs`) includes:

| Field | Description |
|-------|-------------|
| `event_type` | `PolicyEvaluated` (for all policy decisions) |
| `action` | Cedar action name |
| `decision` | `Permit` or `Forbid` |
| `decision_reason` | Matching policy IDs from Cedar diagnostics |
| `correlation_id` | Request correlation ID |
| `workspace_id` / `user_id` | Principal identity |
| `resource_type` / `resource_id` | Target resource |
| `metadata` | Policy reasoning details and OAuth claims (no secrets) |

The `enrich_metadata_with_policy_reasoning()` function adds Cedar diagnostic details (effect, reasons, errors, justification) to audit metadata.

---

## Security Invariants

| # | Invariant | Enforcement |
|:-:|-----------|-------------|
| 1 | **Agents never see raw secrets** | `unprotect` explicitly forbidden for all workspaces (Section 4a) |
| 2 | **Disabled entities blocked** | Every `permit()` requires `principal.enabled`; disabled principals get no permits |
| 3 | **Disabled MCP servers blocked** | Explicit `forbid()` rules override admin workspace permits (Section 4b, 4c) |
| 4 | **Credential ownership scoped** | Workspaces access credentials through `owner` match; admins/operators see only own credentials |
| 5 | **Deny-by-default** | Three independent layers enforce this |
| 6 | **Decision logging** | Every evaluation is auditable via `AuditingPolicyEngine` with policy reasoning |

---

> **See also:** [Credential Encryption](credential-encryption.md) | [Granting MCP Server Access](granting-mcp-server-access.md) | [System Architecture](system-architecture.md)
