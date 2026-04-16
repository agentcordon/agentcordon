> [Home](index.md) · Granting MCP Server Access

# Granting MCP Server Access

This guide shows how to grant a workspace (agent) access to an MCP server, including **cross-workstation scenarios** where the MCP server runs on a different machine.

---

**On this page:**
[Overview](#overview) · [Prerequisites](#prerequisites) · [HTTP MCP Server Setup](#step-by-step-http-mcp-server) · [STDIO Servers](#stdio-mcp-servers-local-only) · [Credential Placeholders](#credential-placeholders-in-headers) · [SSRF Protection](#ssrf-protection) · [Security Considerations](#security-considerations) · [Complete Example](#complete-example)

---

## Overview

MCP servers in AgentCordon can use two transports:

| Transport | Description | Cross-Workstation? |
|-----------|-------------|:------------------:|
| **STDIO** | Subprocess spawned locally via command + args | No -- local only |
| **HTTP/HTTPS** | JSON-RPC over HTTP to an upstream URL | Yes |

> **Which transport should I use?**
> - Use **STDIO** for tools that run on the same machine as the agent (fastest, simplest)
> - Use **HTTP/HTTPS** for tools on remote machines or shared infrastructure

---

## Prerequisites

- AgentCordon server running and accessible from both workstations
- Both workstations enrolled (see [Workspace Enrollment](workspace-enrollment.md))
- The MCP server exposed via HTTP on the host workstation

---

## Step-by-Step: HTTP MCP Server

### Step 1 -- Register the MCP Server

There is no direct `POST /api/v1/mcp-servers` create endpoint. MCP servers are created through one of these paths:

**Option A: Provision from the catalog (recommended)**

```bash
curl -X POST http://localhost:3140/api/v1/mcp-servers/provision \
  -H "Content-Type: application/json" \
  -H "Cookie: session=..." \
  -d '{
    "template_key": "remote-tools",
    "workspace_id": "workspace-a-uuid",
    "secret_value": "sk-..."
  }'
```

This creates the MCP server record from a catalog template, optionally creates or links a credential, and runs best-effort tool discovery automatically. Requires the `manage_mcp_servers` Cedar permission.

**Option B: Import via API**

```bash
curl -X POST http://localhost:3140/api/v1/mcp-servers/import \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <workspace-jwt>" \
  -d '{
    "workspace_id": "workspace-a-uuid",
    "servers": [
      {
        "name": "remote-tools",
        "transport": "http",
        "url": "https://workstation-b.example.com:8080/mcp",
        "tools": [
          { "name": "clone_repo" },
          { "name": "list_files" }
        ],
        "required_credentials": ["<credential-uuid>"]
      }
    ]
  }'
```

Notes on the import endpoint:
- The request body wraps the server array in a `{ workspace_id, servers: [...] }` envelope.
- The `transport` field accepts `"http"` (default) or `"sse"`. There is no `"url"` transport type.
- The `required_credentials` array expects **credential UUIDs**, not human-readable names.
- Cedar authorization evaluates the `create` action on the `System` resource for the authenticated workspace.
- Tool discovery does not happen automatically on import; tools can be provided in the `tools` array.

> **Warning:** The `name` field must **not** contain dots (`.`) -- dots break the 3-part scope format (`{workspace_name}.{mcp_server_name}.{action}`).

**Option C: Provision via OAuth2 flow**

For MCP servers that use OAuth2 authentication:

```bash
# Initiate the OAuth2 flow (returns an authorize URL)
curl -X POST http://localhost:3140/api/v1/mcp-servers/oauth/initiate \
  -H "Content-Type: application/json" \
  -H "Cookie: session=..." \
  -d '{
    "template_key": "github-mcp",
    "workspace_id": "workspace-a-uuid"
  }'
```

The server returns an `authorize_url`. After the user completes the OAuth2 consent flow, the callback at `GET /api/v1/mcp-servers/oauth/callback` handles token exchange, credential creation, and MCP server provisioning automatically.

---

### Step 2 -- Default Policy: Same-Owner Access

Before creating any custom policies, note that **the default Cedar policy (3a) already grants MCP access to same-owner workspaces**:

```cedar
// 3a. Enabled workspaces can use MCP servers owned by the same user.
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

This means: if the admin who provisioned the MCP server also owns the workspace, **no additional policy is needed**. The workspace automatically inherits access.

---

### Step 3 -- Create a Cedar Policy for Cross-Owner Access

If the workspace and MCP server have **different owners**, you need to grant access explicitly. Cedar policies control all access -- choose one of these approaches:

#### Option A: Grant via Permissions API

```bash
curl -X POST http://localhost:3140/api/v1/mcp-servers/{server-id}/permissions \
  -H "Content-Type: application/json" \
  -H "Cookie: session=..." \
  -d '{
    "workspace_id": "workspace-a-uuid",
    "permission": "mcp_tool_call"
  }'
```

This returns `201 Created` with the generated policy details:

```json
{
  "data": {
    "policy_id": "...",
    "policy_name": "grant:mcp:{server_id}:{workspace_id}:mcp_tool_call"
  }
}
```

The auto-generated Cedar policy:

```cedar
permit(
  principal == AgentCordon::Workspace::"workspace-a-uuid",
  action == AgentCordon::Action::"mcp_tool_call",
  resource == AgentCordon::McpServer::"server-id"
);
```

You can also create **deny** policies by adding `"mode": "deny"` to the request body. Deny policies generate `forbid` rules.

#### Option B: Grant Specific Tools Only

```bash
curl -X POST http://localhost:3140/api/v1/mcp-servers/{server-id}/permissions \
  -H "Content-Type: application/json" \
  -H "Cookie: session=..." \
  -d '{
    "workspace_id": "workspace-a-uuid",
    "permission": "mcp_tool_call:clone_repo"
  }'
```

Generates a tool-specific policy:

```cedar
permit(
  principal == AgentCordon::Workspace::"workspace-a-uuid",
  action == AgentCordon::Action::"mcp_tool_call",
  resource == AgentCordon::McpServer::"server-id"
) when {
  context.tool_name == "clone_repo"
};
```

Tool names in the `mcp_tool_call:<tool_name>` format must be 1-128 alphanumeric, underscore, or hyphen characters.

#### Option C: Generate Tag-Based Policies

Use the generate-policies endpoint to create Cedar policies based on agent tags and specific tools:

```bash
curl -X POST http://localhost:3140/api/v1/mcp-servers/{server-id}/generate-policies \
  -H "Content-Type: application/json" \
  -H "Cookie: session=..." \
  -d '{
    "tools": ["clone_repo", "list_files"],
    "agent_tags": ["team-a", "data-team"]
  }'
```

This generates one policy per (tool, tag) combination. For example, the policy for tag `team-a` and tool `clone_repo`:

```cedar
// Auto-generated: Allow agents tagged "team-a" to use tool "clone_repo" on MCP server "{server_id}"
permit(
  principal is AgentCordon::Workspace,
  action == AgentCordon::Action::"mcp_tool_call",
  resource == AgentCordon::McpServer::"{server_id}"
) when {
  principal.tags.contains("team-a") &&
  context.tool_name == "clone_repo"
};
```

Limits: maximum 50 tools and 50 agent tags per request. Duplicate policy names are skipped.

#### Option D: Write a Custom Cedar Policy

```bash
curl -X POST http://localhost:3140/api/v1/policies \
  -H "Content-Type: application/json" \
  -H "Cookie: session=..." \
  -d '{
    "name": "workspace-a-remote-tools-access",
    "cedar_policy": "permit(\n  principal == AgentCordon::Workspace::\"workspace-a-uuid\",\n  action in [AgentCordon::Action::\"mcp_tool_call\", AgentCordon::Action::\"mcp_list_tools\"],\n  resource == AgentCordon::McpServer::\"server-id\"\n);",
    "enabled": true
  }'
```

---

### Step 4 -- Set Up Credentials (if needed)

If the MCP server requires authentication, create a credential and link it. Credentials can be provided during provisioning (`secret_value` or `credential_id` fields on the provision endpoint) or created separately:

```bash
agentcordon credentials create \
  --name workstation-b-api-key \
  --service remote-tools \
  --value "sk-..."
```

The `required_credentials` field on the MCP server record contains **credential UUIDs** that tell the broker which credentials to resolve and inject when connecting.

---

### Step 5 -- Call the MCP Tool from Workstation A

```bash
# List available MCP servers
agentcordon mcp-servers

# List tools on a server
agentcordon mcp-tools

# Call a tool
agentcordon mcp-call remote-tools clone_repo --arg url=https://github.com/user/repo
```

These CLI commands route through the broker, which:

1. Syncs MCP server configs from `GET /api/v1/workspaces/mcp-servers`
2. Resolves credentials via ECIES-encrypted envelopes from the server
3. Authorizes the call via Cedar policy check on the server (`mcp_tool_call` action)
4. Injects resolved credentials into the upstream HTTP request headers
5. Forwards the JSON-RPC `tools/call` request to the upstream MCP server URL

For AI agent integration, `agentcordon init` generates a `.mcp.json` entry that allows Claude Code and other MCP-compatible agents to discover AgentCordon tools natively.

---

## STDIO MCP Servers (Local Only)

STDIO servers are spawned as local subprocesses and **cannot** be accessed from other workstations. However, you can still manage access policies for them.

### Register a STDIO MCP Server

Import a STDIO server via the import endpoint:

```json
{
  "workspace_id": "workspace-a-uuid",
  "servers": [
    {
      "name": "local-tools",
      "transport": "http",
      "url": "",
      "tools": [
        { "name": "read_file" },
        { "name": "write_file" }
      ]
    }
  ]
}
```

The same Cedar policy mechanisms apply -- the broker evaluates policies before routing calls.

---

## Credential Placeholders in Headers

For HTTP MCP servers, the broker resolves credentials automatically at connection time. When an MCP server has `required_credentials` set, the broker:

1. Fetches the credential via `GET /api/v1/workspaces/mcp-servers?include_credentials=true`
2. Decrypts the ECIES envelope using the broker's P-256 private key
3. Applies credential transforms (e.g., `bearer` adds an `Authorization: Bearer` header)
4. Connects to the upstream URL with the resolved headers

For OAuth2 credentials (`oauth2_user_authorization` type), the broker automatically exchanges the stored refresh token for an access token before injection. If the provider rotates the refresh token, the new value is persisted back to the server.

> **Important:** Credential values are **never logged**.

---

## SSRF Protection

HTTP MCP server URLs are validated to prevent SSRF:

- **Blocked by default:** loopback, private networks (10.x, 172.16.x, 192.168.x), link-local (169.254.x)
- **To allow local development:** `AGTCRDN_PROXY_ALLOW_LOOPBACK=true`

---

## Security Considerations

| # | Property | Details |
|:-:|----------|---------|
| 1 | **Cedar deny-by-default** | Workspaces have no MCP access unless explicitly granted or the same-owner default policy (3a) applies |
| 2 | **Per-tool granularity** | Policies can restrict access to specific tools via `context.tool_name` conditions |
| 3 | **Credential isolation** | Credentials are delivered via ECIES envelopes; only the broker with its P-256 key can decrypt |
| 4 | **Disabled servers blocked** | Forbid rules in the default policy (4b) prevent all `mcp_tool_call` and `mcp_list_tools` actions on disabled servers |
| 5 | **Audit trail** | Every `mcp_tool_call` and `mcp_list_tools` action is logged with tool name, workspace, and decision |
| 6 | **Transport security** | Use HTTPS for production HTTP MCP servers |
| 7 | **Grant/deny modes** | Permissions API supports both `grant` (permit) and `deny` (forbid) policy modes |

---

## Complete Example

```bash
# ===============================================
#  On the AgentCordon Server (Admin)
# ===============================================

# 1. Provision the MCP server from a catalog template
curl -X POST http://server:3140/api/v1/mcp-servers/provision \
  -H "Content-Type: application/json" \
  -H "Cookie: session=..." \
  -d '{
    "template_key": "data-pipeline",
    "workspace_id": "workspace-a-uuid",
    "secret_value": "sk-..."
  }'

# Tool discovery happens automatically during provisioning.
# If the MCP server and workspace share the same owner,
# the default Cedar policy (3a) grants access automatically.

# 2. (Optional) Grant cross-owner access -- only needed if different owners
curl -X POST http://server:3140/api/v1/mcp-servers/{id}/permissions \
  -H "Content-Type: application/json" \
  -H "Cookie: session=..." \
  -d '{ "workspace_id": "workspace-b-uuid", "permission": "mcp_tool_call" }'

curl -X POST http://server:3140/api/v1/mcp-servers/{id}/permissions \
  -H "Content-Type: application/json" \
  -H "Cookie: session=..." \
  -d '{ "workspace_id": "workspace-b-uuid", "permission": "mcp_list_tools" }'

# 3. (Optional) Generate tag-based per-tool policies
curl -X POST http://server:3140/api/v1/mcp-servers/{id}/generate-policies \
  -H "Content-Type: application/json" \
  -H "Cookie: session=..." \
  -d '{
    "tools": ["run_etl", "check_status"],
    "agent_tags": ["data-team"]
  }'

# ===============================================
#  On Workstation A (the agent)
# ===============================================

# 4. Discover available tools
agentcordon mcp-tools

# 5. Call a tool
agentcordon mcp-call data-pipeline run_etl \
  --arg dataset=users \
  --arg date=2026-03-26
```

---

## API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/mcp-servers` | List MCP servers |
| `GET` | `/api/v1/mcp-servers/{id}` | Get MCP server detail (with installed workspaces and tools) |
| `PUT` | `/api/v1/mcp-servers/{id}` | Update MCP server (name only) |
| `DELETE` | `/api/v1/mcp-servers/{id}` | Delete MCP server (cascades grant/deny policies) |
| `POST` | `/api/v1/mcp-servers/import` | Bulk import MCP servers (workspace JWT auth) |
| `POST` | `/api/v1/mcp-servers/provision` | Provision from catalog template (session auth) |
| `POST` | `/api/v1/mcp-servers/oauth/initiate` | Start OAuth2 provisioning flow |
| `GET` | `/api/v1/mcp-servers/oauth/callback` | OAuth2 callback handler |
| `GET` | `/api/v1/mcp-servers/{id}/permissions` | List permissions for an MCP server |
| `POST` | `/api/v1/mcp-servers/{id}/permissions` | Grant or deny a permission |
| `DELETE` | `/api/v1/mcp-servers/{id}/permissions/{workspace_id}/{permission}` | Revoke a permission |
| `POST` | `/api/v1/mcp-servers/{id}/generate-policies` | Generate tag-based Cedar policies |

---

> **See also:** [Authorization & Cedar Policy](authorization-and-cedar-policy.md) · [CLI Reference](cli-reference.md) · [System Architecture](system-architecture.md)
