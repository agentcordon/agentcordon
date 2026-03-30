# Workspace Enrollment -- AgentCordon

You are reading the enrollment instructions from an **AgentCordon Server**.

## Architecture

```
Agent/CLI (agentcordon) --> Broker (agentcordon-broker, port 3141) --> Server (port 3140) --> upstream APIs
                                        |                                     |
                                  OAuth tokens,                    Cedar policies, encrypted vault,
                                  credential proxy                 audit trail
```

AgentCordon uses a three-tier model:
- **CLI** (`agentcordon`) -- thin agent-side tool. Manages Ed25519 workspace identity, signs requests to the broker. Never touches credentials.
- **Broker** (`agentcordon-broker`) -- per-user daemon. Holds OAuth tokens, vends credentials, proxies upstream requests. Credentials never leave the broker.
- **Server** (`agent-cordon-server`) -- control plane. OAuth authorization server, Cedar policy engine, encrypted vault, audit pipeline.

## Quick Start (via CLI)

### 1. Initialize your workspace

```bash
agentcordon init
agentcordon register
```

`agentcordon init` generates a workspace keypair. `agentcordon register` talks to the broker, which opens an approval page in your browser.

### 2. Approve enrollment

Your human opens the approval URL in their browser, verifies the code, and clicks Approve.

### 3. Discover credentials

```bash
agentcordon credentials list
```

Or via API:

```
GET http://localhost:3140/api/v1/credentials
Authorization: Bearer <your-jwt>
```

### 4. Proxy requests

```bash
agentcordon proxy <name> GET https://api.github.com/repos/owner/repo
```

Or via API:

```
POST http://localhost:3140/api/v1/proxy/execute
Authorization: Bearer <your-jwt>
Content-Type: application/json

{
  "credential_id": "<id-from-step-3>",
  "target_url": "https://api.github.com/repos/owner/repo",
  "method": "GET",
  "headers": { "Accept": "application/json" }
}
```

## Quick Start (via API)

### 1. Register a workspace

Open [http://localhost:3140/register](http://localhost:3140/register) in your browser to create a workspace identity (Ed25519 keypair). Alternatively, use the CLI:

```bash
agentcordon init
agentcordon register
```

An admin approves enrollment via the approval URL displayed during registration.

### 2. Poll for approval

```
GET http://localhost:3140/api/v1/enroll/session/{session_token}/status
```

Poll every 2-3 seconds until status is `"approved"`.

### 3. Discover credentials

```
GET http://localhost:3140/api/v1/credentials
Authorization: Bearer <your-jwt>
```

### 4. Proxy requests

```
POST http://localhost:3140/api/v1/proxy/execute
Authorization: Bearer <your-jwt>
Content-Type: application/json

{
  "credential_id": "<id-from-step-3>",
  "target_url": "https://api.github.com/repos/owner/repo",
  "method": "GET",
  "headers": { "Accept": "application/json" }
}
```

## Granting Credentials to a Workspace

Before an agent can use credentials, an admin must:

1. **Create a credential** via the web UI or API (`POST /api/v1/credentials`)
2. **Ensure a Cedar policy grants access** to the workspace

### Default Access: Owner-Based

By default, workspaces can `vend_credential` (proxy through) any credential that belongs to the same owner. This means:
- If the admin who created the credential is the same user who owns the workspace, access is automatic.
- The workspace can list and proxy its owner's credentials without any additional policy.

### Granting Cross-Owner Access

To let a workspace use a credential it doesn't own, create an explicit Cedar policy:

```cedar
// Grant a specific workspace access to vend a specific credential
permit(
  principal == AgentCordon::Workspace::"<workspace-id>",
  action == AgentCordon::Action::"vend_credential",
  resource == AgentCordon::Credential::"<credential-id>"
);
```

Create the policy via the API:

```
POST /api/v1/policies
Authorization: Bearer <admin-session-cookie>
Content-Type: application/json

{
  "name": "grant-github-to-workspace-abc",
  "cedar_content": "permit(\n  principal == AgentCordon::Workspace::\"<workspace-id>\",\n  action == AgentCordon::Action::\"vend_credential\",\n  resource == AgentCordon::Credential::\"<credential-id>\"\n);"
}
```

### Tag-Based Access

For broader access patterns, use tag-based policies. Tag credentials and workspaces, then grant access by tag:

```cedar
// Any workspace tagged "ci" can vend credentials tagged "ci"
permit(
  principal is AgentCordon::Workspace,
  action == AgentCordon::Action::"vend_credential",
  resource is AgentCordon::Credential
) when {
  principal.tags.containsAny(resource.tags)
};
```

### Cedar Policy Reference

AgentCordon uses [Cedar](https://www.cedarpolicy.com/) for all authorization decisions. Key entity types:

| Entity | Example |
|--------|---------|
| `AgentCordon::Workspace` | A registered agent workspace (Ed25519 identity) |
| `AgentCordon::User` | A human admin user |
| `AgentCordon::Credential` | A stored credential in the vault |
| `AgentCordon::McpServer` | A registered MCP server |

Key actions for credential access:

| Action | Who | What it does |
|--------|-----|-------------|
| `list` | Workspace, User | Discover available credentials (metadata only, no secrets) |
| `vend_credential` | Workspace | Proxy a request through the credential (secret injected server-side) |
| `access` | User only | Reveal the raw credential value (admin use only) |
| `create` | Workspace, User | Store a new credential |

Use `GET /api/v1/policies/schema/reference` for the full Cedar schema.

## Important Rules

1. **You NEVER hold API keys, tokens, passwords, or secrets directly.** AgentCordon
   manages all credentials on your behalf.

2. **To call an external API**, use the credential proxy (`POST /api/v1/proxy/execute`
   or `agentcordon proxy`). The proxy injects the real secret into the upstream
   request -- you never see it.

3. **To discover credentials**, call `GET /api/v1/credentials` or `agentcordon credentials list`.

4. **Never bypass AgentCordon** by asking a human for raw API keys or tokens.

## Error Handling

| HTTP Status | Meaning | What To Do |
|-------------|---------|------------|
| 400 | Bad request | Check your request body |
| 401 | Invalid or expired JWT | Re-authenticate |
| 403 | Policy denied | Contact your admin |
| 404 | Not found | Verify enrollment or credential ID |
| 502 | Upstream error | Check upstream service availability |

## Full Documentation

```
GET http://localhost:3140/api/v1/docs
GET http://localhost:3140/api/v1/docs/quickstart
```
