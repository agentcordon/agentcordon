> [Home](index.md) · Granting MCP Server Access

# Granting MCP Server Access

This guide shows how to grant a workspace (agent) access to an MCP server, including **cross-workstation scenarios** where the MCP server runs on a different machine.

---

**On this page:**
[Overview](#overview) · [Prerequisites](#prerequisites) · [Install a server](#step-1----install-the-mcp-server) · [Marketplace templates](#adding-your-own-server-to-the-marketplace) · [OAuth2 servers](#oauth2-servers) · [Provider clients](#oauth-provider-clients) · [Policies](#step-2----default-policy-same-owner-access) · [Call a tool](#step-5----call-the-mcp-tool-from-workstation-a) · [Sharing](#sharing-with-more-workspaces) · [Narrowing tools](#narrowing-the-tools-a-server-exposes) · [Disabling](#disabling-a-server) · [Credential injection](#credential-injection) · [SSRF Protection](#ssrf-protection) · [Security Considerations](#security-considerations) · [Complete Example](#complete-example) · [API Reference](#api-reference)

---

## Overview

An MCP server record carries one of two transports:

| Transport | Description | Cross-Workstation? |
|-----------|-------------|:------------------:|
| **`http`** (default) | JSON-RPC over HTTP to an upstream URL | Yes |
| **`sse`** | Server-sent events over the same upstream URL | Yes |

Both are remote: the **broker** makes the outbound call, so the MCP server can live on
another machine and several workspaces can share one record.

> [!NOTE]
> **There is no STDIO transport.** `McpTransport` has exactly two variants, `http` and
> `sse`, and every path that accepts a transport string rejects anything else. A tool that
> only speaks STDIO has to be fronted by an HTTP MCP server before AgentCordon can broker
> it. Nothing in AgentCordon spawns a local subprocess.

---

## Prerequisites

- AgentCordon server running and accessible from both workstations, with `AGTCRDN_BASE_URL`
  set to the URL users reach it on (OAuth2 installs and the device flow both need it)
- Both workstations enrolled (see [Workspace Enrollment](workspace-enrollment.md))
- The MCP server exposed via HTTP on the host workstation
- A signed-in admin session with the `manage_mcp_servers` permission

> **This guide drives the admin UI.** Everything below has a screen: `/mcp-servers` for the
> installed servers and the per-server detail page, `/mcp-servers/marketplace` for the
> catalog and the install modal; `/settings` for OAuth
> provider clients; `/security` -- the **Policies** item in the top bar -- for Cedar. The `curl` forms are given so you can automate,
> and every one of them needs the session cookie **and** a matching `X-CSRF-Token` header
> (`crates/server/src/middleware/csrf.rs`) or a user bearer token -- a missing header
> answers `403 csrf_validation_failed`, which reads like an authorization problem and is
> not one.

---

## Step-by-Step: HTTP MCP Server

### Step 1 -- Install the MCP server

Everything in this step is a screen in the admin UI. Sign in as a user with the
`manage_mcp_servers` permission and open **`/mcp-servers`**, which lists the servers already
installed. Press **Add server** in the page header to reach the catalog at
**`/mcp-servers/marketplace`** (`/marketplace` and `/mcp-marketplace` redirect there).

#### From the marketplace (the normal path)

1. Find the server in the marketplace grid. Each card shows its name, description, and an
   auth badge -- **No Auth**, **API Key**, or **OAuth**.
2. Click the card. The install modal opens.
3. Pick the **workspace** to bind it to.
4. Fill in what the auth badge asks for:
   - **No Auth** -- nothing. Click **Install**.
   - **API Key** -- a **Credential** select with two options. Leave it on **Create new
     credential** (the default) and paste the key into the *API Key / Secret* box below it;
     it is encrypted at rest and never readable back, and a hint under the box names where
     the key will be sent -- the template's header, its query parameter, or
     `Authorization: Bearer` when it names neither. Or switch the select to **Use
     existing credential**, which replaces the box with a picker of your vault credentials.
     Click **Install**.
   - **OAuth** -- click **Connect**. You are redirected to the provider's consent page and
     back. See [OAuth2 servers](#oauth2-servers) below.
5. Provisioning creates the MCP record, links or creates the credential, binds the MCP to
   the chosen workspace, and runs tool discovery (`initialize` ->
   `notifications/initialized` -> `tools/list`) best-effort. Each discovered tool keeps its
   description and its `inputSchema`, which is what `agentcordon mcp-tools --schema` shows
   an agent later.

The button posts `POST /api/v1/mcp-servers/provision` (or `/oauth/initiate` for OAuth) with
the session cookie and CSRF token the page already holds. You do not need to construct
either by hand.

> **If tool discovery fails, the install still stands -- and says so.** Discovery is
> best-effort: an upstream that is down, or one the [SSRF guard](#ssrf-protection) refuses
> (a loopback or private address without `AGTCRDN_PROXY_ALLOW_LOOPBACK=true`), leaves the
> server installed with no tools. The install modal reports
> *"Installed; tool discovery failed: &lt;reason&gt;"*, the response carries the same reason as
> `tool_discovery_error`, and an `mcp_tool_discovery_failed` audit event records it.
> Fix the cause, then press **Rediscover tools** on the server's detail page
> (`POST /api/v1/mcp-servers/{id}/discover-tools`) -- no need to delete and reinstall.
> A tool call still works while the list is empty, because the broker forwards
> `tools/call` regardless; it is `agentcordon mcp-tools` that comes back empty.

> **One install per template per user.** A second install of the same template returns
> `409 you already have an MCP server from template '<key>'`. To give a second workspace
> access, share the existing record -- see [Sharing with more workspaces](#sharing-with-more-workspaces).

> **Choosing the credential type for an API-key server.** Pasting a raw key into the
> install modal creates a **`generic`** credential, which the broker injects as
> `Authorization: Bearer <key>`. That is right for most vendors and wrong for an upstream
> that wants `X-API-Key` or a query parameter.
>
> For those, create the credential first and then point the install at it:
>
> 1. **Credentials -> New**, type `api_key_header` (or `api_key_query`), with
>    `metadata.header_name` (or `metadata.param_name`) filled in -- both are required and
>    `POST /api/v1/credentials` refuses the create without them.
> 2. In the MCP install modal, set the **Credential** select to **Use existing credential**
>    and pick it from the picker that appears
>    (API: `POST /api/v1/mcp-servers/provision` with `credential_id` instead of
>    `secret_value`).
>
> An existing credential is linked as-is, so the broker injects it according to that
> credential's own type. See
> [Credential Encryption -- API Key (Header)](credential-encryption.md#api-key-header).

#### Adding your own server to the marketplace

The catalog is compiled into the server binary from `data/mcp-templates/`. To add a private
or in-house server, point **`AGTCRDN_MCP_TEMPLATES_DIR`** at a directory of JSON templates:

```yaml
# docker-compose.yml (or docker run -e / -v)
environment:
  AGTCRDN_MCP_TEMPLATES_DIR: /srv/mcp-templates
volumes:
  - ./mcp-templates:/srv/mcp-templates:ro
```

- Each `*.json` file in the directory is one MCP server template. Templates are keyed by
  their `key`, so a file whose `key` matches a built-in **replaces** it.
- A file larger than 64 KiB, a file that does not parse, or one that fails the schema below
  is skipped. The server log names the file and **every** problem in it at once, each
  naming the field and its legal values -- fix a template in one restart, not one restart
  per field.
- The directory is canonicalised and every file must resolve inside it -- symlinks pointing
  out are refused.
- **The directory is read once, at startup.** Restart the server after adding or editing a
  template; nothing rescans it. This is why the loader reports every problem together.
- **Check the mount worked in the log, not the grid.** On the success path the server log
  records one INFO line naming the directory it read and the templates it loaded from it.
  No such line means the variable or the mount is wrong and nothing was overlaid -- the
  marketplace then shows only the built-ins, which looks like a working install.

`AGTCRDN_CREDENTIAL_TEMPLATES_DIR` and `AGTCRDN_POLICY_TEMPLATES_DIR` work the same way for
the credential and policy catalogs.

##### Template schema

Four fields are required. Everything else has a default, so the shortest useful template is
a handful of lines.

| Field | Required | Type | Legal values / default |
|-------|:--------:|------|------------------------|
| `key` | **yes** | string | Any non-empty string, unique in the catalog. It is the record's name, the credential's `service`, and the marketplace card's identity. |
| `name` | **yes** | string | Any non-empty string. The card's display name. |
| `upstream_url` | **yes** | string | The MCP endpoint the broker calls. Must pass the [SSRF guard](#ssrf-protection) unless `AGTCRDN_PROXY_ALLOW_LOOPBACK=true`. |
| `auth_method` | **yes** | string | `none`, `api_key`, or `oauth2`. Nothing else loads. Drives the card's auth badge (**No Auth** / **API Key** / **OAuth**) and what the install modal asks for. |
| `description` | no | string | Card body text. Defaults to empty; write one. |
| `transport` | no | string | `http` (default) or `sse`. There is no STDIO transport. |
| `category` | no | string | Free text; it becomes a filter chip. The built-ins use `productivity`, `developer-tools`, and `payments`. Defaults to `custom`. |
| `tags` | no | array of strings | Search keywords, and the tags the provisioned MCP record carries. Defaults to `[]`. |
| `icon` | no | string | Logo key for the card. Defaults to the template's `key`; a key with no bundled logo draws the name's first letter, so leaving it out is fine. |
| `sort_order` | no | integer >= 0 | Position in the grid, ascending, ties broken by name. The built-ins run 10--120; defaults to `1000`, after all of them. |
| `credential_template_key` | no | string | Credential template to base the auto-created credential on. Defaults to `key`. |
| `api_key_header` | no | string | `auth_method: "api_key"` only -- see below. |
| `api_key_query` | no | string | `auth_method: "api_key"` only -- see below. |
| `oauth2_resource_url` | no | string | `auth_method: "oauth2"` only -- see below. |
| `oauth2_prefer_dcr` | no | boolean | `auth_method: "oauth2"` only. Defaults to `true`. |
| `oauth2_scopes` | no | string | `auth_method: "oauth2"` only. Space-separated; `""` means "ask for the provider's default". |

A minimal no-auth template:

```json
{
  "key": "acme-notes",
  "name": "Acme Notes",
  "description": "Internal notes and search.",
  "upstream_url": "https://mcp.acme.internal/notes",
  "auth_method": "none"
}
```

**Where an API-key template's key goes.** An `auth_method: "api_key"` template may name the
placement its upstream expects, and provisioning creates the matching credential type:

```json
{
  "key": "acme-internal",
  "name": "Acme Internal",
  "upstream_url": "https://mcp.acme.internal/",
  "transport": "http",
  "auth_method": "api_key",
  "api_key_header": "X-API-Key"
}
```

- `api_key_header: "X-API-Key"` -> an `api_key_header` credential with
  `metadata.header_name`, injected as `X-API-Key: <key>`.
- `api_key_query: "api_key"` -> an `api_key_query` credential with `metadata.param_name`,
  appended to the request URL as `?api_key=<key>`.
- **Neither** -> a `generic` credential with the `bearer` transform, i.e.
  `Authorization: Bearer <key>`. That is the default, so every template written before this
  field behaves exactly as it did.

Setting both is a template error and the file is skipped. The placement is used for the
tool-discovery probe at install time as well as for every later call, so a server that only
accepts its custom header no longer fails the install with a 401.

**An OAuth2 template.** `oauth2_resource_url` is the RFC 9728 protected-resource URL the
server fetches to find the authorization server; without it, discovery falls back to the
`resource_metadata` hint the MCP endpoint returns with its own `401`. Give it when you know
it -- it is one round trip fewer and one failure mode fewer. See
[OAuth2 servers](#oauth2-servers) for what happens next.

```json
{
  "key": "acme-oauth",
  "name": "Acme (OAuth)",
  "description": "Acme's hosted MCP server, via OAuth2.",
  "upstream_url": "https://mcp.acme.example/mcp",
  "transport": "http",
  "auth_method": "oauth2",
  "oauth2_resource_url": "https://mcp.acme.example",
  "oauth2_prefer_dcr": true,
  "oauth2_scopes": "",
  "category": "productivity",
  "tags": ["acme", "oauth"],
  "sort_order": 200
}
```

No client id or secret goes in the template. AgentCordon registers itself with the
provider (RFC 7591 Dynamic Client Registration) when the authorization server supports it,
and otherwise you configure the client once under **Settings -> OAuth Provider Clients** -- see
[OAuth provider clients](#oauth-provider-clients).

#### OAuth2 servers

Clicking **Connect** on an OAuth template makes the **server** do the discovery and the
token exchange. No provider secret ever reaches the broker or the CLI.

1. The server fetches the resource's RFC 9728
   `/.well-known/oauth-protected-resource` -- from the template's `oauth2_resource_url`, or
   from the `resource_metadata` hint the MCP endpoint returns with its own `401`.
2. It reads `authorization_servers[0]`. **That authorization server may live on a different
   origin from the MCP resource server** -- that is what RFC 9728 exists for, and it is the
   normal enterprise shape (`mcp.corp.example` delegating to `login.corp.example`).
3. It fetches that server's RFC 8414 metadata and checks it *against itself*: the `issuer`
   must identify the URL the metadata came from, and every endpoint the document advertises
   must be same-origin with that issuer. A metadata document cannot redirect the token
   exchange to a third origin.
4. If the authorization server advertises a `registration_endpoint` and the template prefers
   it, the server performs RFC 7591 Dynamic Client Registration, sending
   `AGTCRDN_INSTANCE_LABEL` (default `AgentCordon`) as `client_name` and
   `{AGTCRDN_BASE_URL}/api/v1/mcp-servers/oauth/callback` as the redirect URI.
5. You are redirected to the provider's consent page (authorization code + PKCE `S256`).
6. The callback exchanges the code, stores the refresh token as an
   `oauth2_user_authorization` credential, provisions the MCP, and runs tool discovery.

Every URL fetched along the way passes the SSRF guard first, so a hostile resource server
cannot steer discovery onto your internal network.

> **`AGTCRDN_BASE_URL` must be set** for any of this. The redirect URI registered with the
> provider is built from it.

#### OAuth provider clients

When an authorization server does **not** support Dynamic Client Registration, the install
fails with:

> ...does not support Dynamic Client Registration. Configure it manually in
> Settings > OAuth Provider Clients.

Open **`/settings`**, pick **OAuth clients** in the section rail, press **Add Client**, and fill
in the client id and secret you registered by hand at the provider, plus its authorize and
token endpoints.

> [!IMPORTANT]
> **`Authorization server URL` must be the bare origin, and it must match byte for byte.**
> Discovery looks the row up by `normalize_as_url(authorization_servers[0])` -- the value
> lowercased and reduced to `scheme://host[:port]`, with the path discarded. The form stores
> what you type, only trimmed. So `https://login.example.com/` (trailing slash),
> `https://login.example.com/oauth2` (a path), and `https://Login.Example.com` (mixed case)
> all fail to match, and the retry gives you the *same* "does not support Dynamic Client
> Registration" message with nothing saying why. Enter exactly
> `https://login.example.com` -- scheme, host, and a port only when the URL has a
> non-default one.

Two consequences of that origin key:

- One provider client per origin. Two authorization servers behind a single origin cannot
  both have a client row.
- Every `oauth2_user_authorization` credential obtained from that authorization server
  shares the row. The credential's `metadata.authorization_server_url` is the join key; the
  client secret lives only on the provider-client row, never on the credential.

`POST /api/v1/oauth-provider-clients/{id}/reregister` re-runs discovery and DCR against the
same authorization server URL and updates the row in place.

**Who may change one.** Creating, editing, deleting and re-registering a provider client
require the `manage_oauth_provider_clients` Cedar action, which the default policy grants to
enabled admins only -- the row is shared by every tenant with an MCP server at that origin.
An operator can still list the clients and see which one an origin uses (that stays on
`manage_mcp_servers`); the listing never carries the client secret. Dynamic Client
Registration during an install is not affected: the server creates that row on the
operator's behalf.

**Deleting one is refused while it is in use.** A `DELETE` answers `409` and names the
counts -- the `oauth2_user_authorization` credentials issued against that authorization
server, and the OAuth2 MCP servers that authenticate with them -- because the `client_id`
and `client_secret` their token exchange needs live only on this row. Editing is allowed
even with dependents: that is how a rotated provider secret gets in, and the audit event
records which fields changed and how much was depending on the row when they did, never the
secret value.

#### Bulk import via API

`POST /api/v1/mcp-servers/import` creates servers from a JSON envelope. It is authenticated
as a **workspace** (an OAuth bearer access token, not a session), and is meant for a
workspace registering its own servers on startup -- not for an admin at a terminal.

```bash
curl -X POST https://agentcordon.example.com/api/v1/mcp-servers/import \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <workspace access token>" \
  -d '{
    "workspace_id": "workspace-a-uuid",
    "servers": [
      {
        "name": "remote-tools",
        "transport": "http",
        "url": "https://workstation-b.example.com:8080/mcp",
        "tools": [
          {
            "name": "clone_repo",
            "description": "Clone a repository into the workspace",
            "input_schema": { "type": "object", "properties": { "url": { "type": "string" } } }
          },
          { "name": "list_files" }
        ],
        "required_credentials": ["<credential-uuid>"]
      }
    ]
  }'
```

- The server array is wrapped in a `{ workspace_id, servers: [...] }` envelope.
- `transport` accepts `"http"` (default) or `"sse"`. There is no `"url"` transport type.
- `required_credentials` takes **credential UUIDs**, not names.
- Cedar evaluates the `create` action on the `System` resource for the authenticated
  workspace.
- **Tool discovery does not run on import.** Supply `tools` yourself, or use the
  marketplace path, which does discover. A tool entry's `description` and `input_schema`
  are stored the way discovery stores them, so `agentcordon mcp-tools` shows the same
  metadata for an imported server as for a provisioned one. The MCP spelling
  `inputSchema` is accepted, so a workspace can forward a `tools/list` answer verbatim.
  Re-importing a server that already exists fills in only what the record is missing --
  names for one that has none, metadata for one whose tools are still bare names.

> **Warning:** `name` must **not** contain a dot (`.`) -- dots break the 3-part scope format
> (`{workspace_name}.{mcp_server_name}.{action}`).

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

If the workspace and MCP server have **different owners**, you need to grant access
explicitly. The **Grant Access** form on the MCP detail page's **Access** tab does A and B below; the
`curl` equivalents are given for automation. Cedar policies control all access -- choose one
of these approaches:

#### Option A: Grant a whole action

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

You can also create **deny** policies by adding `"mode": "deny"` to the request body. Deny
policies generate `forbid` rules.

A deny stops the *call* and nothing else: the tool stays in every listing the agent sees, so
it is still discovered and still attempted, and each attempt writes an
`mcp_tool_call_denied` audit row. To take a tool out of the listing entirely, narrow the
server's `allowed_tools` -- see
[Narrowing the tools a server exposes](#narrowing-the-tools-a-server-exposes).

#### Option B: Grant specific tools only

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

#### Option C: Generate tag-based policies

In the admin UI this is the **Generate policies** button on the MCP server's **Access** tab.
It calls the endpoint below with an empty body, so it writes one grant per tool the server
has, for every tag the workspaces bound to it carry, and reports how many it created. It
skips names that already exist, so pressing it twice is safe and the second press reports
`0`.

Over the API:

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

Both fields are optional, so the shortest form of this call is an empty body:

```bash
curl -X POST http://localhost:3140/api/v1/mcp-servers/{server-id}/generate-policies \
  -H "Content-Type: application/json" \
  -H "Cookie: session=..." \
  -d '{}'
```

- Omitted `tools` means **every tool the server currently has**: its `allowed_tools`, or
  what discovery found when it has no allow-list.
- Omitted `agent_tags` means **every tag the workspaces bound to this server carry**.
- An explicit empty list (`"tools": []`) is a `400`, and so is a default that resolves to
  nothing -- a server with no known tools, or one bound only to untagged workspaces. The
  message names the missing half; creating no policies quietly would read as success.

Limits: maximum 50 tools and 50 agent tags per request. Duplicate policy names are skipped.

The rows it writes are named `grant:mcp:{server_id}:tag:{tag}:mcp_tool_call:{tool}` -- the
same `grant:` convention the Access tab's Grant/Deny control uses. That is what marks them
*generated* rather than authored: the Policies list hides them from its default view and
shows them under **Grants only**, and the last-enabled-policy guard does not count them, so
generating policies never takes the `default` policy out of its own protection. (Rows an
older install wrote as `mcp-{server_id}-{tool}-{tag}` are renamed onto the new convention on
the next server start.)

#### Option D: Write a custom Cedar policy (`/policies` -> **New**)

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

### Step 4 -- Set up credentials (if needed)

If the MCP server requires authentication, the install modal already handled it: pasting a
key creates the credential, or you picked an existing one. This step is only for linking a
credential to a server created some other way (import), or for pre-creating a credential of
a specific type before installing. Create one in the admin UI (**Credentials -> Add Credential**, where
the type picker and the AWS / OAuth2 field sets live) or from an enrolled workspace:

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

# List tools across all servers
agentcordon mcp-tools

# Learn a tool's exact argument names before calling it
agentcordon mcp-tools --schema --server remote-tools --tool clone_repo

# Call a tool
agentcordon mcp-call remote-tools clone_repo --arg url=https://github.com/user/repo
```

These CLI commands route through the broker, which:

1. Syncs MCP server configs from `GET /api/v1/workspaces/mcp-servers`
2. Resolves credentials via ECIES-encrypted envelopes from the server
3. Authorizes the call via Cedar policy check on the server (`mcp_tool_call` action)
4. Injects resolved credentials into the upstream HTTP request headers
5. Forwards the JSON-RPC `tools/call` request to the upstream MCP server URL

For AI agent integration, `agentcordon init` installs the AgentCordon
[Agent Skill](https://agentskills.io/specification) — `.agents/skills/agentcordon/SKILL.md`,
copied to `.claude/skills/` and `.kiro/skills/` for the runtimes that read those — and the
skill tells the agent to reach MCP through these three commands, including the rules for
choosing between several servers. It deliberately does **not** write a `.mcp.json` entry:
there is no `agentcordon mcp-serve` subcommand for one to point at, and that surface is the
deferred third tier of
[ADR-0013](adr/0013-init-installs-the-agentcordon-skill-per-runtime.md).

---

### Sharing with more workspaces

Provisioning binds the MCP to exactly one workspace. To make the same MCP available to more
workspaces you own, open the MCP's detail page, go to its **Access** tab and use
**Share with workspace**
(API: `POST /api/v1/mcp-servers/{id}/workspaces`). One record, many bindings, the same
credentials and policies everywhere.

**Where a binding lives.** Every binding, the provisioning one included, is a row in the
`mcp_server_workspaces` junction, and that is the only place to read one. Both
`GET /api/v1/mcp-servers` and `GET /api/v1/mcp-servers/{id}` report the live set as
`installed_workspaces`, and `GET /api/v1/mcp-servers/{id}/workspaces` returns just that
list. The **Workspaces** column on `/mcp-servers` and the *Workspaces with access* table on
the detail page's **Access** tab are both rendered from it.

> The response's `workspace_id` / `workspace_name` are a **legacy** field pair, not the
> binding. They carry the provisioning workspace for records created before the junction
> consolidation and are `null` for everything provisioned since, so nothing should read
> them to answer "which workspaces can use this server?" -- use `installed_workspaces`.

- **No cross-user binding.** Every workspace you bind must have the same owner as the MCP.
  Binding one owned by another user returns `403`; admin and root may override.
- **You cannot remove the last binding.** An MCP with zero bindings is an orphan, so
  unsharing the final workspace returns `409` with a message pointing at
  `DELETE /api/v1/mcp-servers/{id}`. Admins are subject to the same rule.
- **Unsharing is eventually consistent.** The target workspace's broker keeps the MCP in
  its local cache until its next sync tick (`AGTCRDN_MCP_SYNC_INTERVAL`, default 60
  seconds).

### Narrowing the tools a server exposes

A per-tool Cedar deny refuses the *call*; it does not hide the *tool*. The agent still sees
it in `agentcordon mcp-tools`, still discovers it through `agentcordon_mcp_tools` or an
`--expose`d `tools/list`, and still tries it. When you want an agent not to see a tool at
all, narrow the server's `allowed_tools`.

In the admin UI: the MCP server's **Tools** tab has a tick per tool and a **Save allowed
tools**. Untick a tool and save; untick every tool to expose none.

Over the API:

```bash
curl -X PUT "$S/api/v1/mcp-servers/{id}" \
  -H "Content-Type: application/json" -H "Cookie: session=..." \
  -d '{"allowed_tools": ["clone_repo", "list_files"]}'
```

- Every name must be one the server publishes -- the `tools` array on
  `GET /api/v1/mcp-servers/{id}`. An unknown name is a `400` naming every stray, and
  nothing is changed.
- `[]` means **no tools at all**. It is a real choice, not an empty update.
- Omitting the field leaves the allow-list alone.

What changes for an agent:

| Surface | Effect |
|---------|--------|
| `agentcordon mcp-tools`, `agentcordon_mcp_tools`, `tools/list` with `--expose` | A narrowed tool is not listed. The broker is handed only the allowed tools, and does not probe the upstream behind that list. |
| `agentcordon mcp-call`, `agentcordon_mcp_call` | A call to a narrowed tool is refused before Cedar is consulted, and writes the same `mcp_tool_call_denied` audit row every other refusal writes (`reason: tool_not_allowed`). |
| **Rediscover tools** | Keeps the narrowing. A tool the upstream has newly published appears on the Tools tab unticked, ready for you to allow. A server nobody has narrowed still takes everything discovery finds. |

Narrowing takes effect for a running broker on its next sync tick
(`AGTCRDN_MCP_SYNC_INTERVAL`, default 60 seconds); the refusal at call time is immediate.

### Disabling a server

For immediate revocation, or to stop a misbehaving server without losing its bindings,
credential links and policies, **disable** it: the **Disable** button in the MCP detail page
header, or `PUT /api/v1/mcp-servers/{id}` with `{"enabled": false}`. The default policy's
forbid on `!resource.enabled` refuses every `mcp_tool_call` and `mcp_list_tools`
immediately, ahead of any broker cache refresh, and workspace sync stops handing the server
to brokers. `{"enabled": true}` puts it back. `DELETE` is the destructive alternative -- it
cascades the junction rows and the grant/deny policies.

---

## What about local (STDIO) MCP servers?

They are out of scope for AgentCordon as it stands. The broker's job is to hold a
credential and make an authenticated network call; a subprocess on the agent's own machine
has neither half of that problem, and nothing in the product spawns one. `transport` accepts
`http` or `sse` and nothing else — importing a record with an empty `url` produces a server
the broker cannot reach.

If a tool you need only speaks STDIO, put an HTTP MCP shim in front of it and register the
shim's URL. The Cedar policies, per-tool grants, credential injection and audit trail then
work exactly as they do for any other HTTP server.

---

## Credential Injection

For HTTP MCP servers, the broker resolves credentials automatically at connection time. When an MCP server has `required_credentials` set, the broker:

1. Fetches the credential via `GET /api/v1/workspaces/mcp-servers?include_credentials=true`
2. Decrypts the ECIES envelope using the broker's P-256 private key
3. Applies the credential transform (`bearer` adds an `Authorization: Bearer` header;
   `api_key_header` adds `{header_name}: {value}`; `api_key_query` appends
   `?{param_name}={value}`)
4. Connects to the upstream URL with the resolved headers

For an OAuth2 credential (`oauth2_user_authorization` or `oauth2_client_credentials`), the
**server** runs the `refresh_token` or `client_credentials` exchange and seals only the
resulting short-lived access token and its `expires_at` into the envelope. The refresh
token and the provider client secret never leave the server. A refresh token the provider
rotates is persisted server-side with a secret-history row and a `credential_secret_rotated`
audit event. The broker never calls a token endpoint.

> **Important:** Credential values are **never logged**, and the broker leak-scans what
> comes back. An MCP server that echoes what it was called with -- in a tool result, an
> error message, or a `tools/list` answer -- has every injected value replaced with
> `[REDACTED]` before any of it reaches the agent. The scan covers `tools/call` results and
> the broker's own discovery probes, and it is the same scan `/proxy` runs on an upstream
> response body.

---

## SSRF Protection

HTTP MCP server URLs are validated to prevent SSRF:

- **Blocked by default:** every loopback, private and reserved address -- RFC 1918, CGNAT
  (100.64/10), link-local (169.254/16), 0/8, 192.0.0/24, 198.18/15, the TEST-NETs,
  multicast, 240/4, NAT64 `64:ff9b::/96`, and 6to4. The check runs against the **resolved**
  address, so a hostname that resolves into one of those ranges is refused too, and it
  covers the broker's live `tools/list` probe as well as `tools/call`.
- **`AGTCRDN_PROXY_ALLOW_LOOPBACK=true` turns the whole guard off**, not just the loopback
  rule. Development only.

### Which process to set it on

`AGTCRDN_PROXY_ALLOW_LOOPBACK` is read by the **server** and the **broker** separately, each
for its own outbound calls. Setting it on one does nothing for the other:

| Set on | What it unblocks |
|--------|------------------|
| **Server** (`agent-cordon-server`) | MCP tool discovery -- the `initialize` / `tools/list` probe an install runs against the template's `upstream_url` -- and OAuth discovery: the MCP endpoint's 401 probe, the RFC 9728 protected-resource document, and the RFC 8414 authorization-server metadata |
| **Broker** (`agentcordon-broker`) | `agentcordon mcp-call` (`tools/call` forwarding) and `agentcordon proxy` |

A private or loopback MCP server needs it in **both**. The failure modes differ, which is
what makes a half-configured pair confusing:

- **Server only:** installs and discovers tools; `agentcordon mcp-call` then fails with
  `Blocked by SSRF protection: target address is in a private or reserved range`.
- **Broker only:** the install reports **success** and discovers **no tools**, silently --
  the probe is best-effort and its refusal is not surfaced in the UI or the audit log. The
  server lists the record with an empty tool set, `agentcordon mcp-tools` shows nothing,
  and yet `agentcordon mcp-call` works, because the broker forwards `tools/call` regardless.
  Restart the server with the variable set and reinstall to get the tool list.

Separately, an `oauth2_client_credentials` credential's `oauth2_token_endpoint` is governed
by its own rule -- HTTPS required, with the literal hosts `localhost`, `127.0.0.1` and `::1`
exempt -- which this variable does not affect.

> [!IMPORTANT]
> **There is no allow-list form.** No CIDR variable, no per-host exception, no
> "allow this one origin". The guard is a single boolean per process: on, or every private
> and reserved range at once. An internal deployment that must reach an RFC 1918 upstream
> has to accept that trade-off, or put the upstream behind a name that resolves publicly.

---

## Security Considerations

| # | Property | Details |
|:-:|----------|---------|
| 1 | **Cedar deny-by-default** | Workspaces have no MCP access unless explicitly granted or the same-owner default policy (3a) applies |
| 2 | **Per-tool granularity** | Policies can restrict access to specific tools via `context.tool_name` conditions |
| 3 | **Credential isolation** | Credentials are delivered via ECIES envelopes; only the broker with its P-256 key can decrypt |
| 4 | **Disabled servers blocked** | Forbid rules in the default policy (4b) refuse every `mcp_tool_call` and `mcp_list_tools` on a server whose `enabled` is false. Set it with the **Disable** button in the MCP detail page header or `PUT /api/v1/mcp-servers/{id}` `{"enabled": false}` -- see [Disabling a server](#disabling-a-server). |
| 5 | **Audit trail** | Every `mcp_tool_call` and `mcp_list_tools` action is logged with tool name, workspace, and decision |
| 6 | **Transport security** | Use HTTPS for production HTTP MCP servers |
| 7 | **Grant/deny modes** | Permissions API supports both `grant` (permit) and `deny` (forbid) policy modes |

---

## Complete Example

### In the admin UI

1. **`/mcp-servers`** -> **Add server** -> click **Data Pipeline** -> pick workspace
   `workspace-a` -> paste the API key -> **Install**. Tool discovery runs; the detail page
   now lists `run_etl` and `check_status` with their descriptions and input schemas.
2. If `workspace-a` and the MCP have the same owner, you are done -- default policy 3a
   already permits. Otherwise open the server's **Access** tab and grant
   `mcp_tool_call` (and `mcp_list_tools`) to the workspace.
3. To let a second workspace you own use the same server, use **Share with workspace** on
   the detail page's **Access** tab.
4. To expose fewer than all of its tools, untick them on the **Tools** tab and **Save
   allowed tools**.

### The same thing over the API

Every call needs the session cookie **and** a matching `X-CSRF-Token` header. The value the
UI uses is in the `agtcrdn_csrf` cookie the login response sets.

```bash
S=https://agentcordon.example.com
COOKIE="agtcrdn_session=...; agtcrdn_csrf=$CSRF"

# 1. Provision from a catalog template. Tool discovery runs automatically.
curl -X POST "$S/api/v1/mcp-servers/provision" \
  -H "Content-Type: application/json" \
  -H "Cookie: $COOKIE" -H "X-CSRF-Token: $CSRF" \
  -d '{
    "template_key": "data-pipeline",
    "workspace_id": "workspace-a-uuid",
    "secret_value": "sk-..."
  }'

# 2. (Optional) Grant cross-owner access -- only needed for different owners.
for perm in mcp_tool_call mcp_list_tools; do
  curl -X POST "$S/api/v1/mcp-servers/{id}/permissions" \
    -H "Content-Type: application/json" \
    -H "Cookie: $COOKIE" -H "X-CSRF-Token: $CSRF" \
    -d "{ \"workspace_id\": \"workspace-b-uuid\", \"permission\": \"$perm\" }"
done

# 3. (Optional) Generate tag-based per-tool policies.
curl -X POST "$S/api/v1/mcp-servers/{id}/generate-policies" \
  -H "Content-Type: application/json" \
  -H "Cookie: $COOKIE" -H "X-CSRF-Token: $CSRF" \
  -d '{ "tools": ["run_etl", "check_status"], "agent_tags": ["data-team"] }'

# 4. (Optional) Narrow the tools the server exposes at all.
curl -X PUT "$S/api/v1/mcp-servers/{id}" \
  -H "Content-Type: application/json" \
  -H "Cookie: $COOKIE" -H "X-CSRF-Token: $CSRF" \
  -d '{ "allowed_tools": ["run_etl", "check_status"] }'

# 5. (Optional) Stop the server immediately without losing its bindings.
curl -X PUT "$S/api/v1/mcp-servers/{id}" \
  -H "Content-Type: application/json" \
  -H "Cookie: $COOKIE" -H "X-CSRF-Token: $CSRF" \
  -d '{ "enabled": false }'
```

### On workstation A (the agent)

```bash
agentcordon mcp-servers                                          # what am I bound to?
agentcordon mcp-tools                                            # what can they do?
agentcordon mcp-tools --schema --server data-pipeline --tool run_etl   # exact arguments
agentcordon mcp-call data-pipeline run_etl --arg dataset=users --arg date=2026-03-26
```

---

## API Reference

Every session-authenticated call needs the `agtcrdn_session` cookie **and** a matching
`X-CSRF-Token` header, or a user bearer token.

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/mcp-servers` | List MCP servers, each with its bound workspaces as `installed_workspaces` |
| `GET` | `/api/v1/mcp-servers/{id}` | Get MCP server detail: the record, every bound workspace via the junction, and the discovered tools with their descriptions and input schemas |
| `PUT` | `/api/v1/mcp-servers/{id}` | Update MCP server: `name`, `enabled` and/or `allowed_tools`, all optional; an absent field is left alone and unknown fields are rejected. `{"enabled": false}` drops the server out of broker sync and makes every `mcp_tool_call` / `mcp_list_tools` on it forbidden — see [Disabling a server](#disabling-a-server). `allowed_tools` is the tool allow-list — see [Narrowing the tools a server exposes](#narrowing-the-tools-a-server-exposes); a name the server does not have is a `400`. |
| `DELETE` | `/api/v1/mcp-servers/{id}` | Delete MCP server (cascades junction rows and grant/deny policies) |
| `GET` | `/api/v1/mcp-servers/{id}/workspaces` | The workspaces currently bound to this MCP through the junction |
| `POST` | `/api/v1/mcp-servers/{id}/workspaces` | Share an MCP with more workspaces owned by the caller |
| `DELETE` | `/api/v1/mcp-servers/{id}/workspaces/{workspace_id}` | Unshare an MCP from one workspace (409 on the last binding) |
| `POST` | `/api/v1/mcp-servers/import` | Bulk import (workspace bearer-token auth) |
| `POST` | `/api/v1/mcp-servers/provision` | Provision from a catalog template (session auth). Takes `secret_value` **or** `credential_id`. |
| `POST` | `/api/v1/mcp-servers/oauth/initiate` | Start the OAuth2 provisioning flow |
| `GET` | `/api/v1/mcp-servers/oauth/callback` | OAuth2 callback handler |
| `GET` | `/api/v1/mcp-servers/{id}/permissions` | List permissions for an MCP server |
| `POST` | `/api/v1/mcp-servers/{id}/permissions` | Grant or deny a permission (`"mode": "deny"` generates a `forbid`) |
| `DELETE` | `/api/v1/mcp-servers/{id}/permissions/{workspace_id}/{permission}` | Revoke a permission |
| `POST` | `/api/v1/mcp-servers/{id}/discover-tools` | Re-run tool discovery against the upstream (**Rediscover tools**). `502` with the reason if the probe fails. |
| `POST` | `/api/v1/mcp-servers/{id}/generate-policies` | Generate tag-based Cedar policies (max 50 tools × 50 tags) |
| `GET` | `/api/v1/mcp-templates` | The marketplace catalog (built-ins plus `AGTCRDN_MCP_TEMPLATES_DIR`) |
| `GET` / `POST` | `/api/v1/oauth-provider-clients` | List / create a manually configured OAuth provider client |
| `GET` / `PUT` / `DELETE` | `/api/v1/oauth-provider-clients/{id}` | Read, update or delete one |
| `POST` | `/api/v1/oauth-provider-clients/{id}/reregister` | Re-run discovery and DCR against the same authorization server URL |

---

> **See also:** [Authorization & Cedar Policy](authorization-and-cedar-policy.md) · [CLI Reference](cli-reference.md) · [System Architecture](system-architecture.md)
