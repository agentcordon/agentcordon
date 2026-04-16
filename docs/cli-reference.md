> [Home](index.md) > CLI Reference

# CLI Reference

Complete reference for the `agentcordon` command-line tool -- the workspace agent that generates identity keypairs, registers with the broker, and bridges credentials and MCP servers.

---

## Quick Reference

```
agentcordon init         [--agent AGENT]
agentcordon setup        <SERVER_URL>
agentcordon register     [--scope SCOPE]... [--force] [--no-browser]
agentcordon status
agentcordon credentials
agentcordon credentials  create --name NAME --service SVC --value VAL
agentcordon proxy        CREDENTIAL METHOD URL [--header K:V]... [--body JSON] [--json] [--raw]
agentcordon mcp-servers
agentcordon mcp-tools
agentcordon mcp-call     SERVER TOOL [--arg K=V]...
```

---

**On this page:**
[Exit Codes](#exit-codes) -- [Environment Variables](#environment-variables) -- [Commands](#commands) -- [Files & Directories](#files-and-directories) -- [Credential Types](#credential-types-and-transforms) -- [Authentication](#authentication)

---

## Exit Codes

| Code | Meaning |
|:----:|---------|
| `0` | Success |
| `1` | General error |
| `2` | Broker not running |
| `3` | Workspace not registered |
| `4` | Authentication failed |
| `5` | Authorization denied |
| `6` | Upstream error (proxied service returned an error) |

---

## Environment Variables

| Variable | Used By | Default | Description |
|----------|---------|---------|-------------|
| `AGTCRDN_BROKER_URL` | All commands (except `init`) | Auto-discovered via port file | Broker URL override (e.g. `http://localhost:9876`) |
| `AGTCRDN_WORKSPACE_DIR` | `init`, keypair loading | `.` (current directory) | Override the workspace root where `.agentcordon/` lives |
| `AGTCRDN_LOG_LEVEL` | All commands | `warn` | Log level filter (e.g. `info`, `debug`, `trace`) |
| `AGTCRDN_PROXY_ALLOW_LOOPBACK` | Broker (affects `proxy`, `mcp-call`) | `false` | Set to `true` on the **broker** to allow loopback/private-network URLs |

> **Note:** `AGTCRDN_PROXY_ALLOW_LOOPBACK` is a broker-side environment variable, not a CLI flag. Set it when starting `agentcordon-broker`.

---

## Commands

### `agentcordon init`

> Generate an Ed25519 keypair and prepare the workspace for registration.

```
agentcordon init [OPTIONS]
```

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--agent <AGENT>` | string | `claude-code` | Target agent: `claude-code`, `codex`, `openclaw`, or `all` |

**What it does:**

1. Generates an Ed25519 keypair (`.agentcordon/workspace.key`, `.agentcordon/workspace.pub`)
2. Sets directory permissions to `0700` and private key permissions to `0600` (Unix)
3. Adds `.agentcordon/` to `.gitignore`
4. Generates agent-specific instruction files:
   - `claude-code`: updates `AGENTS.md` and `CLAUDE.md`
   - `codex`: creates `.codex/instructions.md`
   - `openclaw`: creates `.openclaw/instructions.md`
   - `all`: generates all of the above
5. Ensures `.mcp.json` contains an `agentcordon` MCP server entry (`agentcordon mcp-serve`)

Idempotent: if a keypair already exists, prints the identity and regenerates agent files without overwriting keys.

**Examples:**

```bash
# Generate keys for Claude Code (default)
agentcordon init

# Generate keys for all supported agents
agentcordon init --agent all

# Generate keys for Codex
agentcordon init --agent codex
```

**Output:**
```
Workspace identity: sha256:a1b2c3d4...
```

---

### `agentcordon setup`

> One-command onboarding: start broker, generate keys, register workspace.

```
agentcordon setup <SERVER_URL>
```

| Argument | Type | Required | Description |
|----------|------|:--------:|-------------|
| `<SERVER_URL>` | string | Yes | AgentCordon server URL (e.g. `http://server:3140`) |

**What it does:**

1. Discovers or starts the broker daemon (auto-selects port, default 9876)
2. Runs `init` (idempotent keypair generation for `claude-code`)
3. Runs `register` with default scopes (`credentials:discover`, `credentials:vend`, `mcp:discover`, `mcp:invoke`)

This is the recommended first-run command for new workspaces.

**Examples:**

```bash
agentcordon setup http://localhost:3140
agentcordon setup https://agentcordon.example.com
```

**Output:**
```
Setting up AgentCordon...

  Broker: http://localhost:9876
Workspace identity: sha256:a1b2c3d4...

! First, copy your one-time code: ABCD-1234
Press Enter to open https://... in your browser...

  Setup complete! Try:
    agentcordon credentials
    agentcordon proxy <credential> GET <url>
```

---

### `agentcordon register`

> Register this workspace with the broker via RFC 8628 device authorization flow.

```
agentcordon register [OPTIONS]
```

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--scope <SCOPE>` | string (repeatable) | `credentials:discover credentials:vend mcp:discover mcp:invoke` | OAuth scopes to request |
| `--force` | bool | `false` | Clear existing broker registration before re-registering (use when server-side workspace was deleted but broker holds stale state) |
| `--no-browser` | bool | `false` | Do not auto-open the authorization URL in the browser (useful for headless/SSH/CI environments) |

**What it does:**

1. Connects to the broker
2. If `--force`: sends a deregister request to clear stale state
3. Posts a signed registration request with the workspace public key and requested scopes
4. Displays a one-time code and verification URL
5. Opens the browser (unless `--no-browser`)
6. Polls the broker until authorization is approved or denied

**Examples:**

```bash
# Register with default scopes (opens browser)
agentcordon register

# Register without opening browser (headless)
agentcordon register --no-browser

# Re-register after server-side workspace deletion
agentcordon register --force

# Request specific scopes
agentcordon register --scope credentials:discover --scope credentials:vend
```

**Output:**
```
! First, copy your one-time code: ABCD-1234
Press Enter to open https://server/device in your browser...

Waiting for approval... done!
Logged in as my-workspace. Scopes: [credentials:discover, credentials:vend, mcp:discover, mcp:invoke]
```

---

### `agentcordon status`

> Check workspace registration and broker connectivity.

```
agentcordon status
```

No flags. Requires the broker to be running and a valid keypair.

**Output:**
```
Broker: http://localhost:9876 (healthy)
Server: https://agentcordon.example.com (reachable)
Workspace: sha256:a1b2c3d4...
Registered: yes
Scopes: credentials:discover, credentials:vend, mcp:discover, mcp:invoke
Token: valid (expires in 4m 07s)
```

---

### `agentcordon credentials`

> List credentials available to this workspace.

```
agentcordon credentials
```

No flags. Requires the broker to be running and the workspace to be registered.

**Output:**
```
NAME            SERVICE  TYPE     VAULT   EXPIRES
github-token    github   bearer   local   never
aws-prod        aws      aws      local   2026-05-01T00:00:00Z
```

---

### `agentcordon credentials create`

> Create a new credential in the vault via the broker.

```
agentcordon credentials create --name <NAME> --service <SERVICE> --value <VALUE>
```

| Flag | Type | Required | Description |
|------|------|:--------:|-------------|
| `--name <NAME>` | string | Yes | Credential name (unique within workspace) |
| `--service <SERVICE>` | string | Yes | Service identifier (e.g. `github`, `openai`) |
| `--value <VALUE>` | string | Yes | Secret value to store |

The credential is created with type `generic`. All three flags are required and must be non-empty.

**Examples:**

```bash
agentcordon credentials create \
  --name github-token \
  --service github \
  --value "ghp_abc123..."

agentcordon credentials create \
  --name slack-api \
  --service slack \
  --value "xoxb-..."
```

**Output:**
```
Created credential 'github-token' (service: github)
```

---

### `agentcordon proxy`

> Proxy an HTTP request through the broker with credential injection.

```
agentcordon proxy <CREDENTIAL> <METHOD> <URL> [OPTIONS]
```

| Argument / Flag | Type | Required | Description |
|-----------------|------|:--------:|-------------|
| `<CREDENTIAL>` | string | Yes | Credential name |
| `<METHOD>` | string | Yes | HTTP method (`GET`, `POST`, `PUT`, `PATCH`, `DELETE`, `HEAD`, `OPTIONS`) |
| `<URL>` | string | Yes | Target URL |
| `--header <KEY:VALUE>` | string | No | Additional headers (repeatable) |
| `--body <STRING>` | string | No | Request body (string, or `@file` to read from file) |
| `--json` | bool | No | Pretty-print response body as JSON |
| `--raw` | bool | No | Print only response body (for piping, no status/headers) |

Requires the broker to be running and the workspace to be registered. The broker resolves the credential, injects it into the request according to its type, and forwards the request to the target URL.

> **SSRF Protection:** Private IPs, loopback, and link-local addresses are blocked by the broker by default. For local development, start the broker with `AGTCRDN_PROXY_ALLOW_LOOPBACK=true`.

**Examples:**

```bash
# GET with credential injection
agentcordon proxy github-token GET https://api.github.com/user

# POST with body
agentcordon proxy slack-token POST https://slack.com/api/chat.postMessage \
  --body '{"channel": "#general", "text": "Hello"}'

# POST with body from file
agentcordon proxy my-api POST https://api.example.com/data \
  --body @payload.json

# With custom headers and JSON pretty-printing
agentcordon proxy my-api GET https://api.example.com/data \
  --header "Accept: application/json" \
  --header "X-Request-Id: abc123" \
  --json

# Raw output for piping
agentcordon proxy my-api GET https://api.example.com/data --raw | jq .
```

**Default output:**
```
HTTP 200
content-type: application/json
x-request-id: abc123

{"login":"octocat","id":1}
```

**Error output (ambiguous credential name):**
```
Error: multiple credentials match 'github' (ambiguous_credential)

Hint: multiple credentials match. Use one of these IDs:
  550e8400-...  github-readonly
  660f9511-...  github-admin
```

---

### `agentcordon mcp-servers`

> List MCP servers available to this workspace.

```
agentcordon mcp-servers
```

No flags. Requires the broker to be running and the workspace to be registered. Results are deduplicated by server name.

**Output:**
```
NAME      DESCRIPTION       TRANSPORT  TOOLS
github    GitHub MCP        http       create_issue, list_repos, search_code
slack     Slack MCP server  http       send_message, list_channels
```

---

### `agentcordon mcp-tools`

> List all available MCP tools across all servers.

```
agentcordon mcp-tools
```

No flags or arguments. Requires the broker to be running and the workspace to be registered.

**Output:**
```
SERVER  TOOL          DESCRIPTION
github  create_issue  Create a GitHub issue
github  list_repos    List repositories
slack   send_message  Send a Slack message
```

---

### `agentcordon mcp-call`

> Call a tool on an MCP server.

```
agentcordon mcp-call <SERVER> <TOOL> [OPTIONS]
```

| Argument / Flag | Type | Required | Description |
|-----------------|------|:--------:|-------------|
| `<SERVER>` | string | Yes | MCP server name |
| `<TOOL>` | string | Yes | Tool name |
| `--arg <KEY=VALUE>` | string | No | Tool arguments (repeatable) |

Requires the broker to be running and the workspace to be registered. The broker checks Cedar policy authorization before forwarding the call.

> **Argument parsing:** Values are auto-parsed as JSON types where possible. `--arg count=5` becomes `{"count": 5}`, `--arg flag=true` becomes `{"flag": true}`, `--arg name=test` becomes `{"name": "test"}`.

**Examples:**

```bash
agentcordon mcp-call github create_issue \
  --arg repo=myorg/myrepo \
  --arg title="Bug report" \
  --arg body="Steps to reproduce..."

agentcordon mcp-call data-pipeline run_etl \
  --arg dataset=users \
  --arg limit=1000
```

**Output (success):**
```
Issue #42 created: https://github.com/myorg/myrepo/issues/42
```

**Output (error):**
```
MCP tool returned an error:
tool not found: 'nonexistent_tool'
```

---

## Files and Directories

### `.agentcordon/` -- Workspace State Directory

Created by `agentcordon init`. Added to `.gitignore` automatically. Directory permissions are set to `0700` on Unix.

| File | Permissions | Description |
|------|:-----------:|-------------|
| `workspace.key` | `0600` | Ed25519 private signing key (hex-encoded 32-byte seed) |
| `workspace.pub` | `0644` | Ed25519 public key (hex-encoded 32 bytes) |

### `~/.agentcordon/` -- User-Level Broker State

Used by the broker daemon (`agentcordon-broker`). Located in the user's home directory.

| File | Description |
|------|-------------|
| `broker.port` | Port file written by the broker, read by the CLI for auto-discovery |
| `broker.key` | P-256 keypair for the broker |
| `tokens.enc` | Encrypted token store |
| `workspaces.json` | Plaintext workspace recovery store |

### `.mcp.json` -- MCP Server Configuration

Standard MCP client configuration. After `init`, contains an `agentcordon` entry that routes MCP requests through the broker:

```json
{
  "mcpServers": {
    "agentcordon": {
      "command": "agentcordon",
      "args": ["mcp-serve"]
    }
  }
}
```

Existing entries in `.mcp.json` are preserved; only the `agentcordon` key is added or updated.

---

## Credential Types and Transforms

When using `proxy` or `mcp-call`, the credential type determines how it is injected into the outgoing request:

| Type | Transform | HTTP Result |
|------|-----------|-------------|
| `generic` | Bearer token | `Authorization: Bearer <value>` |
| `bearer` | Bearer token | `Authorization: Bearer <value>` |
| `basic` | Base64 encoding | `Authorization: Basic <base64(value)>` |
| `aws` | AWS SigV4 | `Authorization`, `x-amz-date`, `x-amz-content-sha256` headers |
| `api_key_header` | Custom header | `<header_name>: <value>` (header name from credential metadata) |
| `api_key_query` | Query parameter | `?<param_name>=<value>` (param name from credential metadata) |
| `oauth2_client_credentials` | Client credentials grant, then Bearer | `Authorization: Bearer <access_token>` |
| `oauth2_user_authorization` | Refresh token exchange, then Bearer | `Authorization: Bearer <access_token>` |

If no credential type is set, defaults to `bearer`.

---

## Authentication

The CLI uses Ed25519 request signing to authenticate with the broker. Every request (except `init` and unsigned registration) includes three headers:

| Header | Description |
|--------|-------------|
| `X-AC-PublicKey` | Hex-encoded Ed25519 public key |
| `X-AC-Timestamp` | Unix timestamp (seconds) |
| `X-AC-Signature` | Ed25519 signature of `METHOD\nPATH\nTIMESTAMP\nBODY` |

The broker verifies the signature and maps the public key to a registered workspace.

### Broker Discovery

The CLI discovers the broker in this order:

1. `AGTCRDN_BROKER_URL` environment variable (if set)
2. Port file at `~/.agentcordon/broker.port` (written by the broker on startup)
3. Health check at the discovered URL (`GET /health`)

If neither source yields a reachable broker, the CLI exits with code 2 ("broker not running").

---

> **See also:** [Workspace Enrollment](workspace-enrollment.md) -- [Credential Encryption](credential-encryption.md) -- [System Architecture](system-architecture.md)
