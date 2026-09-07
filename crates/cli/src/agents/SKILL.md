---
name: agentcordon
description: Use when a task needs an API credential, an authenticated HTTP call to an external or internal service, or a tool on an MCP server (issue trackers, deployments, cloud APIs) in a workspace that uses AgentCordon. Lists the credentials this workspace may use, proxies authenticated calls through the broker so raw secrets never reach the agent, and discovers and calls brokered MCP tools. Triggers on "call our internal API", "which credentials do I have", "use the API key/token", "list the MCP tools", "call an MCP tool".
compatibility: Requires the `agentcordon` CLI on PATH and a running `agentcordon-broker`.
---

# AgentCordon

This workspace brokers every API credential through AgentCordon. **Never use a raw
secret, and never send a token you found in the environment, a dotfile or a config
file.** Make the call with `agentcordon proxy` instead: the broker injects the
credential, the server policy-checks the target URL, and the access is audit-logged.

## Identity

Run `agentcordon status` to see this workspace's identity and whether the broker is
reachable. The identity is derived from `.agentcordon/workspace.key`; it is never
written into a markdown file, so `status` is the only place to read it.

## Commands

| Command | What it does |
|---|---|
| `agentcordon status` | Workspace identity, broker connection, registration state |
| `agentcordon credentials` | Table of credentials this workspace may use |
| `agentcordon credentials --json` | The same list as JSON, for filtering |
| `agentcordon proxy <credential> <METHOD> <url>` | Authenticated HTTP call |
| `agentcordon proxy <cred> POST <url> --body '{"k":"v"}'` | ...with a JSON body (`--body @file` reads a file) |
| `agentcordon proxy <cred> GET <url> --header 'Accept:application/json'` | ...with extra headers (repeatable) |
| `agentcordon mcp-servers` | MCP servers this workspace may use |
| `agentcordon mcp-tools` | Every tool on every server, with descriptions |
| `agentcordon mcp-tools --schema --server <s> --tool <t>` | One tool's exact `input_schema` |
| `agentcordon mcp-call <server> <tool> --arg key=value` | Call a tool with flat arguments |
| `agentcordon mcp-call <server> <tool> --args-json '{...}'` | Call with nested/array arguments |
| `agentcordon help` | Full reference |

Two commands are for setting the workspace up, not for doing work in it:
`agentcordon init` writes this skill (re-run it with `--reconfigure` to change which
runtimes it installs for) and `agentcordon register` enrols the workspace with a server
through the device flow. `agentcordon credentials create --name <n> --service <s>
--value <secret> --allowed-url-pattern '<glob>'` stores a *new* secret in the vault; only
run it when you have been given a secret to store, and always fence it with
`--allowed-url-pattern`.

## Choosing a credential

1. Run `agentcordon credentials` first. **Never guess a credential name** — names are
   assigned by an administrator and differ per workspace.
2. Read the `ALLOWED URL` column. It is a glob fence; a credential may only be proxied
   to URLs it matches. Pick the credential whose fence *covers your target URL*.
3. Among credentials that all cover the target, pick the **least privileged** one: the
   narrowest URL fence, then the narrowest scopes.
4. `--json` gives `name`, `service`, `credential_type`, `allowed_url_pattern`,
   `description`, `scopes`, `expires_at`, `expired`, `vault` if you need to filter.

## Choosing an MCP server

1. `agentcordon mcp-servers`, then `agentcordon mcp-tools`. Several servers may be
   listed and they are **not interchangeable**.
2. **Match the service the task is about** — the issue tracker for an issue, the
   deployment platform for a deploy. Server names and tool descriptions are the signal;
   the `DESCRIPTION` column is often empty and proves nothing.
3. **Prefer the server whose authenticated identity fits the question.** Two servers may
   expose an identically named tool while speaking to different accounts or tenants.
4. **Never pick an unauthenticated server for a question about identity, permissions or
   private data.** It will return a plausible-looking anonymous answer. "Least privilege"
   applies to *credentials*, not to choosing a server.
5. If two still fit, say which you picked and why.
6. **Before calling a tool, read its schema** with
   `agentcordon mcp-tools --schema --server <s> --tool <t>`. Never guess argument names.

## The broker

You do not configure the broker. `agentcordon-broker` binds a port the OS picks and
writes the URL to `~/.agentcordon/broker.port`; the CLI reads that file. There is no
default port to assume. `AGTCRDN_BROKER_URL` is an **override only** — do not export it
speculatively, a wrong value overrides working discovery. If `agentcordon status` cannot
reach the broker, start one: `agentcordon-broker --server-url <server>`.

## Loopback (local development)

To proxy to a `localhost` / `127.0.0.1` URL, the **broker** must have been started with
the flag:

```
AGTCRDN_PROXY_ALLOW_LOOPBACK=true agentcordon-broker --server-url <server>
```

The broker reads it once, at startup. The CLI never looks at it, so prefixing an
`agentcordon proxy` command with it does nothing — you must restart the broker.

## When a call is refused

- **`url_pattern_denied`** — the credential is fenced to a URL pattern that does not
  cover your target. The message names the pattern. Do **not** retry with a raw token
  and do not rewrite the URL to sneak past the fence: re-run `agentcordon credentials`
  and pick a credential whose `ALLOWED URL` covers the target. If none does, say so and
  ask for one; an administrator has to widen the fence or issue a new credential.
- **`Blocked by SSRF protection`** — the target resolves to a private or reserved
  address. See "Loopback" above; the broker must be restarted with the flag.
- **broker not running** — start `agentcordon-broker --server-url <url>`.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | General error (includes an SSRF refusal) |
| 2 | Broker not running |
| 3 | Workspace not registered — run `agentcordon register` |
| 4 | Authentication failed |
| 5 | Authorization denied (includes `url_pattern_denied`) |
| 6 | Upstream error — the remote service failed, not AgentCordon |
