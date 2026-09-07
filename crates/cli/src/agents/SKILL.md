---
name: agentcordon
description: Use when a task needs an API credential, an authenticated HTTP call to an external or internal service, or a tool on an MCP server (issue trackers, deployments, cloud APIs) in a workspace that uses AgentCordon. Lists the credentials this workspace may use, proxies authenticated calls through the broker so raw secrets never reach the agent, and discovers and calls brokered MCP tools. Triggers on "call our internal API", "which credentials do I have", "use the API key/token", "list the MCP tools", "call an MCP tool".
compatibility: Requires the `agentcordon` CLI on PATH and a running `agentcordon-broker`.
---

# AgentCordon

**Never use a raw secret** — not one from the environment, a dotfile, or a config file. Every
authenticated call goes through the broker, which injects the credential and audits the access.

## Fast path

Call an API. `--auto` picks the credential whose URL fence covers the target; the body comes
back on stdout and one status line on stderr:

```
agentcordon proxy --auto <METHOD> <url> [--body '{"k":"v"}'] [--header 'Accept:application/json']
```

If it refuses (exit 7) it names the candidates; rerun with one of them in place of `--auto`.

Call an MCP tool. Read the schema first unless you already know the argument names:

```
agentcordon mcp-tools --schema --server <server> --tool <tool>
agentcordon mcp-call <server> <tool> --arg key=value
```

Only if a call errors, run `agentcordon credentials` or `agentcordon mcp-servers`; the error names the fence or the fix.

## Choosing

- **Never guess a credential name.** They are assigned per workspace; `agentcordon credentials`
  is the only list.
- The `ALLOWED URL` column is a glob fence. Take a credential whose fence covers the target, and
  among those the **least privileged** one: narrowest fence, then narrowest scopes.
- MCP servers are **not interchangeable**. Match the service the task is about, and prefer the
  server whose authenticated identity fits the question. Say which you picked and why.
- **Never pick an unauthenticated server** for a question about identity, permissions or private
  data: it returns a plausible-looking anonymous answer.

## When a call is refused

- `url_pattern_denied` — the credential's fence does not cover the target, and the message names
  the pattern. Pick another credential. Never retry with a raw token, and never rewrite the URL
  to get past the fence; if nothing covers the target, say so and ask for a credential.
- `Blocked by SSRF protection` — a loopback or private target that no credential is pinned to. A
  credential fenced to exactly that host (no wildcard in the host, e.g. `https://ha.example.ts.net/*`)
  is forwarded to a private address; the message shows the pattern an admin would write. Otherwise,
  for local development only, restart the broker as
  `AGTCRDN_PROXY_ALLOW_LOOPBACK=true agentcordon-broker --server-url <server>`; it reads the flag once, at startup.
- Exit codes: 2 broker not running · 3 not registered · 4 auth failed · 5 authorization denied
  (includes `url_pattern_denied`) · 6 upstream failed, not AgentCordon · 7 `--auto` found none or several.

## Reference

- `agentcordon status` — identity, broker connection, registration, configured server.
- `mcp-call <s> <t> --args-json '{...}'` for nested arguments (`@file` or `-`); `proxy … --body @file` reads a body from a file.
- `agentcordon credentials create --name <n> --service <s> --value <secret> --allowed-url-pattern '<glob>'` — only when you have been given a secret to store, and always fenced.
- Setup, not work: `agentcordon init` (skill + enrollment), `agentcordon register` (re-enrol).
- You never configure the broker: the CLI finds it via `~/.agentcordon/broker.port`; `AGTCRDN_BROKER_URL` is an override only.
