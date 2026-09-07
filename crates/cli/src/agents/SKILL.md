---
name: agentcordon
description: Use when a task needs an API credential, an authenticated HTTP call to an external or internal service, or a tool on an MCP server (issue trackers, deployments, cloud APIs) in a workspace that uses AgentCordon. Lists the credentials this workspace may use, proxies authenticated calls through the broker so raw secrets never reach the agent, and discovers and calls brokered MCP tools. Triggers on "call our internal API", "which credentials do I have", "use the API key/token", "list the MCP tools", "call an MCP tool".
compatibility: Requires the `agentcordon` CLI on PATH and a running `agentcordon-broker`.
---

# AgentCordon

**Never use a raw secret** — not one from the environment, a dotfile, or a config file. Every
authenticated call goes through the broker, which injects the credential and audits the access.

## Fast path

Call an API with the credential whose URL fence covers your target — `agentcordon credentials --json` lists every `name` with its `allowed_url_pattern`:

```
agentcordon proxy <credential> <METHOD> <url> [--body '{"k":"v"}'] [--header 'Accept:application/json']
```

Call an MCP tool. Read the schema first unless you already know the argument names:

```
agentcordon mcp-tools --schema --server <server> --tool <tool>
agentcordon mcp-call <server> <tool> --arg key=value
```

Only if a call errors, run `agentcordon credentials` or `agentcordon mcp-servers` and read the
error text — it names the fence that blocked you, or the fix.

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
- `Blocked by SSRF protection` — a loopback or private target. The **broker** must have been
  started as `AGTCRDN_PROXY_ALLOW_LOOPBACK=true agentcordon-broker --server-url <server>`. It
  reads the flag once, at startup, so restart it; prefixing an `agentcordon proxy` call does nothing.
- Exit codes: 2 broker not running · 3 not registered · 4 auth failed · 5 authorization denied
  (includes `url_pattern_denied`) · 6 upstream service failed, not AgentCordon.

## Reference

- `agentcordon status` — identity, broker connection, registration, configured server.
- `agentcordon mcp-call <s> <t> --args-json '{...}'` — nested or array arguments (`@file`, or `-` for stdin). `agentcordon proxy <c> POST <url> --body @file` reads a body from a file.
- `agentcordon credentials create --name <n> --service <s> --value <secret> --allowed-url-pattern '<glob>'` — only when you have been given a secret to store, and always fenced.
- Setup, not work: `agentcordon init` (skill + enrollment), `agentcordon register` (re-enrol).
- You never configure the broker. It writes its URL to `~/.agentcordon/broker.port` and the CLI
  reads that; `AGTCRDN_BROKER_URL` is an override only — do not export it speculatively.
