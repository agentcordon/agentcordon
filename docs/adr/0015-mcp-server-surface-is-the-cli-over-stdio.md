# 15. The MCP server surface is the CLI over stdio, with a fixed six tools

- **Status:** Accepted
- **Date:** 2026-09-07

## Context

[ADR-0013](0013-init-installs-the-agentcordon-skill-per-runtime.md) made the Agent Skill the
integration and deferred tier 3, the MCP server surface, to an ADR of its own. This is that
ADR. The work is [issue #54](https://github.com/agentcordon/agentcordon/issues/54) and its
amendment.

The skill works: a headless Claude Code trial used `agentcordon credentials`, `proxy`,
`mcp-servers`, `mcp-tools` and `mcp-call` unprompted in six of six blind runs. But every one of
those was a shell command, and that is a real ceiling:

- **Activation is model-decided.** A skill is loaded when the model judges the description to
  match. ADR-0013 named that as the cost of the decision, and the trial is evidence for one
  runtime at one version, not proof for all of them.
- **The permission model cannot see it.** To a runtime, `agentcordon proxy …` is one more Bash
  command. It cannot show a typed argument list, cannot allow-list per tool, and cannot
  distinguish a credential vend from `rm -rf`.
- **The error envelope is shell output.** The CLI prints structured JSON, and the model has to
  parse it back out of a terminal transcript.
- **0 of 17 surveyed runtimes** could call the credential proxy or a brokered MCP tool without
  reading prose first (`uat/artifacts/reviews/ONBOARDING-landscape.md` § 3).

Sixteen of the seventeen are MCP clients with a stdio transport. Aider is the exception, and
permanently: neither its options reference nor its HISTORY mentions MCP.

## Decision

**`agentcordon mcp-serve` is a stdio MCP server hosted in the CLI, exposing a fixed set of six
tools; re-exporting a brokered server's own tools is opt-in per server. `agentcordon init`
writes each selected runtime's MCP configuration.**

### The surface belongs in the CLI, not on the broker

The broker's HTTP listener authenticates every route by a request signed with the workspace key
(ADR-0008). A runtime's MCP client cannot sign. An HTTP MCP endpoint on the broker would
therefore need a bearer secret held by the runtime — exactly the class of secret
[ADR-0006](0006-secrets-never-leave-the-server.md) keeps out of the agent's hands.

A stdio child process is the opposite shape. The runtime launches it in the workspace
directory; it loads `.agentcordon/workspace.key` through the same `signing::load_keypair` and
reuses `BrokerClient` unchanged. The MCP server is the existing CLI with a JSON-RPC front
instead of clap: same key, same pin check, same four signed headers, same shared-secret
environment, same broker routes.

### Six tools, fixed

An MCP client loads every tool's name, description and input schema into the model's context at
session start. Re-exporting one tool per brokered upstream tool — the original design — would
cost 50–200 tokens per tool in every session, so a single GitHub-sized upstream of about eighty
tools is 10,000+ tokens whether or not the session touches it. That is the opposite of what the
skill achieved.

So the default surface is fixed, and costs the same for a workspace with one upstream or twenty:

| Tool | Broker route |
|---|---|
| `agentcordon_status` | `GET /status` |
| `agentcordon_credentials` | `GET /credentials` |
| `agentcordon_proxy` | `POST /proxy` |
| `agentcordon_mcp_servers` | `POST /mcp/list-servers` |
| `agentcordon_mcp_tools(server)` | `POST /mcp/list-tools`, on demand |
| `agentcordon_mcp_call(server, tool, args)` | `POST /mcp/call` |

About 800 tokens per session. `content` and `isError` come back unchanged, with the
`correlation_id` in each result's `_meta` so the runtime's own transcript carries the audit
handle.

### Re-export is opt-in, per server

Typed re-export — one `<server>__<tool>` per upstream tool, `inputSchema` verbatim,
list-changed notifications — is what earns the schema cost for the one or two servers an agent
calls constantly. It is requested per server, `agentcordon mcp-serve --expose <server>`,
remembered in `.agentcordon/agents.toml`, and written into every runtime's config as
`--expose <server>` argument pairs.

### `init` registers it

`init` writes each selected runtime's MCP configuration alongside the skill, so nothing has to
be hand-edited. Ten runtimes have a project-level file; five configure MCP per user only, and
for those `init` prints the path and the snippet. The command line is identical everywhere:
`agentcordon`, `mcp-serve`, plus the `--expose` pairs. Never an absolute path — PATH resolution
stays the user's, and a committed file has to work on the next machine.

Three rules govern every writer. A file that is absent is created. A file that parses and has
no `agentcordon` entry gets one inserted. A file that does not parse, or that already carries an
`agentcordon` entry saying something else, is left byte-identical and its snippet is printed.

`--no-mcp` skips the whole step and is remembered, because the two integrations are a real
trade-off and not a strict improvement: the skill costs nothing until it is triggered and then
one shell turn per call; the MCP surface costs ~800 tokens in every session and then a native
call with no shell round trip. Both can be installed, and the skill's fast path now opens by
saying to prefer the `agentcordon_*` tools when the runtime shows them.

## Consequences

- **Token cost is now non-zero at rest.** ADR-0013's headline was that the always-on cost
  dropped to a skill's frontmatter. Registering the MCP server puts ~800 tokens back into every
  session of every runtime that reads the config. That is the price of an integration that does
  not depend on a model's judgement, it is bounded and does not grow with the workspace, and
  `--no-mcp` declines it. Runtimes that defer MCP schema loading (Claude Code already does) make
  it cheaper over time.
- **The security model is unchanged.** The runtime talks to a local child over pipes; the child
  signs each broker request with the workspace key; the broker vends and injects; the credential
  never enters the child or the runtime. The `allowed_url_pattern` double check
  ([ADR-0007](0007-target-bound-vends.md)) runs on the broker regardless of which client asked,
  and `mcp_authorize` still emits its policy-evaluation audit row. Attribution stays the
  workspace `pk_hash`: the runtime is not an entity.
- **One new exposure, and it is the generic one.** A repository can commit a project-level MCP
  entry whose `command` is not the real binary. Every runtime that reads project-level MCP
  config already gates it — Claude Code prompts to approve a project `.mcp.json`, Codex and
  Junie honour it only in a trusted project, Kiro and Cursor prompt on first use — and `init`
  writes the bare name `agentcordon`, so what runs is whatever the user's PATH resolves.
- **`init` now creates directories it did not before** — `.cursor/`, `.roo/`, `.vscode/`,
  `.codex/`, `.junie/mcp/`. ADR-0013's rule that no detection marker may name a path `init`
  writes therefore bites harder: several runtimes had to move from detecting on their config
  directory to detecting on a rules file the runtime itself writes, or lose their project-level
  marker entirely. `--agent auto` is correspondingly less eager for those runtimes, which is the
  right trade against a runtime that can never be deselected.
- **Autostart is the runtime's, not ours.** The runtime spawns `mcp-serve` when its session
  starts, so the process appears without a user command. It still needs a broker; `mcp-serve`
  answers `initialize` when the broker is down and returns an error on `tools/call`, rather than
  failing the runtime's startup.
- **Aider stays prose-only, permanently.** No MCP client, no skills; its shell commands are
  user-approved, which is acceptable for a human-in-the-loop tool.
- **A runtime that changes its config shape needs a registry entry and nothing else.** The
  command line is fixed by this decision, so the only per-runtime knowledge is the file and the
  key.
