> [Home](index.md) > CLI Reference

# CLI Reference

Complete reference for the `agentcordon` command-line tool -- the workspace agent that generates identity keypairs, registers with the broker, and bridges credentials and MCP servers.

---

## Quick Reference

```
agentcordon init         [--agent RUNTIME]... [--reconfigure]
agentcordon register     [--server-url URL] [--name NAME] [--scope SCOPE]... [--force]
agentcordon status
agentcordon credentials  [--json]
agentcordon credentials  create --name NAME --service SVC --value VAL
agentcordon proxy        CREDENTIAL METHOD URL [--header K:V]... [--body JSON] [--json] [--raw] [--headers]
agentcordon proxy --auto METHOD URL [--header K:V]... [--body JSON] [--json] [--raw] [--headers]
agentcordon mcp-servers
agentcordon mcp-tools    [--schema [--server NAME] [--tool NAME]]
agentcordon mcp-call     SERVER TOOL [--arg K=V]... [--args-json SRC] [--json]
```

---

**On this page:**
[The fast path](#for-agents-the-fast-path) -- [Exit Codes](#exit-codes) -- [Environment Variables](#environment-variables) -- [Commands](#commands) -- [Files & Directories](#files-and-directories) -- [Credential Types](#credential-types-and-transforms) -- [Authentication](#authentication)

---

## For agents: the fast path

One authenticated call is **one command**, and what comes back is the response
body and one line saying what it was.

```bash
# An HTTP API. The credential is the one whose URL fence covers this target.
agentcordon proxy --auto GET https://api.example.com/v1/things

# With a body:
agentcordon proxy --auto POST https://api.example.com/v1/things --body '{"name":"x"}'

# Machine-readable: one compact {status, headers, body} object.
agentcordon proxy --auto GET https://api.example.com/v1/things --json

# An MCP tool. Prints the tool's text; --json for the whole result.
agentcordon mcp-call <SERVER> <TOOL> --arg key=value
```

`proxy --auto` prints the **body** on stdout and one summary line on stderr:

```
HTTP 200 · 27 B · content-type: application/json · via example-api
{"things":[]}
```

Only reach for the rest when `--auto` refuses:

| It said | Do this |
|---|---|
| `no credential is fenced for <url>` (exit 7) | `agentcordon credentials` -- nothing covers that URL; the target may be wrong, or the credential may not exist yet. |
| `several credentials are fenced for <url>` (exit 7) | Pick one from the list it printed: `agentcordon proxy <name> <METHOD> <url>`. |
| `... (url_pattern_denied)` (exit 5) | The credential you named is fenced elsewhere. `--auto` would have avoided this. |
| exit 2 | The broker is not running. |
| exit 3 | `agentcordon register`. |

`agentcordon credentials` and `agentcordon mcp-tools --schema` are for when
you need to *see* the catalogue -- not something to run before every call.

---

## Exit Codes

| Code | Meaning | Emitted by |
|:----:|---------|------------|
| `0` | Success | every command |
| `1` | General error -- a bad argument, a malformed request, or a refusal that never reached an upstream (an SSRF-blocked target is the common one) | every command |
| `2` | Broker not running | every command except `init` |
| `3` | Workspace not registered, or it must re-register (`agentcordon register --force`) | every command except `init` |
| `4` | Authentication failed -- the broker rejected the workspace signature | every command except `init` |
| `5` | Authorization denied -- a policy, a scope, or a credential's `allowed_url_pattern` refused the request | every command except `init` |
| `6` | Upstream error -- the service on the far side of the broker (a proxied API, an MCP server, or the AgentCordon server during registration) answered with an error or could not be reached | `proxy`, `mcp-tools`, `mcp-call`, `register` |
| `7` | `proxy --auto` found no credential fenced for the target, or more than one. Nothing was proxied. Its own code because the fix is to name a credential (or create one), not to register or to change a policy | `proxy --auto` |

`init` never talks to the broker or the network, so it only ever exits `0` or `1`.

An **SSRF refusal exits `1` from both `proxy` and `mcp-call`**. The broker refuses the target
before it makes any request, so nothing upstream ever answered and `6` would misreport it.
The two routes label the refusal differently on the wire (`bad_request` from `/proxy`,
`ssrf_blocked` from `/mcp/call`); the exit code is the same either way, so a script can wrap
both commands and treat the one guard uniformly.

---

## Environment Variables

| Variable | Used By | Default | Description |
|----------|---------|---------|-------------|
| `AGTCRDN_BROKER_URL` | All commands (except `init`) | Auto-discovered via port file | Broker URL override. Accepted only if it is plain `http://` to a loopback host (`localhost`, `*.localhost`, `127.0.0.1`, `[::1]`) or any `https://` URL; anything else is refused before a request is made. The URL is health-checked and must publish the broker key. |
| `AGTCRDN_BROKER_SHARED_SECRET` | All commands (except `init`); also the broker | unset | Sent as `X-AgentCordon-Broker-Secret` on every request. Required when the broker was started with `--shared-secret` (the same variable configures the broker). |
| `AGTCRDN_BROKER_CA` | All commands (except `init`) | unset (system roots only) | Path to a PEM certificate or CA bundle to trust for the broker connection, in addition to the system roots. Needed when the broker serves its own certificate (`agentcordon-broker --tls-cert`). See [Serving the broker over TLS](#serving-the-broker-over-tls). |
| `AGTCRDN_WORKSPACE_DIR` | `init`, keypair loading | `.` (current directory) | Override the workspace root where `.agentcordon/` lives |
| `AGTCRDN_LOG_LEVEL` | All commands | `warn` | Log level filter (e.g. `info`, `debug`, `trace`) |
| `AGTCRDN_DATA_DIR` (`--data-dir`) | Broker only | `~/.agentcordon` | Directory for the broker's keys, tokens and runtime files. The **CLI does not read it** -- see [Files and Directories](#files-and-directories). |
| `AGTCRDN_PROXY_ALLOW_LOOPBACK` | Broker (affects `proxy`, `mcp-call`); **also the server**, for its own outbound calls | `false` | Set to `true` on the **broker** to allow loopback/private-network URLs from `proxy` and `mcp-call`. The server reads the same variable independently -- see the note below. |

> **Note:** `AGTCRDN_PROXY_ALLOW_LOOPBACK` is not a CLI flag. It is read by two separate
> processes, each for its own outbound calls, and setting it on one does nothing for the
> other:
>
> | Set on | Covers |
> |--------|--------|
> | `agentcordon-broker` | `agentcordon proxy` (`/proxy`) and `agentcordon mcp-call` -- every call the broker makes to an upstream with a credential injected |
> | `agent-cordon-server` | MCP tool discovery (the `initialize` / `tools/list` probe a marketplace install runs against the upstream URL) and OAuth discovery (the MCP endpoint's 401 probe, the RFC 9728 protected-resource document, the RFC 8414 authorization-server metadata) |
>
> An upstream on a private or loopback address needs it in **both**: without the broker's
> copy, `proxy` and `mcp-call` are refused with `Blocked by SSRF protection`; without the
> server's, a marketplace install still reports success and discovers no tools. See
> [Granting MCP Server Access -- SSRF Protection](granting-mcp-server-access.md#ssrf-protection).

**Broker flags for a non-loopback bind.** `agentcordon-broker --bind` defaults to `127.0.0.1`. A non-loopback bind (for example `0.0.0.0` in a container) is refused at startup unless one of these is set:

| Flag | Env | Effect |
|------|-----|--------|
| `--shared-secret <SECRET>` | `AGTCRDN_BROKER_SHARED_SECRET` | Every request except `GET /health` must carry the secret in `X-AgentCordon-Broker-Secret` (constant-time compare); the CLI sends it from the same variable. |
| `--tls-cert <PEM> --tls-key <PEM>` | `AGTCRDN_BROKER_TLS_CERT`, `AGTCRDN_BROKER_TLS_KEY` | The broker terminates TLS itself: it serves HTTPS on its bind address instead of plaintext HTTP. See [Serving the broker over TLS](#serving-the-broker-over-tls). |

The broker also takes an advisory lock on `<data-dir>/broker.lock`; a second broker on the same data directory exits with "another agentcordon-broker is already running on this data directory".

### Serving the broker over TLS

`--tls-cert` and `--tls-key` are given together and name PEM files: a certificate chain and its unencrypted private key (PKCS#8 or PKCS#1/SEC1). With both set, the broker terminates TLS on its own listener; without them it serves plaintext HTTP, unchanged.

```
agentcordon-broker --bind 0.0.0.0 \
  --tls-cert /etc/agentcordon/broker.pem \
  --tls-key  /etc/agentcordon/broker-key.pem
```

- Both files are read at startup. An unreadable file, a file with no `CERTIFICATE` block, or a certificate and key that do not belong together stops the broker before it binds, with a message naming the flag at fault -- a broker that reaches the listening state can complete a handshake.
- HTTP/1.1 and HTTP/2 are both offered (ALPN). Graceful shutdown is unchanged: `SIGTERM`/`Ctrl-C` stops accepting and lets in-flight requests finish.
- A failed handshake closes that one connection. There is no plaintext fallback on the TLS port.
- The port file (`~/.agentcordon/broker.port`) records the URL to dial (`https://127.0.0.1:<port>` for a TLS broker; a broker bound to every interface is reached on loopback), so local discovery works for TLS brokers too. The CLI still accepts the bare-port form older brokers wrote. `AGTCRDN_BROKER_URL` overrides discovery.

**Trusting the broker's certificate from the CLI.** Set `AGTCRDN_BROKER_CA` to a PEM file -- the broker's own `--tls-cert` file for a self-signed certificate, or the issuing CA -- and every certificate in it becomes an additional trust anchor for the CLI's broker connection, on top of the system roots. Verification is never disabled. Without it, a broker serving a certificate this machine does not trust is refused with a message naming `AGTCRDN_BROKER_CA`; a broker that is simply not running still exits 2 as before. The broker key pin (`.agentcordon/broker.fingerprint`) is a separate, unchanged check: TLS authenticates the transport, the pin authenticates the broker's P-256 key.

```
export AGTCRDN_BROKER_URL=https://broker.internal:9876
export AGTCRDN_BROKER_CA=/etc/agentcordon/broker.pem
agentcordon status
```

**The shared-secret alternative.** TLS is not required. A non-loopback bind is also accepted with `--shared-secret` alone, for a deployment that terminates TLS in a reverse proxy in front of the broker (or runs on a trusted container network): every request except `GET /health` must then carry the secret in `X-AgentCordon-Broker-Secret`, which the CLI sends from `AGTCRDN_BROKER_SHARED_SECRET`. The two can be combined; either one satisfies the non-loopback bind guard.

---

## Commands

### `agentcordon init`

> Generate an Ed25519 keypair and install the AgentCordon skill for the agent runtimes you use.

```
agentcordon init [--agent <RUNTIME>]... [--reconfigure]
```

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--agent <RUNTIME>` | string, repeatable | see below | A runtime id from the table, or `auto`, `all`, `none` |
| `--reconfigure` | bool | `false` | Ignore the remembered choice and pick again |

**What it does:**

1. Generates an Ed25519 keypair (`.agentcordon/workspace.key`, `.agentcordon/workspace.pub`), `0700` on the directory and `0600` on the private key (Unix).
2. Adds `.agentcordon/` to `.gitignore`.
3. Decides which runtimes to install for (below).
4. Writes the **AgentCordon skill** into every skill directory those runtimes read.
5. Remembers the choice in `.agentcordon/agents.toml` and prints a summary naming every file it wrote and which runtime reads it.

Idempotent: a rerun reports the same identity, leaves the keypair alone, and rewrites a skill file only if its content differs.

#### The skill

`init` writes one file, `SKILL.md`, in the [Agent Skills](https://agentskills.io/specification) format. It carries everything an agent needs: the command list, how to pick a credential by its URL fence, how to pick an MCP server, the loopback rule, the exit codes, and what to do when a call is refused.

It is a skill rather than a block in `AGENTS.md` because a skill is loaded as ~100 tokens of metadata and its body is read only when the task is actually about credentials or MCP. An always-on prose block cost that context in every session of every runtime, ran into Windsurf's 12,000-character rule-file cap and Codex's 32 KiB instruction-chain cap, and was shadowed outright by Zed's first-match rule. See [ADR-0013](adr/0013-init-installs-the-agentcordon-skill-per-runtime.md).

The skill does **not** carry the workspace identity. It is derived from the key and changes when the key does, so a file holding a copy goes stale; the skill tells the agent to run `agentcordon status` instead.

`.agents/skills/agentcordon/SKILL.md` is always written. It is the open-standard path, thirteen of the fifteen runtimes below read it, and it is what Aider's `read:` entry points at.

#### Targets

| `--agent` | Runtime | Detected by | Extra file written |
|---|---|---|---|
| `claude-code` | Claude Code | `claude` on PATH, `~/.claude`, `CLAUDE.md`, `.claude/settings.json` | `.claude/skills/agentcordon/SKILL.md` |
| `codex` | OpenAI Codex CLI | `codex` on PATH, `~/.codex`, `.codex/` | — |
| `opencode` | OpenCode | `opencode` on PATH, `~/.config/opencode`, `opencode.json[c]`, `.opencode/` | — |
| `gemini` | Gemini CLI | `gemini` on PATH, `~/.gemini`, `.gemini/`, `GEMINI.md` | — |
| `copilot` | GitHub Copilot (VS Code and CLI) | `copilot` on PATH, `~/.copilot`, `.github/copilot-instructions.md`, `.vscode/` | — |
| `cursor` | Cursor | `cursor` on PATH, `~/.cursor`, `.cursor/` | — |
| `windsurf` | Windsurf | `windsurf` on PATH, `~/.codeium/windsurf`, `.windsurf/`, `.devin/` | — |
| `cline` | Cline | `~/.cline`, `.clinerules`, `.cline/` | `.claude/skills/agentcordon/SKILL.md` |
| `roo` | Roo Code | `~/.roo`, `.roo/`, `.roorules` | — |
| `aider` | Aider | `aider` on PATH, `~/.aider.conf.yml`, `.aider.input.history` | `.aider.conf.yml` (`read:` entry) |
| `amp` | Amp | `amp` on PATH, `~/.config/amp`, `.amp/` | — |
| `goose` | Goose | `goose` on PATH, `~/.config/goose`, `.goosehints`, `.goose/` | — |
| `zed` | Zed | `zed` on PATH, `~/.config/zed`, `.zed/` | — |
| `junie` | JetBrains Junie | `~/.junie`, `.junie/` | — |
| `kiro` | Kiro | `kiro` on PATH, `~/.kiro`, `.kiro/steering`, `.kiro/settings` | `.kiro/skills/agentcordon/SKILL.md` |

An em dash in the last column means the portable `.agents/skills/` copy is the file that runtime reads; nothing further is needed.

Aider is the only runtime with no skill discovery at all, so it is the only one that gets a pointer file: a `read:` key in `.aider.conf.yml`, marker-delimited. A config that already has a `read:` key is left byte-identical and the line is printed for you to merge, because a YAML mapping may carry only one.

No detection marker is ever a path `init` writes. A runtime that detected on its own installed skill could never be deselected.

Three keywords are not runtimes:

| Value | Meaning |
|---|---|
| `auto` | Every runtime detected in this workspace or your home directory. The default. |
| `all` | Every runtime in the table. |
| `none` | Only the portable `.agents/skills/` copy. |

`--agent` is repeatable and the values combine, so `--agent auto --agent kiro` is "what you found, plus Kiro". `openclaw` still parses, for compatibility: it installs the portable skill and prints a one-line notice. OpenClaw reads `<workspace>/.agents/skills`, not the project-local `.openclaw/instructions.md` older versions wrote.

#### Choosing, and remembering the choice

With no `--agent`, `init` decides in this order:

1. The choice remembered in `.agentcordon/agents.toml`, unless `--reconfigure`.
2. A multi-select picker, if **both** stdin and stdout are a terminal. Detected runtimes are pre-checked, and the list starts with "All runtimes" and "None — install only the portable skill".
3. Otherwise `auto`.

`init` never prompts off a terminal, which is what keeps scripts and the UAT harness working. `.agentcordon/agents.toml` is inside the gitignored `.agentcordon/` directory, so the choice is per-checkout.

`init` does not touch `.mcp.json`. MCP tools are reached through the broker (`agentcordon mcp-tools`, `agentcordon mcp-call`), not through a native MCP server entry; there is no `agentcordon mcp-serve` for one to point at.

**Examples:**

```bash
# Detect what you use and install for it (interactive when on a terminal)
agentcordon init

# Non-interactive, explicit
agentcordon init --agent claude-code --agent codex

# Every runtime; or none but the portable skill
agentcordon init --agent all
agentcordon init --agent none

# Change your mind
agentcordon init --reconfigure
```

**Output:**
```
Workspace identity: sha256:a1b2c3d4...

AgentCordon skill:
  created   .agents/skills/agentcordon/SKILL.md
            read by OpenAI Codex CLI
  created   .claude/skills/agentcordon/SKILL.md
            read by Claude Code

Runtimes: Claude Code, OpenAI Codex CLI
(from --agent; saved to .agentcordon/agents.toml — rerun `agentcordon init --reconfigure` to choose again.)
```

---

### `agentcordon register`

> Register this workspace with the broker via the RFC 8628 device authorization flow. This is the canonical onboarding command.

```
agentcordon register [OPTIONS]
```

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--server-url <URL>` | string | `$AGTCRDN_SERVER_URL` | AgentCordon server URL (e.g. `http://server:3140`). If provided and no broker is running, `register` auto-starts a local broker pointed at this server before kicking off the device flow. |
| `--name <NAME>` | string | current directory's basename | Workspace display name. Names are not unique -- two workspaces may share one as long as their keypairs differ. |
| `--scope <SCOPE>` | string (repeatable) | `credentials:discover credentials:vend mcp:discover mcp:invoke` | OAuth scopes to request |
| `--force` | bool | `false` | Clear existing broker registration before re-registering (use when the server-side workspace was deleted but the broker holds stale state). Also re-pins the broker key. |

**What it does:**

1. Locates a running broker via `AGTCRDN_BROKER_URL` or `~/.agentcordon/broker.port`. If none is running and `--server-url` (or `AGTCRDN_SERVER_URL`) is provided, auto-starts a broker pointed at that server and waits for it to report healthy.
2. If `--force`: sends a deregister request to clear stale state.
3. Posts a signed registration request with the workspace public key and requested scopes.
4. Displays a short human-readable activation code and an `/activate` URL (plus a prefilled one if the server returned it).
5. Polls the broker until the approval is recorded or the device code expires.

The command does NOT try to auto-open a browser. The broker frequently runs on a different host / container / SSH session than the user's browser (the point of RFC 8628 device flow), so a local `xdg-open` would open the URL on the wrong machine. Copy/paste the URL yourself on whichever device has the browser.

If no broker is running and no server URL is available, the command exits with code `2` ("broker not running") and prints: `Start the broker first: agentcordon-broker --server-url <url>` / `Or pass --server-url to agentcordon register and it will auto-start the broker.`

**Examples:**

```bash
# Recommended first-run: init the workspace, then register (auto-starts broker)
agentcordon init
agentcordon register --server-url http://localhost:3140

# Register against an already-running broker
agentcordon register

# Re-register after server-side workspace deletion
agentcordon register --force

# Request specific scopes
agentcordon register --scope credentials:discover --scope credentials:vend
```

> **If the printed URL looks unreachable** (`http://0.0.0.0:3140/activate` is the classic
> case), the server has no `AGTCRDN_BASE_URL` and fell back to its bind address. The code is
> still valid: open `https://<the URL you reach the server on>/activate?user_code=<code>`
> instead, then ask the operator to set `AGTCRDN_BASE_URL`. See
> [Workspace Enrollment](workspace-enrollment.md#enrollment-flow).
>
> The installer routes fall back differently: `GET /install.sh` and `GET /install.ps1` build
> their `SERVER_URL` from the `Host` header of the request that fetched them, with the scheme
> taken from `X-Forwarded-Proto` and defaulting to `http` (the server never terminates TLS
> itself). So the installer never prints `0.0.0.0`, and behind a TLS-terminating proxy that
> does not send `X-Forwarded-Proto: https` it points at `http://` — one more reason to set
> `AGTCRDN_BASE_URL`.

**Output:**

Everything up to the last line goes to **stderr**, so the code stays visible when stdout is
captured or piped.

```

! First, copy your one-time code: tidy-zoned-zit-ramp

Then open this URL in your browser:
  https://agentcordon.example.com/activate

Or use this link to skip typing the code:
  https://agentcordon.example.com/activate?user_code=tidy-zoned-zit-ramp

Waiting for approval... (expires in 10 minutes) done!
Logged in as my-workspace. Scopes: [credentials:discover, credentials:vend, mcp:discover, mcp:invoke]
```

The expiry is the server's `expires_in` for this device code -- 10 minutes by default,
`AGTCRDN_DEVICE_CODE_TTL_SECS` on the server. When it runs out the command exits with
`Code expired. Run agentcordon register to try again.` The prefilled link is only printed
when the server returned one.

---

### `agentcordon status`

> Check workspace registration and broker connectivity.

```
agentcordon status
```

No flags. Requires the broker to be running and a valid keypair.

**Output:**
```
Broker: http://127.0.0.1:52318 (healthy)
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
agentcordon credentials [--json]
```

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--json` | bool | `false` | Emit the broker's envelope as JSON instead of a table, for filtering |

Requires the broker to be running and the workspace to be registered.

**Output:**
```
NAME          SERVICE  TYPE     ALLOWED URL                VAULT       EXPIRES
github-token  github   bearer   https://api.github.com/*   default     never
aws-prod      aws      aws      * (any URL)                production  2026-05-01T00:00:00Z

* (any URL) means the credential is not fenced and may be proxied anywhere. Prefer the narrowest fence that covers your target URL.
```

`ALLOWED URL` is the credential's `allowed_url_pattern`: the glob a proxied URL must match,
checked by the server on the vend and again by the broker before injection
([ADR-0007](adr/0007-target-bound-vends.md)). It is the column to choose by — match your
target against it, then take the narrowest fence that still covers the target. `* (any URL)`
rather than `-` because an unfenced credential is the least safe one, not a missing value.

An expired credential's `EXPIRES` cell is suffixed `(EXPIRED)`.

There is no `DESCRIPTION` column. The broker's projection withholds `description` from an
agent along with `transform_script`, `metadata`, `owner_username` and `tags`; it is
operator-facing prose and stays on the control plane.

`VAULT` is the vault's **display name**. It is unique among the vaults one user owns but
free across owners, so two vaults reachable from here may both be called `production` if
they belong to different people. A workspace groups by the name it can read; the vault's id
is a control-plane concern and the CLI never shows it. See
[Credential Encryption § Vaults](credential-encryption.md#vaults).

---

### `agentcordon credentials create`

> Create a new credential in the vault via the broker.

```
agentcordon credentials create --name <NAME> --service <SERVICE> --value <VALUE>
                              [--allowed-url-pattern <PATTERN>]
```

| Flag | Type | Required | Description |
|------|------|:--------:|-------------|
| `--name <NAME>` | string | Yes | Credential name (unique within workspace) |
| `--service <SERVICE>` | string | Yes | Service identifier (e.g. `github`, `openai`) |
| `--value <VALUE>` | string | Yes | Secret value to store |
| `--allowed-url-pattern <PATTERN>` | string | No | Restrict the URLs this credential may be proxied to (e.g. `https://api.github.com/*`) |

The credential is created with type `generic`. The first three flags are required and must be non-empty.

> **Without `--allowed-url-pattern` the credential is unrestricted:** it can be injected into
> a request to *any* URL. The pattern is matched structurally (scheme, host and port as parsed
> values, host globs at label boundaries, `*` on the path), and it is checked twice -- by the
> server when it vends the credential, and by the broker again before it injects. The success
> line says which of the two you got. Narrow it here, at creation time under **Allowed URL
> pattern** (directly beneath *Service* on **Credentials -> Add Credential**), or later on the
> credential's page under **Edit -> URL Restriction**. See
> [Credential Encryption -- Data Model](credential-encryption.md).

**Examples:**

```bash
# Fenced to one API
agentcordon credentials create \
  --name github-token \
  --service github \
  --value "ghp_abc123..." \
  --allowed-url-pattern "https://api.github.com/*"

# Unrestricted -- usable against any URL
agentcordon credentials create \
  --name slack-api \
  --service slack \
  --value "xoxb-..."
```

**Output:**
```
Created credential 'github-token' (service: github, allowed URLs: https://api.github.com/*)
```

Without a pattern:
```
Created credential 'slack-api' (service: slack, allowed URLs: UNRESTRICTED - this credential can be proxied to any URL; narrow it with --allowed-url-pattern)
```

---

### `agentcordon proxy`

> Proxy an HTTP request through the broker with credential injection.

```
agentcordon proxy <CREDENTIAL> <METHOD> <URL> [OPTIONS]
agentcordon proxy --auto <METHOD> <URL> [OPTIONS]
```

| Argument / Flag | Type | Required | Description |
|-----------------|------|:--------:|-------------|
| `<CREDENTIAL>` | string | Unless `--auto` | Credential name |
| `<METHOD>` | string | Yes | HTTP method (`GET`, `POST`, `PUT`, `PATCH`, `DELETE`, `HEAD`, `OPTIONS`) |
| `<URL>` | string | Yes | Target URL |
| `--auto` | bool | No | Choose the credential whose URL fence covers `<URL>`, instead of naming one. See [Choosing the credential with `--auto`](#choosing-the-credential-with---auto). |
| `--header <KEY:VALUE>` | string | No | Additional headers (repeatable) |
| `--body <STRING>` | string | No | Request body (string, or `@file` to read from file) |
| `--json` | bool | No | Emit one compact `{status, headers, body}` object |
| `--raw` | bool | No | Print only the response body, with no summary line on stderr |
| `--headers` | bool | No | Print the status line and every response header above the body, on stdout |

Requires the broker to be running and the workspace to be registered. The broker resolves the credential, injects it into the request according to its type, and forwards the request to the target URL.

#### Choosing the credential with `--auto`

`--auto` fetches the listing the broker already holds (`agentcordon credentials`) and
picks from it. The rule is fixed, so two runs choose the same credential:

1. An **expired** credential is never a candidate.
2. A **fenced** credential is a candidate when its `allowed_url_pattern` covers the
   target. The comparison is structural, not textual: the scheme, host and port are
   compared as values, a `*` in the host stands for exactly one DNS label, and a `*`
   in the path or query matches any run of characters. `https://*.github.com/*` does
   **not** cover `https://api.github.com.attacker.example/x`, nor
   `https://api.github.com:8443/x`.
3. **Exactly one** fenced candidate is used.
4. With no fenced candidate, an **unfenced** credential (`* (any URL)`) is used, and
   `proxy` says so on stderr. An unfenced credential is never preferred over one whose
   fence covers the target.
5. **Zero** candidates, or **more than one**, is a refusal with exit code `7`. `--auto`
   never guesses.

The listing costs one request to the broker, which serves it from a 30-second
per-workspace cache -- so `--auto` adds no broker-to-server round trip. The **vend**
is still one round trip per call: that is the audit record, and it is where the target
is checked against the fence.

> **SSRF Protection:** Private IPs, loopback, and link-local addresses are blocked by the
> broker by default. For local development, start the **broker** with
> `AGTCRDN_PROXY_ALLOW_LOOPBACK=true` -- that is the process that makes this call, so it is
> the only one `proxy` needs. The **server** reads the same variable for its *own* outbound
> calls (MCP tool discovery and OAuth discovery); reaching a private upstream end to end
> therefore usually means setting it in both places. The guard is all-or-nothing -- there is
> no allow-list or CIDR exception. See
> [Granting MCP Server Access -- SSRF Protection](granting-mcp-server-access.md#ssrf-protection).

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

# With custom headers, as one JSON object
agentcordon proxy my-api GET https://api.example.com/data \
  --header "Accept: application/json" \
  --header "X-Request-Id: abc123" \
  --json

# Raw output for piping
agentcordon proxy my-api GET https://api.example.com/data --raw | jq .

# Without naming a credential: the one whose fence covers this URL
agentcordon proxy --auto GET https://api.example.com/data
```

**Default output.** The **body**, and only the body, goes to stdout, byte for byte
with nothing appended. Everything else is one line on stderr:

```
HTTP 200 · 26 B · content-type: application/json
{"login":"octocat","id":1}
```

With `--auto`, the summary line names the credential that was chosen:

```
HTTP 200 · 26 B · content-type: application/json · via github-token
{"login":"octocat","id":1}
```

`--raw` prints the same stdout with no summary line at all -- the form to pipe or
hash. `--headers` puts the status line and every response header on stdout above the
body, for a response whose headers are the point:

```
HTTP 302
location: https://example.com/moved
content-length: 0

```

`--json` is one compact object on one line. A header that arrived more than once
(`Set-Cookie`, `Link`) is an array of its values; `body` is parsed JSON when the
response's content type says JSON, and a string otherwise:

```
{"status":200,"headers":{"content-type":"application/json"},"body":{"login":"octocat","id":1}}
```

**Error output.** Errors print as `Error: <message> (<code>)`. The code tells you which
screen to go to.

Ambiguous credential name:
```
Error: multiple credentials match 'github' (ambiguous_credential)

Hint: multiple credentials match. Use one of these IDs:
  550e8400-...  github-readonly
  660f9511-...  github-admin
```

Target outside the credential's URL pattern:
```
Error: credential 'github-token' is fenced to the URL pattern https://api.github.com/*, which does not cover https://evil.example/steal. This is the credential's allowed_url_pattern, not a policy decision: widen the pattern on the credential, or use a credential that covers this target. (url_pattern_denied)
```
`url_pattern_denied` is the credential's own `allowed_url_pattern`, set at creation
(`--allowed-url-pattern`) or in the admin UI on the credential's page under **Edit ->
URL Restriction**. It is *not* a Cedar decision -- nothing under **Policies** (`/security`)
will change it.

No credential is fenced for the target (`--auto`, exit `7`):
```
Error: no credential is fenced for https://api.gitlab.com/user; run agentcordon credentials
```

More than one is (`--auto`, exit `7`):
```
Error: several credentials are fenced for https://api.github.com/repos/a/b; name one:
  gh-read  https://api.github.com/*
  gh-write  https://api.github.com/repos/*

Run: agentcordon proxy gh-read <METHOD> https://api.github.com/repos/a/b
```

Refused by Cedar policy:
```
Error: Access denied by server policy (forbidden)
```
`forbidden` is the policy engine. Look at the workspace's permissions on the credential, and
at `/policies`.

---

### `agentcordon mcp-servers`

> List MCP servers available to this workspace.

```
agentcordon mcp-servers
```

No flags. Requires the broker to be running and the workspace to be registered. Results are deduplicated by server name. Only servers this workspace is bound to *and* Cedar permits `mcp_list_tools` on are listed -- a server you cannot use is not named in the refusal either.

**Output:**
```
NAME      DESCRIPTION       TRANSPORT  TOOLS
github    GitHub MCP        http       create_issue, list_repos, search_code
slack     Slack MCP server  http       send_message, list_channels
```

The `DESCRIPTION` column shows `-` when the sync payload carries no description for that
server. Use `agentcordon mcp-tools` for what a server can actually do -- the tool list, with
each tool's own description, is the reliable signal.

---

### `agentcordon mcp-tools`

> List all available MCP tools across all servers.

```
agentcordon mcp-tools [--schema] [--server <NAME>] [--tool <NAME>]
```

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--schema` | bool | `false` | Emit the raw JSON list, including each tool's `input_schema`, instead of the text table. This is how you learn a tool's exact argument names before calling it. |
| `--server <NAME>` | string | all | With `--schema`, restrict output to one server |
| `--tool <NAME>` | string | all | With `--schema`, restrict output to one tool |

Requires the broker to be running and the workspace to be registered.

**Output:**
```
SERVER  TOOL          DESCRIPTION
github  create_issue  Create a GitHub issue
github  list_repos    List repositories
slack   send_message  Send a Slack message
```

**Output (`--schema --server github --tool create_issue`):**
```json
[
  {
    "server": "github",
    "tool": "create_issue",
    "description": "Create a GitHub issue",
    "input_schema": {
      "type": "object",
      "properties": {
        "repo":  { "type": "string" },
        "title": { "type": "string" },
        "body":  { "type": "string" }
      },
      "required": ["repo", "title"]
    }
  }
]
```

A tool's description and `input_schema` are whatever the upstream MCP server returned from
`tools/list` at discovery time. A server that publishes neither shows `-` and a `null`
schema; `--arg` still works, you just have to be told the argument names by other means.

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
| `--args-json <SRC>` | string | No | The full `tools/call.arguments` object as JSON. `SRC` may be inline JSON, `@<path>` to read a file, or `-` to read stdin. Individual `--arg` values override fields from it. |
| `--json` | bool | No | Emit the whole `tools/call` result as one compact JSON object instead of just the tool's text |

Requires the broker to be running and the workspace to be registered. The broker checks Cedar policy authorization before forwarding the call.

Run `agentcordon mcp-tools --schema --server <SERVER> --tool <TOOL>` first if you do not
know the argument names -- guessing them is the one thing this command cannot help with.

> **Argument parsing:** `--arg` values are auto-parsed as JSON types where possible. `--arg count=5` becomes `{"count": 5}`, `--arg flag=true` becomes `{"flag": true}`, `--arg name=test` becomes `{"name": "test"}`. For nested objects and arrays use `--args-json`.

**Examples:**

```bash
agentcordon mcp-call github create_issue \
  --arg repo=myorg/myrepo \
  --arg title="Bug report" \
  --arg body="Steps to reproduce..."

agentcordon mcp-call data-pipeline run_etl \
  --arg dataset=users \
  --arg limit=1000

# Structured arguments
agentcordon mcp-call data-pipeline run_etl \
  --args-json '{"dataset":"users","filters":{"since":"2026-01-01"},"columns":["id","email"]}'

# ...from a file, overriding one field
agentcordon mcp-call data-pipeline run_etl --args-json @job.json --arg limit=10
```

**Output (success).** The tool's text, and nothing else. Structured content blocks
are flattened in order: a `text` block is its text, an embedded resource is the text
inside it, and a block that carries no text (an image, a binary resource) is named --
`[image image/png]`, `[resource file:///b.bin]` -- rather than dropped.

```
Issue #42 created: https://github.com/myorg/myrepo/issues/42
```

`--json` prints the whole result instead, on one line:

```
{"content":[{"type":"text","text":"Issue #42 created: ..."}],"isError":false}
```

**Output (error).** A failed call writes the agent-facing error envelope to stdout and
one `Error: ...` line to stderr, and exits non-zero. A tool that answered with
`isError` exits `6`:

```json
{
  "error": {
    "kind": "tool_error",
    "tool": "nonexistent_tool",
    "message": "tool not found: 'nonexistent_tool'"
  }
}
```

---

## Files and Directories

### `.agentcordon/` -- Workspace State Directory

Created by `agentcordon init`. Added to `.gitignore` automatically. Directory permissions are set to `0700` on Unix.

| File | Permissions | Description |
|------|:-----------:|-------------|
| `workspace.key` | `0600` | Ed25519 private signing key (hex-encoded 32-byte seed) |
| `workspace.pub` | `0644` | Ed25519 public key (hex-encoded 32 bytes) |
| `broker.fingerprint` | `0600` | Pinned SHA-256 fingerprint of the broker's public key, written by `register` (or on first use of an older workspace); every connection compares it to `/health` and refuses on mismatch |

### `~/.agentcordon/` -- User-Level Broker State

Used by the broker daemon (`agentcordon-broker`). Located in the user's home directory.

The CLI resolves the home directory on every platform (Unix `$HOME`, macOS `$HOME`, Windows `USERPROFILE`/`HOMEDRIVE`+`HOMEPATH`). If no home directory can be resolved, commands that need `~/.agentcordon/` (including `init`, `register`, and any signed command that reads the broker port file) exit non-zero with a clear error rather than writing to a fallback path.

| File | Description |
|------|-------------|
| `broker.port` | Broker URL written by the broker on startup (`0600`; older brokers wrote a bare port), read by the CLI for auto-discovery |
| `broker.pid` | PID file (`0600`) |
| `broker.lock` | Single-instance advisory lock (`0600`), held for the life of the broker process |
| `broker.key` | P-256 keypair for the broker (`0600`) |
| `tokens.enc` | Encrypted token store (`0600`) |
| `workspaces.json` | Plaintext workspace recovery store (`0600`) |

The directory itself is created `0700`.

#### Moving it: `--data-dir` / `AGTCRDN_DATA_DIR`

`agentcordon-broker --data-dir <PATH>` (or `AGTCRDN_DATA_DIR=<PATH>`) puts all six files
above somewhere other than `~/.agentcordon`. This is the "data directory" the advisory lock
on `<data-dir>/broker.lock` is named against. Use it for a second broker on one host, a
service account with no home directory, or an XDG-tidy install.

> **The CLI does not read `AGTCRDN_DATA_DIR`.** Broker auto-discovery always reads
> `~/.agentcordon/broker.port` and nothing else. A broker started on a different data
> directory writes its port file there, where the CLI never looks, so every CLI command
> fails with exit code `2` (broker not running) until you point it at the broker yourself:
>
> ```bash
> agentcordon-broker --data-dir /srv/agentcordon --port 4241 &
> export AGTCRDN_BROKER_URL=http://127.0.0.1:4241
> agentcordon status
> ```
>
> Pinning the port with `--port` / `AGTCRDN_BROKER_PORT` is what makes that `AGTCRDN_BROKER_URL`
> knowable in advance; with the default `0` the broker picks a free port and records it only
> in the relocated `broker.port`.

---

## Credential Types and Transforms

When using `proxy` or `mcp-call`, the credential type determines how it is injected into the outgoing request. There are six types, and they are the same names `agentcordon credentials` prints and the admin UI's Type picker shows:

| Type | Injection used | HTTP Result |
|------|----------------|-------------|
| `generic` | Bearer token, unless `transform_name` says otherwise | `Authorization: Bearer <value>` |
| `aws` | AWS SigV4 | `Authorization` and `x-amz-date` headers (`x-amz-content-sha256` for S3-family services, `x-amz-security-token` when the credential carries a session token) |
| `api_key_header` | Custom header — a property of the type | `<header_name>: <value>` (from `metadata.header_name`, required at create time) |
| `api_key_query` | Query parameter — a property of the type | `?<param_name>=<value>` (from `metadata.param_name`, required at create time) |
| `oauth2_client_credentials` | Client credentials grant **on the server**, then Bearer | `Authorization: Bearer <access_token>` |
| `oauth2_user_authorization` | Refresh token exchange **on the server**, then Bearer | `Authorization: Bearer <access_token>` |

If no credential type is set, defaults to `generic`, which injects a Bearer token.

### `transform_name` -- the four names you may set

The column above is *what happens*. `transform_name` is a separate, shorter list -- the
only values the API accepts. Anything else is refused with `unknown transform_name
'<name>'; expected one of: identity, basic-auth, bearer, aws-sigv4`.

| `transform_name` | Effect |
|------------------|--------|
| `bearer` | `Authorization: Bearer <value>` — the `generic` default |
| `basic-auth` | `Authorization: Basic <base64(value)>` — store `user:password` as the secret |
| `identity` | The value is passed through untouched |
| `aws-sigv4` | AWS SigV4 — implied by the `aws` type, so you never need to name it |

**A custom header or a query parameter is not a transform.** Those come from the
`api_key_header` and `api_key_query` *types*. Set `transform_name` from the **Transform**
select on **Credentials -> Add Credential** (offered for `generic`, the one type with a
choice) or on **Edit** on the credential's page, or send `transform_name` to
`POST`/`PUT /api/v1/credentials`.
`agentcordon credentials create` does not set it.

Two of these need fields the CLI never sees, set when the credential is created in the
admin UI. They are worth knowing about because the failure shows up here, at call time:

- **`aws`** — `aws_region` and `aws_service` are optional *only* when the target host ends
  in `.amazonaws.com`, where the signer infers them from the hostname. Against a VPC
  endpoint, an S3-compatible store, LocalStack, or an API Gateway behind a custom domain,
  a credential stored without both fields fails at proxy time. Fill both in on the AWS
  credential form. See
  [Credential Encryption -- AWS](credential-encryption.md#aws).
- **`oauth2_client_credentials`** — the token endpoint must be `https://`, with the sole
  exception of the literal hosts `localhost`, `127.0.0.1` and `::1`. Any other plain-HTTP
  endpoint (a Docker service name, an internal hostname, a private IP) is refused at
  create time with `oauth2_token_endpoint must use HTTPS`. See
  [Credential Encryption -- OAuth2 Client Credentials](credential-encryption.md#oauth2-client-credentials).

---

## Authentication

The CLI uses Ed25519 request signing to authenticate with the broker. Every request (except `init` and the self-signed registration body) includes four headers:

| Header | Description |
|--------|-------------|
| `X-AC-PublicKey` | Hex-encoded Ed25519 public key |
| `X-AC-Timestamp` | Unix timestamp (seconds); must be within 30 seconds of the broker's clock |
| `X-AC-Nonce` | 16 random bytes, lowercase hex, fresh per request |
| `X-AC-Signature` | Ed25519 signature of `METHOD\nPATH_WITH_QUERY\nTIMESTAMP\nNONCE\nBODY` |

The broker verifies the signature, maps the public key to a registered workspace, and refuses a `(public key, nonce)` pair it has already accepted within the window (`401`). When the broker runs with `--shared-secret`, `X-AgentCordon-Broker-Secret` is required as well (from `AGTCRDN_BROKER_SHARED_SECRET`).

> **Breaking change:** the nonce is inside the signed bytes, and the register body gained `timestamp` and `nonce`. A CLI and broker on different sides of this change cannot communicate (`401 signature verification failed`); upgrade them together.

### Canonical `PATH_WITH_QUERY`

The signed path-and-query is canonicalised identically on the CLI and broker sides:

- Strip a single trailing `/` from the path unless the path is exactly `/`.
- If the request URL has a query string, append `?` followed by the query string verbatim -- do not re-sort or re-encode parameters.
- If there is no query string, append nothing. A bare trailing `?` is never emitted.
- Any URL fragment (`#...`) is stripped before signing.

Examples: `/foo/bar`, `/foo/bar?a=1&b=2`, `/` (root), `/?a=1` (root with query). The shapes `/foo/bar/` and `/foo/bar?` are never signed.

> **Breaking change (v0.4.0):** The signed payload was `METHOD\nPATH\nTIMESTAMP\nBODY`; it is now `METHOD\nPATH_WITH_QUERY\nTIMESTAMP\nNONCE\nBODY` — the query string is covered and a fresh per-request nonce was added. The register body gained `timestamp` and `nonce` for the same reason. There is no dual-accept window: a CLI and broker on different sides of this change cannot communicate, and the mismatched side receives `401 signature verification failed` on every signed request. Upgrade the CLI and broker together. See [Upgrading](upgrading.md#signing-format-change-v040).

### Broker Discovery

The CLI discovers the broker in this order:

1. `AGTCRDN_BROKER_URL` environment variable (if set). It must be plain `http://` to a loopback host or any `https://` URL; otherwise the CLI refuses before making a request.
2. Port file at `~/.agentcordon/broker.port` (written by the broker on startup)
3. Health check at the discovered URL (`GET /health`). The response must be `status: ok` and carry `key_fingerprint`; a broker that does not publish its key is refused with an upgrade hint.
4. Pin check: the fingerprint is compared to `.agentcordon/broker.fingerprint`. A mismatch is refused (exit code 4) with both values in the message; `agentcordon register --force` re-pins.

If neither source yields a reachable broker, the CLI exits with code 2 ("broker not running").

---

> **See also:** [Workspace Enrollment](workspace-enrollment.md) -- [Credential Encryption](credential-encryption.md) -- [System Architecture](system-architecture.md)
