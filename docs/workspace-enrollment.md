> [Home](index.md) > Workspace Enrollment

# Workspace Enrollment

A **workspace** is the identity unit for an autonomous agent or device. Enrollment is the process by which a workspace establishes its identity with the AgentCordon server using an **RFC 8628 Device Authorization Grant** flow, mediated by a local **broker** process.

---

**On this page:**
[Data Model](#workspace-data-model) | [Key Generation](#key-generation) | [Enrollment Flow](#enrollment-flow) | [Post-Enrollment Authentication](#post-enrollment-authentication) | [Client-Side State](#client-side-state) | [API Endpoints](#api-endpoints) | [Security Properties](#security-properties)

---

## Workspace Data Model

The `Workspace` struct (`crates/core/src/domain/workspace.rs`) contains:

| Field | Type | Description |
|-------|------|-------------|
| `id` | UUID | Unique workspace identifier |
| `name` | String | Human-readable name (defaults to current directory name) |
| `status` | Enum | `Pending`, `Active`, `Disabled`, or `Revoked`. The one lifecycle field: only `Active` can authenticate; `Disabled` is reversible; `Revoked` is final. The API also returns a derived `enabled` (`status == Active`). |
| `pk_hash` | Option\<String\> | SHA-256 hex digest of the raw 32-byte Ed25519 public key |
| `encryption_public_key` | Option\<String\> | P-256 JWK for ECIES credential vending |
| `owner_id` | Option\<UserId\> | Admin who approved the workspace |
| `parent_id` | Option\<WorkspaceId\> | For future sub-workspace delegation |
| `tags` | Vec\<String\> | Policy-matching tags (e.g., `"admin"`) |
| `tool_name` | Option\<String\> | Agent type (e.g., `"claude-code"`, `"cursor"`) |

---

## Key Generation

Running `agentcordon init` generates an Ed25519 keypair (`crates/cli/src/commands/init.rs`):

| Key | Algorithm | Storage | Purpose |
|-----|-----------|---------|---------|
| Signing key | Ed25519 | `.agentcordon/workspace.key` (hex seed) | Request signing (CLI-to-broker authentication) |
| Verifying key | Ed25519 | `.agentcordon/workspace.pub` (hex public key) | Signature verification, identity binding |

The `pk_hash` is computed as `SHA-256(raw_32_byte_public_key)` and printed as `sha256:{hex}`.

The `init` command also:
- Creates `.agentcordon/` with mode `0700` (Unix), adds it to `.gitignore`
- Installs the AgentCordon [Agent Skill](https://agentskills.io/specification) into the skill directory each selected agent runtime reads: always `.agents/skills/agentcordon/SKILL.md`, plus `.claude/skills/` for Claude Code and Cline and `.kiro/skills/` for Kiro. Which runtimes is asked on a terminal, taken from `--agent`, or detected; the answer is remembered in `.agentcordon/agents.toml`. See [`agentcordon init`](cli-reference.md#agentcordon-init) and [ADR-0013](adr/0013-init-installs-the-agentcordon-skill-per-runtime.md).
- **No instruction file carries the workspace identity.** It is derived from the key and would go stale on regeneration; the skill tells the agent to run `agentcordon status`.

- Registers the CLI as an **MCP server** with each selected runtime, so the same operations
  are available as native tools: `.mcp.json` for Claude Code, and the equivalent file for the
  others (`.codex/config.toml`, `opencode.json`, `.vscode/mcp.json`, `.cursor/mcp.json`, and
  so on). Every entry spawns the same thing — `agentcordon mcp-serve`, by bare name, so the
  file stays portable across machines. A structured file that already exists is left alone
  unless it parses and has no `agentcordon` key; where a runtime only takes a user-level
  registration, `init` prints the command instead of writing anything.
  `--no-mcp` skips this and installs the skill only.

The two surfaces are the same operations and the same permissions
([ADR-0014](adr/0014-mcp-server-surface-is-the-cli-over-stdio.md)). The skill costs nothing
until an agent triggers it and then one shell turn per call; the MCP registration costs a
fixed set of tool schemas in every session and then a native call with no shell round trip.
Having both installed is the default because different runtimes prefer different ones.

> **Note:** The keypair is generated once and reused across subsequent registrations. Running `init` again is idempotent.

---

## Enrollment Flow

There is **one** enrollment method: the RFC 8628 device authorization grant, with the local
broker mediating between the CLI and the server. It works for a headless host, a container
and a remote SSH session alike, because approval happens in a browser that need not be on
the same machine as the CLI.

Two commands start it, and they run the same code:

| Command | When |
|---|---|
| `agentcordon init` | Setting a project up. The last thing `init` does, after the keypair and the skill, is enroll. `--no-register` skips it. |
| `agentcordon register` | Re-enrolling: after a server-side workspace deletion (`--force`), to change the requested scopes, or for a workspace set up with `--no-register`. |

Neither needs `--server-url` on a machine whose installer recorded one; see
[the precedence](cli-reference.md#the-server-url-and-where-it-comes-from). The approval
screens are the same either way.

> **Prerequisite: `AGTCRDN_BASE_URL`.** The activation URL the CLI prints
> (`verification_uri`) is `AGTCRDN_BASE_URL` + `/activate`. When that variable is unset the
> server falls back to `http://` + its listen address, so the shipped container prints
> `http://0.0.0.0:3140/activate` and enrollment stalls at a URL no browser can open. Set
> `AGTCRDN_BASE_URL` on the server to the URL users actually reach it on, then restart.
> (If you hit this before reading it: the `/activate` page accepts `?user_code=<code>` on
> any origin that reaches the server, so opening
> `https://<your real server URL>/activate?user_code=<the printed code>` completes the
> approval.)

### Interactive Registration (RFC 8628 Device Flow)

This implements the [RFC 8628 Device Authorization Grant](https://datatracker.ietf.org/doc/html/rfc8628).

```
  CLI                       Broker                    Server                   Admin (Browser)
  ───                       ──────                    ──────                   ───────────────
  1. Sign:
     workspace_name \n
     public_key \n scopes \n
     timestamp \n nonce
     POST /register
     {workspace_name,
      public_key, scopes,
      timestamp, nonce,
      signature}
                  ────────────►
  2.              Verify Ed25519
                  self-signature,
                  timestamp skew (30s),
                  nonce not replayed.
                  Compute pk_hash =
                  SHA-256(public_key).
                  POST /api/v1/oauth/
                  device/code
                  {client_id, scope,
                   workspace_name,
                   public_key_hash}
                                    ────────────►
  3.                                Generate device_code
                                    + user_code (EFF
                                    wordlist, 4 words).
                                    Store device_code_hash
                                    + pk_hash_prefill.
                                    Return device_code,
                                    user_code,
                                    verification_uri,
                                    expires_in, interval.
                                  ◄────────────
  4.              Store pending entry
                  {device_code, pk_hash}.
                  Spawn background poll
                  task.
                  Return user_code +
                  verification_uri
                  to CLI. (device_code
                  NEVER leaves broker.)
  ◄──────────────
  5. Print:
     "Copy your one-time
      code: {user_code}"
     Open browser to
     /activate?user_code=
     {user_code}
                                                                ────────────►
  6.                                                             Open /activate
                                                                 Enter user_code
                                                                 Click "Approve"
                                                                 POST /api/v1/oauth/
                                                                 device/approve
                                                                 {user_code,
                                                                  public_key_hash}
                                                               ◄────────────
  7.                                Verify Cedar policy:
                                    MANAGE_WORKSPACES.
                                    Verify pk_hash matches
                                    pk_hash_prefill.
                                    CAS-flip row to Approved.
                                    Create workspace record
                                    (status=Active).
                                    Create per-workspace
                                    OAuth client.
                                  ◄──────────────────────────────────────────
  8.              Background poll:
                  POST /api/v1/oauth/
                  token {grant_type=
                  urn:ietf:params:oauth:
                  grant-type:device_code,
                  device_code, client_id}
                                    ────────────►
  9.                                 CAS-consume device_code.
                                    Issue access_token +
                                    refresh_token against
                                    workspace OAuth client.
                                  ◄────────────
  10.             Store workspace state:
                  {access_token,
                   refresh_token,
                   scopes, expiry}.
                  Persist to encrypted
                  token store.
  ◄──────────────
  11. Poll GET /status.
      Broker returns
      {registered: true,
       scopes: [...]}.
      Print "Logged in as
      {workspace_name}."
```

**UX:** The CLI mirrors the `gh auth login` experience -- it prints the one-time code, waits for Enter, opens the browser to the `/activate` page, then polls the broker's `/status` endpoint until the background device-code poll task reports success or failure.

**User code format:** 4 words from a curated 256-word EFF-style wordlist, giving approximately 32 bits of entropy. Combined with a configurable TTL (default 600 seconds) and per-IP rate limiting on `/activate`, this meets the v0.3.0 threat model.

**Re-registration:** If a pending entry already exists for the same `pk_hash`, it is replaced. If an approved workspace already exists, a new device flow is initiated and the server replaces the owning user on approval.

### The approval screens

Two pages carry the human half of enrollment.

**`/activate`** -- the approval screen, reached from the link the CLI prints. It is titled
**Activate a new device** and shows, above the form: the workspace being authorized, the
device key as `sha256:<hash>`, and -- when that key is already registered -- a warning that
approving re-registers the existing workspace rather than creating a new one. The form is
one **Activation code** field (prefilled and skipped past when the link carried
`?user_code=`), the list of permissions the workspace is asking for, and two buttons,
**Deny** and **Approve**. Approving lands on `/activate/success`; denying lands on
`/activate/denied`, and an expired code on `/activate/expired`.

**`/register`** -- reached from **Register Workspace** in the header of the Workspaces page,
or from *Register a workspace* in the dashboard's first-run checklist. It is instructions,
not a form: *Register a New Workspace* carries the install and `agentcordon register`
commands on Linux / macOS / Windows tabs. When the CLI sends a fingerprint in the URL, the
page also shows *Approve Workspace Registration* -- the fingerprint to check against what the
CLI printed, and an **Approve Registration** button.

Once a workspace exists, its page at `/workspaces/{id}` is where its lifecycle is managed:
**Disable** is a button in the page header (reversible), and **Revoke** and **Delete** --
both final -- are in the header's overflow menu (the **&hellip;** button). Its **Access** tab
lists the MCP servers the workspace can reach and the consent grants it holds; **History**
lists its audit events.

---

### Headless and CI/CD environments

There is no pre-shared-token enrollment path. Earlier documentation described a
`POST /api/v1/workspaces/provision` flow and an `agentcordon init --server --token` form;
neither route was ever registered, `init` has no such flags, and migration 020 drops the
`provisioning_tokens` table the design would have used.

The device flow covers the headless case as it stands: the CLI can run anywhere, and the
4-word code is approved in a browser by a human with the `manage_workspaces` permission.
For an unattended pipeline, enroll the workspace once by hand — the keypair in
`.agentcordon/` and the broker's token store both survive restarts, and the refresh grant
keeps the access token current without further human involvement. A pipeline that only
needs the workspace *set up* (the keypair and the skill, no enrollment) runs
`agentcordon init --no-register`; `init` never prompts off a terminal, but the device flow
is not a prompt, so `--no-register` is what stops it.

### First-Run Onboarding

One command, from the project directory:

```bash
agentcordon init
```

It generates the keypair, installs the AgentCordon skill for the runtimes you use, registers
`agentcordon mcp-serve` with the ones that read an MCP config, and then enrolls: it starts a broker if none is running, prints the four-word code and the activation
URL, and polls until you approve. It ends on two lines:

```
Registered as my-project at https://agentcordon.example.com.
Try: agentcordon credentials
```

A rerun on an enrolled workspace says so in one line and starts no second device flow.

The server URL comes from `--server-url`, then `AGTCRDN_SERVER_URL`, then
`server_url` in `~/.agentcordon/config.toml` — which your server's installer wrote, so on a
machine set up that way nothing has to be typed. If none of the three is set, `init` says
so and names all of them. When a server URL is known and no broker is running, a local
broker is auto-started pointed at it. The requested scopes default to
`credentials:discover`, `credentials:vend`, `mcp:discover`, and `mcp:invoke`.

`--name` sets the workspace's display name; without it the name is the current directory's
basename. Names are **not** unique — two workspaces may share one as long as their keypairs
differ, and the device-code exchange binds the token to the approved public-key hash rather
than to the name.

### Re-enrolling

`agentcordon register` is unchanged and is what you run to enroll a workspace again:
`--force` clears a stale broker registration (and re-pins the broker key) after the
server-side workspace was deleted; `--scope` asks for a different set of scopes. It takes
the same server-URL precedence and prints the same code, link and expiry, because it is the
same flow.

---

## Post-Enrollment Authentication

After enrollment, the workspace authenticates to the **server** using **OAuth 2.0 Bearer tokens** (opaque access tokens issued during the device flow).

The `AuthenticatedOAuthWorkspace` extractor (`crates/server/src/extractors/oauth.rs`) validates incoming workspace requests:

1. Extract Bearer token from `Authorization` header
2. SHA-256 hash the token
3. Look up `oauth_access_tokens` by hash
4. Verify token is not revoked and not expired
5. Resolve the client and the workspace the token is bound to by id in one store call
6. Verify the client is not revoked and `workspace.status == Active`
7. Return authenticated workspace entity with user_id and scopes

**Token lifetimes:**
- Access token: 15 minutes
- Refresh token: 30 days (with rotation)

The **broker** mediates between the CLI and server. CLI-to-broker requests use Ed25519 request signatures (`crates/broker/src/auth.rs`):

1. CLI signs `METHOD\nPATH_WITH_QUERY\nTIMESTAMP\nNONCE\nBODY` with the workspace Ed25519 key. `PATH_WITH_QUERY` is canonicalised: a single trailing `/` is stripped from the path (unless the path is `/`), the query string is appended verbatim after `?` when present, and any URL fragment is dropped. `NONCE` is 16 random bytes as lowercase hex, fresh per request. See [CLI Reference -- Authentication](cli-reference.md#authentication) for examples.
2. Sends public key, timestamp, nonce, and signature in request headers (`X-AC-PublicKey`, `X-AC-Timestamp`, `X-AC-Nonce`, `X-AC-Signature`)
3. Broker verifies the Ed25519 signature, checks timestamp skew (max 30 seconds), and refuses a `(public key, nonce)` pair it has already accepted within the window (a bounded seen-set; entries live for 60 seconds, oldest evicted at capacity). A replayed request gets `401`.
4. Broker forwards the request to the server using the stored OAuth access token

The register body carries the same protection: `NAME\nPUBLIC_KEY\nSCOPES\nTIMESTAMP\nNONCE` is signed, and the broker applies the same skew window and seen-set before asking the server for a device code.

**Broker key pinning.** The broker publishes its P-256 public key on `GET /health` (`encryption_public_key`, base64url of the uncompressed SEC1 point, and `key_fingerprint`, its SHA-256 as hex). Enrolling — from either `agentcordon init` or `agentcordon register` — pins the fingerprint in `.agentcordon/broker.fingerprint` (mode `0600`, next to the workspace key). Every later CLI connection compares the live fingerprint to the pin and refuses on mismatch with a message naming both values; `agentcordon register --force` re-pins. A workspace enrolled before pinning existed has its pin written on first successful use, with a one-line notice on stderr.

---

## Client-Side State

After enrollment, state is stored in three locations:

### CLI Workspace Directory (`.agentcordon/`)

| File | Contents |
|------|----------|
| `workspace.key` | Ed25519 private key seed (hex, mode 0600) |
| `workspace.pub` | Ed25519 public key (hex, mode 0644) |
| `broker.fingerprint` | The pinned broker key (hex, mode 0600) |
| `agents.toml` | The agent runtimes `init` installed the skill and the MCP registration for |

### CLI User Config (`~/.agentcordon/config.toml`)

Written by `install.sh` / `install.ps1`, not by the CLI. One key, `server_url`, holding the
origin the installer was fetched from; it is the last of the three
[server-URL sources](cli-reference.md#the-server-url-and-where-it-comes-from), and it is
what makes `agentcordon init` need no `--server-url`. It is **not** moved by
`AGTCRDN_DATA_DIR` — the CLI does not read that variable.

### Broker Token Store

The broker persists OAuth tokens in an **AES-256-GCM encrypted token store** (`~/.agentcordon/tokens.enc`; the directory moves with `--data-dir` / `AGTCRDN_DATA_DIR`). Per-workspace state includes:

| Field | Description |
|-------|-------------|
| `client_id` | OAuth client ID (bootstrap or per-workspace) |
| `access_token` | Current OAuth access token |
| `refresh_token` | OAuth refresh token for token rotation |
| `scopes` | Granted OAuth scopes |
| `token_expires_at` | Access token expiry timestamp |
| `workspace_name` | Human-readable workspace name |
| `token_status` | `Valid`, `Expired`, or `Refreshing` |

> **Note:** The `.agentcordon/` directory is automatically added to `.gitignore`. The broker's token store is a separate encrypted file, not inside `.agentcordon/`.

#### Relocating the broker's data directory

`agentcordon-broker --data-dir <PATH>`, or `AGTCRDN_DATA_DIR=<PATH>`, moves the whole
user-level broker directory -- `broker.key`, `tokens.enc`, `workspaces.json`, `broker.port`,
`broker.pid` and `broker.lock` -- off `~/.agentcordon`. Needed for a second broker on one
host, a service account with no home directory, or an XDG-tidy install.

> **The CLI does not read `AGTCRDN_DATA_DIR`.** It resolves the broker by reading
> `~/.agentcordon/broker.port` and nothing else. A relocated broker writes its port file
> into the new directory, so auto-discovery cannot see it and every CLI command exits `2`
> ("broker not running") until you set `AGTCRDN_BROKER_URL`:
>
> ```bash
> agentcordon-broker --data-dir /srv/agentcordon --port 4241 --server-url https://agentcordon.example.com &
> export AGTCRDN_BROKER_URL=http://127.0.0.1:4241
> agentcordon register --name my-workspace
> ```
>
> Pin the port with `--port` / `AGTCRDN_BROKER_PORT` so the URL is knowable up front; the
> default `0` picks a free port and records it only in the relocated `broker.port`.

---

## API Endpoints

### Server Endpoints (port 3140)

| Method | Path | Auth | Purpose |
|--------|------|:----:|---------|
| POST | `/api/v1/oauth/device/code` | -- | Initiate RFC 8628 device authorization |
| POST | `/api/v1/oauth/device/approve` | Session | Admin approves device authorization by `user_code` |
| POST | `/api/v1/oauth/device/deny` | Session | Admin denies device authorization by `user_code` |
| POST | `/api/v1/oauth/token` | -- | Exchange device_code for access + refresh tokens |
| GET | `/activate` | -- | User-facing device activation page (accepts `?user_code=`) |
| POST | `/activate` | Session | Browser form approval, same effect as `/oauth/device/approve` |
| GET | `/api/v1/workspaces` | Session | List workspaces |
| GET | `/api/v1/workspaces/{id}` | Session | Workspace detail |
| PUT | `/api/v1/workspaces/{id}` | Session | Update, including `{"enabled": false}` to disable and `{"enabled": true}` to re-enable |
| POST | `/api/v1/workspaces/{id}/revoke` | Session | **Final.** Sets `status = revoked` and, in one transaction, revokes the workspace's OAuth clients and every access and refresh token issued to them |
| DELETE | `/api/v1/workspaces/{id}` | Session | Delete the workspace record |

### Broker Endpoints (auto-selected port on `127.0.0.1`)

The broker binds `127.0.0.1` on a port the OS picks (`AGTCRDN_BROKER_PORT` defaults to `0`)
and writes the URL to `~/.agentcordon/broker.port`. The CLI reads that file; there is no
default port to configure. `AGTCRDN_BROKER_URL` overrides discovery and is needed only when
the CLI cannot see that file — a different container, a different host.


| Method | Path | Auth | Purpose |
|--------|------|:----:|---------|
| POST | `/register` | -- | CLI initiates device flow (self-signed request) |
| GET | `/status` | Ed25519 sig | Check registration/token status |
| POST | `/deregister` | Ed25519 sig | Clear broker registration |
| GET | `/health` | -- | Broker health check |

---

## Security Properties

- **RFC 8628 device flow** -- the opaque `device_code` never leaves the broker; only the short `user_code` is shown to the user
- **Ed25519 signature binding** -- the CLI self-signs the registration request with its Ed25519 key; the broker verifies before forwarding to the server
- **pk_hash binding** -- the workspace's public key hash is bound to the device code at issue time and re-verified on approval, preventing approval hijacking
- **CAS (compare-and-swap) state transitions** -- device code approval and token exchange use atomic CAS operations, preventing double-approve and double-consume races
- **Cedar policy gate** -- device approval requires the `MANAGE_WORKSPACES` Cedar permission; no implicit grants
- **Opaque tokens** -- access and refresh tokens are opaque (256-bit, base64url); only SHA-256 hashes are persisted in the database
- **Token rotation** -- refresh token use issues a new access + refresh token pair and revokes the old pair
- **Encrypted token store** -- the broker encrypts persisted OAuth tokens with AES-256-GCM
- **Rate limiting** -- per-IP rate limiting on the `/activate` endpoint and device approve/deny endpoints
- **Timestamp skew and nonce** -- CLI-to-broker Ed25519 signatures (and the register body) carry a timestamp checked to a 30-second window and a per-request nonce the broker remembers for the window; a replay within the window is refused with `401`
- **Pinned broker key** -- the CLI pins the broker's key fingerprint at `register` and refuses a broker whose key differs
- **Broker edge** -- `AGTCRDN_BROKER_URL` must be loopback or `https://`; a non-loopback broker bind is refused unless `--tls-cert/--tls-key` or `--shared-secret` is configured; one broker per data directory (`broker.lock`); every broker artifact is created owner-only (`0700` directory, `0600` files)
- **Hard deadline** -- the broker's background poll task enforces a 15-minute hard cap, independent of server TTL

---

> **See also:** [Master Key](master-key.md) | [Credential Encryption](credential-encryption.md) | [CLI Reference](cli-reference.md)
