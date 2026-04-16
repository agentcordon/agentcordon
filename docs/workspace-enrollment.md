> [Home](index.md) > Workspace Enrollment

# Workspace Enrollment

A **workspace** is the identity unit for an autonomous agent or device. Enrollment is the process by which a workspace establishes its identity with the AgentCordon server using an **RFC 8628 Device Authorization Grant** flow, mediated by a local **broker** process.

---

**On this page:**
[Data Model](#workspace-data-model) | [Key Generation](#key-generation) | [Enrollment Flows](#enrollment-flows) | [Post-Enrollment Authentication](#post-enrollment-authentication) | [Client-Side State](#client-side-state) | [API Endpoints](#api-endpoints) | [Security Properties](#security-properties)

---

## Workspace Data Model

The `Workspace` struct (`crates/core/src/domain/workspace.rs`) contains:

| Field | Type | Description |
|-------|------|-------------|
| `id` | UUID | Unique workspace identifier |
| `name` | String | Human-readable name (defaults to current directory name) |
| `status` | Enum | `Pending`, `Active`, or `Revoked` |
| `enabled` | bool | Whether the workspace can authenticate |
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
- Generates agent instruction files (`AGENTS.md`, `CLAUDE.md`, etc.) with the workspace identity
- Ensures `.mcp.json` contains an `agentcordon` MCP server entry

> **Note:** The keypair is generated once and reused across subsequent registrations. Running `init` again is idempotent.

---

## Enrollment Flows

AgentCordon supports **two enrollment methods** depending on your environment.

### Flow 1: Interactive Registration (RFC 8628 Device Flow)

The standard enrollment for human-supervised agents. This implements the [RFC 8628 Device Authorization Grant](https://datatracker.ietf.org/doc/html/rfc8628), with the local broker mediating between the CLI and the server.

```
  CLI                       Broker                    Server                   Admin (Browser)
  ───                       ──────                    ──────                   ───────────────
  1. Sign:
     workspace_name \n
     public_key \n scopes
     POST /register
     {workspace_name,
      public_key, scopes,
      signature}
                  ────────────►
  2.              Verify Ed25519
                  self-signature.
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

---

### Flow 2: Provisioning Token (CI/CD)

For automated environments where browser approval is impractical.

> **Tip:** Use this flow for CI/CD pipelines, headless servers, and automated agent deployments.

**Step 1 -- Admin creates token:**

```bash
POST /api/v1/workspaces/provision   # requires user auth
```

Server generates 32-byte random token, stores `SHA256(token)` with **1-hour TTL**, and returns:

```
AGENTCORDON_PROVISION_TOKEN={token}
```

**Step 2 -- Agent uses token:**

```bash
agentcordon init --server {url} --token {token}
```

CLI sends token + Ed25519 public key to `POST /api/v1/workspaces/provision/complete`. Server validates token hash, checks expiry, marks token as **used (single-use)**, and creates workspace.

---

### One-Command Setup

The `agentcordon setup <server_url>` command (`crates/cli/src/commands/setup.rs`) wraps the full onboarding sequence:

1. Discover or start the broker daemon (default port 9876)
2. Run `agentcordon init` (idempotent keypair generation)
3. Run `agentcordon register` with default scopes (`credentials:discover`, `credentials:vend`, `mcp:discover`, `mcp:invoke`)

---

## Post-Enrollment Authentication

After enrollment, the workspace authenticates to the **server** using **OAuth 2.0 Bearer tokens** (opaque access tokens issued during the device flow).

The `AuthenticatedOAuthWorkspace` extractor (`crates/server/src/extractors/oauth.rs`) validates incoming workspace requests:

1. Extract Bearer token from `Authorization` header
2. SHA-256 hash the token
3. Look up `oauth_access_tokens` by hash
4. Verify token is not revoked and not expired
5. Load the OAuth client to find the associated workspace (via `public_key_hash`)
6. Verify `workspace.enabled == true` and `status == Active`
7. Return authenticated workspace entity with user_id and scopes

**Token lifetimes:**
- Access token: 15 minutes
- Refresh token: 30 days (with rotation)

The **broker** mediates between the CLI and server. CLI-to-broker requests use Ed25519 request signatures (`crates/broker/src/auth.rs`):

1. CLI signs `method | path | timestamp | body` with workspace Ed25519 key
2. Sends public key, timestamp, and signature in request headers
3. Broker verifies Ed25519 signature and checks timestamp skew (max 30 seconds)
4. Broker forwards the request to the server using the stored OAuth access token

---

## Client-Side State

After enrollment, state is stored in two locations:

### CLI Workspace Directory (`.agentcordon/`)

| File | Contents |
|------|----------|
| `workspace.key` | Ed25519 private key seed (hex, mode 0600) |
| `workspace.pub` | Ed25519 public key (hex, mode 0644) |

### Broker Token Store

The broker persists OAuth tokens in an **AES-256-GCM encrypted token store** (path configurable via `--token-store`). Per-workspace state includes:

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

---

## API Endpoints

### Server Endpoints (port 3140)

| Method | Path | Auth | Purpose |
|--------|------|:----:|---------|
| POST | `/api/v1/oauth/device/code` | -- | Initiate RFC 8628 device authorization |
| POST | `/api/v1/oauth/device/approve` | Session | Admin approves device authorization by `user_code` |
| POST | `/api/v1/oauth/device/deny` | Session | Admin denies device authorization by `user_code` |
| POST | `/api/v1/oauth/token` | -- | Exchange device_code for access + refresh tokens |
| GET | `/activate` | -- | User-facing device activation page |
| POST | `/api/v1/workspaces/provision` | Session | Create CI/CD provisioning token |
| POST | `/api/v1/workspaces/provision/complete` | -- | Complete CI/CD provisioning |

### Broker Endpoints (default port 9876)

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
- **Timestamp skew** -- CLI-to-broker Ed25519 signatures enforce max 30-second tolerance, preventing replay
- **Hard deadline** -- the broker's background poll task enforces a 15-minute hard cap, independent of server TTL

---

> **See also:** [Master Key](master-key.md) | [Credential Encryption](credential-encryption.md) | [CLI Reference](cli-reference.md)
