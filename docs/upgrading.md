> [Home](index.md) > Upgrading

# Upgrading

How to update the AgentCordon server and CLI client to a new version. Both components are designed for **zero-downtime upgrades** -- migrations run automatically, secrets persist, and clients reconnect transparently.

---

**On this page:**
[What Persists](#what-persists-across-upgrades) | [Server Upgrade](#upgrading-the-server) | [Database Migrations](#database-migrations) | [CLI Upgrade](#upgrading-the-cli-client) | [Client Compatibility](#client-compatibility) | [Upgrading from 0.3.x](#upgrading-from-03x) | [Pre-Upgrade Checklist](#pre-upgrade-checklist) | [Post-Upgrade Verification](#post-upgrade-verification) | [Upgrade Scenarios](#upgrade-scenarios)

---

## What Persists Across Upgrades

| Data | Location | Persists? |
|------|----------|:---------:|
| Database (SQLite) | `/data/agent-cordon.db` | Yes |
| Master secret | `/data/.secret` (sibling of DB file) | Yes |
| Root password | `/data/.root_password` (Docker entrypoint) | Yes |
| Cedar policies | `policies` table in database | Yes |
| Credentials (encrypted) | `credentials` table in database | Yes |
| Workspaces & enrollments | `workspaces` table in database | Yes |
| Audit log | `audit_events` table in database | Yes |
| Environment config | `.env` file or env vars | Yes (you manage this) |

> [!CAUTION]
> The `/data` volume is the single source of truth. **Never delete this volume during an upgrade.**

---

## Upgrading the Server

### Docker Compose (Recommended)

This is the standard upgrade path. Migrations run automatically on startup.

```bash
# 1. Pull the latest image
docker compose pull

# 2. Restart the container
docker compose up -d

# 3. Verify health
docker compose ps
curl http://localhost:3140/health
```

The server startup sequence is:

1. Load configuration from environment variables
2. Initialize tracing/logging
3. Resolve the master secret (env var `AGTCRDN_MASTER_SECRET` > persisted `.secret` file next to the database > auto-generate and persist)
4. Derive cryptographic keys (the AES-256-GCM key ring and the session hash key; no signing keypair is derived -- the ES256 JWT issuer is gone)
5. Open the database and run any pending migrations automatically
6. Seed the default Cedar policy if the `policies` table is empty (first boot only -- skipped on upgrades)
7. Load all enabled policies into the Cedar engine
8. Bootstrap the root user if no users exist (first boot only -- skipped on upgrades)
9. Begin accepting connections

The Docker entrypoint (`docker-entrypoint.sh`) handles root password persistence separately: it reads `AGTCRDN_ROOT_PASSWORD` from env, falls back to `/data/.root_password`, or auto-generates and persists a new one. The master secret is handled entirely by the Rust server binary.

> [!TIP]
> To pin a specific version instead of `latest`:
> ```bash
> # Edit docker-compose.yml or use an override
> # image: ghcr.io/agentcordon/agentcordon:v0.3.0
> docker compose pull
> docker compose up -d
> ```

#### Rollback

If something goes wrong, roll back to the previous image:

```bash
docker compose down
# Edit docker-compose.yml to pin the previous version tag
docker compose up -d
```

> [!WARNING]
> If the new version ran migrations that the old version doesn't understand, the old version may fail to start. **Always back up `/data` before upgrading.**

---

### Binary (Manual)

If you run the server binary directly (without Docker):

```bash
# 1. Download the new binary
curl -fsSL https://github.com/agentcordon/agentcordon/releases/latest/download/agent-cordon-server-x86_64-unknown-linux-gnu \
  -o /usr/local/bin/agent-cordon-server.new

chmod +x /usr/local/bin/agent-cordon-server.new

# 2. Stop the current server
systemctl stop agentcordon  # or kill the process

# 3. Replace the binary
mv /usr/local/bin/agent-cordon-server.new /usr/local/bin/agent-cordon-server

# 4. Start the server
systemctl start agentcordon

# 5. Verify
curl http://localhost:3140/health
```

Migrations run automatically on startup -- no manual migration step is needed.

### Notable migrations in this release

| Version | What it does | What to know |
|---------|--------------|--------------|
| 016 | Adds `workspace_id` to OAuth clients, access tokens, and refresh tokens, backfilled through the key hash each row was issued against. | A client whose key hash matches no workspace stays unbound and cannot authenticate, as before. Tokens now follow their workspace even if its key hash changes. |
| 017 | Folds the `enabled` flag into `status`: switched-off workspaces become `disabled`. | The `enabled` column is kept in step for older readers; the API still returns `enabled` (true only when `active`). Revoked workspaces cannot be re-enabled. |
| 018 | Indexes `credentials.name`. | None. |
| 019 | Rebuilds `credential_secret_history` so `key_version` exists on every install, backfilled to 1. | Runs with foreign keys off around the rebuild. After upgrading, `key_version` means "which master key sealed this row"; see `docs/master-key.md` for the new rotation procedure and the `AGTCRDN_MASTER_KEY_VERSION` / `AGTCRDN_PREVIOUS_MASTER_SECRET` variables. |
| 020 | Drops `workspace_used_jtis`, `workspace_registrations`, `provisioning_tokens`, and `crypto_state`. | Rows in those tables are discarded; nothing read them. |

Also on first start after this upgrade:

- The server takes an advisory lock on `<db path>.lock` and refuses to start a second instance against the same database. Set `AGTCRDN_REPLICA_MODE=unsafe-shared` only if you knowingly run replicas.
- If `AGTCRDN_MASTER_SECRET` is a short or low-entropy passphrase, the server keeps deriving the key exactly as before (your data stays readable) and logs a warning. Rotate to a strong secret through the key-ring procedure in `docs/master-key.md`; a fresh install with a weak secret is stretched with Argon2id and a persisted `.master-salt` instead.


---

## Database Migrations

### How They Work

Migrations are **automatic, idempotent, and forward-only**. On every
startup, the server:

1. Creates the `schema_migrations` table if it does not exist
2. Queries which migration versions have already been applied
3. Runs any unapplied migrations in order
4. Each migration is wrapped in a savepoint for safe rollback **on failure during application**
5. Records the migration version and `applied_at` timestamp in `schema_migrations`

> [!NOTE]
> AgentCordon is **forward-only** — no `down` scripts ship with the
> project. Rolling back to a previous server version after a new
> migration has already applied is done by restoring the database
> backup you took in the pre-upgrade checklist, not by running a
> reverse migration. The savepoint in step 4 covers in-migration
> failure (the migration aborts cleanly); it does not give you a
> path to un-apply a migration that has already committed. Plan
> upgrades around your backup, not around a down-migration that does
> not exist.

### Migration Sequence

Migrations use sequential numeric versions. Each entry in the `MIGRATIONS` array is `(version, sql)`:

```
migrations/
  001_init.sql                                  # Baseline schema (all core tables)
  002_mcp_oauth_states.sql                      # MCP OAuth2 authorization state tracking
  003_mcp_oauth_apps.sql                        # MCP OAuth app configurations (per-template)
  004_mcp_user_ownership.sql                    # Add user ownership to MCP servers
  005_oauth_provider_clients.sql                # Rename mcp_oauth_apps -> oauth_provider_clients, restructure by authorization_server_url
  006_device_codes.sql                          # RFC 8628 device authorization grant + bootstrap client seed
  007_credential_name_unique.sql                # No-op (originally a UNIQUE INDEX on credentials.name; see below)
  008_bootstrap_client_mcp_discover_scope.sql   # Add mcp:discover to bootstrap client's allowed_scopes
  009_device_code_pk_hash.sql                   # Bind workspace public_key_hash at device_code issue time
  010_mcp_server_workspaces.sql                 # M:N junction — one MCP can be bound to many workspaces owned by the same user
  011_drop_credential_name_unique.sql           # Drop the 007 index on databases that applied it
  012_relax_mcp_servers_workspace_id.sql        # Make mcp_servers.workspace_id nullable (table rebuild, foreign keys off)
  013_restore_mcp_server_workspace_bindings.sql # Repair bindings lost by the original 012
  014_user_oidc_identities.sql                  # (provider, subject) → user links for OIDC login
  015_refresh_token_families.sql                # family_id on refresh tokens for reuse detection
  016_oauth_workspace_id.sql                    # workspace_id on OAuth clients and tokens, backfilled via key hash
  017_workspace_status_disabled.sql             # fold `enabled` into `status`
  018_credential_name_index.sql                 # index credentials.name
  019_secret_history_key_version.sql            # key_version on credential_secret_history (table rebuild, foreign keys off)
  020_drop_dead_tables.sql                      # drop workspace_used_jtis, workspace_registrations, provisioning_tokens, crypto_state
```

A migration whose first line is `-- migration-mode: foreign_keys_off` rebuilds a table. The runner applies it with foreign-key enforcement disabled, in one transaction, runs `PRAGMA foreign_key_check` before committing, and re-enables enforcement. Without this, `DROP TABLE` on a parent cascades into every child table.

### Migration Details (v0.3.0)

**007 -- No-op.** This migration originally added a `UNIQUE INDEX` on `credentials(name)` and failed at startup on any database that already held two credentials with the same name. Credential names are not unique by design (011 dropped the index), so 007 is now empty. Version 7 stays in the sequence for databases that recorded it. No pre-upgrade check is needed.

**008 -- Bootstrap client mcp:discover scope.** The bootstrap client (`agentcordon-broker`) seeded by migration 006 was missing the `mcp:discover` scope. Without it, the broker's device authorization grant request was rejected with `400 invalid_scope`. This migration updates `allowed_scopes` to include `credentials:discover,credentials:vend,mcp:discover,mcp:invoke`.

**009 -- Device code pk_hash binding.** Adds a `pk_hash_prefill` column to `device_codes` for defense-in-depth: the broker sends its public key hash when requesting a device code, and the approver must present a matching hash. Prevents a malicious approver from attaching a different signing identity.

**010 -- `mcp_server_workspaces` junction.** Introduces an M:N
relationship between MCP servers and workspaces so a single MCP record
can be bound to multiple workspaces owned by the same user. The
migration creates
`mcp_server_workspaces(mcp_server_id, workspace_id, created_at, created_by_user)`
with a composite primary key on `(mcp_server_id, workspace_id)` and
`ON DELETE CASCADE` from both parent tables, and **backfills one row
per existing MCP** using its current `mcp_servers.workspace_id`. After
the migration runs, every previously-provisioned MCP has exactly one
junction row that reproduces the old 1:1 binding — so broker
`mcp_sync` output, Cedar policy evaluation, and CLI behavior are
unchanged on upgrade. No operator action is required.

`mcp_servers.workspace_id` is retained as an **immutable audit
anchor** — the workspace the MCP was first provisioned for. It is set
once at provision time and never mutated afterwards (not by share, not
by unshare, not even by unsharing the original workspace while others
remain bound). It is no longer the routing key; current bindings live
in the junction.

New endpoints manage bindings post-install:

- `POST /api/v1/mcp-servers/{id}/workspaces` — add bindings (owner-
  only; cross-user bind is rejected at the handler with 403).
- `DELETE /api/v1/mcp-servers/{id}/workspaces/{workspace_id}` — remove
  a binding. **Last-binding rule:** if the deletion would leave the
  MCP with zero bindings, the call returns **409 Conflict** with
  `{"error":{"code":"conflict","message":"cannot remove last workspace
  binding — delete the MCP server instead"}}` and no row is removed.
  Admins are subject to the same rule — it is a state invariant. To
  remove the final workspace, delete the MCP record itself
  (`DELETE /api/v1/mcp-servers/{id}`), which cascades the junction and
  its grant/deny policies. Scripts that automate unshare should
  anticipate the 409 and call the delete endpoint in that case.

Unshare is **eventually consistent**: the target workspace's broker
keeps the MCP in its local cache until its next `mcp_sync` tick (~30
s). For immediate revocation, disable the MCP
(`PUT /api/v1/mcp-servers/{id}` with `enabled=false`) or delete it;
Cedar policy 3a's `resource.enabled` guard short-circuits disabled
MCPs even before the broker cache refreshes.

**Rollback caveat.** Per the forward-only migration policy above,
rolling back past 010 is done by restoring a pre-upgrade database
backup — there is no down migration. If you instead roll the binary
back without restoring the DB, the older server will read
`mcp_servers.workspace_id` directly and honor only that original
binding; any additional bindings you created are silently inert (the
junction table persists but the old binary does not query it). No data
is lost; re-upgrading restores the full binding set.

### Backup Before Upgrading

```bash
cp /data/agent-cordon.db /data/agent-cordon.db.backup-$(date +%Y%m%d)
```

---

## Upgrading the CLI Client

The CLI client (`agentcordon`) is a **single static binary**, and so is the broker. Upgrading is a file replacement -- no migration, no state changes.

### `agentcordon update` (Recommended)

```bash
agentcordon update
```

One command replaces **both** binaries and restarts the running broker, so it also solves the
footgun the manual steps below have: the broker keeps running the old binary until it is
restarted, and the restart has to re-supply the flags it was started with.

`update` is **server-pinned**. It learns the target version from `{server_url}/install.sh`
(`AGTCRDN_VERSION`) -- the same lockstep pin the installer uses ([ADR-0010](adr/0010-installer-pinned-to-server-version.md),
[ADR-0016](adr/0016-agentcordon-update-is-server-pinned-self-update.md)) -- so a workspace never
runs ahead of its server. The server URL resolves exactly as for `init` and `register`: the
`--server-url` flag, then `AGTCRDN_SERVER_URL`, then `server_url` in `~/.agentcordon/config.toml`.

It downloads `agentcordon` and `agentcordon-broker` for your platform plus `SHA256SUMS` from the
matching GitHub release, **verifies both binaries before installing either**, and swaps each in
atomically (a temp file in the same directory, then `rename` over the target). A checksum
mismatch aborts and leaves your current binaries untouched. It then discovers the running broker,
captures its command line, stops it, and starts the new binary **with the same flags** -- or, if
it cannot read the old command line, restarts with `--server-url` and `--port` and warns which
other flags (`--bind`, `--shared-secret`, `--proxy-allow-loopback`, `--tls-cert`/`--tls-key`) may
need re-applying.

| Flag | Effect |
|------|--------|
| `--check` | Report the current and available versions and exit; change nothing. |
| `--force` | Reinstall even when already on the server's pinned version. |
| `--server-url <url>` | Learn the target version from this server (same precedence as `init`/`register`). |
| `--yes` | Skip the confirmation prompt (for scripts). The CLI never prompts when stdin is not a terminal. |

> [!NOTE]
> `agentcordon update` is not yet available on **Windows** -- a running `.exe` cannot be replaced
> in place. On Windows, re-run the install one-liner (`install.ps1`) and restart the broker, as
> below.

If `update` is unavailable (an older CLI, Windows, or a server with no matching published
release), use one of the manual paths below.

### Install Script

The AgentCordon server hosts an install script that auto-detects your platform:

```bash
curl -fsSL https://agentcordon.example.com/install.sh | sh
```

The script is POSIX `sh`, so `| sh`, `| bash`, `| dash` and `| zsh` all work, and it never
re-fetches itself from a second URL -- the address you pipe from is the only one it uses.
It downloads `agentcordon` and `agentcordon-broker` for your OS/architecture into
`~/.local/bin`, fetches the release's `SHA256SUMS`, and **verifies both binaries against it
before installing them**. A checksum mismatch aborts the install and leaves nothing behind.
Set `AGENTCORDON_SKIP_CHECKSUM=1` only if you are installing from a release that predates
`SHA256SUMS`.

**Supported platforms:**

| OS | Architecture | Target Triple |
|----|-------------|---------------|
| Linux | x86_64 | `x86_64-unknown-linux-gnu` |
| Linux | ARM64 | `aarch64-unknown-linux-gnu` |
| macOS | Intel | `x86_64-apple-darwin` |
| macOS | Apple Silicon | `aarch64-apple-darwin` |
| Windows | x86_64 | `x86_64-pc-windows-msvc` |

### GitHub Releases (Manual)

```bash
# Linux x86_64
curl -fsSL https://github.com/agentcordon/agentcordon/releases/latest/download/agentcordon-x86_64-unknown-linux-gnu \
  -o ~/.local/bin/agentcordon
chmod +x ~/.local/bin/agentcordon

# macOS Apple Silicon
curl -fsSL https://github.com/agentcordon/agentcordon/releases/latest/download/agentcordon-aarch64-apple-darwin \
  -o ~/.local/bin/agentcordon
chmod +x ~/.local/bin/agentcordon

# Verify checksums
curl -fsSL https://github.com/agentcordon/agentcordon/releases/latest/download/SHA256SUMS -o SHA256SUMS
sha256sum -c SHA256SUMS --ignore-missing
```

### Cargo Install

```bash
cargo install agentcordon
```

### Verify the Upgrade

```bash
agentcordon --version
agentcordon status
```

---

## Client Compatibility

> [!IMPORTANT]
> Upgrade the server, every broker, and every CLI together for this release. The CLI-to-broker signature now includes a nonce (`X-AC-Nonce`) and the register body carries a timestamp and nonce, so an old CLI is refused by a new broker and vice versa. The broker now receives short-lived upstream access tokens from the server instead of refresh tokens and client secrets, sends the proxied request's method and target URL when it vends, parses response headers as a list, and no longer calls `POST /api/v1/workspaces/mcp/rotate-refresh-token` (removed). An old broker against a new server fails MCP calls and vends for pattern-bound credentials; a new broker against an old server cannot sync MCP credentials.

### No Re-Registration Required

The CLI state in `.agentcordon/` is **forward-compatible**:

- **Keypairs** (`.agentcordon/workspace.key`, `.agentcordon/workspace.pub`) -- Ed25519 signing keypair, unchanged across versions. The private key is a hex-encoded seed (mode 0600), the public key is hex-encoded (mode 0644).
- **Broker token store** -- encrypted with a P-256 key derived at broker startup. Tokens are re-negotiated automatically when expired.
- **OAuth access token** -- the broker refreshes it with the refresh grant at `/api/v1/oauth/token` when it expires; no user action is needed.

> [!TIP]
> After upgrading the binary, existing workspaces continue working immediately. No `init` or `register` is needed.

### Version compatibility

Nothing enforces a version match at runtime -- there is no handshake, and `--version` will
not warn you. Within a major line the API is additive and any client works with any server.
**Across the 0.3.x to 0.4.0 boundary it does not**, because the CLI-to-broker and
broker-to-server wire formats both changed with no dual-accept window. See
[Upgrading from 0.3.x](#upgrading-from-03x); the failure mode is
`401 signature verification failed` (CLI/broker) or failing MCP calls and pattern-bound
vends (broker/server), not a clear version error.

---

## Breaking Changes

### Upgrading from 0.3.x

> [!CAUTION]
> **The server, every broker, and every CLI move together.** This release changes the
> CLI-to-broker wire format and the broker-to-server wire format. There is no dual-accept
> window in either direction and no version negotiation: a 0.3.x CLI against a 0.4.0 broker
> (or the reverse) gets `401 signature verification failed` on every signed command, and a
> 0.3.x broker against a 0.4.0 server fails MCP calls and vends for any credential that
> carries an `allowed_url_pattern`. Plan the upgrade as one change, not three.

Upgrade in this order: **server, then each broker, then the CLI on the same machine as that
broker.** A broker and its CLI are almost always co-located, so in practice you replace both
binaries in one step:

```bash
curl -fsSL https://agentcordon.example.com/install.sh | sh   # replaces both binaries
pkill -f agentcordon-broker && agentcordon-broker --server-url https://agentcordon.example.com &
agentcordon status
```

The installer the server serves is pinned to **that server's own version** rather than to the
newest published release, so it either installs the matching pair or stops and tells you no
release exists for that version yet and to build from source ([Installation, from
source](installation.md#from-source)) -- which is exactly the lockstep this section
requires. `agentcordon status` warns if the broker it finds is a different version from the
CLI.

Nothing needs re-enrolling. The Ed25519 keypair in `.agentcordon/`, the broker's encrypted
token store, and every workspace's OAuth tokens all survive.

Releases from 0.4.0 on are cut by one tagged command and published by CI ([Releasing](releasing.md)):
each one publishes a multi-arch (`linux/amd64` and `linux/arm64`) server image tagged by version --
`ghcr.io/agentcordon/agentcordon:0.4.0` as well as `0.4`, `latest` and `sha-<commit>` -- alongside
binaries whose checksums are in the release's `SHA256SUMS`, and the installer served by a running
server resolves the release matching that server's own version.

#### Wire-format changes (the lockstep requirement)

| What | Before | Now |
|------|--------|-----|
| CLI-to-broker signed payload | `METHOD\nPATH\nTIMESTAMP\nBODY` | `METHOD\nPATH_WITH_QUERY\nTIMESTAMP\nNONCE\nBODY`, with a fresh 16-byte `X-AC-Nonce` per request; the broker refuses a `(key, nonce)` pair it has already seen inside the 30-second window |
| `POST /register` body | name, key, scopes, signature | plus `timestamp` and `nonce`, both covered by the signature |
| Broker vend request | credential name only | plus the proxied request's `method` and `target_url`, so the server can enforce `allowed_url_pattern` |
| Vend / MCP-sync envelope for OAuth credentials | upstream refresh token + provider client secret | a short-lived upstream access token and its `expires_at`; the refresh token and client secret never leave the server |
| Proxy response headers | single-valued map | list of pairs |
| `POST /api/v1/workspaces/mcp/rotate-refresh-token` | called by the broker | **removed** -- the server rotates and persists refresh tokens itself |

#### Routes removed

| Route | Replacement |
|-------|-------------|
| `GET /.well-known/jwks.json`, the ES256 JWT issuer | None needed. Nothing verified those JWTs anywhere a client could reach; workspace bearer credentials are opaque OAuth 2.0 access tokens. |
| `GET /api/v1/workspaces/{id}/permissions` (permissions token) | None. Authorization is decided server-side per request. |
| `/api/v1/workspace-identities/*`, including its two revoke routes | `POST /api/v1/workspaces/{id}/revoke`, which authorizes `manage_workspaces` against the workspace and its owner |
| `POST /api/v1/mcp/proxy` | Never worked; it only returned a "moved" error |
| Policy-sync, audit-stream WebSocket, audit-ingest and tool-report control-plane routes | None had a caller in the broker or the CLI |
| `POST /api/v1/workspaces/mcp/rotate-refresh-token` | Server-side rotation |
| `agentcordon setup <url>` | `agentcordon init && agentcordon register --server-url <url>` |

#### Operator-visible behaviour changes

- **A second server on the same database is refused.** Startup takes an advisory lock on
  `<db path>.lock`. If you knowingly run replicas over one SQLite file, set
  `AGTCRDN_REPLICA_MODE=unsafe-shared` before upgrading, and accept split-brain enforcement.
- **A weak `AGTCRDN_MASTER_SECRET` now warns.** An install that already holds credentials
  keeps deriving its key exactly as before -- your data stays readable -- and logs a warning
  naming the rotation procedure. Only a *fresh* install stretches a weak secret with
  Argon2id and persists `<db dir>/.master-salt`.
- **Argon2 cost is configuration, not a cargo feature.** The `test-crypto` feature is gone.
  `AGTCRDN_ARGON2_M_COST_KIB` / `_T_COST` / `_P_COST` (65536 / 3 / 4) carry it, and an
  invalid value stops startup rather than silently lowering cost.
- **`key_version` changed meaning.** It was a count of re-encryptions; it now names *which
  master-key version sealed that row*. Migration 019 backfills every
  `credential_secret_history` row to 1. Rotation is now a key-ring procedure --
  `AGTCRDN_MASTER_KEY_VERSION` plus `AGTCRDN_PREVIOUS_MASTER_SECRET` -- and
  `POST /api/v1/admin/rotate-key` re-seals history as well as credentials, reporting
  `key_version`, `history_re_encrypted_count` and `total_history_entries` alongside the
  credential counts. Follow [Master Key -- Key Rotation](master-key.md#key-rotation); the
  old "change the secret and restart" runbook lost every credential.
- **A workspace has one lifecycle field.** `enabled` and `status` could disagree; migration
  017 folds them together. The API still returns a derived `enabled` (`status == Active`).
  Re-enabling a revoked workspace answers `409 workspace is revoked; cannot enable`.
- **Revoking a workspace now really revokes access.** `POST /api/v1/workspaces/{id}/revoke`
  revokes the workspace's OAuth clients and every access and refresh token in one
  transaction, and there is a **Revoke** button on the workspace detail page. It is final.
- **`allowed_url_pattern` is enforced.** It was stored and displayed but never checked. The
  server now refuses a vend whose `target_url` does not match, for every credential type,
  and the broker re-checks before injecting. A credential whose pattern does not actually
  cover the URLs your agents call will start failing with `403` at this upgrade -- audit
  your patterns first.
- **Proxied and MCP calls no longer follow redirects**, do not forward hop-by-hop headers,
  send request bodies byte for byte, cap the response at
  `AGTCRDN_PROXY_MAX_RESPONSE_BYTES`, and redact every injected header and query value out
  of the response before it reaches the agent.
- **The SSRF guard covers the full reserved address set** and checks the *resolved* address,
  including on the broker's `tools/list` probe. Targets that used to slip through (0/8,
  192.0.0/24, 198.18/15, the TEST-NETs, multicast, 240/4, NAT64, 6to4) are now refused.
  `AGTCRDN_PROXY_ALLOW_LOOPBACK=true` disables the guard entirely.
- **A non-loopback broker bind is refused** without `--shared-secret`/
  `AGTCRDN_BROKER_SHARED_SECRET` or a `--tls-cert`/`--tls-key` pair. A container running
  `agentcordon-broker --bind 0.0.0.0` will not start until you add one. The broker can now
  terminate TLS itself, and one broker per `--data-dir` is enforced with `broker.lock`.
- **The CLI pins the broker's key.** `agentcordon register` writes
  `.agentcordon/broker.fingerprint` and every later connection compares it to the broker's
  `/health`. Rebuilding a broker's key directory makes existing workspaces refuse it until
  `agentcordon register --force` re-pins. A workspace enrolled before pinning has its pin
  written on first use, with a notice on stderr.
- **The broker's port file records a URL**, not a bare port, so a TLS broker is discoverable
  locally. Old bare-port files are still accepted.
- **OIDC logins bind to the provider's `subject`**, not to a username claim. Existing
  accounts are linked on the next successful login through `user_oidc_identities`
  (migration 014).
- **Audit exports are tenant-scoped** and CSV-injection-safe, and `GET /api/v1/audit?limit=`
  is clamped at 500 -- use `offset` to page. Scripts that asked for everything in one
  request need to page.
- **Operators manage only the workspaces they own.** Default policy 2e no longer grants
  `manage_workspaces` on any resource. If you relied on that, add an explicit policy.
- **Login lockout is keyed by (address, username)**, and the device-approve limiter keys on
  the real peer address. Behind a reverse proxy, set `AGTCRDN_TRUST_FORWARDED_HEADERS=true`
  or every client counts as one.
- **Only root can change root's password.**
- **`agentcordon init` no longer writes `.mcp.json`.** It used to insert
  `{"command":"agentcordon","args":["mcp-serve"]}` for a subcommand that does not exist.
  Existing files are left byte-identical; delete that entry by hand if you have one.
- **A vault is now a row, not a string on the credential.** Until 0.4.0 "owning" a vault
  meant owning any credential that happened to carry the name, so two users who each called
  a vault `team` were, to the server, in the same vault. Migration 021 gives every vault an
  id, a display name with no uniqueness constraint, and an owner; the placement rule is one
  vault per distinct **(name, owning user)** pair among your existing credentials, where the
  owning user is the credential's creator (for a workspace-created credential, the
  workspace's owner, falling back to root), and everything named `default` lands in the one
  system vault (`00000000-0000-0000-0000-000000000001`), which nobody may rename, share or
  delete. In the API the credential's `vault` field is replaced by **`vault_id`** on create
  and update, with `vault_id` and `vault_name` on every response; the share routes move from
  `/api/v1/vaults/{name}/shares` to **`/api/v1/vaults/{id}/shares`**, and there are now
  `POST /api/v1/vaults`, `PATCH /api/v1/vaults/{id}` and `DELETE /api/v1/vaults/{id}`
  (409 while the vault still holds credentials). Sharing is the **owner's** act at any role
  and no longer something `manage_vaults` can do -- an admin reads any share list and
  revokes, but never grants -- and `write` and `admin` shares are refused with 400, `read`
  being the only level the authorization model keeps; pre-existing `write`/`admin` share
  rows are carried over untouched but grant read. Scripts that posted a vault **name**
  anywhere need to create the vault and use its id; the CLI's `VAULT` column is unchanged
  (it was always the display name). Manage all of this from **Settings -> Vaults**.
- **OAuth provider clients are admin-only to change.** Creating, editing, re-registering and
  deleting one needs `manage_oauth_provider_clients`, which the default policy grants to
  admins; an operator still sees the listing on **Settings -> MCP Identity** so they can
  tell which client an origin uses, without the write controls. Deleting a client that
  anything still authenticates with answers `409`, naming both counts -- the
  `oauth2_user_authorization` credentials issued against that authorization server and the
  OAuth2 MCP servers that authenticate with them.
- **Migration 013 restores MCP-to-workspace bindings** that migration 012 destroyed in
  v0.3.2/v0.3.3. It restores each MCP's *original* workspace; bindings added with **Share
  with workspace** after v0.3.2 must be re-created by the owner.
- **The compose files parse again** (an empty `environment:` key made `docker compose up -d`
  fail on `docker-compose.yml`, `docker-compose.dev.yml` and `docker-compose.tailscale.yml`),
  and the from-source `Dockerfile` builds again.

#### Admin UI changes

The console was reorganised in 0.4.0. Nothing was removed from the product, but
several things an operator reaches for have moved. Bookmarks and older links
still work -- every path below that moved kept a redirect. [Admin UI](admin-ui.md)
maps the whole console.

| You are looking for | Where it is now |
|---------------------|-----------------|
| The MCP **marketplace** | Its own page at `/mcp-servers/marketplace`, reached with **Add server** on `/mcp-servers`. It used to be the bottom half of the list page. `/marketplace` and `/mcp-marketplace` redirect there |
| **Delete**, and workspace **Revoke** | The **&hellip;** overflow menu at the right end of the detail page header, on every detail page. They are no longer loose beside Edit; each still confirms |
| **Enable / Disable** for a policy or an MCP server | A button in that record's detail header. It left the policy list row and the edit forms' Enabled checkbox, so the state has one affordance everywhere |
| The workspace **MCP Servers** and **Consents** tabs | One **Access** tab |
| The MCP server **Workspaces** and **Permissions** tabs | One **Access** tab; **Rediscover tools** stays on **Tools** |
| A credential or workspace detail | A full page at `/credentials/{id}` and `/workspaces/{id}` -- one URL per record, on every viewport. `/{id}/view` redirects to it, and the HTML-fragment routes the old two-pane layout used are removed |
| The **theme toggle** and **Sign Out** | The user menu under your name in the top bar, which also holds Settings |
| The **Security** nav item | Renamed **Policies**. The paths under `/security` are unchanged |
| The `/users` page | Redirects to `/settings#users-section`; user management is a section of Settings, which now has a section rail (Account, Vaults, Users, Sign-in, Master key, OAuth clients). Only the create form is still its own page, at `/settings/users/new` |
| The inline **policy tester** on a policy page | Merged into the one tester at `/security/tester`; a policy page links into it prefilled. Its three scenario controls are one **Scenarios** menu |
| The audit log's export button | An **Export** menu in the page header offering CSV, JSONL and Syslog; the API always served all three |
| The audit **event-type pills** | A **Type:** dropdown; the three decision values stay pills |
| The dashboard's health tile and its permanent **Register a Workspace** card | The third tile is an **MCP servers** count, health is a line under the page title, and the card is a first-run checklist shown only while the instance has no workspace |

If you automate against the console with a browser driver, the selectors that
moved are the overflow-menu items (open the **&hellip;** menu first), the merged
Access tabs, and the marketplace's new path.

#### The PostgreSQL backend is gone

The `postgres` cargo feature and its store are deleted in 0.4.0. It was never
finished -- most store operations returned "not yet implemented" -- and SQLite
was always the production path, so there is nothing to migrate off.

What changes for you: `AGTCRDN_DB_TYPE` and `AGTCRDN_DB_URL` are no longer
read, and a server started with either of them set **refuses to boot** with a
message naming the variable. Delete both from your `.env` (and from any
compose file or unit file) before upgrading. `AGTCRDN_DB_PATH` is unchanged
and is now the only database setting.

#### Configuration to check before you upgrade

| Variable | Change |
|----------|--------|
| `AGTCRDN_PORT` | Never read by the server. If a plain `docker run` relies on it, switch to `AGTCRDN_LISTEN_ADDR`. Compose files still use it for the host side of the port mapping. |
| `AGTCRDN_OAUTH_AUTH_CODE_TTL` | Not a real variable. The server reads `AGTCRDN_AUTH_CODE_TTL` (default `600`). |
| `AGTCRDN_BROKER_PORT` | Defaults to `0` (auto-select). There is no default `3141` or `9876`; the CLI discovers the broker through `~/.agentcordon/broker.port`. Drop any `AGTCRDN_BROKER_URL=http://localhost:3141` you exported. |
| `AGTCRDN_JWT_TTL`, `AGTCRDN_SEED_DEMO` | Removed. Nothing read them once the JWT issuer and demo seeding were gone. |
| `AGTCRDN_BASE_URL` | Now effectively required. Enrollment prints an activation URL built from it, and `GET /install.sh` is templated from it. |
| `AGTCRDN_MASTER_KEY_VERSION`, `AGTCRDN_PREVIOUS_MASTER_SECRET` | New; only needed during a master-secret rotation. |
| `AGTCRDN_ARGON2_*` | New; leave at the defaults unless the hardware forces otherwise. |
| `AGTCRDN_DB_TYPE`, `AGTCRDN_DB_URL` | Removed with the PostgreSQL backend. The server refuses to start while either is set. Delete them; keep `AGTCRDN_DB_PATH`. |

### Signing format change (v0.4.0)

The CLI-to-broker Ed25519 signed payload gained the request's query string and a
per-request nonce. The payload changed from:

```
METHOD\nPATH\nTIMESTAMP\nBODY
```

to:

```
METHOD\nPATH_WITH_QUERY\nTIMESTAMP\nNONCE\nBODY
```

where `PATH_WITH_QUERY` is canonicalised (trailing `/` stripped unless the path is `/`; query appended verbatim after `?` when present; fragment dropped). The CLI and broker apply byte-identical canonicalisation.

**Impact:** There is no dual-accept window. A pre-v0.4.0 CLI talking to a v0.4.0+ broker (or vice versa) will receive `401 signature verification failed` on every signed request.

**Action:** Upgrade the CLI binary and the broker on the same machine together. In the typical per-user-broker deployment the two are co-located, so upgrade both before running any signed command (`status`, `credentials`, `proxy`, `mcp-*`).

Details and examples: [CLI Reference -- Authentication](cli-reference.md#authentication).

---

## Pre-Upgrade Checklist

### Server

- [ ] Back up the database (`/data/agent-cordon.db`)
- [ ] Back up the `.secret` file (sibling of the database file)
- [ ] Note the current version (`docker inspect` or check release tag)
- [ ] Review the release notes for breaking changes
- [ ] If using custom Cedar policies, verify compatibility with the new schema version
- [ ] If upgrading from v0.3.2 or v0.3.3, expect migration 013 to restore MCP-to-workspace bindings from each MCP's original workspace; any bindings added via **Share with workspace** after v0.3.2 must be re-created by the owner
- [ ] If upgrading from any 0.3.x, read [Upgrading from 0.3.x](#upgrading-from-03x) first and plan server, brokers and CLIs as **one** change
- [ ] Audit every credential's `allowed_url_pattern` -- it is enforced from this release and a pattern that does not cover the URLs your agents call starts failing with 403
- [ ] Check for `AGTCRDN_PORT` on a non-compose deployment, `AGTCRDN_OAUTH_AUTH_CODE_TTL`, and any exported `AGTCRDN_BROKER_URL=http://localhost:3141`
- [ ] Set `AGTCRDN_BASE_URL` if it is not already set
- [ ] Confirm no second server process shares the database, or set `AGTCRDN_REPLICA_MODE=unsafe-shared` deliberately
- [ ] If any broker binds a non-loopback address, give it `--shared-secret` or a TLS pair before restarting it

### Client

- [ ] Note the current version (`agentcordon --version`)
- [ ] Verify the new binary matches your platform

---

## Post-Upgrade Verification

### Server

```bash
# Health check
curl http://localhost:3140/health
# Expected: {"status":"ok"}

# Check logs for migration output
docker compose logs --tail 50 agentcordon | grep -i migrat

# Verify policies loaded
docker compose logs --tail 50 agentcordon | grep -i policy

# Test a workspace auth flow
agentcordon status
```

### Client

```bash
# Version check
agentcordon --version

# Server connectivity
agentcordon status

# Credential access
agentcordon credentials

# MCP tools (if configured)
agentcordon mcp-tools
```

---

## Upgrade Scenarios

### First-Time Docker Compose Setup

```bash
mkdir ~/agentcordon && cd ~/agentcordon
curl -fsSL https://raw.githubusercontent.com/agentcordon/agentcordon/main/docker-compose.yml -o docker-compose.yml
docker compose up -d
```

On first boot, the server auto-generates the master secret (persisted to `.secret` next to the database), the Docker entrypoint auto-generates the root password (persisted to `/data/.root_password`), and the database is seeded with the default Cedar policy.

---

### Upgrading Docker Compose to a Specific Version

```bash
cd ~/agentcordon

# Back up
docker compose exec agentcordon cp /data/agent-cordon.db /data/agent-cordon.db.bak

# Pull specific version
docker compose pull  # or edit image tag in docker-compose.yml
docker compose up -d

# Verify
docker compose ps
curl http://localhost:3140/health
```

---

### Upgrading the CLI on Multiple Workstations

Each workstation's `.agentcordon/` directory is independent. Upgrade the binary on each machine:

```bash
# On each workstation
curl -fsSL https://agentcordon.example.com/install.sh | sh
agentcordon status
```

No re-enrollment is needed. The existing keypairs and cached state continue working.

---

## Environment Variable Reference

Every variable, with its default, its clamps and which binary reads it, is in
[Configuration](configuration.md). It is the single source of truth; this page no longer
repeats it.

Two things to check specifically before an upgrade:

- **`AGTCRDN_DB_TYPE` and `AGTCRDN_DB_URL` were removed in 0.4.0.** A server started with
  either one set refuses to boot, so an old `.env` fails loudly rather than silently
  opening the wrong database. Remove them and point `AGTCRDN_DB_PATH` at the SQLite file.
- **`AGTCRDN_KDF_SALT`, once set, must stay set** — including through a master-key
  rotation. See [Master Key](master-key.md).

New variables in newer versions always have defaults, so an older configuration keeps
working.

---

> **See also:** [System Architecture](system-architecture.md) | [CLI Reference](cli-reference.md)
