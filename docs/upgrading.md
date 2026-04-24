> [Home](index.md) > Upgrading

# Upgrading

How to update the AgentCordon server and CLI client to a new version. Both components are designed for **zero-downtime upgrades** -- migrations run automatically, secrets persist, and clients reconnect transparently.

---

**On this page:**
[What Persists](#what-persists-across-upgrades) | [Server Upgrade](#upgrading-the-server) | [Database Migrations](#database-migrations) | [CLI Upgrade](#upgrading-the-cli-client) | [Client Compatibility](#client-compatibility) | [Pre-Upgrade Checklist](#pre-upgrade-checklist) | [Post-Upgrade Verification](#post-upgrade-verification) | [Upgrade Scenarios](#upgrade-scenarios)

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
4. Derive cryptographic keys (AES-256-GCM encryptor, ES256 JWT signing keypair, session hash key)
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

---

### PostgreSQL (Experimental)

PostgreSQL support exists as a compile-time feature (`--features postgres`) but is **incomplete**. Many store operations (OAuth, provider clients, device codes) return "not yet implemented" errors. The SQLite backend is the production-ready path.

If you are testing the PostgreSQL backend:

```bash
export AGTCRDN_DB_TYPE=postgres
export AGTCRDN_DB_URL="postgres://user:pass@localhost:5432/agentcordon"
```

> [!IMPORTANT]
> Back up the database first:
> ```bash
> pg_dump -h localhost -U agentcordon agentcordon > backup-$(date +%Y%m%d).sql
> ```
> Then upgrade the server:
> ```bash
> docker compose pull && docker compose up -d
> ```

---

## Database Migrations

### How They Work

Migrations are **automatic and idempotent**. On every startup, the server:

1. Creates the `schema_migrations` table if it does not exist
2. Queries which migration versions have already been applied
3. Runs any unapplied migrations in order
4. Each migration is wrapped in a savepoint for safe rollback on failure
5. Records the migration version and `applied_at` timestamp in `schema_migrations`

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
  007_credential_name_unique.sql                # Enforce globally unique credential names (UNIQUE INDEX)
  008_bootstrap_client_mcp_discover_scope.sql   # Add mcp:discover to bootstrap client's allowed_scopes
  009_device_code_pk_hash.sql                   # Bind workspace public_key_hash at device_code issue time
```

### Migration Details (v0.3.0)

**007 -- Credential name uniqueness.** Adds a `UNIQUE INDEX` on `credentials(name)`. If your database already contains duplicate credential names, this migration will fail on startup and you must resolve duplicates manually before upgrading. The store layer already maps constraint violations to `409 Conflict`.

Before upgrading, run the pre-flight scanner to detect existing duplicates:

```bash
# SQLite (default path)
scripts/migration-007-precheck.sh --db-url sqlite:///data/agent-cordon.db

# PostgreSQL
scripts/migration-007-precheck.sh --db-url "postgres://user:pass@host:5432/agentcordon"

# Or pass via env var
AGTCRDN_DB_URL=sqlite:///data/agent-cordon.db scripts/migration-007-precheck.sh
```

The script is read-only (no auto-dedup). Exit status `0` means safe to upgrade; non-zero means duplicates were found and are printed by name. Resolve them (rename or delete) in the running v0.3.x deployment before replacing the binary.

**008 -- Bootstrap client mcp:discover scope.** The bootstrap client (`agentcordon-broker`) seeded by migration 006 was missing the `mcp:discover` scope. Without it, the broker's device authorization grant request was rejected with `400 invalid_scope`. This migration updates `allowed_scopes` to include `credentials:discover,credentials:vend,mcp:discover,mcp:invoke`.

**009 -- Device code pk_hash binding.** Adds a `pk_hash_prefill` column to `device_codes` for defense-in-depth: the broker sends its public key hash when requesting a device code, and the approver must present a matching hash. Prevents a malicious approver from attaching a different signing identity.

### Backup Before Upgrading

```bash
# SQLite
cp /data/agent-cordon.db /data/agent-cordon.db.backup-$(date +%Y%m%d)

# PostgreSQL (if using experimental postgres backend)
pg_dump agentcordon > agentcordon-backup-$(date +%Y%m%d).sql
```

---

## Upgrading the CLI Client

The CLI client (`agentcordon`) is a **single static binary**. Upgrading is a file replacement -- no migration, no state changes.

### Install Script (Recommended)

The AgentCordon server hosts an install script that auto-detects your platform:

```bash
curl -fsSL https://your-server:3140/install.sh | sh
```

This downloads the latest binary for your OS/architecture to `~/.local/bin/agentcordon`.

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

### No Re-Registration Required

The CLI state in `.agentcordon/` is **forward-compatible**:

- **Keypairs** (`.agentcordon/workspace.key`, `.agentcordon/workspace.pub`) -- Ed25519 signing keypair, unchanged across versions. The private key is a hex-encoded seed (mode 0600), the public key is hex-encoded (mode 0644).
- **Broker token store** -- encrypted with a P-256 key derived at broker startup. Tokens are re-negotiated automatically when expired.
- **JWT** -- automatically re-negotiated when expired (default 15-minute TTL, configurable via `AGTCRDN_JWT_TTL`). The client refreshes transparently on the next command.

> [!TIP]
> After upgrading the binary, existing workspaces continue working immediately. No `init` or `register` is needed.

### No Version Pinning

The CLI does not enforce a version match with the server. As long as the API contract is compatible, any client version works with any server version. The API is designed to be **additive** -- new endpoints are added without removing old ones.

---

## Breaking Changes

### Signing format change (v0.4.0)

The CLI-to-broker Ed25519 signed payload now includes the request's query string. The payload changed from:

```
METHOD\nPATH\nTIMESTAMP\nBODY
```

to:

```
METHOD\nPATH_WITH_QUERY\nTIMESTAMP\nBODY
```

where `PATH_WITH_QUERY` is canonicalised (trailing `/` stripped unless the path is `/`; query appended verbatim after `?` when present; fragment dropped). The CLI and broker apply byte-identical canonicalisation.

**Impact:** There is no dual-accept window. A pre-v0.4.0 CLI talking to a v0.4.0+ broker (or vice versa) will receive `401 signature verification failed` on every signed request.

**Action:** Upgrade the CLI binary and the broker on the same machine together. In the typical per-user-broker deployment the two are co-located, so upgrade both before running any signed command (`status`, `credentials`, `proxy`, `mcp-*`).

Details and examples: [CLI Reference -- Authentication](cli-reference.md#authentication).

---

## Pre-Upgrade Checklist

### Server

- [ ] Back up the database (`/data/agent-cordon.db` or PostgreSQL dump)
- [ ] Back up the `.secret` file (sibling of the database file)
- [ ] Note the current version (`docker inspect` or check release tag)
- [ ] Review the release notes for breaking changes
- [ ] If using custom Cedar policies, verify compatibility with the new schema version
- [ ] If upgrading to a version with migration 007, run `scripts/migration-007-precheck.sh` (supports SQLite and Postgres via `--db-url` or `AGTCRDN_DB_URL`) to detect duplicate credential names before the migration runs on startup

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

### Migrating from SQLite to PostgreSQL

> [!WARNING]
> PostgreSQL support is experimental. Many store operations are not yet implemented. Use SQLite for production deployments.

```bash
# 1. Export data from SQLite (application-level, not raw SQL)
# 2. Set new environment variables
export AGTCRDN_DB_TYPE=postgres
export AGTCRDN_DB_URL="postgres://user:pass@localhost:5432/agentcordon"

# 3. Start the server -- it creates tables and runs PostgreSQL migrations
docker compose up -d

# 4. Re-import data (policies, credentials, workspaces)
```

> [!NOTE]
> There is no built-in SQLite-to-PostgreSQL migration tool. Plan a data migration using the admin API.

---

### Upgrading the CLI on Multiple Workstations

Each workstation's `.agentcordon/` directory is independent. Upgrade the binary on each machine:

```bash
# On each workstation
curl -fsSL https://your-server:3140/install.sh | sh
agentcordon status
```

No re-enrollment is needed. The existing keypairs and cached state continue working.

---

## Environment Variable Reference

All variables have defaults and are backward-compatible. New variables in newer versions do not break older configurations.

| Variable | Default | Notes |
|----------|---------|-------|
| `AGTCRDN_LISTEN_ADDR` | `0.0.0.0:3140` | Server bind address |
| `AGTCRDN_DB_PATH` | `./data/agent-cordon.db` | SQLite database path |
| `AGTCRDN_DB_TYPE` | `sqlite` | `sqlite` or `postgres` (experimental) |
| `AGTCRDN_DB_URL` | -- | Required when `AGTCRDN_DB_TYPE=postgres` |
| `AGTCRDN_MASTER_SECRET` | Auto-generated | Persisted to `.secret` file next to DB. Must be >= 16 chars |
| `AGTCRDN_KDF_SALT` | Auto-derived from master secret | Override HKDF salt (legacy deployments only) |
| `AGTCRDN_ROOT_USERNAME` | `root` | Bootstrap admin username |
| `AGTCRDN_ROOT_PASSWORD` | Auto-generated | Docker entrypoint persists to `/data/.root_password` |
| `AGTCRDN_LOG_LEVEL` | `info` | `trace`, `debug`, `info`, `warn`, `error` |
| `AGTCRDN_LOG_FORMAT` | `json` | `json` or `pretty` |
| `AGTCRDN_SEED_DEMO` | `true` | Seed demo data on first boot |
| `AGTCRDN_JWT_TTL` | `900` | Workspace JWT lifetime in seconds (15 min) |
| `AGTCRDN_SESSION_TTL` | `28800` | User session TTL in seconds (8 hours) |
| `AGTCRDN_PROXY_ALLOW_LOOPBACK` | `false` | Allow proxying to localhost/private-network URLs |
| `AGTCRDN_BASE_URL` | -- | Server base URL (required for OAuth2 MCP flows) |
| `AGTCRDN_DEVICE_CODE_TTL_SECS` | `600` | Device code TTL in seconds (clamped 30--3600) |
| `AGTCRDN_DEVICE_CODE_POLL_INTERVAL_SECS` | `5` | Device flow polling interval (clamped 1--60) |
| `AGTCRDN_OAUTH_AUTH_CODE_TTL` | `300` | OAuth authorization code TTL in seconds |
| `AGTCRDN_INSTANCE_LABEL` | -- | Label for OAuth Dynamic Client Registration |

---

> **See also:** [System Architecture](system-architecture.md) | [CLI Reference](cli-reference.md)
