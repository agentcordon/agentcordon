> [Home](index.md) > System Architecture

# System Architecture

AgentCordon is a **4-crate Rust workspace** that separates concerns into **core** (shared library), **server** (control plane), **broker** (per-user credential daemon), and **cli** (thin workspace agent). The server stores credentials and enforces Cedar policy; the broker manages OAuth tokens and proxies credential-injected API calls; the CLI signs requests to the broker and never touches credentials directly.

---

**On this page:**
[Crate Overview](#crate-overview) · [API Routes](#api-routes) · [Middleware](#middleware-stack) · [Data Flow](#data-flow) · [MCP Architecture](#mcp-architecture) · [Database](#database) · [Deployment](#deployment) · [Observability](#observability)

---

## Crate Overview

```
AgentCordon/
├── crates/
│   ├── core/       # Shared library: crypto, policy, storage, domain models
│   ├── server/     # Control plane: HTTP API, admin UI, policy engine
│   ├── broker/     # Per-user daemon: OAuth tokens, credential proxy, MCP sync
│   └── cli/        # Thin CLI agent: Ed25519 signing, broker communication
├── policies/       # Cedar policy files and schema
├── migrations/     # SQLite migration files
└── data/           # Credential, MCP, and policy templates
```

---

### `core` -- `agent-cordon-core`

The foundation crate, used by server and broker.

| Module | Purpose |
|--------|---------|
| `crypto/` | AES-256-GCM encryption, ECIES (P-256), Ed25519 signing, HKDF-SHA256, Argon2id |
| `policy/` | Cedar policy engine (`CedarPolicyEngine`), entity builders, schema |
| `domain/` | Data models: Agent, Audit, Credential, Device, Mcp, McpOAuth, OAuthProviderClient, Oidc, Policy, Session, User, Vault, Workspace |
| `storage/` | Trait-based DB layer with SQLite and PostgreSQL implementations |
| `auth/` | JWT issuance/validation, OIDC, password hashing |
| `oauth2/` | OAuth2 client credentials token manager, token utilities, scope types |
| `proxy/` | URL safety (SSRF prevention), placeholder substitution, leak scanning |
| `services/` | Business logic services |
| `transform/` | Rhai script engine for custom credential transforms |

> [!NOTE]
> **Storage Architecture:** A composite `Store` trait inherits 14 sub-traits (UserStore, SessionStore, CredentialStore, DeviceCodeStore, SecretHistoryStore, PolicyStore, AuditStore, VaultStore, McpStore, McpOAuthStore, OAuthProviderClientStore, OAuthStore, OidcStore, WorkspaceStore). Implementations for SQLite and PostgreSQL provide the same interface.

---

### `server` -- `agent-cordon-server`

The control plane. Runs on port **3140** (configurable via `AGTCRDN_LISTEN_ADDR`).

**Startup Sequence** (`crates/server/src/main.rs`):

```
 1. Load config from environment variables
 2. Initialize tracing (JSON or pretty format)
 3. Derive cryptographic keys from master secret (HKDF-SHA256)
 4. Initialize storage (SQLite or PostgreSQL) + run migrations
 5. Seed default Cedar policy (if none exist)
 6. Run data migrations (e.g. MCP policy name-to-ID migration)
 7. Wrap policy engine in AuditingPolicyEngine (auto-emits audit events)
 8. Bootstrap root user (auto-generate password if needed)
 9. Load credential, MCP, and policy templates
10. Build HTTP router (axum)
11. Start TCP listener
12. Run background cleanup task (expired sessions, OIDC states, MCP OAuth states, rate limiter entries; configurable interval, default 300s)
```

**AppState** (`crates/server/src/state.rs`):

| Field | Type | Description |
|-------|------|-------------|
| `store` | `Arc<dyn Store>` | Database (SQLite or Postgres) |
| `jwt_issuer` | `Arc<JwtIssuer>` | ES256 JWT signing |
| `policy_engine` | `Arc<AuditingPolicyEngine>` | Cedar authorization with automatic audit event emission |
| `encryptor` | `Arc<AesGcmEncryptor>` | Credential encryption/decryption |
| `config` | `AppConfig` | Server configuration |
| `login_rate_limiter` | `Arc<LoginRateLimiter>` | Per-username login attempt rate limiting |
| `device_approve_limiter` | `Arc<DeviceApproveRateLimiter>` | Per-(IP,user) rate limiter for device flow approve/deny |
| `metrics_handle` | `PrometheusHandle` | Prometheus metrics renderer |
| `session_hash_key` | `[u8; 32]` | HMAC session token hashing |
| `oauth2_token_manager` | `OAuth2TokenManager` | Token caching for OAuth2 credentials |
| `http_client` | `reqwest::Client` | Shared HTTP client for proxy routes |
| `event_bus` | `EventBus` | Tokio broadcast for device SSE |
| `ui_event_bus` | `UiEventBus` | Browser SSE events |
| `sse_tracker` | `SseConnectionTracker` | Per-user SSE connection limiter |
| `credential_templates` | `Vec<CredentialTemplate>` | Pre-loaded credential templates |
| `mcp_templates` | `Vec<McpServerTemplate>` | Pre-loaded MCP server templates |
| `policy_templates` | `Vec<PolicyTemplate>` | Pre-loaded policy templates |

---

### `broker` -- `agentcordon-broker`

The per-user persistent daemon. Binds to an auto-selected port by default (configurable via `AGTCRDN_BROKER_PORT`). Manages OAuth2 tokens, proxies credential-injected API calls, and syncs MCP server configs from the server.

**Key responsibilities:**
- Holds OAuth2 access/refresh tokens in memory (encrypted at rest in `tokens.enc`)
- Handles RFC 8628 device authorization grant flow for workspace registration
- Proxies HTTP requests with credential injection (vend from server, ECIES decrypt, transform, inject)
- Syncs MCP server configs from the server on a configurable interval
- Background token refresh before expiry
- Recovery from encrypted token store with plaintext fallback (`workspaces.json`)

**BrokerState** (`crates/broker/src/state.rs`):

| Field | Type | Description |
|-------|------|-------------|
| `workspaces` | `RwLock<HashMap<String, WorkspaceState>>` | OAuth tokens keyed by Ed25519 public key hash |
| `pending` | `RwLock<HashMap<String, PendingDeviceRegistration>>` | In-flight device authorization registrations |
| `registration_errors` | `RwLock<HashMap<String, String>>` | Recent registration failures for CLI feedback |
| `mcp_configs` | `RwLock<HashMap<String, Vec<CachedMcpServer>>>` | Cached MCP server configs per workspace |
| `server_url` | `String` | AgentCordon server URL |
| `http_client` | `reqwest::Client` | Shared HTTP client |
| `encryption_key` | `p256::SecretKey` | P-256 keypair for ECIES operations |
| `config` | `BrokerConfig` | Broker configuration |
| `oauth2_refresh` | `OAuth2RefreshManager` | OAuth2 refresh token manager |
| `oauth2_cc` | `OAuth2TokenManager` | Client credentials token manager |

**Broker Routes** (`crates/broker/src/routes/mod.rs`):

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/health` | No | Health check |
| POST | `/register` | No | Start device authorization registration |
| GET | `/status` | Ed25519 | Check workspace and token status |
| POST | `/deregister` | Ed25519 | Remove workspace registration |
| GET | `/credentials` | Ed25519 | List available credentials |
| POST | `/credentials/create` | Ed25519 | Store a new credential |
| POST | `/proxy` | Ed25519 | Proxy HTTP request with credential injection |
| POST | `/mcp/list-servers` | Ed25519 | List MCP servers |
| POST | `/mcp/list-tools` | Ed25519 | List MCP tools |
| POST | `/mcp/call` | Ed25519 | Call an MCP tool |

---

### `cli` -- `agentcordon-cli` (binary: `agentcordon`)

The thin CLI binary that agents use. It manages Ed25519 keypairs, signs requests to the broker, and never touches credentials directly.

| Command | Description |
|---------|-------------|
| `init` | Generate Ed25519 keypair, write `.agentcordon/` identity, configure `.mcp.json` |
| `setup` | One-command setup: start broker, generate keys, register workspace |
| `register` | Start device authorization registration via the broker |
| `status` | Check workspace and broker status |
| `credentials` | List available credentials |
| `credentials create` | Create a new credential via the broker |
| `proxy` | Proxy HTTP request through the broker with credential injection |
| `mcp-servers` | List available MCP servers |
| `mcp-tools` | List available MCP tools |
| `mcp-call` | Call an MCP tool |

> See the [CLI Reference](cli-reference.md) for complete command documentation.

---

## API Routes

### Control Plane (Workspace-Facing)

Authenticated with workspace identity OAuth2 access token (`Authorization: Bearer {token}`).

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/workspace-identities` | List workspace identities |
| POST | `/api/v1/workspace-identities/{id}/approve` | Approve a workspace identity |
| DELETE | `/api/v1/workspace-identities/{id}` | Revoke a workspace identity |
| DELETE | `/api/v1/agents/{id}/workspace-identity` | Revoke workspace identity by agent ID |
| GET | `/api/v1/workspaces/policies` | Sync Cedar policies to workspace |
| GET | `/api/v1/workspaces/mcp-servers` | Sync MCP server configs (with optional credential envelopes) |
| GET | `/api/v1/workspaces/mcp-tools` | Sync MCP tools |
| POST | `/api/v1/workspaces/mcp-authorize` | Authorize MCP access |
| POST | `/api/v1/workspaces/mcp/rotate-refresh-token` | Rotate MCP refresh token |
| GET | `/api/v1/workspaces/audit-stream` | WebSocket audit event stream |
| POST | `/api/v1/workspaces/audit-events` | Ingest audit events from workspace |
| POST | `/api/v1/workspaces/mcp-report-tools` | Report discovered tools from workspace |

### OAuth 2.0 Authorization Server

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/oauth/clients` | Dynamic client registration |
| GET | `/api/v1/oauth/clients` | List registered clients |
| DELETE | `/api/v1/oauth/clients/{id}` | Revoke a client |
| GET | `/api/v1/oauth/authorize` | Authorization code flow (GET) |
| POST | `/api/v1/oauth/authorize` | Authorization code flow (POST/consent) |
| POST | `/api/v1/oauth/device/code` | RFC 8628 device code request |
| POST | `/api/v1/oauth/device/approve` | Approve device code (rate-limited) |
| POST | `/api/v1/oauth/device/deny` | Deny device code (rate-limited) |
| POST | `/api/v1/oauth/token` | Token exchange (auth code, device code, refresh) |
| POST | `/api/v1/oauth/revoke` | Token revocation |

### Admin API (User-Facing)

Authenticated with session cookie (from user login).

| Category | Endpoints |
|----------|-----------|
| Auth | Login at `/api/v1/auth/login`, logout, me; OIDC at `/api/v1/auth/oidc/*` |
| Credentials | CRUD at `/api/v1/credentials`, vend at `/{id}/vend`, reveal, secret-history, agent-store |
| Workspaces | List/manage at `/api/v1/workspaces`, tags, permissions |
| Policies | CRUD at `/api/v1/policies`, validate, test, schema, RSOP |
| MCP Servers | CRUD at `/api/v1/mcp-servers`, import, provision, OAuth initiate/callback, generate-policies, permissions |
| Users | CRUD at `/api/v1/users`, change-password |
| Audit | List at `/api/v1/audit`, export (CSV, syslog, JSONL), detail |
| Vaults | List at `/api/v1/vaults`, vault credentials, shares |
| OIDC Providers | CRUD at `/api/v1/oidc-providers` |
| OAuth Provider Clients | CRUD at `/api/v1/oauth-provider-clients` |
| Templates | Credential templates, MCP templates, policy templates |
| Admin | Key rotation at `/api/v1/admin/rotate-key` |
| Stats | Dashboard stats at `/api/v1/stats` |
| Settings | Server settings at `/api/v1/settings` |

### Shared Routes

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Health check |
| GET | `/metrics` | Prometheus metrics |
| GET | `/.well-known/jwks.json` | Public JWT signing keys |
| GET | `/install.sh` | CLI + broker installer script |

---

## Middleware Stack

Applied outside-in on every request:

| Order | Middleware | Description |
|:-----:|-----------|-------------|
| 1 | **Request ID** | Generates UUID, injects into request extensions |
| 2 | **HTTP Metrics** | Prometheus counters and latency histograms |
| 3 | **Request Logging** | Structured JSON logs (method, path, status, latency) |
| 4 | **CSRF Protection** | Token validation for POST/PUT/DELETE |

---

## Data Flow

### Credential Proxy (via Broker)

```
Agent                  CLI                Broker                 Server             Upstream API
─────                  ───                ──────                 ──────             ────────────
  │  agentcordon proxy   │                  │                      │                    │
  │  github-token GET    │                  │                      │                    │
  │  api.github.com/user │                  │                      │                    │
  │─────────────────────►│                  │                      │                    │
  │                      │ POST /proxy      │                      │                    │
  │                      │ (Ed25519 signed) │                      │                    │
  │                      │────────────────►│                      │                    │
  │                      │                  │ POST /credentials/   │                    │
  │                      │                  │  vend-device/        │                    │
  │                      │                  │  github-token        │                    │
  │                      │                  │  + OAuth token       │                    │
  │                      │                  │  + broker P-256 key  │                    │
  │                      │                  │─────────────────────►│                    │
  │                      │                  │                      │ Cedar policy check │
  │                      │                  │                      │ AES-GCM decrypt    │
  │                      │                  │                      │ ECIES encrypt      │
  │                      │                  │   ECIES envelope     │                    │
  │                      │                  │◄─────────────────────│                    │
  │                      │                  │ ECIES decrypt (P-256)│                    │
  │                      │                  │ Apply transform      │                    │
  │                      │                  │ GET + Auth: Bearer   │                    │
  │                      │                  │────────────────────────────────────────── │
  │                      │                  │   response           │                    │
  │                      │                  │◄──────────────────────────────────────────│
  │                      │   response       │                      │                    │
  │                      │◄────────────────│                      │                    │
  │    response          │                  │                      │                    │
  │◄─────────────────────│                  │                      │                    │
```

### MCP Tool Call (via Broker)

```
AI Agent               CLI                 Broker                Server
────────               ───                 ──────                ──────
  │ mcp-call             │                    │                     │
  │ server tool          │                    │                     │
  │─────────────────────►│                    │                     │
  │                      │ POST /mcp/call     │                     │
  │                      │ (Ed25519 signed)   │                     │
  │                      │──────────────────►│                     │
  │                      │                    │ Resolve credential   │
  │                      │                    │ from MCP cache       │
  │                      │                    │ (or vend from server)│
  │                      │                    │ Apply transform      │
  │                      │                    │ POST upstream MCP    │
  │                      │                    │────────────────────►│
  │                      │                    │    response          │
  │                      │                    │◄────────────────────│
  │                      │    response        │                     │
  │                      │◄──────────────────│                     │
  │    response          │                    │                     │
  │◄─────────────────────│                    │                     │
```

---

## MCP Architecture

The broker syncs MCP server configurations from the server and caches them with pre-vended credentials. The CLI's `mcp-call` command routes MCP tool calls through the broker, which resolves credentials and proxies to upstream MCP servers.

The CLI's `init` command configures `.mcp.json` to point at the `agentcordon` binary so AI agents (like Claude Code) can discover MCP tools natively.

### Transport Types

| Transport | How It Works |
|-----------|-------------|
| **HTTP/HTTPS** | Broker sends requests to upstream MCP server URL with credential-injected headers |

### Credential Injection

MCP server credentials are synced from the server with ECIES-encrypted envelopes. The broker decrypts and caches them. During MCP tool calls, credentials are injected into upstream requests based on the server's `auth_method` configuration.

Credential values are **never logged** (the `CachedCredential` type has a manual `Debug` impl that redacts the `value` field).

### Config Sync

MCP server configs are synced on a configurable interval (`AGTCRDN_MCP_SYNC_INTERVAL`, default 60s):

1. **Server** (`GET /api/v1/workspaces/mcp-servers?include_credentials=true`) -- authoritative metadata with ECIES-encrypted credential envelopes
2. **Broker cache** (`BrokerState::mcp_configs`) -- decrypted credentials cached in memory per workspace

---

## Database

| Backend | When to Use | Configuration |
|---------|------------|---------------|
| **SQLite** | Development, single-node | `AGTCRDN_DB_PATH=./data/agent-cordon.db` (default) |
| **PostgreSQL** | Production, multi-node | `AGTCRDN_DB_TYPE=postgres`, `AGTCRDN_DB_URL=postgres://...` |

### Key Tables

`users` . `workspaces` . `workspace_registrations` . `workspace_used_jtis` . `sessions` . `credentials` . `credential_secret_history` . `policies` . `audit_events` . `mcp_servers` . `mcp_oauth_states` . `oauth_clients` . `oauth_auth_codes` . `oauth_access_tokens` . `oauth_refresh_tokens` . `oauth_consents` . `oauth_provider_clients` . `oidc_providers` . `oidc_auth_states` . `vault_shares` . `provisioning_tokens` . `device_codes` . `crypto_state`

Migrations are in `/migrations/` (SQLite). PostgreSQL migrations are compiled into the `agent-cordon-core` crate.

---

## Deployment

### Docker Compose

```yaml
services:
  agentcordon:
    image: ghcr.io/agentcordon/agentcordon:latest
    container_name: agentcordon
    command: ["agent-cordon-server"]
    ports:
      - "${AGTCRDN_PORT:-3140}:3140"
    volumes:
      - agentcordon-data:/data
    environment:
      AGTCRDN_SEED_DEMO: "${AGTCRDN_SEED_DEMO:-true}"
    env_file:
      - path: .env
        required: false
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:3140/health"]
      interval: 10s
      timeout: 5s
      start_period: 15s
      retries: 5
    restart: unless-stopped
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `AGTCRDN_LISTEN_ADDR` | `0.0.0.0:3140` | Server bind address |
| `AGTCRDN_DB_PATH` | `./data/agent-cordon.db` | SQLite database path |
| `AGTCRDN_DB_TYPE` | `sqlite` | `sqlite` or `postgres` |
| `AGTCRDN_DB_URL` | -- | PostgreSQL connection URL |
| `AGTCRDN_MASTER_SECRET` | Auto-generated | Encryption master secret (min 16 chars); persisted to `.secret` file |
| `AGTCRDN_KDF_SALT` | Auto-derived | HKDF salt override (derived from master secret if not set) |
| `AGTCRDN_LOG_LEVEL` | `info` | Tracing level |
| `AGTCRDN_LOG_FORMAT` | `json` | `json` or `pretty` |
| `AGTCRDN_JWT_TTL` | `900` | Workspace identity JWT lifetime (seconds) |
| `AGTCRDN_PROXY_TIMEOUT_SECONDS` | `30` | HTTP proxy request timeout |
| `AGTCRDN_PROXY_ALLOW_LOOPBACK` | `false` | Allow loopback/private URL targets |
| `AGTCRDN_SESSION_TTL` | `28800` | User session TTL in seconds (8 hours) |
| `AGTCRDN_SESSION_CLEANUP_INTERVAL` | `300` | Background cleanup interval in seconds (min 10) |
| `AGTCRDN_ROOT_USERNAME` | `root` | Bootstrap admin username |
| `AGTCRDN_ROOT_PASSWORD` | Auto-generated | Bootstrap admin password |
| `AGTCRDN_SEED_DEMO` | `true` | Seed demo data on first startup |
| `AGTCRDN_BASE_URL` | -- | Server base URL (required for OAuth2 flows) |
| `AGTCRDN_DEVICE_CODE_TTL_SECS` | `600` | Device code lifetime (30--3600) |
| `AGTCRDN_DEVICE_CODE_POLL_INTERVAL_SECS` | `5` | Device code poll interval (1--60) |
| `AGTCRDN_BROKER_PORT` | `0` (auto) | Broker daemon listen port |
| `AGTCRDN_SERVER_URL` | `http://localhost:3140` | Broker's upstream server URL |
| `AGTCRDN_MCP_SYNC_INTERVAL` | `60` | Broker MCP config sync interval (seconds) |

---

## Observability

| Channel | Details |
|---------|---------|
| **Structured logging** | JSON format with tracing spans, correlation IDs, and log levels |
| **Prometheus metrics** | Available at `GET /metrics` -- request counts, latency histograms, policy evaluation counters |
| **Audit events** | Stored in database, queryable via `GET /api/v1/audit`, exportable as CSV/syslog/JSONL |
| **SSE events** | Real-time push to connected clients via `EventBus` (device) and `UiEventBus` (browser) |
| **Correlation IDs** | Every request gets a UUID injected by the request ID middleware |

---

> **See also:** [Master Key](master-key.md) . [Credential Encryption](credential-encryption.md) . [Authorization & Cedar Policy](authorization-and-cedar-policy.md)
