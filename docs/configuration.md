> [Home](index.md) > Configuration

# Configuration

Every AgentCordon binary is configured from the environment. There are no configuration
files and, apart from the broker's flags, no command-line settings. This page is the
single source of truth for those variables: `.env.example`, the server's `--help`, and
the other pages in `docs/` all point here rather than repeating the table.

Port **3140** is the server's default, and every example in the documentation assumes it.
Change it with `AGTCRDN_LISTEN_ADDR` and read the examples with your own port substituted.

**On this page:**
[Server](#server) · [Broker](#broker) · [CLI](#cli) · [The SSRF guard is two variables](#the-ssrf-guard-is-two-variables) · [Variables that are not what they look like](#variables-that-are-not-what-they-look-like)

---

## Server

Binary `agent-cordon-server`. `agent-cordon-server --help` prints an abridged version of
this table; the full one is here.

### Core

| Variable | Default | Description |
|---|---|---|
| `AGTCRDN_LISTEN_ADDR` | `0.0.0.0:3140` | Address and port the server binds. This, not `AGTCRDN_PORT`, is the server's listen setting. |
| `AGTCRDN_BASE_URL` | — | The URL your users reach this server on. The device-flow activation URL, the OAuth2 MCP callback redirect URI, and `GET /install.sh` are all built from it. Set it before anyone enrolls; see [the fallbacks](#agtcrdn_base_url-and-its-two-fallbacks) below. |
| `AGTCRDN_DB_PATH` | `./data/agent-cordon.db` | SQLite database file. SQLite is the only storage backend. The container image sets `/data/agent-cordon.db`. |
| `AGTCRDN_REPLICA_MODE` | `single` | `unsafe-shared` disables the single-instance database guard. An unrecognised value stops startup rather than falling back. |

### Secrets and bootstrap

| Variable | Default | Description |
|---|---|---|
| `AGTCRDN_MASTER_SECRET` | auto-generated | The master encryption key, minimum 16 characters. Unset, the server generates one and writes it to `<db dir>/.secret` (mode 0600). Set and persist it in production. See [Master Key](master-key.md). |
| `AGTCRDN_MASTER_KEY_VERSION` | `1` | Version number of the current master secret. Every encrypted row records the version that sealed it. |
| `AGTCRDN_PREVIOUS_MASTER_SECRET` | — | The secret for version N-1, set only for the duration of a [rotation](master-key.md#key-rotation). Must differ from `AGTCRDN_MASTER_SECRET`, and requires `AGTCRDN_MASTER_KEY_VERSION` of at least 2. |
| `AGTCRDN_ROOT_USERNAME` | `root` | Bootstrap admin username. Used only when the user table is empty. |
| `AGTCRDN_ROOT_PASSWORD` | generated | Bootstrap admin password, printed once to stderr on first boot. Minimum 12 characters when set. The container entrypoint persists a generated one to `/data/.root_password`. |

### Key derivation

Applies to master-secret stretching, password hashing and secret hashing alike. See
[Master Key](master-key.md).

| Variable | Default | Description |
|---|---|---|
| `AGTCRDN_KDF_SALT` | derived per secret | HKDF salt override, applied to the current and the previous master secret alike. Unset, each secret derives its own salt, which is the safe default. Once set it must stay set, including through a rotation. |
| `AGTCRDN_ARGON2_M_COST_KIB` | `65536` | Argon2id memory cost in KiB. An unparseable value stops startup. |
| `AGTCRDN_ARGON2_T_COST` | `3` | Argon2id iterations. |
| `AGTCRDN_ARGON2_P_COST` | `4` | Argon2id lanes. |

### Logging

| Variable | Default | Description |
|---|---|---|
| `AGTCRDN_LOG_LEVEL` | `info` | `trace`, `debug`, `info`, `warn` or `error`. The CLI defaults to `warn` instead. |
| `AGTCRDN_LOG_FORMAT` | `json` | `json` or `pretty`. |

### Sessions, tokens and limits

Values marked "floor" or "clamped" are corrected silently rather than refused.

| Variable | Default | Description |
|---|---|---|
| `AGTCRDN_SESSION_TTL` | `28800` | Admin session lifetime in seconds (8 hours). |
| `AGTCRDN_SESSION_CLEANUP_INTERVAL` | `300` | Interval in seconds for the background sweep of expired sessions, OIDC states, MCP OAuth states and rate-limiter entries. Floor 10. |
| `AGTCRDN_AUTH_CODE_TTL` | `600` | OAuth authorization code TTL in seconds. |
| `AGTCRDN_DEVICE_CODE_TTL_SECS` | `600` | Device code TTL in seconds. Clamped to 30–3600. |
| `AGTCRDN_DEVICE_CODE_POLL_INTERVAL_SECS` | `5` | Interval the broker is told to poll at while awaiting approval. Clamped to 1–60. |
| `AGTCRDN_BOOTSTRAP_TOKEN_TTL` | `900` | Bootstrap token TTL in seconds. Clamped to 60–86400. |
| `AGTCRDN_OIDC_STATE_TTL` | `600` | OIDC login state TTL in seconds. Floor 60. |
| `AGTCRDN_LOGIN_MAX_ATTEMPTS` | `5` | Failed logins per username before lockout. Floor 1. |
| `AGTCRDN_LOGIN_LOCKOUT_SECONDS` | `30` | Lockout duration in seconds. Floor 1. |
| `AGTCRDN_TRUST_FORWARDED_HEADERS` | `false` | Trust `X-Forwarded-For` as the client address for per-address limits. Only behind a reverse proxy that overwrites the header. |

### Outbound calls

| Variable | Default | Description |
|---|---|---|
| `AGTCRDN_PROXY_TIMEOUT_SECONDS` | `30` | Timeout for the server's own outbound calls. |
| `AGTCRDN_PROXY_MAX_RESPONSE_BYTES` | `10485760` | Response cap in bytes (10 MiB). Floor 1 KiB. |
| `AGTCRDN_PROXY_ALLOW_LOOPBACK` | `false` | Turns the SSRF guard off. Development only. See [below](#the-ssrf-guard-is-two-variables). |

### Templates

The credential, MCP and policy catalogues are compiled into the binary from `data/`. Each
variable names a directory of extra JSON templates merged with the built-in set by `key`,
where a runtime template replaces a built-in of the same key. The directories are read
**once at startup**: restart the server after adding or editing a template.

| Variable | Default | Description |
|---|---|---|
| `AGTCRDN_MCP_TEMPLATES_DIR` | — | Extra MCP marketplace templates. This is the only supported way to put your own MCP server in the marketplace; see [Granting MCP Server Access](granting-mcp-server-access.md#adding-your-own-server-to-the-marketplace). |
| `AGTCRDN_CREDENTIAL_TEMPLATES_DIR` | — | Extra credential templates. |
| `AGTCRDN_POLICY_TEMPLATES_DIR` | — | Extra policy templates. |
| `AGTCRDN_INSTANCE_LABEL` | `AgentCordon` | The `client_name` sent in OAuth Dynamic Client Registration. Useful when several AgentCordon instances register with the same provider. |

### `AGTCRDN_BASE_URL` and its two fallbacks

Unset, the server has two different fallbacks and neither is good.

- The device-flow activation URL and the OAuth2 MCP callback redirect URI use `http://`
  plus `AGTCRDN_LISTEN_ADDR`. In the shipped container that is `http://0.0.0.0:3140`, an
  address no browser can open.
- `GET /install.sh` and `GET /install.ps1` use the `Host` header of the request that
  fetched them, with the scheme taken from `X-Forwarded-Proto` and defaulting to `http`.

A TLS deployment that does not set this variable must therefore have its reverse proxy
send `X-Forwarded-Proto: https`, or the installer it serves points at `http://`. Setting
`AGTCRDN_BASE_URL` removes both problems.

---

## Broker

Binary `agentcordon-broker`. Every variable here has an equivalent flag, shown in the
first column; the flag wins over the environment.

| Variable (flag) | Default | Description |
|---|---|---|
| `AGTCRDN_SERVER_URL` (`--server-url`) | `http://localhost:3140` | The AgentCordon server the broker talks to. |
| `AGTCRDN_BROKER_PORT` (`--port`) | `0` | Listen port. `0` means pick a free one and write the URL to `~/.agentcordon/broker.port`, which is how the CLI finds it. There is no fixed default port. |
| `AGTCRDN_BROKER_BIND` (`--bind`) | `127.0.0.1` | Bind address. A non-loopback bind is refused unless TLS or a shared secret is also configured. |
| `AGTCRDN_BROKER_SHARED_SECRET` (`--shared-secret`) | — | Secret every request except `GET /health` must present in `X-AgentCordon-Broker-Secret`. Required for a non-loopback bind without TLS. The CLI reads the same variable. |
| `AGTCRDN_BROKER_TLS_CERT` (`--tls-cert`) | — | PEM certificate chain. Must be given together with the key; the broker then serves HTTPS itself. |
| `AGTCRDN_BROKER_TLS_KEY` (`--tls-key`) | — | PEM private key. |
| `AGTCRDN_DATA_DIR` (`--data-dir`) | `~/.agentcordon` | Directory for the broker's keys, tokens and runtime files: `broker.key`, `tokens.enc`, `workspaces.json`, `broker.port`, `broker.pid`, `broker.lock`. See the warning below. |
| `AGTCRDN_MCP_SYNC_INTERVAL` (`--mcp-sync-interval`) | `60` | MCP config sync interval in seconds. |
| `AGTCRDN_TOKEN_TTL_BUFFER` (`--token-ttl-buffer`) | `60` | Seconds before expiry at which the broker proactively refreshes its access token. |
| `AGTCRDN_PROXY_ALLOW_LOOPBACK` (`--proxy-allow-loopback`) | `false` | Turns the SSRF guard off for the broker's own outbound calls. Development only. See [below](#the-ssrf-guard-is-two-variables). |

> **The CLI does not read `AGTCRDN_DATA_DIR`.** It always looks for
> `~/.agentcordon/broker.port`. A broker started on a different data directory is
> invisible to CLI auto-discovery, and every CLI invocation then needs
> `AGTCRDN_BROKER_URL` pointed at the broker's actual URL.

---

## CLI

Binary `agentcordon`. See the [CLI Reference](cli-reference.md) for commands and flags.

| Variable | Default | Description |
|---|---|---|
| `AGTCRDN_BROKER_URL` | auto-discovered | Override of broker discovery, which normally reads `~/.agentcordon/broker.port`. Must be plain `http://` to a loopback host, or any `https://` URL. This is also the way to reach a broker started on a non-default data directory. |
| `AGTCRDN_BROKER_SHARED_SECRET` | — | Sent as `X-AgentCordon-Broker-Secret` when the broker requires one. |
| `AGTCRDN_BROKER_CA` | — | Extra PEM trust anchor for a broker serving its own certificate. |
| `AGTCRDN_WORKSPACE_DIR` | `.` | Where the CLI looks for and creates the `.agentcordon/` workspace directory. |
| `AGTCRDN_SERVER_URL` | — | Equivalent to `agentcordon register --server-url`. Read by `register` only. |
| `AGTCRDN_LOG_LEVEL` | `warn` | CLI log filter. Note the different default from the server's `info`. |

---

## The SSRF guard is two variables

One resolving check sits in front of every outbound call in the system. It refuses
non-HTTP schemes, `localhost` and any `*.localhost` name before DNS, and every reserved
IPv4 and IPv6 range, unwrapping IPv4-mapped, NAT64 and 6to4 forms first. A hostname that
resolves to a reserved address is refused.

`AGTCRDN_PROXY_ALLOW_LOOPBACK` turns that guard **off entirely** — not just the loopback
rule. Every private and reserved range becomes a reachable target. There is no allow-list
form: no CIDR variable, no per-host exception.

The server and the broker each read the variable for their own outbound calls, and setting
it on one does nothing for the other.

| Set on | Covers |
|---|---|
| **Broker** | `agentcordon proxy` and `agentcordon mcp-call` — every call the broker makes to your API or your MCP server with a credential injected. |
| **Server** | MCP tool discovery (the `initialize` / `tools/list` probe a marketplace install runs) and OAuth discovery (the MCP endpoint's 401 probe, the RFC 9728 protected-resource document, the RFC 8414 authorization-server metadata). |

An upstream on a private or loopback address needs **both**. Without the broker's copy the
call is refused at proxy time; without the server's, a marketplace install reports success
and discovers no tools.

Separately, an `oauth2_client_credentials` token endpoint on plain HTTP is governed by its
own rule — HTTPS required, with the literal hosts `localhost`, `127.0.0.1` and `::1`
exempt — which this variable does not affect.

---

## Variables that are not what they look like

| Variable | What it actually is |
|---|---|
| `AGTCRDN_PORT` | **Not read by the server.** It is the *host* side of the published port mapping in the shipped Compose files (`"${AGTCRDN_PORT:-3140}:3140"`). It has no effect on a plain `docker run` or on the binary. |
| `AGTCRDN_DB_TYPE` | Removed in 0.4.0. It named the PostgreSQL backend; a server started with it set refuses to boot. |
| `AGTCRDN_DB_URL` | Removed in 0.4.0, alongside `AGTCRDN_DB_TYPE`. `AGTCRDN_DB_PATH` takes a file path, not a connection URL. |

OAuth provider clients — the `client_id` and `client_secret` AgentCordon presents to an
upstream authorization server — are **not** environment variables. They are managed in
Settings → MCP Identity → OAuth Provider Clients and stored encrypted in the database. See
[Granting MCP Server Access](granting-mcp-server-access.md).

---

> **See also:** [Deployment](deployment.md) · [Installation](installation.md) · [Master Key](master-key.md) · [System Architecture](system-architecture.md)
