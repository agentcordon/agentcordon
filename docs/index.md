<div align="center">

# AgentCordon

### Secure credential brokering and policy enforcement for autonomous AI agents

[![Server](https://img.shields.io/badge/port-3140-blue)]() [![Cedar](https://img.shields.io/badge/policy-Cedar_v4-green)]() [![Rust](https://img.shields.io/badge/built_with-Rust-orange)]()

</div>

---

AgentCordon sits between your AI agents and the secrets they need. Agents never hold long-lived credentials -- instead, the CLI signs every request to its broker with an Ed25519 workspace key, the broker presents an opaque OAuth 2.0 access token to the server, the server decides with Cedar, and the broker injects the credential into the outgoing call so the agent never sees a raw secret.

> **Port 3140 is the default, and every badge, diagram, URL and example on this page assumes it.** Change it with `AGTCRDN_LISTEN_ADDR` (the address and port the server binary binds) or, under Compose, with `AGTCRDN_PORT` (the *host* side of the published mapping) -- and read the examples with your own port substituted.

---

## Key Capabilities

| | Capability | Description |
|---|---|---|
| | **Zero-Trust Credential Vending** | Credentials encrypted at rest (AES-256-GCM), vended via ECIES -- agents never see raw secrets |
| | **Cedar Policy Engine** | Fine-grained authorization with deny-by-default, tag-based access, and per-tool granularity |
| | **MCP Server Bridge** | Proxy MCP tool calls across workstations with automatic credential injection |
| | **Ed25519 + P-256 Identity** | Ed25519 request signing from the CLI, RFC 8628 device-code enrolment, opaque OAuth 2.0 bearer tokens -- no passwords, no API keys, and no JWT for a client to verify |
| | **Full Audit Trail** | Every credential vend, policy decision, and tool call is logged with correlation IDs |
| | **5-Crate Rust Architecture** | Core library + control-plane server + broker daemon + thin CLI + a shared identity crate, backed by SQLite |

---

## Prerequisites

| You want to | You need |
|-------------|----------|
| Run the server from a Compose file | **Docker with the Compose plugin.** Check with `docker compose version` -- on many distributions the plugin is a separate install from the engine. Without it, use the `docker run` form in step 1(c). |
| Run the server without Compose | **Docker** alone (`docker --version`). |
| Build the server, CLI or broker from source | **A Rust toolchain** (stable). See [Building from Source](../README.md#building-from-source); there are no system libraries to install. |
| Approve a workspace enrollment | **A browser**, on any machine that can reach the server. |

## Quick Start

### 1. Start the server

Three ways, all running the same server -- pick whichever matches what you have.

**(a) From a clone of the repository.** Builds the image from this tree, so it always matches the version you are reading about:

```bash
git clone https://github.com/agentcordon/agentcordon.git
cd agentcordon
docker compose -f docker-compose.build.yml up -d --build
```

**(b) From the published image.** `docker-compose.yml` pulls `ghcr.io/agentcordon/agentcordon:latest`; if no release image exists yet for the version you want, Compose fails on the pull and (a) or (c) is the answer:

```bash
docker compose up -d
```

**(c) Without the Compose plugin.** Plain `docker run`, same volume, same port. From a clone, build the image first, so it matches the tree you are on -- the `docker run` equivalent of (a):

```bash
docker build -t agentcordon:local .
docker run -d --name agentcordon -p 3140:3140 \
  -v agentcordon-data:/data \
  agentcordon:local
```

Without a clone, run the published image -- with (b)'s caveat one step sharper: `:latest` is the tag that always exists, so nothing fails on the pull and you may quietly be running an **older** server than the release you are following.

```bash
docker run -d --name agentcordon -p 3140:3140 \
  -v agentcordon-data:/data \
  ghcr.io/agentcordon/agentcordon:latest
```

Open [http://localhost:3140](http://localhost:3140). Default admin credentials are printed to the console on first boot.

Neither Compose file sets `container_name`, so container and volume names come from the Compose project name (the directory name by default). To run two stacks on one host, give each its own: `COMPOSE_PROJECT_NAME=agentcordon-staging AGTCRDN_PORT=3141 docker compose up -d`.

Then set `AGTCRDN_BASE_URL` to the URL your users will actually type and restart. Everything absolute the server hands out -- the device-flow activation URL, the OAuth2 MCP callback redirect, `GET /install.sh` -- is built from it, and without it the server falls back to `http://` plus its bind address (`http://0.0.0.0:3140` in the shipped container), which no browser can open.

### 2. Install the CLI and the broker

Both are static binaries, and your server serves an installer:

```bash
curl -fsSL https://agentcordon.example.com/install.sh | sh
```

It picks the build for your OS and architecture, verifies it against the release's `SHA256SUMS`, and installs `agentcordon` and `agentcordon-broker` into `~/.local/bin`. On Windows use `irm https://agentcordon.example.com/install.ps1 | iex`. Without a server to install from, take the assets and `SHA256SUMS` straight from [the latest GitHub release](https://github.com/agentcordon/agentcordon/releases/latest).

### 3. Start the broker

The broker daemon runs on the user's machine (or as a shared service) and manages OAuth sessions with the server:

```bash
agentcordon-broker --server-url http://localhost:3140
```

The broker binds `127.0.0.1` on an auto-selected port and writes the URL to `~/.agentcordon/broker.port`, which is how the CLI finds it -- there is no default port to remember and nothing to export. (`--data-dir` / `AGTCRDN_DATA_DIR` moves that directory; the CLI does not read that variable, so a relocated broker needs `AGTCRDN_BROKER_URL`. See the [CLI Reference](cli-reference.md#files-and-directories).)

The broker prints no code and asks for nothing on first run -- it generates its keypair, finds no workspace tokens, and listens. Enrollment is step 4: `agentcordon register` is what requests the device code and prints the 4-word passphrase and the activation URL, which you approve in any browser, on any host. Leave the broker running and carry on.

### 4. Set up a workspace

From your agent's project directory:

```bash
agentcordon init
agentcordon register --server-url http://localhost:3140
```

This uses [RFC 8628 Device Authorization Grant](https://datatracker.ietf.org/doc/html/rfc8628) -- the same flow as `gh auth login` and `az login --use-device-code`. Open the activation URL in any browser, enter the 4-word code, and click **Approve**. `agentcordon register --server-url` auto-starts a local broker if none is running, registers the workspace, and completes the device flow. `agentcordon init` generated the Ed25519 keypair and wrote the agent instruction files.

<details>
<summary>Manual (broker already running)</summary>

If you already have a broker running, `--server-url` is optional:

```bash
agentcordon init                 # Generate Ed25519 keypair + agent instruction files
agentcordon register             # Start the device flow using the running broker
```

</details>

### 5. Use credentials

```bash
agentcordon credentials                                          # List available credentials
agentcordon proxy github-token GET https://api.github.com/user   # Proxied API call
```

`agentcordon proxy` takes a full URL, never a bare path.

The CLI routes all requests through the broker. Credentials are injected server-side and never reach the agent.

---

## Documentation

### Getting Started

| Page | Description |
|------|-------------|
| **[Admin UI](admin-ui.md)** | A map of the browser console -- what is on each screen, its primary action, what is behind the overflow, and which roles see it |
| **[Workspace Enrollment](workspace-enrollment.md)** | How agents establish identity -- Ed25519 keypairs, device-code registration, broker enrollment |
| **[Granting MCP Server Access](granting-mcp-server-access.md)** | Connect workspaces to MCP servers across machines with Cedar policies |
| **[Upgrading](upgrading.md)** | Zero-downtime upgrades for server and CLI -- migrations, backups, rollback |

### Architecture & Security

| Page | Description |
|------|-------------|
| **[System Architecture](system-architecture.md)** | 5-crate overview, API routes, middleware, data flow diagrams |
| **[Master Key](master-key.md)** | HKDF-SHA256 key derivation, zeroization, nonce safety, key rotation |
| **[Credential Encryption](credential-encryption.md)** | AES-256-GCM at rest, ECIES vending, credential transforms, SSRF protection |
| **[Authorization & Cedar Policy](authorization-and-cedar-policy.md)** | Entity types, actions, deny-by-default, default policy walkthrough |

### Reference

| Page | Description |
|------|-------------|
| **[CLI Reference](cli-reference.md)** | Complete command reference -- `register`, `proxy`, `mcp-servers`, `mcp-tools`, `mcp-call`, and all flags |
| **[Releasing](releasing.md)** | Cutting a release: one `cargo release` command, what the tag triggers, pre-releases, and what to do when a job fails |
| **[Domain Glossary](../CONTEXT.md)** and **[Decision Records](adr/README.md)** | Every domain term as the code uses it, with the file it lives in; and one ADR per architectural decision |

---

## Architecture at a Glance

```
                                          ┌──────────────────────────────────┐
┌─────────────────────┐                   │   AgentCordon Server (:3140)     │
│   AI Agent          │                   │                                  │
│   (Claude, Cursor)  │                   │  ┌──────────────────────────┐    │
│                     │                   │  │  Cedar Policy Engine     │    │
│  ┌───────────────┐  │   Ed25519         │  │  (deny-by-default)       │    │
│  │ agentcordon   │──┼──────────┐        │  │                          │    │
│  │ CLI           │  │          │        │  │  AES-256-GCM Vault       │    │
│  └───────────────┘  │          │        │  │  OAuth 2.0 AS + vending  │    │
│                     │  ┌───────▼─────┐  │  └──────────────────────────┘    │
└─────────────────────┘  │ agentcordon │  │                                  │
                         │ broker      │◄─┼─►┌─────────┐  ┌───────────┐     │
                         │ (auto port) │  │  │ SQLite  │                    │
                         └─────────────┘  │  └─────────┘                    │
                                          └──────────────────────────────────┘
```

The broker binds `127.0.0.1` on a port it picks at startup and records in
`~/.agentcordon/broker.port`; the CLI reads that file to find it.

The CLI talks to the **broker** (not the server directly). The broker holds OAuth tokens, vends credentials, and proxies upstream requests. Credentials never leave the broker boundary.

---

## Environment Variables

Key server configuration -- see [System Architecture](system-architecture.md#deployment) for the full list, and [Upgrading](upgrading.md#environment-variable-reference) for every variable with its default.

| Variable | Default | Description |
|----------|---------|-------------|
| `AGTCRDN_LISTEN_ADDR` | `0.0.0.0:3140` | Server bind address. (`AGTCRDN_PORT` is not read by the server -- it is only the host side of the compose port mapping.) |
| `AGTCRDN_BASE_URL` | -- | The URL users reach the server on. The device-flow activation URL, the OAuth2 MCP callback redirect, and `GET /install.sh` are built from it. Set it before anyone enrols. |
| `AGTCRDN_MASTER_SECRET` | Auto-generated | Master encryption key ([details](master-key.md)) |
| `AGTCRDN_DB_PATH` | `./data/agent-cordon.db` | SQLite database path. SQLite is the only storage backend. |
| `AGTCRDN_MCP_TEMPLATES_DIR` | -- | Extra MCP marketplace templates, merged with the built-in catalog at startup ([details](granting-mcp-server-access.md#adding-your-own-server-to-the-marketplace)) |
