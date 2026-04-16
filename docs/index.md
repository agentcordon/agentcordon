<div align="center">

# AgentCordon

### Secure credential brokering and policy enforcement for autonomous AI agents

[![Server](https://img.shields.io/badge/port-3140-blue)]() [![Cedar](https://img.shields.io/badge/policy-Cedar_v4-green)]() [![Rust](https://img.shields.io/badge/built_with-Rust-orange)]()

</div>

---

AgentCordon sits between your AI agents and the secrets they need. Agents never hold long-lived credentials -- instead, they authenticate with Ed25519 challenge-response, request credentials through Cedar policy checks, and the broker injects credentials server-side so agents never see raw secrets.

---

## Key Capabilities

| | Capability | Description |
|---|---|---|
| | **Zero-Trust Credential Vending** | Credentials encrypted at rest (AES-256-GCM), vended via ECIES -- agents never see raw secrets |
| | **Cedar Policy Engine** | Fine-grained authorization with deny-by-default, tag-based access, and per-tool granularity |
| | **MCP Server Bridge** | Proxy MCP tool calls across workstations with automatic credential injection |
| | **Ed25519 + P-256 Identity** | Challenge-response auth with short-lived ES256 JWTs -- no passwords, no API keys |
| | **Full Audit Trail** | Every credential vend, policy decision, and tool call is logged with correlation IDs |
| | **4-Crate Rust Architecture** | Core library + control-plane server + broker daemon + thin CLI, backed by SQLite or PostgreSQL |

---

## Quick Start

### 1. Start the server

```bash
docker compose up -d
```

Open [http://localhost:3140](http://localhost:3140). Default admin credentials are printed to the console on first boot.

### 2. Start the broker

The broker daemon runs on the user's machine (or as a shared service) and manages OAuth sessions with the server:

```bash
agentcordon-broker --server-url http://localhost:3140
```

On first run the broker requests a device code from the server and prints a 4-word passphrase plus an activation URL. Approve the registration in any browser, on any host.

### 3. Set up a workspace

From your agent's project directory:

```bash
agentcordon setup http://localhost:3140
```

This uses [RFC 8628 Device Authorization Grant](https://datatracker.ietf.org/doc/html/rfc8628) -- the same flow as `gh auth login` and `az login --use-device-code`. Open the activation URL in any browser, enter the 4-word code, and click **Approve**. The CLI generates an Ed25519 keypair, registers the workspace with the broker, and writes agent instruction files -- all in one step.

<details>
<summary>Manual setup (advanced)</summary>

If you prefer to control each step individually:

```bash
agentcordon init                 # Generate Ed25519 keypair + agent instruction files
agentcordon register             # Start the device flow and register workspace with broker
```

</details>

### 4. Use credentials

```bash
agentcordon credentials                                    # List available credentials
agentcordon proxy github-token GET https://api.github.com/user   # Proxied API call
```

The CLI routes all requests through the broker. Credentials are injected server-side and never reach the agent.

---

## Documentation

### Getting Started

| Page | Description |
|------|-------------|
| **[Workspace Enrollment](workspace-enrollment.md)** | How agents establish identity -- Ed25519 keypairs, device-code registration, broker enrollment |
| **[Granting MCP Server Access](granting-mcp-server-access.md)** | Connect workspaces to MCP servers across machines with Cedar policies |
| **[Upgrading](upgrading.md)** | Zero-downtime upgrades for server and CLI -- migrations, backups, rollback |

### Architecture & Security

| Page | Description |
|------|-------------|
| **[System Architecture](system-architecture.md)** | 4-crate overview, API routes, middleware, data flow diagrams |
| **[Master Key](master-key.md)** | HKDF-SHA256 key derivation, zeroization, nonce safety, key rotation |
| **[Credential Encryption](credential-encryption.md)** | AES-256-GCM at rest, ECIES vending, credential transforms, SSRF protection |
| **[Authorization & Cedar Policy](authorization-and-cedar-policy.md)** | Entity types, actions, deny-by-default, default policy walkthrough |

### Reference

| Page | Description |
|------|-------------|
| **[CLI Reference](cli-reference.md)** | Complete command reference -- `setup`, `proxy`, `mcp-servers`, `mcp-tools`, `mcp-call`, and all flags |

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
│  └───────────────┘  │          │        │  │  ES256 JWT Issuer        │    │
│                     │  ┌───────▼─────┐  │  └──────────────────────────┘    │
└─────────────────────┘  │ agentcordon │  │                                  │
                         │ broker      │◄─┼─►┌─────────┐  ┌───────────┐     │
                         │ (:3141)     │  │  │ SQLite  │  │ Postgres  │     │
                         └─────────────┘  │  └─────────┘  └───────────┘     │
                                          └──────────────────────────────────┘
```

The CLI talks to the **broker** (not the server directly). The broker holds OAuth tokens, vends credentials, and proxies upstream requests. Credentials never leave the broker boundary.

---

## Environment Variables

Key server configuration -- see [System Architecture](System-Architecture.md#-deployment) for the full list.

| Variable | Default | Description |
|----------|---------|-------------|
| `AGTCRDN_LISTEN_ADDR` | `0.0.0.0:3140` | Server bind address |
| `AGTCRDN_MASTER_SECRET` | Auto-generated | Master encryption key ([details](master-key.md)) |
| `AGTCRDN_DB_TYPE` | `sqlite` | `sqlite` or `postgres` |
| `AGTCRDN_SEED_DEMO` | `true` | Seed demo data on first boot |
