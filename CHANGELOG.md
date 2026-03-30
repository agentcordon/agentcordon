# Changelog

All notable changes to AgentCordon are documented in this file.

## [3.0.0] - 2026-03-30

### Summary

AgentCordon v3.0.0 replaces the Ed25519 challenge-response workspace authentication model with a three-tier OAuth 2.0 architecture. Agents no longer receive credentials directly -- all credential access is brokered through a per-user daemon that holds OAuth tokens and proxies upstream requests.

### Architecture

```
Agent <-> CLI (agentcordon) <-> Broker (agentcordon-broker) <-> Server (agent-cordon-server)
```

- **Server** acts as an OAuth 2.0 Authorization Server with authorization code + PKCE flow, consent page, token endpoint, and dynamic client registration.
- **Broker** is a per-user persistent daemon that holds OAuth tokens, vends credentials to workspaces, and proxies upstream HTTP requests. Credentials never leave the broker boundary.
- **CLI** is a lightweight workspace agent that manages Ed25519 keypairs and signs requests to the broker. It never touches credentials.

### Added

- **OAuth 2.0 Authorization Server** on the AgentCordon server: authorization code + PKCE (S256), token endpoint, client registration, and revocation.
- **Consent page** for human-in-the-loop approval of OAuth grants (server-rendered HTML).
- **Broker daemon** (`agentcordon-broker`): per-user service that manages OAuth sessions, token refresh, credential vending, and upstream HTTP proxying.
- **Thin CLI** (`agentcordon`): new lightweight binary for workspace agents -- manages Ed25519 identity and signs requests to the broker.
- **Client credentials grant** for machine-to-machine flows (service accounts).
- **OAuth token storage** in core (SQLite and Postgres backends).
- **Database migration** `003_oauth.sql` for OAuth clients, authorization codes, and tokens.

### Breaking Changes

- **Gateway crate removed.** The `crates/gateway` crate and its binary are deleted. All gateway functionality is replaced by the broker + CLI split.
- **Ed25519 challenge-response auth removed.** Workspace identity JWTs are no longer issued or accepted. Workspaces authenticate via the broker's OAuth session.
- **Challenge-response endpoints deleted** (`/api/workspace-identity/challenge`, `/api/workspace-identity/registration`).
- **Provisioning tokens endpoint deleted.**
- **`agentcordon` CLI binary replaced.** The binary name is the same but the behavior is completely different -- it now communicates with the broker, not the server directly.
- **Workspace identity JWT validation removed** from server extractors.

### Migration Guide

1. **Deploy the new server** (v3.0.0) -- it includes the OAuth authorization server.
2. **Run the broker daemon** (`agentcordon-broker`) on each user's machine or as a shared service. The broker connects to the server and manages OAuth sessions.
3. **Re-register workspaces.** Old workspace registrations (Ed25519 challenge-response) are not compatible. Use `agentcordon register` to register each workspace with the broker.
4. **Update agent configurations.** The CLI commands (`agentcordon proxy`, `agentcordon credentials`, etc.) work the same way but now route through the broker.
5. **Remove old gateway references.** If you have scripts or configs referencing the `agentcordon` gateway binary, they need to be updated for the new CLI.

### Security Improvements

- Credentials never reach agent workspaces -- they stay within the broker boundary.
- PKCE (S256) enforced on all authorization code flows.
- OAuth tokens are scoped and time-limited with refresh rotation.
- Consent page requires explicit human approval for new grants.
- CSRF protection on consent flow via state parameter.

### Removed

- `crates/gateway` (replaced by `crates/broker` + `crates/cli`)
- Ed25519 challenge-response workspace authentication
- Workspace identity JWT issuance and validation
- `/api/workspace-identity/challenge` endpoint
- `/api/workspace-identity/registration` endpoint
- `/api/control-plane/auth` endpoint
- Provisioning tokens endpoint
- ECIES credential encryption in transit (broker holds credentials directly)

## [0.1.4] - 2026-03-15

- Downscale README GIFs for iOS Safari compatibility
- Fix GLIBC_2.38 runtime error by upgrading base image to debian:trixie-slim
- Security vulnerability reporting via GitHub issue template
- Credential description fields
- Mermaid architecture diagram in README

## [0.1.0] - Initial Release

- AES-256-GCM encrypted credential vault
- Cedar policy engine for authorization
- Ed25519 workspace identity
- Credential proxy with server-side injection
- MCP gateway with policy-controlled tool calls
- Full audit trail
- Docker and Docker Compose deployment
