# Changelog

All notable changes to AgentCordon are documented in this file.

## [0.2.2] - 2026-04-08

### Fixed

- **OAuth2 refresh token rotation** — the broker now persists rotated refresh tokens back to the server when an upstream OAuth provider issues a new `refresh_token` on exchange. Previously, rotated tokens were discarded with a warning, which broke any RFC 6749 §6-compliant provider (Notion, Google, OAuth 2.1 implementations) after the first refresh: the cached access token would mask the problem for ~1 hour, then every subsequent call would return 401 until manual re-consent. The fix is atomic — if the server-side persistence call fails, the new access token is also not cached, preventing state divergence across broker restarts. (`crates/broker/src/oauth2_refresh.rs`, new server endpoint `POST /api/v1/workspaces/mcp/rotate-refresh-token`)
  - **Recovery note**: users currently locked out of a rotating provider must re-authorize the MCP server once through the admin UI. The fix cannot recover refresh tokens that have already been invalidated by the upstream.

- **MCP server template URLs refreshed** — verified all 12 remote MCP templates in `data/mcp-templates/` against current vendor documentation and updated endpoints that had migrated from SSE to streamable HTTP. Changed URLs: `asana` (`/sse` → `/v2/mcp`, deprecating 2026-05-11), `cloudflare` (`/sse` → `/mcp`), `intercom` (`/sse` → `/mcp`), `wix` (`/sse` → `/mcp`). Transport aligned from `sse` to `http` on: `asana`, `atlassian`, `cloudflare`, `github`, `granola`, `intercom`, `linear`, `notion`, `sentry`, `wix`. Granola's `oauth2_resource_url` updated to include the `/mcp` path suffix to match its RFC 9728 protected-resource metadata. PayPal and Square kept on `/sse` since their vendor docs still publish that as canonical.

- **Release workflow publishes broker binary** — `build-broker` matrix added to `.github/workflows/release.yml`, mirroring the CLI's target set (5 targets including Windows). Previously, `/install.sh` served by the running server tried to download `agentcordon-broker-<target>` from GitHub releases and 404'd because no job was uploading it.

- **Linux binary glibc compatibility** — all three Rust build jobs (`build-gateway`, `build-broker`, `build-server`) now run on `ubuntu-22.04` (glibc 2.35) instead of `ubuntu-latest` (glibc 2.39). Fixes `GLIBC_2.38 not found` / `GLIBC_2.39 not found` errors on Ubuntu 22.04, Debian 12, and other distros with older glibc.

- **Install script `curl | sh` compatibility** — the install script served by `GET /install.sh` now re-execs itself under bash when invoked via `sh` (e.g. Debian/Ubuntu `/bin/sh` is dash, which doesn't support `set -o pipefail`). Users running `curl ... | sh` no longer get `Illegal option -o pipefail`.

- **Repository URL** — corrected stale `hotnops/AgentCordon` reference in workspace `Cargo.toml`.

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
