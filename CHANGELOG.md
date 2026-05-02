# Changelog

All notable changes to AgentCordon are documented in this file.

## [Unreleased]

### Added

- **MCP servers can now be shared across multiple workspaces owned by the same user.** New `POST /api/v1/mcp-servers/{id}/workspaces` (body `{ workspace_ids: [UUID] }`, 201 on any added, 200 on all already-bound, idempotent on re-add; 403 for non-owner callers *and* for cross-user bind attempts where a target workspace's owner differs from the MCP's `created_by_user` — admin/root bypass this cross-owner check; 404 for unknown MCP or a workspace that does not exist; 422 on empty array). New `DELETE /api/v1/mcp-servers/{id}/workspaces/{workspace_id}` (204 on success; 403 for non-owner; 404 for unknown MCP or unknown binding; **409 Conflict** with `{"error":{"code":"conflict","message":"cannot remove last workspace binding — delete the MCP server instead"}}` when removing the deletion would leave the MCP with zero bindings — applies to admins too, the rule is a state invariant). The MCP detail page in the web UI has a new **Share with workspace** action — a modal with a multi-select of the owner's other workspaces — plus a per-row ✕ to unshare. New audit events `McpServerSharedWithWorkspace` and `McpServerUnsharedFromWorkspace` (one event per newly-created or -removed row; idempotent re-add emits zero events; the 409 last-binding rejection emits no state-change event). Unshare is eventually consistent: the target workspace's broker keeps the MCP cached until its next `mcp_sync` tick (~30 s) — for immediate revocation, disable or delete the MCP. Backed by a new `mcp_server_workspaces(mcp_server_id, workspace_id, created_at, created_by_user)` junction table with `ON DELETE CASCADE` from both parents; existing 1:1 `mcp_servers.workspace_id` records are backfilled into the junction by migration 010, and `mcp_servers.workspace_id` becomes an immutable audit anchor (never mutated by share, unshare, or removing the original workspace's binding).

### Changed

- **`agentcordon register` is now the one canonical workspace-registration command.** When you pass `--server-url <url>` (or set `AGTCRDN_SERVER_URL`) and no broker is running, `register` auto-starts a local broker pointed at that server before kicking off the RFC 8628 device code flow — matching the old `agentcordon setup` UX. Use `agentcordon init && agentcordon register --server-url <url>` for first-time onboarding.
- Error messages for "workspace needs re-registration" now point users at `agentcordon register --force` instead of the removed `agentcordon setup` command.
- **`GET /api/v1/mcp-servers/{id}` response's `installed_workspaces`** now lists every workspace bound to the MCP via the new junction table (was previously always a 0-or-1-element vec derived from `mcp_servers.workspace_id`). `mcp_servers.workspace_id` is kept as a legacy "original provisioning workspace" field for audit history; routing and authorization queries now go through the junction.
- **`GET /api/v1/mcp-servers?workspace_id=…`** joins through the junction so an MCP bound to multiple workspaces appears in each of their listings. `device_id` is accepted as a legacy alias.
- **Broker `mcp_sync`** queries MCP configs for a workspace by joining through `mcp_server_workspaces` instead of matching `mcp_servers.workspace_id` directly. Cache shape, sync cadence, and the workspace-facing API are unchanged.

### Removed

- **`agentcordon setup` subcommand.** Its broker auto-start behaviour moved into `agentcordon register --server-url`, so there is one registration path instead of two. Users on existing scripts should replace `agentcordon setup <url>` with `agentcordon init && agentcordon register --server-url <url>` (if keypairs are not yet generated) or `agentcordon register --server-url <url>` (if `init` has already run).
- Broken `GET /enroll.md` documentation pointer in the top-level README — the endpoint had no handler and always 404'd.
- Misleading copy on the MCP detail page that said "Workspaces owned by the same user as this MCP server automatically have access…". The Workspaces section on the detail page is now the sole source of truth for which workspaces are bound, and the same-owner Cedar policy (3a) only matches bindings that actually exist in the junction. Similar misleading copy on the MCP Permissions tab ("Default policies allow all enabled workspaces to access enabled MCP servers") is replaced with an accurate same-owner + bound description.

### Fixed

- **OAuth2 `client_credentials` proxy flow now correctly exchanges the client secret for an access token before injecting it into upstream requests.** Previously, the broker read `credential_type` from the ECIES envelope plaintext where the server never writes it, so every `oauth2_client_credentials` proxy call silently skipped the token exchange and injected the raw `client_secret` as a `Bearer` token. Against Microsoft Entra ID this manifested as `AADSTS700016` / `IDX14100: JWT is not well formed, there are no dots (.)`; other providers returned 401s with varying error text. The broker now reads `credential_type` from the outer `VendResponse` envelope where it is actually set. Verified live against Entra (`/v1.0/users`, `$batch`, cache hit and miss, error paths). Only `oauth2_client_credentials` credentials were affected — `oauth2_user_authorization`, `api_key`, and `bearer_token` flows were already correct. Any cached bearer tokens from before the fix are safely ignored because the broker now re-fetches on the correct code path. (`crates/broker/src/routes/proxy.rs`, `crates/broker/src/vend.rs`)

## [0.3.0] - 2026-04-09

### Added

- **RFC 8628 Device Authorization Grant** for workspace registration. The broker prints a 4-word passphrase user code and an activation URL; users approve the registration from any browser, on any host — matching the `gh auth login`, `az login --use-device-code`, and `aws sso login` pattern. New endpoints: `POST /oauth/device/code`, `POST /oauth/token` (extended with the `urn:ietf:params:oauth:grant-type:device_code` grant), and `GET/POST /activate` with `GET /activate/success`. New `device_codes` table. New audit events: `DeviceCodeIssued`, `DeviceCodeApproved`, `DeviceCodeDenied`, `DeviceCodeExpired`.
- **Windows PowerShell installer** — one-liner `irm https://<server>/install.ps1 | iex`. Downloads both `agentcordon.exe` and `agentcordon-broker.exe` from the GitHub release, verifies SHA-256 checksums, installs to `%LOCALAPPDATA%\AgentCordon\bin`, and adds that directory to the user PATH. New server route `GET /install.ps1` serves the templated installer. (`tools/install.ps1`)
- Broker now runs on Windows with the same lifecycle as on Unix: started from a terminal, dies with the terminal, no Windows service required.

### Changed

- Workspace registration UX: users copy a 4-word code into a browser instead of waiting for a loopback redirect. No more ephemeral listener on the broker host.

### Breaking

- **Workspace registration now uses RFC 8628 device flow exclusively.** The previous loopback Authorization Code flow has been removed, along with the broker's ephemeral HTTP listener. Any automation that drove the old loopback callback will stop working. There is no `--legacy-loopback` flag. **Existing registered workspaces are unaffected** — their refresh tokens continue to work and no re-registration is required.

### Fixed

- **Broker works on a different host from the user's browser** — remote dev boxes, containers, headless servers, and SSH sessions. Previously the loopback callback required broker, browser, and server to share a host. This was the original headless-broker bug.

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
