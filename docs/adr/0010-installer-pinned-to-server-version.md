# 10. The installer is pinned to the server's version, and upgrades are lockstep

- **Status:** Accepted
- **Date:** 2026-09-05

## Context

`GET /install.sh` and `GET /install.ps1` are the documented way to obtain the `agentcordon` CLI
and `agentcordon-broker`. They downloaded the **`latest`** GitHub release, whatever that
happened to be, and installed it against whatever server the user had just started.

0.4.0 makes that unsafe. Three wire contracts change with no dual-accept window:

- the CLI↔broker signed payload gains a nonce, and the identity test vectors are re-frozen
  (ADR-0008);
- the broker↔server vend shape gains `method` and `target_url` and returns
  `allowed_url_pattern` (ADR-0007), and the MCP sync envelope no longer carries refresh tokens
  or client secrets (ADR-0006);
- routes are removed (`POST /api/v1/workspaces/mcp/rotate-refresh-token`, the
  `workspace-identities` group, JWKS, the permissions-token endpoint, four dormant
  control-plane routes).

A server built from source and a `latest` installer therefore handed new users a CLI and broker
that could not talk to it, and the failure surfaced as an opaque signature or 404 error. The
installer had other problems in the same neighbourhood: it re-`exec`'d `bash` and re-fetched
itself from the server's *configured* base URL rather than the one the user reached it on, and
it installed two binaries from GitHub with **no integrity check at all**.

## Decision

**The installer serves the server's own version**, not `latest`. `GET /install.sh` and
`GET /install.ps1` substitute the server binary's `CARGO_PKG_VERSION`
(`crates/server/src/install_script.rs`). When no release exists for that version — a server
built from source ahead of a release — the installer says so and points at building from
source, rather than silently installing an incompatible older build.

Around that:

- The script is POSIX `sh` with no re-exec and no second fetch, and it downloads the release's
  `SHA256SUMS` and **verifies both binaries before installing**, aborting on a mismatch.
  `AGENTCORDON_SKIP_CHECKSUM=1` is the escape hatch for a release predating the sums file.
- The fallback `SERVER_URL` takes its scheme from `X-Forwarded-Proto` and defaults to `http`,
  because the server never terminates TLS itself. A TLS-terminating proxy must send the header,
  or the operator sets `AGTCRDN_BASE_URL`.
- **All five crates take their version from `[workspace.package]`.** A binary from this release
  must not report `0.3.3`, which is what a user might install from the published release.
- `agentcordon status` warns when the broker's version differs from the CLI's, naming both.
- `docs/upgrading.md` gains an "Upgrading from 0.3.x" section stating the lockstep requirement
  and the upgrade order, tabulating every wire-format change and every removed route, the
  operator-visible behaviour changes, a config-to-check table, and an expanded pre-upgrade
  checklist.

**Upgrades are lockstep.** Server, broker and CLI at 0.4.0 are upgraded together. There is no
dual-accept window and none is offered.

## Consequences

- A published release must exist before its installer is useful. Between cutting a version and
  publishing its assets, `GET /install.sh` tells the user to build from source. That is the
  intended behaviour, and it is why the CI/release path and the version string are coupled.
- Users cannot mix a 0.3.x CLI with a 0.4.0 broker, or a 0.4.0 broker with a 0.3.x server.
  Mixed pairs fail loudly (signature rejection, 404) rather than subtly.
- Choosing lockstep over compatibility shims is a deliberate trade for a pre-1.0 product: the
  shims would have to carry the *old* vend shape, which is the one that shipped provider
  secrets to the broker, and keeping it readable would have kept the vulnerability alive.
- Offline installs still work: the assets and `SHA256SUMS` can be taken straight from the
  GitHub release.
