# 16. `agentcordon update` is a server-pinned self-update

- **Status:** Accepted
- **Date:** 2026-09-07

## Context

Updating a workspace is two manual steps with a footgun, documented in `docs/upgrading.md` and
filed as [issue #55](https://github.com/agentcordon/agentcordon/issues/55):

1. Re-run the install one-liner (`curl -fsSL <server>/install.sh | sh`) to replace both
   `agentcordon` and `agentcordon-broker` on disk.
2. Manually restart the running broker — the install only swaps the files, and the running
   daemon keeps the old binary until it is restarted.

The footgun is in step 2. The restart has to re-supply the broker's original startup flags
(`--bind`, `--shared-secret`, `--proxy-allow-loopback`, `--port`, `--tls-cert`/`--tls-key`).
Miss one and the broker comes back subtly wrong: it loses loopback egress, or fails the CLI's
non-loopback bind rule, or drops its shared secret. Nothing tells the user which flags the old
broker had.

[ADR-0010](0010-installer-pinned-to-server-version.md) already settled that the CLI and broker
move in lockstep with the server and that the installer serves the server's own version, not
GitHub `latest`, so a workspace is never handed a build that cannot talk to its server. Any
self-update has to honour that same pin, or it reintroduces exactly the mixed-version failures
ADR-0010 removed.

## Decision

**`agentcordon update` replaces both binaries with the server's pinned version and restarts the
running broker with the flags it was already running.** One command, no footgun.

```
agentcordon update [--check] [--force] [--server-url <url>] [--yes]
```

### The version source is the server, not GitHub `latest`

`update` learns its target by fetching `{server_url}/install.sh` and parsing `AGTCRDN_VERSION`.
That script is already templated with the server's `CARGO_PKG_VERSION` (ADR-0010), so it is the
lockstep pin restated: a workspace can never update itself *ahead* of its server, and the
failure ADR-0010 describes — a signed request the server cannot parse — cannot be self-inflicted
by an update. Scraping the script is the v1 mechanism; a small `GET /version` endpoint would be
cleaner and is a follow-up, but it would require a server change and the script is authoritative
today.

The server URL resolves with the same precedence as `init` and `register`: the `--server-url`
flag, then `AGTCRDN_SERVER_URL`, then `server_url` in `~/.agentcordon/config.toml`. It is held
to the same loopback-or-https rule as `AGTCRDN_BROKER_URL`.

### The binaries come from the release, verified before either is installed

`update` downloads `agentcordon-<triple>`, `agentcordon-broker-<triple>` and `SHA256SUMS` from
the same GitHub release the installer uses, selecting the target triple by the same OS/arch
mapping as `install_script.sh`. **Both binaries are verified against `SHA256SUMS` before either
is installed**; a mismatch aborts and leaves the current binaries untouched. This is the
installer's integrity contract, reused: the same reason ADR-0010 gave for verifying downloads
applies to a self-update that runs unattended.

### The swap is atomic, and Unix-only for now

Each binary is written to a temp file in the *same directory* as its target (the CLI is
`std::env::current_exe()`; the broker is its sibling), made executable, and `rename`d over the
target. The rename is atomic within one filesystem, so a crash mid-write never leaves a
half-written binary on `PATH`. On Unix, renaming over a *running* binary is safe — the running
process holds the old inode and only new `exec`s see the replacement — which is what lets
`update` replace its own binary and the live broker's.

Windows locks a running `.exe` and cannot rename over it; the fix is the rename-self-aside
pattern (move the running exe to a `.old` name, then write the new one). That is **not
implemented in v1**: `update` refuses on Windows with a message pointing at the install
one-liner, rather than failing partway.

### The broker restart captures the running argv

`update` discovers the running broker through `~/.agentcordon/broker.port` (the CLI's own
discovery path), reads its command line from `/proc/<pid>/cmdline` (pid from
`~/.agentcordon/broker.pid`, with a `ps` fallback), stops it, and starts the freshly-installed
binary with the *same* argv. That is what removes the footgun: whatever flags the broker was
running, it comes back with. If argv cannot be recovered (no procfs — macOS — or the pid is
gone), `update` falls back to `--server-url <resolved> --port <same>` and **warns which flags
may need re-applying**. If no broker is running, there is nothing to restart and `update` says
so.

The restart is a plain spawn: the new broker must *outlive* the `update` process, unlike the
autostart path (`broker_autostart`), which on Windows binds the broker to the CLI's lifetime via
a Job Object.

### Confirmation and the escape hatches

`update` prompts for confirmation before replacing anything, unless `--yes`, and never prompts
when stdin is not a terminal (a script piping into it proceeds). `--check` reports current vs
available and changes nothing. `--force` reinstalls even when already current.

## Consequences

- **A workspace updates itself in one command, in lockstep with its server.** The two-step
  manual path in `docs/upgrading.md` stays documented as the fallback and as the only path on
  Windows.
- **Windows users still update manually.** The self-replace pattern is a known follow-up; until
  then `update` refuses on Windows loudly rather than corrupting a binary.
- **A server built from `main` ahead of a release cannot be self-updated to,** for the same
  reason the installer cannot install it: there is no matching published release, so the download
  404s and `update` says to build from source. This is the intended coupling from ADR-0010, not
  a regression.
- **The integrity contract is duplicated, not shared, with `install_script.sh`.** The shell
  installer and the Rust `update` verify the same `SHA256SUMS` the same way, in two languages.
  A change to the release layout (triple names, asset names, sums format) has to move in both.
  The unit tests pin the triple mapping and the sums format against the installer's shapes so a
  drift fails a test rather than a user's update.
- **`update` reads a pid file the broker already writes.** No new broker state: `broker.pid` has
  existed beside `broker.port` since the daemon's file setup. A broker started with a custom
  `--data-dir` is undiscoverable by both the port-file path and the pid-file path, so `update`
  treats it as "no broker running" and the config-derived fallback with its warning covers the
  restart.
