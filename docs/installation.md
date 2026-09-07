> [Home](index.md) > Installation

# Installation

AgentCordon is three binaries. The **server** is the control plane and normally runs as a
container; the **broker** and the **CLI** are static binaries that run on each user's
machine. This page covers every way to get them.

The [README](../README.md#quick-start) quick start takes one path end to end. Come here
when you want a different one: a build from source, a machine without the Compose plugin,
or Windows.

Port **3140** is the server's default, and every example here assumes it. Change it with
`AGTCRDN_LISTEN_ADDR`, or under Compose with `AGTCRDN_PORT` (the host side of the
published mapping), and read the examples with your own port substituted.

**On this page:**
[Prerequisites](#prerequisites) · [The server](#the-server) · [The CLI and the broker](#the-cli-and-the-broker) · [What the installer writes](#what-the-installer-writes) · [Windows](#windows) · [From source](#from-source) · [What gets installed where](#what-gets-installed-where)

---

## Prerequisites

| You want to | You need |
|---|---|
| Run the server from a Compose file | Docker with the Compose plugin. Check with `docker compose version`; on many distributions the plugin is a separate install from the engine. |
| Run the server without Compose | Docker alone (`docker --version`), driven with `docker run`. |
| Build any of the three binaries | A Rust toolchain (stable). There are no system libraries to install. |
| Approve a workspace enrollment | A browser, on any machine that can reach the server. The device flow is copy-a-code-and-click-Approve; there is no loopback callback to forward. |

---

## The server

All four routes below run the same server. Pick the one that matches what you have.

### Docker Compose, published image

The shipped `docker-compose.yml` pulls `ghcr.io/agentcordon/agentcordon:latest`, publishes
`${AGTCRDN_PORT:-3140}:3140`, and mounts a named `agentcordon-data` volume on `/data`.

```bash
curl -fsSLO https://raw.githubusercontent.com/agentcordon/agentcordon/main/docker-compose.yml
docker compose up -d
```

Pin a version by editing the `image:` line to `ghcr.io/agentcordon/agentcordon:0.4.0`. The
release workflow pushes `<version>`, `<major>.<minor>`, `latest` (stable releases only) and
`sha-<short>`, all multi-arch for `linux/amd64` and `linux/arm64`.

### Docker Compose, built from a clone

`docker-compose.build.yml` compiles the image from this tree's `Dockerfile`, so it always
matches the source you are reading.

```bash
git clone https://github.com/agentcordon/agentcordon.git
cd agentcordon
docker compose -f docker-compose.build.yml up -d --build
```

### Plain `docker run`

Without the Compose plugin, the same volume and port by hand:

```bash
docker run -d --name agentcordon -p 3140:3140 \
  -v agentcordon-data:/data \
  ghcr.io/agentcordon/agentcordon:0.4.0
```

From a clone, build the image first and use `agentcordon:local` as the final argument:

```bash
docker build -t agentcordon:local .
```

### Tailscale sidecar

`docker-compose.tailscale.yml` runs the server behind a Tailscale sidecar with no
published ports, reachable only from your tailnet. Set `TS_AUTHKEY` first; the server
appears on the tailnet as `agentcordon` (override with `TS_HOSTNAME`).

```bash
export TS_AUTHKEY=tskey-auth-...
docker compose -f docker-compose.tailscale.yml up -d
```

### After the server starts

Open `http://localhost:3140`. The bootstrap admin username is `root` unless you set
`AGTCRDN_ROOT_USERNAME`; the password is generated on first boot and printed once to the
container's stderr (`docker compose logs agentcordon`). In the container it is also
persisted to `/data/.root_password`.

Set `AGTCRDN_BASE_URL` to the URL your users will actually type, and restart. Everything
absolute the server hands out is built from it. See
[Configuration](configuration.md#agtcrdn_base_url-and-its-two-fallbacks) for what happens
when it is unset, and [Deployment](deployment.md) for the production shape.

> **Running two stacks on one host?** Neither `docker-compose.yml` nor
> `docker-compose.build.yml` sets `container_name`, so container and volume names come from
> the Compose project name — the directory name by default. Give each stack its own project
> name and host port:
> `COMPOSE_PROJECT_NAME=agentcordon-staging AGTCRDN_PORT=3141 docker compose up -d`.

---

## The CLI and the broker

### From your server's installer

Your server serves an installer for both binaries, pinned to the server's own version
([ADR-0010](adr/0010-installer-pinned-to-server-version.md)):

```bash
curl -fsSL https://agentcordon.example.com/install.sh | sh
```

It detects your OS and architecture, downloads `agentcordon` and `agentcordon-broker` from
the matching GitHub release, verifies them against the release's `SHA256SUMS`, and installs
them to `~/.local/bin`. It is POSIX `sh` and never re-fetches itself, so `sh`, `bash`,
`dash` and `zsh` all behave identically, and it works on a server reachable at an address
the server does not know it has.

A checksum mismatch aborts the install and nothing is written.
`AGENTCORDON_SKIP_CHECKSUM=1` opts out, and must be set deliberately.

If no release exists yet for the server's version, the installer refuses and says so rather
than installing a mismatched CLI. That message is reserved for an actual HTTP 404 — a proxy,
a DNS failure or a rate-limit is reported as a network failure instead, because "build from
source" is the wrong advice for a connection problem.

`AGENTCORDON_SKIP_DOWNLOAD=1` skips the download and does everything else: use it when you
built the two binaries from source into `~/.local/bin` yourself and still want the server
recorded and PATH persisted.

## What the installer writes

Three things, each announced as it happens, and each with an opt-out.

### The binaries

`agentcordon` and `agentcordon-broker`, mode `0755`, in `~/.local/bin`.

### The server it came from

The installer is served *by* your server, so it knows the origin you fetched it from. It
records that in `~/.agentcordon/config.toml`:

```toml
server_url = "https://agentcordon.example.com"
```

This is why `agentcordon init` and `agentcordon register` need no `--server-url`. The CLI
resolves a server URL in one order everywhere: the `--server-url` flag, then
`AGTCRDN_SERVER_URL`, then this file. `agentcordon status` prints which of the three
answered. (The CLI does not read `AGTCRDN_DATA_DIR`, so neither does the installer: the
config file is always under `~/.agentcordon/`.)

Only the `server_url` key is rewritten, so anything else you put in the file survives. If the
file already names a *different* server, the installer replaces it and prints both URLs —
running a second server's installer must not silently repoint the machine.

### PATH

`export PATH="…:$PATH"` printed to a terminal is gone when that terminal closes, and it does
not parse in nushell at all. So, like rustup and uv, the installer appends a
marker-delimited block to the file your login shell actually reads, chosen from `$SHELL`:

| `$SHELL` | File | Line |
|---|---|---|
| bash | `~/.bashrc` (`~/.bash_profile` on macOS, whose terminals are login shells) | `export PATH="$HOME/.local/bin:$PATH"` |
| zsh | `~/.zshrc` | `export PATH="$HOME/.local/bin:$PATH"` |
| fish | `~/.config/fish/conf.d/agentcordon.fish` | `fish_add_path "$HOME/.local/bin"` |
| nushell | `~/.config/nushell/env.nu` | `$env.PATH = ($env.PATH \| prepend "…/.local/bin")` |

The block is delimited by `# >>> agentcordon >>>` and `# <<< agentcordon <<<`; deleting it
undoes the change, and a second install leaves the file byte-identical. Nothing is written
when `~/.local/bin` is already on your `PATH`, or when `$SHELL` is one the installer has no
rule for — it prints the line for you to add instead.

**`AGENTCORDON_NO_MODIFY_PATH=1`** declines the edit and prints the line. `install.ps1`
honours it too.

Open a new terminal, or source the file, before running `agentcordon`.

### Then set up a project

Installing the binaries does not set up a project. From the project directory your coding
agent opens:

```bash
agentcordon init
```

`init` asks which agent runtimes you use, pre-checking the ones it can see, writes the
AgentCordon [Agent Skill](https://agentskills.io/specification) into the directory each of
them reads — `.agents/skills/agentcordon/SKILL.md` for most, `.claude/skills/` for Claude
Code and Cline, `.kiro/skills/` for Kiro — and then enrolls the workspace with the server
recorded above. It remembers the runtime choice, so a rerun is quiet; `--reconfigure` asks
again, `--agent <id>` skips the question, and `--no-register` skips the enrollment. The full
target table is in [the CLI reference](cli-reference.md#agentcordon-init), and the approval
step is in [Workspace Enrollment](workspace-enrollment.md).

It also registers `agentcordon mcp-serve` in each of those runtimes' MCP configuration —
`.mcp.json` for Claude Code, `.codex/config.toml` for Codex, `.cursor/mcp.json` for Cursor and
so on, ten runtimes in all; the five that configure MCP per user rather than per project get
the path and the snippet printed for you to paste. Claude Code asks once, interactively, before
it trusts a project's `.mcp.json`; open the project in `claude` and approve the `agentcordon`
server the first time, or a headless run will not see the tools. That is what makes the credential proxy and
the brokered MCP tools **native tools** the runtime can type-check and permission, instead of a
shell command the model has to remember. The trade-off is a real one and it is why there is a
flag: the skill costs nothing until a task triggers it, while the MCP tools cost about 800
tokens of schemas in every session — a fixed number, whether the workspace has one brokered
server or twenty. `--no-mcp` takes the skill and skips the schemas, and the picker asks once so
the answer is yours either way. [System Architecture](system-architecture.md#a-native-tool-call-through-mcp-serve)
has a flowchart of which surface an agent ends up on and what each costs. See
[ADR-0015](adr/0015-mcp-server-surface-is-the-cli-over-stdio.md).

### From GitHub Releases

Without a server to install from, take the assets straight from a release. Pick the target
triple for your machine: `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`,
`x86_64-apple-darwin`, `aarch64-apple-darwin`.

```bash
base=https://github.com/agentcordon/agentcordon/releases/download/v0.4.0
target=aarch64-apple-darwin
curl -fsSL "$base/agentcordon-$target"        -o ~/.local/bin/agentcordon
curl -fsSL "$base/agentcordon-broker-$target" -o ~/.local/bin/agentcordon-broker
curl -fsSL "$base/SHA256SUMS"                 -o /tmp/SHA256SUMS
chmod +x ~/.local/bin/agentcordon ~/.local/bin/agentcordon-broker
```

Verify the two downloads against `/tmp/SHA256SUMS` before running them. Take the version
that matches your server: the CLI and the server must be on the same release, because the
0.4.0 signing format is not compatible with 0.3.x. See
[Upgrading](upgrading.md#signing-format-change-v040).

Every released binary carries a signed build-provenance attestation, verifiable with
`gh attestation verify`.

---

## Windows

Windows 10 and 11, x86-64 only. There is no ARM64 Windows build.

The server's installer is the fastest route:

```powershell
irm https://agentcordon.example.com/install.ps1 | iex
```

It downloads `agentcordon.exe` and `agentcordon-broker.exe` from the matching GitHub
release, verifies them against the release's `SHA256SUMS`, installs them to
`%LOCALAPPDATA%\AgentCordon\bin`, adds that directory to your user PATH
(`AGENTCORDON_NO_MODIFY_PATH=1` declines that), and records the server in
`%USERPROFILE%\.agentcordon\config.toml`. No admin rights, and no Windows service: the
broker runs in the terminal you start it from and exits when that terminal closes, exactly
as on Unix.

Without a server to install from, download the two `*-x86_64-pc-windows-msvc.exe` assets
and `SHA256SUMS` from [a release](https://github.com/agentcordon/agentcordon/releases) and
check them yourself:

```powershell
Get-FileHash .\agentcordon-x86_64-pc-windows-msvc.exe -Algorithm SHA256
```

Then, in a new terminal, from your project directory:

```powershell
agentcordon init
```

A manual download records no server, so pass `agentcordon init --server-url
https://agentcordon.example.com` once, or set `AGTCRDN_SERVER_URL`.

`install.ps1` verifies both binaries against the release's `SHA256SUMS` and **refuses** an
asset with no entry, exactly as `install.sh` does.

The device flow is identical on Windows: copy the four-word code into a browser and
approve.

---

## From source

```bash
git clone https://github.com/agentcordon/agentcordon.git
cd agentcordon
cargo build --release
```

Three binaries land in `target/release/`:

| Binary | Crate | Purpose |
|---|---|---|
| `agent-cordon-server` | `agent-cordon-server` | The control plane: admin API and console, OAuth authorization server, vault, Cedar policy engine. Binds `0.0.0.0:3140` by default. |
| `agentcordon-broker` | `agentcordon-broker` | The per-user daemon: holds the workspace's OAuth tokens, asks the server to vend credentials, injects them into outgoing calls, fronts MCP servers. Binds `127.0.0.1` on a port it picks. |
| `agentcordon` | `agentcordon-cli` | The workspace CLI an agent runs. Talks only to the broker. |

Released binaries for macOS and Windows cover the CLI and the broker only; the server is
released for Linux, and a server on another platform is a source build.

---

## What gets installed where

| Path | Written by | Contents |
|---|---|---|
| `~/.local/bin/` | `install.sh` | `agentcordon`, `agentcordon-broker` |
| `%LOCALAPPDATA%\AgentCordon\bin` | `install.ps1` | `agentcordon.exe`, `agentcordon-broker.exe` |
| your login shell's startup file | `install.sh` (`install.ps1` sets the user PATH instead) | one marker-delimited block adding `~/.local/bin` to `PATH`. `AGENTCORDON_NO_MODIFY_PATH=1` opts out. |
| `~/.agentcordon/config.toml` | `install.sh`, `install.ps1` | `server_url` — the origin the installer was fetched from, so the CLI needs no `--server-url` (`0600`, in a `0700` directory) |
| `~/.agentcordon/` | the broker | `broker.key`, `tokens.enc`, `workspaces.json`, `broker.port`, `broker.pid`, `broker.lock`. Moved by `--data-dir` / `AGTCRDN_DATA_DIR`, which the CLI does not read — `config.toml` stays here either way. |
| `.agentcordon/` in a project | `agentcordon init` | `workspace.key` (0600, in a 0700 directory), `workspace.pub`, `agents.toml`, and `broker.fingerprint` from the enrollment. Moved by `AGTCRDN_WORKSPACE_DIR`. |
| `.agents/skills/agentcordon/` in a project | `agentcordon init` | `SKILL.md` — the AgentCordon [Agent Skill](https://agentskills.io/specification). Copied to `.claude/skills/` and `.kiro/skills/` for the runtimes that read those instead. |
| `/data/` in the container | the server | `agent-cordon.db`, `.secret`, `.master-salt`, `.root_password` |

---

> **Next:** [Workspace Enrollment](workspace-enrollment.md) · [Configuration](configuration.md) · [Deployment](deployment.md) · [CLI Reference](cli-reference.md)
