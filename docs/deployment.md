> [Home](index.md) > Deployment

# Deployment

What a production AgentCordon install needs beyond the [installation](installation.md)
steps: TLS in front of it, a base URL, a durable volume, one process per database, and a
backup you have restored at least once.

Every configuration variable named here is defined in
[Configuration](configuration.md#server).

**On this page:**
[The shape of a deployment](#the-shape-of-a-deployment) · [TLS and the reverse proxy](#tls-and-the-reverse-proxy) · [The base URL](#the-base-url) · [Storage and volumes](#storage-and-volumes) · [One process per database](#one-process-per-database) · [Secrets](#secrets) · [Backups](#backups) · [Upgrades](#upgrades) · [Observability](#observability)

---

## The shape of a deployment

One server process, one SQLite database, behind a TLS-terminating reverse proxy. Brokers
run on users' machines and dial the server; nothing dials a broker from outside its host.

A complete `docker run` for production:

```bash
docker run -d \
  --name agentcordon \
  -p 127.0.0.1:3140:3140 \
  -e AGTCRDN_MASTER_SECRET="$(openssl rand -hex 32)" \
  -e AGTCRDN_BASE_URL="https://agentcordon.example.com" \
  -e AGTCRDN_TRUST_FORWARDED_HEADERS=true \
  -v agentcordon-data:/data \
  --restart unless-stopped \
  ghcr.io/agentcordon/agentcordon:0.4.0
```

`docker-compose.yml` is the Compose form of the same thing: it publishes
`${AGTCRDN_PORT:-3140}:3140`, mounts `agentcordon-data:/data`, sets `restart:
unless-stopped`, and reads an optional `.env`. Put the environment variables above in that
`.env`.

Pin the image tag. `latest` moves with each stable release, so an unattended `docker
compose pull` can migrate your database to a version you did not choose.

---

## TLS and the reverse proxy

The server never terminates TLS itself. Put it behind a proxy that does.

This is not optional hardening. The admin session cookie is set `Secure`, so a browser
keeps it only over HTTPS or on `127.0.0.1`. Reached at `http://<lan-ip>:3140`, login
appears to succeed and then bounces straight back to the login page.

The proxy must send:

| Header | Why |
|---|---|
| `X-Forwarded-Proto: https` | `GET /install.sh` and `GET /install.ps1` take their scheme from this header, defaulting to `http`. Without it the installer you serve tells users to fetch over plain HTTP. Setting `AGTCRDN_BASE_URL` also fixes this; send the header anyway. |
| `X-Forwarded-For` | The client address for per-address limits — login lockout and device-code approval. Set `AGTCRDN_TRUST_FORWARDED_HEADERS=true` only when the proxy **overwrites** this header rather than appending to a client-supplied one. |

Nginx:

```nginx
location / {
    proxy_pass         http://127.0.0.1:3140;
    proxy_set_header   Host              $host;
    proxy_set_header   X-Forwarded-Proto $scheme;
    proxy_set_header   X-Forwarded-For   $remote_addr;
    proxy_http_version 1.1;
    proxy_set_header   Connection        "";
    proxy_buffering    off;
}
```

`proxy_buffering off` and HTTP/1.1 keep the console's server-sent events flowing; with
buffering on, the dashboard and audit pages stop updating live.

Caddy sets both headers itself:

```caddy
agentcordon.example.com {
    reverse_proxy 127.0.0.1:3140
}
```

Bind the published port to `127.0.0.1` when the proxy is on the same host, as in the
`docker run` above, so nothing reaches the server except through the proxy.

An alternative to a public listener is the Tailscale sidecar in
`docker-compose.tailscale.yml`, which puts the server on your tailnet with no published
ports at all. Tailscale terminates TLS for you.

---

## The base URL

Set `AGTCRDN_BASE_URL` to the URL your users type, before anyone enrols a workspace.

The device-flow activation URL, the OAuth2 MCP callback redirect URI, and the installer at
`GET /install.sh` are all built from it. Unset, the activation URL becomes `http://` plus
the listen address — `http://0.0.0.0:3140` in the shipped container, which no browser can
open — and every user who tries to enrol is stuck.

Changing it later is safe for enrolment but not free: an OAuth2 MCP server registered
under the old redirect URI must be re-authorized, because the redirect URI is part of what
the upstream provider registered.

---

## Storage and volumes

One volume holds everything that must survive a container replacement.

| Path | What it is |
|---|---|
| `/data/agent-cordon.db` | The SQLite database: users, workspaces, credentials, policies, audit events. Plus its `-wal` and `-shm` companions. |
| `/data/.secret` | The master secret, generated on first boot when `AGTCRDN_MASTER_SECRET` is unset. Mode 0600. **Lose this and every stored credential is unreadable.** |
| `/data/.master-salt` | The Argon2id salt, created once when a weak master secret has to be stretched. Must travel with the database. |
| `/data/.root_password` | The generated bootstrap admin password, written by the container entrypoint. |
| `/data/agent-cordon.db.lock` | The single-instance advisory lock. Recreated on each boot. |

Because these all live in the named volume, replacing the container is lossless: stop it,
start a new one with the same `-v agentcordon-data:/data`, and users, credentials and the
admin password survive. This is how you add or change an environment variable on the
`docker run` path, where there is no `.env` to edit.

---

## One process per database

The server keeps its policy cache, rate limiters and SSE state in memory, so two processes
over one SQLite file enforce two different pictures of the world. To make that
unmistakable, startup takes an advisory `flock` on `<db path>.lock` before running
migrations and holds it for the life of the process. A second process is refused with a
message naming the holder.

The kernel releases the lock when the process exits, however it exits, so there is no stale
lock to clean up.

`AGTCRDN_REPLICA_MODE=unsafe-shared` skips the guard. It does not make two processes safe;
it moves the split-brain problem to you. A rolling deployment that briefly runs two
containers over one volume needs this and will behave inconsistently while both are up.
Prefer stop-then-start.

The broker takes the same kind of lock on `broker.lock` in its data directory.

---

## Secrets

Set `AGTCRDN_MASTER_SECRET` explicitly in production and store it wherever you store your
other secrets. A secret with at least 32 bytes of real material — `openssl rand -hex 32`
gives one — is used directly; anything weaker is stretched with Argon2id against the salt
in `.master-salt`.

Left unset, the server generates one into `/data/.secret`. That works, but it means your
only copy of the key to your credential store is inside the volume you are backing up
alongside the ciphertext.

Rotating the master secret is a two-variable, one-request runbook:
`AGTCRDN_MASTER_KEY_VERSION`, `AGTCRDN_PREVIOUS_MASTER_SECRET`, then
`POST /api/v1/admin/rotate-key`. It is documented in full in [Master Key](master-key.md).

---

## Backups

The unit of backup is the whole `/data` volume, not just the database file. A database
without its `.secret` and `.master-salt` is ciphertext you cannot open.

Take a consistent copy with SQLite's own backup, which is safe against a running server:

```bash
docker exec agentcordon sqlite3 /data/agent-cordon.db ".backup '/data/backup.db'"
docker cp agentcordon:/data/backup.db ./agent-cordon-$(date +%F).db
docker cp agentcordon:/data/.secret   ./agent-cordon-$(date +%F).secret
```

Copying the `.db` file directly out from under a running server can capture a torn state,
because the write-ahead log is a separate file.

Restore is the reverse: stop the server, put the files back in the volume, start it. Do
this once on a scratch host before you need it. Back up before every upgrade; migrations
are forward-only and there is no down-migration.

---

## Upgrades

Pull the new image, recreate the container, let it migrate on boot. The full procedure —
what persists, the migration sequence, the pre-upgrade checklist and the rollback path —
is in [Upgrading](upgrading.md).

Two things specific to a deployment:

- **The CLI and the server move together.** The installer at `GET /install.sh` is pinned to
  the server's version ([ADR-0010](adr/0010-installer-pinned-to-server-version.md)), so
  re-running it on each workstation after a server upgrade is the whole client-side
  procedure. The 0.4.0 signing format is not compatible with 0.3.x clients.
- **Take a backup first.** Migrations run automatically on boot and are forward-only.

---

## Observability

| Channel | Where |
|---|---|
| Health | `GET /health`, unauthenticated. What the container `HEALTHCHECK` calls. |
| Metrics | `GET /metrics`, Prometheus text format: request counts, latency histograms, policy evaluation counters. |
| Logs | Structured JSON on stdout by default (`AGTCRDN_LOG_FORMAT=pretty` for a terminal), with a correlation id on every request. |
| Audit | `GET /api/v1/audit` in the admin API and the Audit page in the console, exportable as CSV, syslog or JSONL. |

Audit writes are best-effort: a failed audit insert is logged as a warning and does not
fail the operation it describes. Nothing deletes audit rows.

---

> **See also:** [Installation](installation.md) · [Configuration](configuration.md) · [Upgrading](upgrading.md) · [Master Key](master-key.md)
