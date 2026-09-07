# A real v0.3.3 database

`agent-cordon.db` is not hand-built. It was produced by the **v0.3.3 server
binary**, compiled from the `v0.3.3` tag (commit `c75f132`), running against a
fresh SQLite file and populated over HTTP through its own admin API, the way a
v0.3.3 operator would have populated it. Nothing was inserted by hand, and no
row was written by any newer code. It stops at schema version 12.

`crates/server/tests/upgrade_v033.rs` opens this file through the real server
and asserts that migrations 013–020 leave the install working: the users can
still log in, the workspace's OAuth tokens still authenticate, the credentials
still decrypt, and the audit trail survives.

## What is in it

| | |
| --- | --- |
| Users | `root` (root admin), `fixture-admin` (admin), `fixture-viewer` (viewer) |
| Workspace | `fixture-workspace`, registered and activated through the RFC 8628 device flow with a real Ed25519 key (`workspace-ed25519.pem`) |
| OAuth | one `agentcordon-broker` access token + rotating refresh token, issued to the workspace by the device-code exchange |
| Credentials | `fixture-api-key` (generic, URL-pattern bound) and `fixture-rotated-key` (rotated twice, so two history rows) |
| Policies | the shipped default plus two Cedar grants letting the workspace vend each credential |
| MCP | `fixture-mcp`, imported by the workspace itself, with its junction-table binding |
| Audit | 29 events — logins, user creation, credential writes, policy evaluation, a real vend |

Every id, secret, password and token is listed in `fixture.json`, which is the
manifest the test reads. Nothing here is a real secret.

## The tokens are stale on purpose

v0.3.3 hard-codes its OAuth token lifetimes — `ACCESS_TOKEN_TTL_SECS = 900`
and a 30-day refresh, both constants in `crates/server/src/routes/oauth/token.rs`
with no environment override — so the access token in this database stopped
being live fifteen minutes after the file was made, and the refresh token
lapses a month later. A checked-in fixture cannot avoid that; a test built on
one must not depend on it.

So `Upgraded::boot` shifts every timestamp in `oauth_access_tokens` and
`oauth_refresh_tokens` on its temp copy by one offset — the age of the
fixture — before the server opens it. Each token keeps the exact lifetime
v0.3.3 gave it, and nothing else in the row moves: not the token hash, not
the client binding, not the scopes, not any other table. What the tests then
assert is what the migrations actually do — the token still resolves through
its client to its workspace, and still reaches the credential material — not
that a token minted in 2026 is eternally live. The lifetimes above are pinned
by `the_fixture_carries_the_v033_token_lifetimes`, which reads this file
directly, so a regenerated fixture that changed them fails loudly.

## The master secret matters

The database was sealed under `AGTCRDN_MASTER_SECRET=fixture-secret-v033!`,
with `AGTCRDN_KDF_SALT` unset so the salt is derived from the secret, as
`AppConfig` does. That secret is **weak** by the rule introduced after v0.3.3
(20 raw bytes, under the 32-byte threshold), and v0.3.3 fed it to HKDF
unchanged.

This is the point of the fixture. On upgrade the store is `Populated` and no
`.master-salt` file exists next to the database, so `resolve_secret` must take
the `LegacyWeak` branch: the secret keeps feeding HKDF unchanged, no salt file
is written, and every credential stays decryptable. Writing a salt here, or
stretching the secret, would orphan the ciphertext. See `docs/master-key.md`.

## Regenerating

```sh
./regenerate.sh [workdir]
```

It adds a temporary git worktree at the `v0.3.3` tag, builds the server there,
runs it on `127.0.0.1:31417` against a fresh database, drives the whole
population over `curl`, checkpoints the WAL and vacuums the file down (~380 KB),
then copies the database, the workspace key and a refreshed `fixture.json` back
into this directory. Every id, token and key changes; the test reads them from
`fixture.json`, so it keeps passing. Remove the temporary worktree afterwards
with the `git worktree remove` line the script prints.
