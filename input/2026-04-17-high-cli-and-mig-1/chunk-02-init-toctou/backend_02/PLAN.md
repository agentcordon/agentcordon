# ENGINEER PLAN — backend_02

Parent chunk: chunk-02-init-toctou
Parent plan: 2026-04-17-high-cli-and-mig-1

## Prior art consulted

- `wiki/workspace-identity/keypair-and-signing.md` — confirms the
  `.agentcordon/` layout (0700), `workspace.key` (0600 hex seed), and
  `workspace.pub` (0644 hex public key). Nothing changes about the on-disk
  shape — only the syscall sequence that creates the files.
- `wiki/workspace-identity/_index.md` — no additional constraints beyond
  the keypair-and-signing article.
- `wiki/process/dev-builds-only.md` — verification uses `cargo test` /
  `cargo build` in dev profile only. No `--release` anywhere.
- Reviewed `wiki/_master-index.md` and `wiki/known-bugs/` (no directory
  exists at that path — nothing to pull from there).

## Approach

The current first-time-create branch at `crates/cli/src/commands/init.rs:46-71`
does a non-atomic check-then-write: the path is `exists()`-tested at line 30,
then (if missing) `fs::write` creates or overwrites it, and only afterwards
does `fs::set_permissions` tighten it to 0o600. That has two defects:

1. An attacker who wins the race between the exists-check and the `fs::write`
   can swap in a symlink / pre-created file before we write, and we would
   happily truncate it with the key material. (This is the `CLI-1` finding.)
2. On Unix there is a brief window where `workspace.key` exists with
   umask-default perms (typically 0o644) before the explicit
   `set_permissions(0o600)` runs. Another local user could `read` the seed
   during that window.

Fix for both: open the file with `std::fs::OpenOptions::new().write(true).create_new(true)`.
`create_new(true)` maps to `O_CREAT | O_EXCL` on Unix and `CREATE_NEW` on
Windows, so the syscall itself fails with `ErrorKind::AlreadyExists` if
anything is at the path (including a symlink). On Unix we additionally call
`.mode(0o600)` (or `0o644` for the public key) via
`std::os::unix::fs::OpenOptionsExt::mode`, which is passed as the `mode_t`
argument to `open(2)` — so the file is created with the correct perms from
the first instant it exists. This makes the later `set_permissions` calls
redundant on Unix, so we remove them (they are already `#[cfg(unix)]`).

On Windows, `OpenOptions::create_new(true)` alone is sufficient per
`docs.rs/std::fs::OpenOptions::create_new` — Rust std guarantees the
`CREATE_NEW` mapping. NTFS ACL inheritance from the parent `.agentcordon/`
directory (created with `fs::create_dir_all` at line 46) handles perms.

The `if key_path.exists()` idempotent short-circuit at lines 30-43 is
preserved **unchanged**. Only the first-time-create branch is hardened.

Error handling: if `create_new` returns `ErrorKind::AlreadyExists`, we emit
`"keypair file appeared concurrently — re-run `agentcordon init`"` via
`CliError::general(...)` and exit non-zero. Same message for both key and
pubkey. All other I/O errors are propagated with the same
`"failed to write private key: {e}"` / `"failed to write public key: {e}"`
phrasing already used today — just wrapping `OpenOptions::open` + `write_all`
rather than `fs::write`.

Reused pieces:
- `CliError::general` — `crates/cli/src/error.rs:31`.
- `std::os::unix::fs::OpenOptionsExt` — already used in the Rust ecosystem
  for this exact purpose; no MSRV impact.

## Files I will change

- `crates/cli/src/commands/init.rs` — replace `fs::write` + follow-up
  `fs::set_permissions` at lines 58-71 with `OpenOptions::new().write(true)
  .create_new(true).mode(…)` + `write_all`, keyed off whether we hit the
  `AlreadyExists` race. Adjust imports: swap the `PermissionsExt` import
  (no longer needed for the key/pub paths) for `OpenOptionsExt`. The
  directory-perm setting at lines 48-50 still uses `PermissionsExt`, so
  that import stays (under `#[cfg(unix)]`). One new private helper
  `create_new_file(path, mode, body)` keeps the two create sites DRY and
  gives the new unit test a seam.

## Unit tests I will write

Added to the existing `#[cfg(test)] mod tests` block in `init.rs`:

1. `create_new_file_rejects_existing_path` — pre-create a file at the
   target path, call the new helper, assert the returned `CliError`
   contains `"appeared concurrently"` and `exit_code` is `GeneralError`.
   Exercises the race-loser branch directly.
2. `create_new_file_creates_with_mode` (Unix-only) — invoke the helper
   on a fresh path, then `metadata(...).permissions().mode() & 0o777`
   should equal the requested mode (0o600 and 0o644 cases).
3. `create_new_file_writes_exact_body` — invoke the helper, then
   `fs::read_to_string` returns the exact body we passed in.

I will NOT add a `run()`-level integration test that races a real
concurrent process — the helper-level test gives identical coverage
without needing thread coordination.

The three existing tests (`ensure_entry_creates_file_when_missing`,
`ensure_entry_preserves_existing_servers`, `ensure_entry_is_idempotent`)
continue to pass unchanged.

## How I'll run the tests

From the worktree `/workspace/.worktrees/backend_02-chunk-02-init-toctou`:

- `cargo test -p agentcordon-cli commands::init::tests` — focused run of
  the init tests.
- `cargo test -p agentcordon-cli` — full CLI crate tests.
- `cargo fmt --all --check`
- `cargo clippy --workspace -- -D warnings`
- `cargo build --workspace` (dev profile only, per
  `wiki/process/dev-builds-only.md`).
