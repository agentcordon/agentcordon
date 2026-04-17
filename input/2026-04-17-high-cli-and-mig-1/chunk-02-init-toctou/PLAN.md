# CHUNK PLAN — chunk-02-init-toctou

Parent plan: 2026-04-17-high-cli-and-mig-1
Role: backend
Engineer: backend_02

## Scope

Make the first-time keypair-creation path in `agentcordon init` TOCTOU-safe.
An attacker with write access to `~/.agentcordon/` could currently race
between the `key_path.exists()` check and the `fs::write` call — this chunk
closes that gap by switching to `OpenOptions::create_new(true)` (atomic
"create or fail with EEXIST" at the syscall layer).

Resolves CLI-1.

## Acceptance criteria

- `crates/cli/src/commands/init.rs::run` no longer calls `fs::write` for
  the **first-time-create path** (current lines 59-71). Instead, both
  `workspace.key` and `workspace.pub` are created via
  `std::fs::OpenOptions::new().write(true).create_new(true)` and then
  `write_all`'d.
- On Unix, the private-key file is opened with mode `0o600` set atomically
  via `OpenOptionsExt::mode(0o600)` BEFORE the file exists — so the file
  never has wider perms even momentarily. The public-key file is opened
  with mode `0o644` the same way. The `set_permissions` calls at lines
  62 and 70 become unnecessary on Unix and can be removed.
- On Windows, plain `OpenOptions::new().write(true).create_new(true)` is
  used (NTFS ACL inheritance from the parent `.agentcordon/` directory
  handles permissions). No `windows`-crate `CreateFileW` invocation is
  needed — Rust's `OpenOptions::create_new` already maps to `CREATE_NEW`
  on Windows and returns `ErrorKind::AlreadyExists` on race.
- If `OpenOptions::create_new` returns `ErrorKind::AlreadyExists` for the
  private key, the CLI emits a clear error message:
  `"keypair file appeared concurrently — re-run `agentcordon init`"` and
  exits non-zero. Same handling for the public key (a partial-write race
  where the private key was created but the public key was created by
  another process between the two calls).
- The existing `if key_path.exists()` idempotent short-circuit at lines
  30-43 is **preserved unchanged**. Only the first-time-create branch
  (lines 46+) is hardened. Re-running `agentcordon init` on an existing
  workspace must continue to work exactly as it does today.
- `fs::create_dir_all(&dir)` and the directory `0o700` permission setting
  at lines 46-50 stay as-is. (The directory is created with default perms
  then chmod'd; that's a pre-existing micro-window the parent PLAN does
  not require us to close. Document this scope decision in your commit
  message but do NOT widen the chunk to address it.)
- New unit test `init_create_new_rejects_existing_key`: pre-create
  `workspace.key` between the existence-check and the create-new call
  (simulate the race by writing a file directly via `fs::write` after the
  short-circuit but before run() reaches the create-new path — easiest:
  manually invoke a helper that wraps just the create-new logic and
  assert it errors with the expected message when the file pre-exists).
  If extracting a helper feels like scope creep, instead write an
  integration test that pre-creates `workspace.key` to look like a stale
  partial state (file present, dir present, no `.pub` file) and asserts
  the error path is hit.
- All existing `init` tests (the `tests` module at lines 406+) continue
  to pass.

## Files expected to change

- `crates/cli/src/commands/init.rs` — only the first-time-create branch
  inside `run()` (current lines 46-71) and the imports at the top of the
  file (`use std::os::unix::fs::OpenOptionsExt` for the mode bits).

## Reuse

- `std::fs::OpenOptions` is already in std; no new dep.
- `std::os::unix::fs::OpenOptionsExt::mode()` is already used in the
  Rust ecosystem (no MSRV bump).
- `std::io::ErrorKind::AlreadyExists` for race-loser detection.
- Existing `CliError::general(...)` helper for the new error message.

## Prior art (from wiki)

- `wiki/workspace-identity/keypair-and-signing.md` — describes the
  workspace.key / workspace.pub layout. No process change; only the
  syscall sequence changes.

## Dependencies on other chunks

- None. Independent of chunks 01, 03, 04.

## Notes for the engineer

- **DEV BUILDS ONLY.** Never `cargo build --release`. Standard
  verification: `cargo fmt --all`, `cargo clippy --workspace -- -D
  warnings`, `cargo test -p agentcordon-cli`, `cargo build --workspace`.
- Do NOT touch `wiki/**`, `docs/**`, `input/BUGS.md`, the server crate,
  the broker crate, the Cedar policy bundle, or any pre-existing server
  test failures.
- The root-user bypass at `crates/core/src/policy/cedar/mod.rs:86-95` is
  intentional by design — do not refile if encountered during review.
- The idempotent short-circuit at lines 30-43 is load-bearing. Tests rely
  on `init` being safe to re-run. Don't even reformat that block.
- Use `OpenOptions::new().write(true).create_new(true)` — NOT
  `.create(true).write(true).truncate(true)`, which would happily
  overwrite an existing file (the bug we're fixing).
- After opening, use `file.write_all(seed_hex.as_bytes())` followed by an
  explicit `file.sync_all()` is NOT required (per project conventions —
  the existing `fs::write` did not call `sync_all` either; matching that).
- Windows handling: just rely on `OpenOptions::create_new` mapping to
  `CREATE_NEW` (which Rust std guarantees). No `windows`-crate code, no
  raw FFI, no `CreateFileW`. Keep the change small.
