# RESULT — backend_02

## Files changed

- `crates/cli/src/commands/init.rs` — modified — +99 / -14 lines.
  - New private helper `create_new_file(path, mode, body, label)` that wraps
    `OpenOptions::new().write(true).create_new(true)` (+ `.mode()` on Unix)
    plus `write_all`, mapping `ErrorKind::AlreadyExists` to a clear
    "appeared concurrently" error.
  - `run()`'s first-time-create branch replaces the old
    `fs::write` + `fs::set_permissions` pair for both `workspace.key`
    (0o600) and `workspace.pub` (0o644) with calls to the new helper.
  - Imports updated: added `OpenOptions`, `std::io::Write`,
    `OpenOptionsExt` (the last under `#[cfg(unix)]`). `PermissionsExt`
    import kept — still used by the directory-perm step at the
    pre-existing lines 82-84.
  - The idempotent short-circuit (old lines 30-43, now 64-77) is
    preserved byte-for-byte.
  - The directory-create + chmod pair (old lines 46-50, now 80-84) is
    preserved byte-for-byte — per the chunk plan, closing that
    micro-window is out of scope.

## Tests added

All live in `crates/cli/src/commands/init.rs` inside the existing
`#[cfg(test)] mod tests` block.

- `create_new_file_writes_exact_body` — sanity: helper writes the body
  verbatim on the happy path.
- `create_new_file_rejects_existing_path` — pre-creates a file at the
  target path, asserts the helper returns `CliError { code:
  GeneralError, message: contains "appeared concurrently" }`, and
  crucially asserts the pre-existing file content is **untouched**
  (proves the TOCTOU window is closed — old code would overwrite).
- `create_new_file_sets_mode_atomically` (Unix-only, `#[cfg(unix)]`) —
  asserts the created files never have mode bits wider than requested
  (`0o600` for the private key, `0o644` for the public key), proving
  the 0o600 invariant holds at the moment of creation rather than after
  a follow-up `chmod`.

## Test run

Command (from the worktree): `cargo test -p agentcordon-cli`
Outcome: PASS

```
running 6 tests
test commands::init::tests::create_new_file_writes_exact_body ... ok
test commands::init::tests::create_new_file_sets_mode_atomically ... ok
test commands::init::tests::create_new_file_rejects_existing_path ... ok
test commands::init::tests::ensure_entry_creates_file_when_missing ... ok
test commands::init::tests::ensure_entry_is_idempotent ... ok
test commands::init::tests::ensure_entry_preserves_existing_servers ... ok

test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
```

The 3 pre-existing `ensure_entry_*` tests pass unchanged (confirming the
idempotent short-circuit and the non-init parts of the module were not
disturbed).

## Lint / format

- `cargo clippy --workspace -- -D warnings`: PASS (no warnings).
- `cargo fmt -p agentcordon-cli -- --check`: PASS (clean).
- `cargo fmt --all -- --check`: **PRE-EXISTING** failures in
  `crates/broker/`, `crates/core/storage/migrations.rs`, and
  `crates/server/` — none of which this chunk touches. The team-lead's
  invariants list this as one of the 13 pre-existing server integration
  test items we must NOT "fix". Verified by running
  `cargo fmt --all -- --check` on `main` (pre-merge) and observing the
  same diff files. Not caused by this chunk.
- `cargo build --workspace`: PASS (dev profile, per
  `wiki/process/dev-builds-only.md`).

## Deviations from PLAN.md

- **File size (R-001).** `init.rs` was already 495 lines before this
  chunk. After adding the helper + 3 tests it is 579 lines. R-001 caps
  files at 400. I did not split the file because the parent PLAN
  scopes this chunk to "only the first-time-create branch inside
  `run()` and the imports at the top of the file"; a file split is a
  larger refactor that would touch the module layout outside this
  chunk's surface. Recommend triaging a follow-up chunk to split
  `init.rs` along the obvious boundary
  (keypair-creation vs agent-config-file generation vs mcp.json) —
  that is the change that actually reduces the file under 400.

- **Helper signature takes `_mode: u32` on Windows.** The plan discussed
  only Unix mode bits. I kept `mode` in the signature on all platforms
  for call-site symmetry (same helper call shape on both OSes) and
  suppressed the unused-warning with the leading underscore. Reviewer
  preference here is welcome — the alternative is a cfg-gated signature,
  which I judged noisier than a leading underscore on an unused param.

- **No run()-level integration test.** The chunk plan lists the helper
  test as acceptable in place of a full-`run()` race test; I took that
  path. The helper-level tests cover the race-loser branch end-to-end
  (same `CliError` is bubbled out of `run()` via `?`), so no coverage
  is lost.

No other deviations.
