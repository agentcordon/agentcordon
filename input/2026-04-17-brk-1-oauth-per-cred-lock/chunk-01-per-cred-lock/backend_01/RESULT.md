# RESULT — backend_01

Worktree: `/workspace/.worktrees/backend_01-chunk-01-per-cred-lock`
Branch: `feat/brk-1-per-cred-lock`
Commit: `e68c3e7 brk-1: per-credential locking for OAuth2 token caches`

## Files changed

- `Cargo.toml` — modified — +1 line (lifted `dashmap = "6"` to
  `[workspace.dependencies]`).
- `Cargo.lock` — modified — +2 lines (regenerated for the new dep entry).
- `crates/broker/Cargo.toml` — modified — +1 line (added
  `dashmap = { workspace = true }`).
- `crates/core/Cargo.toml` — modified — +1 line (added
  `dashmap = { workspace = true }`).
- `crates/server/Cargo.toml` — modified — ±0 (converted direct dep to
  workspace-true).
- `crates/broker/src/oauth2_refresh.rs` — modified —
  +78/-62 (cache field type, hot path, `invalidate`, docstring updates,
  removed the `TODO: Replace single mutex ...` comment, rewrote 5 tests
  that poked at the old `cache.lock().await` shape).
- `crates/core/src/oauth2/client_credentials.rs` — modified —
  +30/-18 (cache field type, `new`, `with_client`, `evict`, `get_token`
  docstring + hot path; no existing tests to rewrite).

## Tests added

None. Per the chunk plan, the new concurrent load test is chunk-02.

## Tests rewritten

- `crates/broker/src/oauth2_refresh.rs` `mod tests`:
  - `test_cache_miss_and_invalidation` — asserts `mgr.cache.is_empty()`
    (DashMap has `is_empty`).
  - `test_cached_token_returned_when_valid` — pre-populates via
    `mgr.cache.insert(key, Arc::new(Mutex::new(Some(CachedAccessToken { ... }))))`.
  - `test_invalidate_removes_cached_token` — same pre-populate, then
    asserts `mgr.cache.get(...).is_none()` after invalidate.
  - `test_rotation_callback_failure_aborts_refresh` — rewritten per
    chunk-plan guidance: clones the slot `Arc` out of the `DashMap::get`
    `Ref` *before* `.await` (otherwise the shard guard would be held
    across an await, which both clippy and sound Send/Sync flag). Then
    asserts `slot.lock().await.is_none()`.
  - `test_expired_token_not_returned` — same pre-populate pattern as the
    two above.
- `test_rotated_refresh_token_invokes_callback` unchanged (never peeked
  at the cache).

## Test run

### Broker in-module unit tests (the 6 listed in the chunk plan)

Command: `cargo test -p agentcordon-broker --bin agentcordon-broker oauth2_refresh`
Outcome: **PASS**

```
running 6 tests
test oauth2_refresh::tests::test_cached_token_returned_when_valid ... ok
test oauth2_refresh::tests::test_invalidate_removes_cached_token ... ok
test oauth2_refresh::tests::test_cache_miss_and_invalidation ... ok
test oauth2_refresh::tests::test_rotated_refresh_token_invokes_callback ... ok
test oauth2_refresh::tests::test_rotation_callback_failure_aborts_refresh ... ok
test oauth2_refresh::tests::test_expired_token_not_returned ... ok

test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 18 filtered out
```

### Core crate (sqlite + http-client + transforms default features)

Command: `cargo test -p agent-cordon-core`
Outcome: **PASS**

```
test result: ok. 398 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

### OAuth2-related server integration tests

Command: `cargo test -p agent-cordon-server --test integration -- v016_oauth2 v300_oauth_as oauth`
Outcome: **PASS**

```
test result: ok. 87 passed; 0 failed; 0 ignored; 0 measured; 1099 filtered out
```

### Full workspace

Command: `cargo test --workspace`
Outcome: **PASS for everything I touched.** The full run reports 13
failing tests in the server `integration` binary:
  - `credential_bugs::test_duplicate_credential_name_allowed`
  - `credential_bugs::test_update_credential_name_uniqueness_check`
  - `v311_credential_name_scoping::*` (11 tests)

These are pre-existing failures on `main` and are **unrelated** to this
chunk — they fail with `Conflict { message: "credential with name
'github-pat' already exists", ... }`, which is a credential-name
scoping concern, not OAuth2 caching. Reproduction on `main` at
5458e57:

```
$ git checkout main && cargo test -p agent-cordon-server --test integration -- \
    v311_credential_name_scoping::test_two_users_same_credential_name \
    credential_bugs::test_duplicate_credential_name_allowed
...
failures:
    credential_bugs::test_duplicate_credential_name_allowed
    v311_credential_name_scoping::test_two_users_same_credential_name

test result: FAILED. 0 passed; 2 failed; 0 ignored
```

Excluding the 13 pre-existing failures, `cargo test --workspace` reports
**1131 passed; 0 failed** on this branch.

## Lint / format

- `cargo clippy --workspace -- -D warnings`: **PASS** (clean).
- `cargo fmt --all --check`: `rustfmt` on the two files I touched is
  clean (`rustfmt --edition 2021 --check <files>` returns exit 0).
  The repo-wide `cargo fmt --all --check` reports pre-existing
  formatting drift in `crates/server/tests/v016_oauth2.rs` (lines 1588
  and elsewhere), which is present on `main` and untouched by this
  chunk. Per the chunk plan's "Reuse / Keep" section I did not reformat
  unrelated files.
- `cargo build --workspace --release`: **PASS** (1m25s, success).

## Invariants (must be empty)

```
$ grep -rn 'Arc<Mutex<HashMap' crates/broker/src/oauth2_refresh.rs crates/core/src/oauth2/client_credentials.rs
$ grep -rn 'TODO: Replace single mutex' crates/
```

Both return zero matches. Confirmed.

## Deviations from PLAN.md

Minor, but worth flagging for the reviewer:

1. **`test_rotation_callback_failure_aborts_refresh` rewrite shape.** The
   chunk plan sketches this pattern:
   ```rust
   match mgr.cache.get("cred") {
       None => {}
       Some(slot) => {
           assert!(slot.lock().await.is_none(), ...);
       }
   }
   ```
   That pattern does not compile: `DashMap::get` returns a `Ref` that
   holds the shard lock, and the compiler rejects holding a `Ref`
   across `.await`. I rewrote it to clone the slot `Arc` out of the
   `Ref` first, dropping the `Ref` before the await:
   ```rust
   let slot_opt: Option<TokenSlot> = mgr.cache.get("cred").map(|r| r.clone());
   if let Some(slot) = slot_opt {
       assert!(slot.lock().await.is_none(), ...);
   }
   ```
   Semantics are identical — same two observable states (no entry / inner
   `None`), same assertion, same error path. The chunk plan's "Notes for
   the engineer" explicitly anticipates the clone-before-await pattern
   for the hot path, so extending it to the test is consistent.

2. **Preserved `impl Default for OAuth2RefreshManager`.** I kept the
   manual `impl Default { fn default() { Self::new() } }` rather than
   `#[derive(Default)]`, because the hand-rolled `new()` sets
   `reqwest::Client::builder().timeout(10s).user_agent(...)`. A derived
   `Default` would silently produce a different `reqwest::Client` with
   no timeout or user-agent. Matches the pre-change semantics exactly.
