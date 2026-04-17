# ENGINEER PLAN — backend_01

Parent chunk: chunk-01-per-cred-lock
Parent plan: 2026-04-17-brk-1-oauth-per-cred-lock

## Prior art consulted

- `wiki/known-bugs/brk-1-oauth-cache-mutex.md` — confirms DashMap is the
  approved fix shape; this is the bug we close.
- `wiki/known-bugs/brk-2-refresh-rotation-callback.md` — adjacent bug whose
  atomicity invariant (callback-before-cache-write, cache stays empty on
  callback failure) must be preserved exactly.
- `wiki/known-bugs/_index.md` — scanned; no other BRK-* overlap beyond BRK-2.
- `wiki/_master-index.md` — scanned to locate topic indices; nothing else
  directly relevant for a lock-scope change.
- `.claude/best-practices.md` — relevant rules: R-001..R-006 (hygiene),
  R-100..R-103 (errors), R-110..R-113 (async), R-150..R-152 (testing).
  R-113 (`Arc<Mutex<T>>` smell) does not bar this fix: the per-credential
  inner `Arc<tokio::sync::Mutex<Option<CachedToken>>>` is required to hold
  single-flight semantics across an `.await` HTTP round-trip. A `RwLock`
  would not serialise writers for a single key, and dropping the lock
  across `.await` would reintroduce the thundering herd. The parent plan
  explicitly prescribes this shape.

## Approach

Both managers today hold `Arc<Mutex<HashMap<K, V>>>` across the full
check-acquire-HTTP-insert sequence. Swap that for
`DashMap<K, Arc<tokio::sync::Mutex<Option<V>>>>`:

1. `cache.entry(key.clone()).or_insert_with(|| Arc::new(Mutex::new(None))).clone()`
   — brief DashMap shard-level write to get-or-insert the per-key slot.
   The guard goes out of scope immediately (let-binding captures the
   clone, not the guard).
2. `.lock().await` the inner `tokio::sync::Mutex<Option<CachedValue>>`.
3. Check the `Option` under the per-key lock. If fresh, return.
4. Otherwise run the existing HTTP refresh body verbatim and — for the
   broker — the rotation-callback block verbatim. Only on both success
   do we write `Some(fresh)` into the slot.
5. `invalidate`/`evict` call `cache.remove(&key)`. Any concurrent holder
   of the old `Arc<Mutex<...>>` finishes against the detached slot; its
   writes are harmless because the slot is no longer reachable from the
   map. Next caller `entry()`s a fresh slot.

Reused utilities (cited by path:line on main):

- `crates/broker/src/oauth2_refresh.rs:120-216` — HTTP refresh body +
  rotation callback; lifted verbatim into the new "under per-credential
  lock" block.
- `crates/core/src/oauth2/client_credentials.rs:150-231` — existing
  `acquire_token_inner` helper stays untouched; only `get_token` is
  rewritten.
- `crates/broker/src/oauth2_refresh.rs:299-323` — `mock_token_endpoint`
  test helper stays as-is.

## Files I will change

- `Cargo.toml` — add `dashmap = "6"` under `[workspace.dependencies]`.
- `crates/broker/Cargo.toml` — add `dashmap = { workspace = true }`.
- `crates/core/Cargo.toml` — add `dashmap = { workspace = true }`.
- `crates/server/Cargo.toml` — convert direct `dashmap = "6"` to
  `dashmap = { workspace = true }`.
- `crates/broker/src/oauth2_refresh.rs` — cache field type, `new`,
  `get_access_token`, `invalidate`, docstring updates, deletion of the
  `TODO: Replace single mutex` comment at lines 107-109; rewrite the 4
  in-module tests that touch `mgr.cache.lock().await`:
  - `test_cache_miss_and_invalidation` → assert `mgr.cache.is_empty()`
  - `test_cached_token_returned_when_valid` → pre-populate via
    `mgr.cache.insert(key, Arc::new(Mutex::new(Some(CachedAccessToken{...}))))`
  - `test_invalidate_removes_cached_token` → assert
    `mgr.cache.get("test-cred").is_none()` (DashMap returns `None` after
    `.remove`) — fine because `invalidate` calls `.remove` directly.
  - `test_rotation_callback_failure_aborts_refresh` → assert either no
    entry OR the inner `Option` is `None` (DashMap will contain an entry
    because `or_insert_with` ran before the refresh failed).
  - `test_expired_token_not_returned` → pre-populate like the second test.
- `crates/core/src/oauth2/client_credentials.rs` — cache field type, `new`,
  `with_client`, `evict`, `get_token`; update the docstring on
  `get_token` (lines 104-107) to describe per-credential-lock semantics.
  No existing `#[cfg(test)] mod tests` in this file — nothing to rewrite.

## Unit tests I will write

The parent plan explicitly says **this chunk adds no new concurrent load
test** — that is chunk-02. I will only rewrite the existing in-module
broker tests to match the new cache shape. No new tests added.

Tests that must still pass:

- `agentcordon-broker` crate, module `oauth2_refresh::tests`:
  - `test_cache_miss_and_invalidation`
  - `test_cached_token_returned_when_valid`
  - `test_invalidate_removes_cached_token`
  - `test_rotated_refresh_token_invokes_callback` (unchanged — no cache peek)
  - `test_rotation_callback_failure_aborts_refresh`
  - `test_expired_token_not_returned`
- Workspace tests unchanged: any `client_credentials` / `oauth2` tests in
  `crates/server/tests/v016_oauth2.rs`, `v300_oauth_as.rs` etc.

## How I'll run the tests

- Focused broker tests:
  `cargo test -p agentcordon-broker --lib oauth2_refresh::tests::`
- Core crate build/tests (sqlite feature = default):
  `cargo test -p agent-cordon-core`
- Full workspace:
  `cargo test --workspace`
- Lint:
  `cargo clippy --workspace -- -D warnings`
- Format:
  `cargo fmt --all --check`
- Release build:
  `cargo build --workspace --release`
- Invariant greps (must be empty):
  `grep -rn 'Arc<Mutex<HashMap' crates/broker/src/oauth2_refresh.rs crates/core/src/oauth2/client_credentials.rs`
  `grep -rn 'TODO: Replace single mutex' crates/`
