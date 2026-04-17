# CHUNK PLAN — chunk-01-per-cred-lock

Parent plan: 2026-04-17-brk-1-oauth-per-cred-lock
Role: backend
Engineer: backend_01

## Scope

Replace the single `Arc<Mutex<HashMap<K, V>>>` cache in both OAuth2 token
managers with `DashMap<K, Arc<Mutex<Option<V>>>>` so that concurrent refreshes
for *different* credentials proceed in parallel while single-flight-per-key
is preserved. Covers both `crates/broker/src/oauth2_refresh.rs`
(`OAuth2RefreshManager`) and `crates/core/src/oauth2/client_credentials.rs`
(`OAuth2TokenManager`). Lifts `dashmap` to workspace dependencies and
re-wires all three crates that use it. Updates the existing in-module tests
that currently reach into `mgr.cache.lock()` directly.

## Acceptance criteria

- Root `Cargo.toml` has `dashmap = "6"` under `[workspace.dependencies]`.
- `crates/broker/Cargo.toml` adds `dashmap = { workspace = true }`.
- `crates/core/Cargo.toml` adds `dashmap = { workspace = true }`.
- `crates/server/Cargo.toml` changes `dashmap = "6"` to
  `dashmap = { workspace = true }`.
- `crates/broker/src/oauth2_refresh.rs` cache field type is
  `DashMap<String, Arc<tokio::sync::Mutex<Option<CachedAccessToken>>>>`
  (wrap the whole DashMap in an `Arc` if needed for `Clone` semantics — but
  DashMap is cheap-clone via internal `Arc`; verify whichever satisfies
  `#[derive(Clone)]`).
- `crates/core/src/oauth2/client_credentials.rs` cache field type is
  `DashMap<CredentialId, Arc<tokio::sync::Mutex<Option<CachedToken>>>>`
  (same note on `Clone`).
- Public method signatures unchanged:
  `OAuth2RefreshManager::get_access_token`, `OAuth2RefreshManager::invalidate`,
  `OAuth2TokenManager::get_token`, `OAuth2TokenManager::evict`,
  `OAuth2TokenManager::with_client`, `OAuth2TokenManager::new` — **no
  caller-facing change**.
- Hot path:
  1. Brief DashMap entry insert (`entry(key).or_insert_with(|| Arc::new(Mutex::new(None))).clone()`).
  2. Drop the DashMap guard before `.await`.
  3. Lock the per-credential mutex.
  4. Check `Option<Cached*>` under that lock; return if fresh.
  5. Otherwise run the HTTP refresh (existing logic verbatim), run the
     rotation callback (broker only), then write `Some(fresh)` into the slot.
- Rotation-callback atomicity (broker, lines ~171-205 of the old file):
  on callback failure, do NOT write into the slot. The slot stays `None`
  (or whatever stale `Some(expired)` was there). The error propagates as
  `OAuth2RefreshError::RotationPersistFailed` exactly as today.
- `invalidate` / `evict` call `cache.remove(&key)`. A concurrent holder of
  the old `Arc<Mutex<...>>` must still be able to finish its work against
  the detached slot — document this invariant in a short inline comment.
- `// TODO: Replace single mutex ...` comment at
  `crates/broker/src/oauth2_refresh.rs:107-110` is deleted.
- The analogous "serializing all credential token acquisitions is acceptable
  for v1.0" wording at `crates/core/src/oauth2/client_credentials.rs:104-107`
  is updated to describe the new per-credential-lock model (or removed if
  the replacement doc comment on `get_token` is sufficient).
- Existing in-module tests that peek at the cache are rewritten against the
  new shape. Listed tests MUST all still pass:
  - `oauth2_refresh::tests::test_cache_miss_and_invalidation`
  - `oauth2_refresh::tests::test_cached_token_returned_when_valid`
  - `oauth2_refresh::tests::test_invalidate_removes_cached_token`
  - `oauth2_refresh::tests::test_rotated_refresh_token_invokes_callback`
  - `oauth2_refresh::tests::test_rotation_callback_failure_aborts_refresh`
  - `oauth2_refresh::tests::test_expired_token_not_returned`
  - All `oauth2::client_credentials::tests::*` in the core crate (inspect
    that test module — any that touch `cache.lock()` must be rewritten).
- `cargo clippy --workspace -- -D warnings` clean.
- `cargo test --workspace` green.
- `cargo fmt --all --check` clean.
- `cargo build --workspace --release` succeeds.
- `grep -rn 'Arc<Mutex<HashMap' crates/broker/src/oauth2_refresh.rs crates/core/src/oauth2/client_credentials.rs`
  returns zero matches.
- `grep -rn 'TODO: Replace single mutex' crates/` returns zero matches.

## Files expected to change

- `Cargo.toml` — add `dashmap = "6"` under `[workspace.dependencies]`.
- `crates/broker/Cargo.toml` — add `dashmap = { workspace = true }`.
- `crates/core/Cargo.toml` — add `dashmap = { workspace = true }`.
- `crates/server/Cargo.toml` — convert direct dep to workspace-true.
- `crates/broker/src/oauth2_refresh.rs` — cache type + hot path + tests.
- `crates/core/src/oauth2/client_credentials.rs` — cache type + hot path +
  any tests that touch the cache directly.

## Reuse

- Keep `CachedAccessToken` / `CachedToken` structs as-is. Only the map/lock
  wrapper changes.
- Keep the existing HTTP refresh body (form building, response parsing,
  error mapping, expiry buffering) exactly as-is — lift it unchanged into
  the new "under per-credential lock" block.
- Keep the rotation-callback block
  (`crates/broker/src/oauth2_refresh.rs:171-205`) byte-identical modulo
  indentation — its ordering is the atomicity invariant.
- Keep `Default`, `Debug`, `Clone` impls and their semantics.

## Prior art (from wiki)

- `wiki/known-bugs/brk-1-oauth-cache-mutex.md` — the bug this chunk fixes.
- `wiki/known-bugs/brk-2-refresh-rotation-callback.md` — adjacent; do NOT
  expand scope into retry logic. The atomicity guarantee it depends on
  must remain intact.
- `wiki/credentials/transforms.md` — confirms both managers feed the same
  transform pipeline; no semantic change allowed.
- `wiki/mcp-gateway/oauth-for-mcp.md` — MCP uses `OAuth2RefreshManager`,
  so a regression surfaces as MCP latency.

## Dependencies on other chunks

- None. This is the first chunk and must merge before chunk-02.

## Notes for the engineer

- DashMap is `Clone` via internal `Arc` — you do NOT need to wrap it in an
  outer `Arc`. Just `#[derive(Clone)]` on the manager. `DashMap::entry` is
  a sync API; it returns a guard that must be dropped before `.await`.
  The safe pattern is:
  ```rust
  let slot = self
      .cache
      .entry(key.clone())
      .or_insert_with(|| Arc::new(Mutex::new(None)))
      .clone();
  // guard dropped here
  let mut slot_guard = slot.lock().await;
  ```
  Don't `await` while holding the DashMap entry guard — clippy will yell
  and it would defeat the purpose of the change.
- Use `tokio::sync::Mutex`, not `std::sync::Mutex`, since the lock is held
  across `.await` points during the HTTP refresh. Matches today's code.
- `OAuth2TokenManager::with_client` and `OAuth2TokenManager::new` both
  construct the cache — update both.
- `test_cache_miss_and_invalidation` today does
  `let cache = mgr.cache.lock().await; assert!(cache.is_empty())` — rewrite
  as `assert!(mgr.cache.is_empty())` (DashMap has an `is_empty()` method).
- `test_cached_token_returned_when_valid` pre-populates via
  `cache.insert(key, CachedAccessToken { ... })`. Rewrite as
  `mgr.cache.insert(key.to_string(), Arc::new(Mutex::new(Some(CachedAccessToken { ... }))))`.
- `test_rotation_callback_failure_aborts_refresh` asserts
  `cache.get("cred").is_none()` — rewrite as "either no entry OR entry's
  inner Option is None". The plan explicitly says: on rotation-callback
  failure, no cache write. With the new model there will be an entry in
  the DashMap (created by `or_insert_with`) but its `Option` will be
  `None`. So the right assertion is:
  ```rust
  match mgr.cache.get("cred") {
      None => {} // fine
      Some(slot) => {
          assert!(slot.lock().await.is_none(),
              "inner token slot must be empty after rotation-callback failure");
      }
  }
  ```
- Make sure `Arc` and `Mutex` imports stay scoped; remove `HashMap` import
  if no longer needed.
- This chunk does NOT add the new concurrent load test — that's chunk-02.
  Do not get distracted scope-creeping into it.
- Do NOT edit any `wiki/*.md` file — knowledge-maintainer handles that.
- Do NOT push; do NOT use `--no-verify`.
