# PLAN — 2026-04-17-brk-1-oauth-per-cred-lock

## Context

Both OAuth2 token managers in this workspace hold a single `Arc<Mutex<HashMap>>` as their token cache and deliberately hold the lock across the upstream HTTP round-trip to prevent a thundering herd on expired tokens. The comment on [crates/broker/src/oauth2_refresh.rs:107-110](crates/broker/src/oauth2_refresh.rs#L107-L110) and [crates/core/src/oauth2/client_credentials.rs:104-107](crates/core/src/oauth2/client_credentials.rs#L104-L107) calls this out explicitly: "serializes all token refreshes — acceptable for small credential counts."

The side effect is that every credential operation in the broker funnels through one lock. Under concurrent load — or whenever a provider is slow — the broker's tail latency spikes across every OAuth2-backed credential, not just the one whose provider is struggling. This is tracked as BRK-1 (High). The identical pattern in `core/oauth2/client_credentials.rs` is the same bug under a different ID and must be fixed in the same pass so the fix surface is consistent.

This plan replaces the single mutex with per-credential locking while preserving the existing single-flight semantics.

## Goals

- `OAuth2RefreshManager::get_access_token` in the broker crate allows concurrent refreshes for **different** credential names to proceed in parallel.
- `OAuth2TokenManager::get_token` in the core crate allows concurrent refreshes for **different** credential IDs to proceed in parallel.
- Both still single-flight per credential: at most one in-flight upstream refresh per credential at a time; other concurrent callers for that same credential wait and reuse the freshly acquired token.
- All existing unit tests in both files pass unchanged.
- A new concurrent load test proves single-flight-per-key and per-key parallelism.
- The rotation-callback atomicity guarantee ([crates/broker/src/oauth2_refresh.rs:171-205](crates/broker/src/oauth2_refresh.rs#L171-L205)) is preserved: callback failure leaves the cache empty and propagates `RotationPersistFailed`.
- `dashmap` is lifted to `[workspace.dependencies]` in the root `Cargo.toml` to avoid drift.
- The BRK-1 wiki article's "No load test exercising this today" line can be deleted, and the bug can be marked fixed once the plan merges.

## Non-goals

- No change to caller call-sites. The public method signatures (`get_access_token`, `get_token`, `evict`, `invalidate`) must stay stable.
- No change to token-response parsing, rotation callback contract, or expiry-buffer semantics.
- No change to BRK-2 (refresh rotation-callback retry story). That's tracked separately; do not expand scope into retry logic.
- No change to MCP-specific OAuth code paths outside `OAuth2RefreshManager`.
- No moka adoption. We discussed it and rejected it for dependency weight.
- No metrics work. `key_rotations_total` / similar is CROSS-10, out of scope here.

## Prior art (from wiki)

Wiki articles consulted:

- `wiki/known-bugs/brk-1-oauth-cache-mutex.md` — source of this plan. Fix sketch explicitly names DashMap or moka.
- `wiki/known-bugs/brk-2-refresh-rotation-callback.md` — adjacent concern. This plan must not regress the atomicity invariant BRK-2 depends on.
- `wiki/credentials/transforms.md` — confirms both managers feed the same transform pipeline, so a stale semantic change would ripple into both credential-vend and MCP-OAuth paths.
- `wiki/mcp-gateway/oauth-for-mcp.md` — MCP tool calls share `OAuth2RefreshManager`; any regression surfaces as MCP latency.
- `wiki/authentication/oauth2-server.md` and `wiki/credentials/vending-ecies.md` — referenced for context; no constraints specific to this change.

Open known-bugs that overlap:

- `wiki/known-bugs/brk-1-oauth-cache-mutex.md` — this plan closes BRK-1.
- `wiki/known-bugs/brk-2-refresh-rotation-callback.md` — out of scope; plan must preserve current atomicity so BRK-2 remains exactly as tracked (no worse, no better).

## Approach

Replace `Arc<Mutex<HashMap<K, V>>>` with `DashMap<K, Arc<Mutex<Option<V>>>>` in both managers. The DashMap entry holds a per-credential `tokio::sync::Mutex<Option<CachedToken>>`. Hot path:

1. `cache.entry(key).or_insert_with(|| Arc::new(Mutex::new(None))).value().clone()` — brief shard-level write to get or create the per-key slot, then drop the DashMap write guard immediately.
2. `slot.lock().await` — per-credential mutex guards the check-and-acquire.
3. If `*slot` is `Some(cached)` and `cached.expires_at > now`, return the cached value.
4. Otherwise run the existing upstream refresh logic **under the per-credential lock**, insert the fresh token into the slot on success. This preserves single-flight per key.

Concurrency invariants:

- **Map contention**: the DashMap write guard is held only long enough to `or_insert_with`. No map-level lock is held across the HTTP call.
- **Per-credential single-flight**: the `Mutex<Option<CachedToken>>` is held across the HTTP call, exactly like today's single global lock — just scoped per credential.
- **Different credentials**: their slots are different `Arc<Mutex>`, so they never contend.
- **Rotation-callback atomicity**: the existing ordering (callback success → cache write) is preserved. On callback failure the slot is left `None` / previous-expired and the error propagates; no partial state.
- **Eviction**: `invalidate` / `evict` simply remove the key from the DashMap. Any concurrent holder of the old `Arc<Mutex>` finishes their work against the old slot and is garbage-collected when the Arc drops. Next caller creates a fresh slot.

Files that need changes are listed below. The `dashmap` workspace dep is lifted to the root `Cargo.toml` so `broker`, `core`, and the existing `server` usage all reference the same version.

## Files affected (anticipated)

- `Cargo.toml` — add `dashmap = "6"` to `[workspace.dependencies]`.
- `crates/broker/Cargo.toml` — add `dashmap = { workspace = true }`.
- `crates/core/Cargo.toml` — add `dashmap = { workspace = true }`.
- `crates/server/Cargo.toml` — change direct `dashmap = "6"` to `dashmap = { workspace = true }` for consistency (do not drop; server still needs it).
- `crates/broker/src/oauth2_refresh.rs` — replace `Arc<Mutex<HashMap<String, CachedAccessToken>>>` with `DashMap<String, Arc<Mutex<Option<CachedAccessToken>>>>`. Update `get_access_token`, `invalidate`, and the tests that touch `mgr.cache.lock().await` directly.
- `crates/core/src/oauth2/client_credentials.rs` — same transformation for `HashMap<CredentialId, CachedToken>`. Update `get_token`, `evict`, and any tests that peek at the inner map.
- `crates/broker/tests/` or `crates/core/tests/` — new concurrent load test (see E2E plan below). Pick the location that aligns with where existing OAuth2 tests live; grep both crates and place the new test alongside the closest existing concurrent or mock-endpoint test file.
- `wiki/known-bugs/brk-1-oauth-cache-mutex.md` — knowledge-maintainer will mark this `status: fixed` and cite the merge commit. **This edit is the knowledge-maintainer's job, not the engineer's.**
- `wiki/credentials/transforms.md` — knowledge-maintainer will update the line citing BRK-1. Same note.

## E2E test plan

The architect-reviewer will run through these steps in order after merge.

1. `cargo clippy --workspace -- -D warnings` — no warnings.
2. `cargo test --workspace` — all existing tests pass. Specifically these broker/core tests still pass:
   - `oauth2_refresh::tests::test_cache_miss_and_invalidation`
   - `oauth2_refresh::tests::test_cached_token_returned_when_valid`
   - `oauth2_refresh::tests::test_invalidate_removes_cached_token`
   - `oauth2_refresh::tests::test_rotated_refresh_token_invokes_callback`
   - `oauth2_refresh::tests::test_rotation_callback_failure_aborts_refresh`
   - `oauth2_refresh::tests::test_expired_token_not_returned`
   - (and the equivalent `oauth2::client_credentials::tests::*`)
3. `cargo test --workspace -- brk_1_concurrent` runs the new concurrent load test (see below). Must pass deterministically on a clean build.
4. The new test proves:
   a. **Per-key single-flight**: launch 20 concurrent `get_access_token` calls for the same credential name against a mock token endpoint that increments a request counter. Assert the counter ends at exactly `1` (not 20). All 20 callers receive the same token.
   b. **Per-key parallelism**: launch 10 concurrent calls, each for a *different* credential name, against a mock token endpoint that sleeps `200ms` per request. Assert total wall time `< 800ms` — i.e. refreshes ran in parallel, not serially. (The existing single-mutex code would take `>= 2000ms`.) Use a generous upper bound to avoid CI flakiness.
   c. **Rotation-callback atomicity preserved**: repeat `test_rotation_callback_failure_aborts_refresh` but with 5 concurrent callers for the same credential. Assert zero callers see a cached token and exactly one callback attempt was made.
5. `grep -rn 'Arc<Mutex<HashMap' crates/broker/src/oauth2_refresh.rs crates/core/src/oauth2/client_credentials.rs` returns no matches (the old shape is gone).
6. `grep -rn 'TODO: Replace single mutex' crates/` returns no matches (the comment-warning on the old code is removed).
7. `cargo fmt --all --check` is clean.
8. `cargo build --workspace --release` succeeds (catches any release-mode issues from changed generic bounds).

## Out of scope / deferred

- **BRK-2 retry logic**: rotation-callback retry-with-backoff remains a separate plan.
- **moka migration**: not adopted now; can be revisited if we later need TTL-aware eviction or built-in single-flight across process restarts.
- **Metrics on refresh rate / lock wait time**: would be good observability but is CROSS-10, deferred.
- **MCP-specific concurrent load test**: the new test in this plan exercises the manager directly, which is sufficient since MCP uses the same `OAuth2RefreshManager`. An end-to-end MCP-invoke concurrency test is valuable but separate.
- **Eviction-during-in-flight-refresh race**: `invalidate` removing a key while another task holds the per-credential lock is well-defined (the holder finishes against a detached Arc). Adding an explicit regression test for this is nice-to-have but not required to land BRK-1.
