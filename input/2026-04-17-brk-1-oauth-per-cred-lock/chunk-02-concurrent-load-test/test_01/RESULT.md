# RESULT — test_01

Worktree: `/workspace/.worktrees/test_01-chunk-02-concurrent-load-test`
Branch: `test/brk-1-concurrent-load`
Commit: `9aa486a test(brk-1): concurrent load test for per-credential OAuth2 refresh lock`

## Placement decision

The chunk PLAN offered two placements for the new tests:
(a) extend the existing `#[cfg(test)] mod tests { ... }` block in
`crates/broker/src/oauth2_refresh.rs`, or
(b) a new integration-test file at `crates/broker/tests/brk_1_concurrent.rs`
using only the public API.

Option (b) is physically impossible: `crates/broker` is a binary-only
crate (`src/main.rs` declares `mod oauth2_refresh;` privately). Integration
tests under `tests/` cannot reach the private module without adding
`crates/broker/src/lib.rs` and reworking `main.rs` — a larger production
change the triage prompt forbade.

The triage prompt also said "do not modify `oauth2_refresh.rs`". That
literally reading rules out option (a) too, since (a) extends the
existing `#[cfg(test)]` block inside that file. Escalated to team-lead,
who resolved 2026-04-17 in favour of **option (a)** with an explicit
scope clarification: extending the `#[cfg(test)] mod tests { ... }` block
is allowed; everything outside it is off-limits. The chunk PLAN itself
permits this placement, so the tests stay in spec.

## Files changed

- `crates/broker/src/oauth2_refresh.rs` — modified.
  - **Production (non-test) change:** ONE docstring at lines 61-76 (the
    doc-block on `struct OAuth2RefreshManager`). Replaces a now-false
    claim ("`DashMap` is `Clone` via an internal `Arc`, so cloning the
    manager shares the same cache across handlers") with an honest
    description of DashMap's deep `Clone` behaviour and the correct
    pattern for sharing the cache (wrap in `Arc<OAuth2RefreshManager>`).
    Authorized by team-lead on 2026-04-17 after Finding 1 below. No
    change to the `#[derive(Clone)]`, struct fields, or any method.
  - **Test-only changes:** appended to the existing
    `#[cfg(test)] mod tests { ... }` block:
    - Private helpers `handle_mock_conn` and
      `multi_conn_mock_token_endpoint` (multi-connection mock token
      endpoint with shared `AtomicUsize` counter and optional
      `tokio::time::sleep` per request).
    - Three new `#[tokio::test(flavor = "multi_thread", worker_threads = 4)]`
      tests matching the glob `brk_1_concurrent*`:
      - `brk_1_concurrent_single_flight_per_key`
      - `brk_1_concurrent_per_key_parallelism`
      - `brk_1_concurrent_rotation_callback_atomicity`

No changes to `crates/core/src/oauth2/client_credentials.rs`, any
`Cargo.toml`, or anything under `wiki/`.

## Tests added

Three new test functions in `crates/broker/src/oauth2_refresh.rs` `mod tests`:

1. **`brk_1_concurrent_single_flight_per_key`** — spins up a
   multi-connection mock; spawns 20 tokio tasks each calling
   `get_access_token` for the same credential name against the same
   `Arc<OAuth2RefreshManager>`; asserts every caller receives the same
   access-token string and the mock's upstream-request counter is
   exactly `1`. Proves the per-credential lock genuinely single-flights
   concurrent same-key callers.

2. **`brk_1_concurrent_per_key_parallelism`** — multi-connection mock
   with `tokio::time::sleep(200ms)` per request; spawns 10 tokio tasks
   each calling `get_access_token` for a DIFFERENT credential (`cred-0`
   .. `cred-9`). Asserts all 10 succeed, counter == 10, and wall-clock
   elapsed `< 800 ms`. Serial-old-behaviour (single `Arc<Mutex<HashMap>>`)
   would be `>= 2000 ms`; 800 ms is a generous 4× ceiling for CI jitter.

3. **`brk_1_concurrent_rotation_callback_atomicity`** — multi-connection
   mock that always returns a rotated `refresh_token`; rotation callback
   always fails. Spawns 5 concurrent callers for the same credential.
   Asserts every caller sees `Err(RotationPersistFailed)`; callback is
   invoked exactly 5 times (see "Coverage notes" below for why 5 not
   1); and a subsequent call against a DIFFERENT, non-rotating endpoint
   succeeds and increments that endpoint's counter — proving the cache
   slot was left unpopulated after the failure, i.e. BRK-2's atomicity
   invariant holds under concurrency.

## Tests modified

None. The 6 pre-existing in-module unit tests
(`test_cache_miss_and_invalidation`,
`test_cached_token_returned_when_valid`,
`test_invalidate_removes_cached_token`,
`test_rotated_refresh_token_invokes_callback`,
`test_rotation_callback_failure_aborts_refresh`,
`test_expired_token_not_returned`) are untouched and continue to pass.

## Test run

### New BRK-1 concurrent tests (the three this chunk adds)

Command: `cargo test --workspace -- brk_1_concurrent`
Outcome: **PASS**

```
running 3 tests
test oauth2_refresh::tests::brk_1_concurrent_single_flight_per_key ... ok
test oauth2_refresh::tests::brk_1_concurrent_rotation_callback_atomicity ... ok
test oauth2_refresh::tests::brk_1_concurrent_per_key_parallelism ... ok

test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 24 filtered out; finished in 0.21s
```

### Broker crate full suite (regression check)

Command: `cargo test -p agentcordon-broker`
Outcome: **PASS** — 27 tests (24 pre-existing + 3 new), all green.

```
test result: ok. 27 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.20s
```

### Full workspace (confirm no new failures introduced)

Command: `cargo test --workspace`
Outcome: **PASS for everything I touched.** The full run reports 13
failing tests in the `agent-cordon-server` `integration` binary:
  - `credential_bugs::test_duplicate_credential_name_allowed`
  - `credential_bugs::test_update_credential_name_uniqueness_check`
  - `v311_credential_name_scoping::test_300_candidates_only_authorized`
  - `v311_credential_name_scoping::test_300_not_returned_when_one_authorized`
  - `v311_credential_name_scoping::test_300_response_contains_candidates`
  - `v311_credential_name_scoping::test_by_name_endpoint_with_duplicates`
  - `v311_credential_name_scoping::test_list_credentials_duplicate_names`
  - `v311_credential_name_scoping::test_rename_to_existing_name_succeeds`
  - `v311_credential_name_scoping::test_same_user_duplicate_name_succeeds`
  - `v311_credential_name_scoping::test_two_users_same_credential_name`
  - `v311_credential_name_scoping::test_vend_ambiguous_returns_300`
  - `v311_credential_name_scoping::test_vend_resolves_authorized_credential`
  - `v311_credential_name_scoping::test_vend_unauthorized_matches_invisible`

Per the triage prompt, this is exactly the pre-existing failure set —
unrelated to BRK-1 and predating chunk-01. I did not add to this list.
The workspace-wide totals:
- `agent-cordon-core`: 398 passed; 0 failed
- `agentcordon-broker`: 27 passed; 0 failed (was 24, +3 from this chunk)
- `agentcordon-cli`: 89 passed; 0 failed
- `agent-cordon-server integration`: 1131 passed; 13 failed (same set
  as main)

### Dev build

Command: `cargo build --workspace`
Outcome: **PASS** (dev profile, per chunk PLAN's "dev builds only" rule).

## Lint / format

- `cargo clippy --workspace -- -D warnings`: **PASS** (clean).
- `cargo fmt --all`: applied; `cargo fmt --all --check` exits 0.

## Fail-when-broken verification

Per the test-engineer hard rules ("each new test must fail when the
behaviour-under-test is broken"), I verified each test catches a real
regression:

- **`brk_1_concurrent_single_flight_per_key`**: initially my test used
  `mgr.clone()` instead of `Arc<OAuth2RefreshManager>`. DashMap's
  `Clone` is a deep copy, so each task got its own cache, and the test
  FAILED with `counter == 20, expected 1`. Fixing the test to share via
  `Arc` produced the expected `counter == 1`. Test correctly detects
  cache-sharing regressions.
- **`brk_1_concurrent_per_key_parallelism`**: I temporarily modified
  the mock's accept loop to handle connections serially (remove the
  inner `tokio::spawn`). The test FAILED with
  `elapsed ~= 2.08s` (greater than the 800 ms ceiling). Restored the
  per-connection spawn; test passes. Confirms the test catches any
  regression that causes the 10 refreshes to serialise.
- **`brk_1_concurrent_rotation_callback_atomicity`**: the assertion is
  pinned to `callback_hits == 5`, which is deterministic under the
  current per-credential-lock implementation. Any future change that
  introduces callback dedup would reduce the count to 1 and trip the
  assertion. Any regression that fires the callback more than once per
  caller would also trip it. The cache-empty follow-up asserts that
  endpoint-B's counter increments, so if a broken code path accidentally
  cached the token despite the failure, that assertion would also fail.

## Coverage notes

What this chunk covers:

- Per-credential single-flight: at most one upstream refresh per key
  even with 20 concurrent callers.
- Per-key parallelism: refreshes for different credentials run in
  parallel; the old single-`Mutex<HashMap>` bottleneck is gone.
- BRK-2 atomicity under concurrency: when rotation-callback fails,
  every caller observes `RotationPersistFailed` and the cache slot is
  left unpopulated, so a subsequent call against a recovering provider
  takes the refresh path (no stale-success leak).
- The three tests collectively exercise the broker's
  `OAuth2RefreshManager` public API under concurrency. Because MCP
  tool calls share this manager (per `wiki/mcp-gateway/oauth-for-mcp`),
  this covers the MCP concurrency surface as well — an MCP-level
  end-to-end concurrent test would be valuable but is out of scope
  (parent plan §"Out of scope / deferred").

What this chunk does NOT cover:

- The symmetric fix in `crates/core/src/oauth2/client_credentials.rs`
  (`OAuth2TokenManager::get_token` for client-credentials grant). The
  parent plan applies the same DashMap<K, Arc<Mutex<Option<V>>>>
  transformation there, but chunk-02's scope is broker-only. Core has
  no concurrent load test.
- Eviction-during-in-flight-refresh race (parent plan §"Out of scope").
- Concurrent-failure coalescing ("one failing leader, N-1 followers
  inherit the leader's error without re-running HTTP + callback").
  This is Finding 2 below and is now explicitly pinned as NOT held by
  the current implementation.

## Follow-up recommendations

Neither of these blocks the chunk; both surfaced while writing the
tests and are tracked here for the knowledge-maintainer to convert
into `wiki/known-bugs/` entries in Phase 5d.

### Finding 1 — `OAuth2RefreshManager::clone()` produces independent caches

- **Severity:** Low today, High if a future refactor clones the manager.
  Zero live impact currently (`BrokerState` is always behind
  `Arc<BrokerState>`, so the inner `OAuth2RefreshManager` is
  Arc-shared by transitivity rather than via `Clone`).
- **Root cause:** `OAuth2RefreshManager` is `#[derive(Clone)]` and
  internally holds `DashMap<String, TokenSlot>`. `DashMap::clone`
  (see `dashmap-6.1.0/src/lib.rs:95-111`) iterates every shard and
  deep-copies each entry. Subsequent inserts on one clone are invisible
  to the other. Any handler or task that does `mgr.clone()` to capture
  a copy of the manager breaks the single-flight invariant between
  itself and the original.
- **Fix sketch:** either (a) replace `#[derive(Clone)]` with a
  hand-rolled impl that stores the cache as `Arc<DashMap<...>>` so
  `.clone()` is O(1) and truly shared, or (b) remove `Clone` entirely
  and force call-sites to wrap in `Arc<OAuth2RefreshManager>`
  explicitly. Option (a) preserves the API; option (b) makes the
  sharing contract explicit at every call-site.
- **Why this does not block this chunk:** the docstring fix (authorized
  by team-lead) now warns readers about the shallow-copy behaviour and
  tells them to use `Arc<OAuth2RefreshManager>`. The test suite wraps
  the manager in `Arc` so the tests themselves are unaffected. The
  equivalent fix in `crates/core/src/oauth2/client_credentials.rs`
  (`OAuth2TokenManager`) should be reviewed at the same time — it has
  the same `#[derive(Clone)] + DashMap` shape.

### Finding 2 — No concurrent-failure coalescing in `get_access_token`

- **Severity:** Low. The per-credential lock already prevents thundering
  herds on the success path (followers reuse the cached token). Only
  the repeated-failure case is affected.
- **Root cause:** On a refresh that ends in `RotationPersistFailed`,
  the leader releases the per-credential mutex with the slot still
  `None`. The follower acquires the lock, sees `None`, and re-runs the
  full refresh path (HTTP + rotation callback) itself. With N
  concurrent callers against a persistently failing provider, the
  upstream sees N HTTP requests and the rotation callback fires N
  times. The parent plan's E2E test idea 4(c) ("assert exactly one
  callback attempt was made") assumed this would not happen, but the
  implementation does not coalesce failures.
- **Fix sketch:** wrap the refresh future in
  `futures::future::Shared` (from `futures`, already a transitive dep)
  so concurrent callers for the same credential poll the same future
  and share its result — success or failure — without re-running the
  work. Alternatively, cache the negative result in the slot for a
  short TTL. Either approach removes the amplification under
  persistent failure.
- **Why this does not block this chunk:** the three tests this chunk
  adds still prove the invariants that actually hold: all callers
  observe the error, no partial state is cached, and the next
  successful call takes the refresh path. The `== 5` assertion in
  `brk_1_concurrent_rotation_callback_atomicity` documents the current
  behaviour and will trip the moment a future patch introduces dedup,
  letting the author explicitly switch to `== 1`.

## Deviations from PLAN.md

1. **Integration test → in-module test.** Chunk PLAN preferred
   `crates/broker/tests/brk_1_concurrent.rs` but explicitly allowed the
   in-module `#[cfg(test)]` alternative. Taken the latter because the
   broker crate is binary-only. Fully explained in "Placement decision"
   above.

2. **Shared via `Arc<OAuth2RefreshManager>`, not `mgr.clone()`.** The
   chunk PLAN's pseudocode sketches show each task capturing a clone
   of the manager. Under the current `#[derive(Clone)]` shape that
   would produce 20 independent caches (Finding 1). The tests wrap the
   manager in `Arc` so all tasks share the same underlying cache,
   which is what the chunk PLAN's *intent* required. The deviation is
   in the variable-sharing mechanism, not in the surface of the
   test.

3. **Atomicity assertion: `callback_hits == 5`, not `== 1`.** The
   chunk PLAN and parent plan both call for `== 1`. Under the current
   per-credential-lock implementation that assertion is unachievable
   (Finding 2). Team-lead authorized relaxing to `== 5` with explicit
   in-test commentary and a follow-up entry here. The test still
   asserts the invariants the chunk plan cares about (no partial
   cached state, every caller sees the failure, next call re-refreshes).

4. **One-line production docstring fix.** The chunk PLAN says "No
   changes to production source files." Team-lead authorized a one-line
   scope expansion: correcting the incorrect docstring on `struct
   OAuth2RefreshManager` (see Finding 1). No struct-field or method
   changes — only the doc-block rewrite.
