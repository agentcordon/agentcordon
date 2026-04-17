# ENGINEER PLAN — test_01

Parent chunk: chunk-02-concurrent-load-test
Parent plan: 2026-04-17-brk-1-oauth-per-cred-lock

## Prior art consulted

- `wiki/known-bugs/brk-1-oauth-cache-mutex.md` — severity and fix sketch
  (DashMap / moka). Told me this test is the BRK-1 regression pin.
- `wiki/known-bugs/brk-2-refresh-rotation-callback.md` — adjacent
  concern. The atomicity test case must preserve BRK-2 exactly as-is
  (callback failure → cache empty, `RotationPersistFailed` propagates).
  Do not expand into retry logic.
- `wiki/testing/organization.md` — integration tests in this repo
  consolidate into `crates/server/tests/main.rs`; broker has no existing
  `tests/` dir. Placement decision below explains why that does not
  apply here.
- `wiki/testing/ci-and-features.md` — standard build commands
  (`cargo test --workspace`, `cargo clippy --workspace -- -D warnings`,
  `cargo fmt --all`). Dev builds only.
- `wiki/testing/coverage.md` — explicitly lists BRK-1 concurrent load
  as a gap; this chunk closes it.
- Existing in-module tests in `crates/broker/src/oauth2_refresh.rs`
  (especially `mock_token_endpoint` at lines 310-334) — single-shot
  mock; the new tests need a multi-connection variant.

## Placement decision

The chunk PLAN offered two placements: (a) in the existing
`#[cfg(test)] mod tests { ... }` block of
`crates/broker/src/oauth2_refresh.rs`, or (b) a new integration-test
file at `crates/broker/tests/brk_1_concurrent.rs` using the public API
only.

Option (b) is not physically available: `crates/broker` is a
binary-only crate (`src/main.rs` with `mod oauth2_refresh;`); integration
tests cannot reach private modules of a binary without adding a
`lib.rs` and reworking `main.rs`, which would itself be a production
source change that the triage prompt forbids. The triage prompt also
forbids editing `oauth2_refresh.rs`, which on a literal read would rule
out option (a) too.

Team-lead resolved the contradiction (2026-04-17): take option (a).
May extend the existing `#[cfg(test)] mod tests { ... }` block with new
test functions and helpers; may NOT touch anything outside that block.
Chunk PLAN itself explicitly allows this placement, so the tests remain
in spec.

## Test type

integration (in-module integration-style: exercises only the public
`OAuth2RefreshManager` API, hits a real localhost TCP mock via the
real `reqwest` client).

## What I will test

Three scenarios, all against the public
`OAuth2RefreshManager::get_access_token` API.

- Scenario 1: `brk_1_concurrent_single_flight_per_key` — Setup:
  multi-connection mock token endpoint with shared `AtomicUsize`
  counter. Action: spawn 20 concurrent `get_access_token` calls for the
  same credential name against that endpoint. Expected: every call
  returns the same access token string, counter == 1. Proves
  single-flight per credential.

- Scenario 2: `brk_1_concurrent_per_key_parallelism` — Setup:
  multi-connection mock that `tokio::time::sleep`s 200 ms per
  connection before responding. Action: spawn 10 concurrent
  `get_access_token` calls, each for a DIFFERENT credential name
  (`cred-0` .. `cred-9`). Expected: wall-clock `< 800 ms` (serial would
  be `>= 2000 ms`), all 10 succeed, counter == 10. Proves per-key
  parallelism.

- Scenario 3: `brk_1_concurrent_rotation_callback_atomicity` — Setup:
  mock that always returns a rotated `refresh_token`; rotation callback
  always fails. Action: 5 concurrent `get_access_token` calls for the
  same credential. Expected: every result is
  `Err(OAuth2RefreshError::RotationPersistFailed(_))`; callback
  invocation counter == 1 (single-flight-under-failure); the
  per-credential slot is left unpopulated — verified via public API by
  making one more `get_access_token` call with a DIFFERENT,
  non-rotating mock, and asserting that mock's counter increments
  (i.e. the cache was empty so the next call took the refresh path).
  Preserves BRK-2 atomicity invariant under concurrency.

## Files I will create/change

- `crates/broker/src/oauth2_refresh.rs` — EXTEND the existing
  `#[cfg(test)] mod tests { ... }` block ONLY. Add:
  - A private `multi_conn_mock_token_endpoint` helper (accepts
    connections in a loop, spawns a per-connection task, shared
    `AtomicUsize` counter, optional `tokio::time::sleep` per request,
    parameterised JSON response body).
  - Three `#[tokio::test(flavor = "multi_thread", worker_threads = 4)]`
    functions named `brk_1_concurrent_single_flight_per_key`,
    `brk_1_concurrent_per_key_parallelism`,
    `brk_1_concurrent_rotation_callback_atomicity`.
  - NO changes to any non-test code in the file.
- `input/2026-04-17-brk-1-oauth-per-cred-lock/chunk-02-concurrent-load-test/test_01/PLAN.md` — this file.
- `input/2026-04-17-brk-1-oauth-per-cred-lock/chunk-02-concurrent-load-test/test_01/RESULT.md` — written after tests pass.

No changes outside the `#[cfg(test)]` block. No changes to
`crates/core/src/oauth2/client_credentials.rs`, any `Cargo.toml`,
or anything under `wiki/`.

## Test runner & command

```
cargo test --workspace -- brk_1_concurrent
```

Also run before declaring done:
- `cargo fmt --all`
- `cargo clippy --workspace -- -D warnings`
- `cargo test -p agentcordon-broker`
- `cargo test --workspace` (to confirm no new failures outside the
  pre-existing `agent-cordon-server` ones listed in the triage prompt)
- `cargo build --workspace` (dev profile)

No environment setup needed. No db. Mock is pure tokio TCP.

## Reuse

- `OAuth2RefreshManager::{new, get_access_token}` — public API (in-crate).
- `RotationCallback`, `RotationError`, `OAuth2RefreshError` — public
  types already in the module.
- `tokio::net::TcpListener`, `tokio::io::{AsyncReadExt, AsyncWriteExt}`
  for the mock — same shape as the existing in-module
  `mock_token_endpoint`, adapted to a per-connection spawn loop.
- `futures_util::future::join_all` — `futures-util = "0.3"` is already
  in the broker's `[dependencies]`.
- `std::sync::atomic::AtomicUsize` — in std.

## Determinism strategy

- Mock uses `tokio::time::sleep` (not `std::thread::sleep`) so the
  runtime can interleave.
- Wall-clock ceiling is 800 ms for the parallelism test (4× the
  per-request sleep) — generous for CI jitter.
- No retry loops in the tests. If flaky, raise the ceiling — do not
  add retries.
- All three tests use `#[tokio::test(flavor = "multi_thread")]` so the
  runtime actually runs tasks in parallel, not cooperatively on one
  thread (important for the wall-clock assertion).
