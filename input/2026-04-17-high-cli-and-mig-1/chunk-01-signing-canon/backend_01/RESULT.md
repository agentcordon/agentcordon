# RESULT — backend_01

## Files changed

- `crates/cli/src/signing.rs` — modified — 223 lines (was 143; added
  `canonicalise_path_and_query` helper, updated `sign_request` doc
  comment, added 7 unit tests).
- `crates/cli/src/broker.rs` — modified — 332 lines (was 314; added
  `canonical_sign_path` helper; updated 5 signed call sites `get`,
  `post`, `post_raw`, `post_signed_empty`, `get_raw` to canonicalise
  before signing).
- `crates/broker/src/auth.rs` — modified — 237 lines (was 317; added
  byte-identical `canonicalise_path_and_query`; replaced
  `request.uri().path().to_string()` with canonical form; test module
  moved to `auth_tests.rs` via `#[path]` attribute to stay under the
  R-001 400-line file cap).
- `crates/broker/src/auth_tests.rs` — **new** — 180 lines (test module
  pulled out of `auth.rs`; contains the 4 pre-existing tests updated
  trivially plus the 3 new chunk tests).

## Tests added

- `crates/cli/src/signing.rs::tests::canonicalise_plain_path` — asserts
  `("/foo/bar", None) → "/foo/bar"`.
- `crates/cli/src/signing.rs::tests::canonicalise_strips_trailing_slash` —
  asserts `("/foo/bar/", None) → "/foo/bar"`.
- `crates/cli/src/signing.rs::tests::canonicalise_with_query` — asserts
  `("/foo/bar", Some("a=1&b=2")) → "/foo/bar?a=1&b=2"`.
- `crates/cli/src/signing.rs::tests::canonicalise_strips_trailing_slash_with_query`
  — asserts `("/foo/bar/", Some("a=1&b=2")) → "/foo/bar?a=1&b=2"`.
- `crates/cli/src/signing.rs::tests::canonicalise_root_path` — asserts
  `("/", None) → "/"`.
- `crates/cli/src/signing.rs::tests::canonicalise_root_with_query` —
  asserts `("/", Some("a=1")) → "/?a=1"`.
- `crates/cli/src/signing.rs::tests::canonicalise_root_with_empty_query` —
  asserts `("/", Some("")) → "/"`.
- `crates/broker/src/auth.rs::tests::canonicalise_path_and_query_cases` —
  same 7 assertions, proving byte-identical behaviour across crates.
- `crates/broker/src/auth.rs::tests::test_verify_signature_with_query_string`
  — signs `GET\n/foo/bar?a=1&b=2\nTS\n` (with trailing-slash stripped via
  canonicalisation) and verifies success.
- `crates/broker/src/auth.rs::tests::test_reject_signature_when_query_dropped`
  — signs over `/foo?a=1`, verifies over `/foo`, expects
  `Err(AuthError::InvalidSignature)`.

Existing tests (`test_verify_valid_signature`, `test_reject_expired_timestamp`,
`test_reject_invalid_signature`, `test_pk_hash`) are unchanged because their
paths (`/status`) are already in canonical form — no query, no trailing
slash. The new tests cover the payload-shape changes.

## Test run

Command: `cargo fmt --all && cargo clippy --workspace -- -D warnings && cargo test -p agentcordon-cli && cargo test -p agentcordon-broker && cargo build --workspace` (from the worktree at `/workspace/.worktrees/backend_01-chunk-01-signing-canon`)

Outcome: PASS

```
$ cargo clippy --workspace -- -D warnings
    Checking agent-cordon-core v0.3.0
    Checking agentcordon-cli v0.3.0
    Checking agent-cordon-server v0.3.0
    Checking agentcordon-broker v0.3.0
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 10.25s

$ cargo test -p agentcordon-cli
running 10 tests
test signing::tests::canonicalise_plain_path ... ok
test signing::tests::canonicalise_root_with_empty_query ... ok
test signing::tests::canonicalise_root_path ... ok
test signing::tests::canonicalise_root_with_query ... ok
test signing::tests::canonicalise_strips_trailing_slash ... ok
test signing::tests::canonicalise_with_query ... ok
test signing::tests::canonicalise_strips_trailing_slash_with_query ... ok
test commands::init::tests::ensure_entry_preserves_existing_servers ... ok
test commands::init::tests::ensure_entry_creates_file_when_missing ... ok
test commands::init::tests::ensure_entry_is_idempotent ... ok
test result: ok. 10 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out

$ cargo test -p agentcordon-broker
running 30 tests
test auth::tests::canonicalise_path_and_query_cases ... ok
test auth::tests::test_verify_signature_with_query_string ... ok
test auth::tests::test_reject_signature_when_query_dropped ... ok
test auth::tests::test_verify_valid_signature ... ok
test auth::tests::test_reject_expired_timestamp ... ok
test auth::tests::test_reject_invalid_signature ... ok
test auth::tests::test_pk_hash ... ok
... (23 other pre-existing broker tests — all pass)
test result: ok. 30 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out

$ cargo build --workspace
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 20.51s
```

## Lint / format

- `cargo clippy --workspace -- -D warnings`: PASS
- `cargo fmt --all --check` (my three modified files only, via
  `rustfmt --check --edition 2021 crates/cli/src/signing.rs
  crates/cli/src/broker.rs crates/broker/src/auth.rs`): PASS

  **Caveat**: `cargo fmt --all --check` reports pre-existing diff in
  files this chunk does not touch: `crates/broker/src/routes/proxy.rs`,
  `crates/core/src/storage/migrations.rs`, and several server-crate
  files. These were already malformed on `main` before this chunk;
  running `cargo fmt --all` reformats them, but that touches files
  outside the chunk's scope (server crate is explicitly excluded by
  the plan), so I reverted those unrelated changes. Flagging for the
  reviewer: the pre-existing fmt issue is not introduced or addressed
  by this chunk.

## Deviations from PLAN.md

(none) — implementation follows the plan exactly. The CLI helper is
`pub(crate)` rather than `pub` so only `broker.rs` in the same crate
can reach it (no external consumers); this matches plan intent of
"helper in both crates".

## Round 2 changes

- **R-001 (file size cap).** Round 1 pushed `crates/broker/src/auth.rs`
  to 424 lines, exceeding the 400-line cap by 24. Split the test module
  into a sibling file `crates/broker/src/auth_tests.rs` referenced via
  `#[cfg(test)] #[path = "auth_tests.rs"] mod tests;` at the bottom of
  `auth.rs`. Post-split line counts: `auth.rs` 237, `auth_tests.rs` 180
  — both comfortably under the cap. No logic changed; all 30 broker
  tests still pass, clippy clean, rustfmt clean on all four modified
  files.

## Breaking change note

The Ed25519-signed payload now includes the query string as
`METHOD\nPATH_WITH_QUERY\nTIMESTAMP\nBODY`. Any pre-2026-04-17 CLI
against the new broker (or new CLI against an old broker) will fail
signature verification with HTTP 401 "Signature verification failed".
This is the hard-break approved in the plan — no dual-accept window —
and will be called out in the commit message.
