# CHUNK PLAN — chunk-01-signing-canon

Parent plan: 2026-04-17-high-cli-and-mig-1
Role: backend
Engineer: backend_01

## Scope

Atomic, paired change to the Ed25519-signed request payload on BOTH the CLI
signer and the broker verifier so that the URL query string is included and
both sides agree on a single canonical path-and-query form. Resolves CLI-2,
BRK-2, and CLI-3 in one commit.

This is a **hard breaking change**. No dual-accept window. Old CLI against
new broker must produce a clear 401. Document in the commit message and
RESULT.md.

## Acceptance criteria

- A new helper `canonicalise_path_and_query(path: &str, query: Option<&str>)
  -> String` exists in BOTH `crates/cli/src/signing.rs` and
  `crates/broker/src/auth.rs`. Two byte-identical copies — do NOT extract a
  shared workspace crate.
- Canonicalisation rule (must match exactly on both sides):
  - Strip a single trailing `/` from `path` UNLESS `path == "/"`.
  - If `query` is `Some(q)`, append `"?"` + `q` verbatim (do NOT re-sort
    params, do NOT touch percent-encoding).
  - If `query` is `None` or `Some("")`, append nothing.
  - Fragments: never present in `Uri::query()` and never in the path the CLI
    passes; nothing extra to strip.
- Canonical output shape (pinned by tests on both sides):
  - `("/foo/bar", None)` → `/foo/bar`
  - `("/foo/bar/", None)` → `/foo/bar`
  - `("/foo/bar", Some("a=1&b=2"))` → `/foo/bar?a=1&b=2`
  - `("/foo/bar/", Some("a=1&b=2"))` → `/foo/bar?a=1&b=2`
  - `("/", None)` → `/`
  - `("/", Some("a=1"))` → `/?a=1`
  - `("/", Some(""))` → `/`
- `sign_request` now takes the canonicalised path-with-query as its `path`
  parameter (signature stays `(keypair, method, path, body)` for minimal
  callsite churn — the canonicalisation happens at the BrokerClient layer
  before calling `sign_request`).
- Every BrokerClient method in `crates/cli/src/broker.rs` that currently
  passes a bare `path: &str` to `sign_request` is updated to first split
  the incoming `path` into path + optional query, run them through
  `canonicalise_path_and_query`, and then call `sign_request` with the
  canonical form. The HTTP request URL itself is built unchanged
  (`format!("{}{}", self.base_url, path)`).
- Broker `auth_middleware` reconstructs the verification payload via
  `canonicalise_path_and_query(request.uri().path(),
  request.uri().query())` instead of `request.uri().path().to_string()`.
- Broker test fixtures in `crates/broker/src/auth.rs::tests` are updated:
  the test_verify_valid_signature, test_reject_expired_timestamp, and
  test_reject_invalid_signature paths now exercise the new payload shape.
  Add a new test `test_verify_signature_with_query_string` that signs with
  query, verifies success, and a paired negative test
  `test_reject_signature_when_query_dropped` (sign with query, send
  without).
- New CLI unit tests in `crates/cli/src/signing.rs::tests` pin the 7 cases
  listed in the parent PLAN's E2E section 3(a) for `canonicalise_path_and_query`.

## Files expected to change

- `crates/cli/src/signing.rs` — add `canonicalise_path_and_query`; add unit
  tests; document the new payload format on `sign_request`.
- `crates/cli/src/broker.rs` — update all 5 call sites (`get`, `post`,
  `post_raw`, `post_signed_empty`, `get_raw` at lines 76, 98, 124, 148, 187)
  to canonicalise before signing. The `path: &str` parameter on each
  method continues to be a path-with-query string (callers already pass
  e.g. `"/api/v1/credentials/by-name?name=foo"` style strings; verify by
  grep — if any caller passes ONLY a path, no harm done because
  `canonicalise_path_and_query("/foo", None)` is `/foo`).
- `crates/broker/src/auth.rs` — add `canonicalise_path_and_query` (a
  byte-identical copy of the CLI helper); replace
  `request.uri().path().to_string()` at line 109 with the canonicalised
  form; update the 3 existing tests; add 2 new tests.

## Reuse

- `axum::http::Uri::path()` and `axum::http::Uri::query()` already exist
  on the broker side — no new dependency.
- On the CLI side: split a `path: &str` like `"/foo?a=1"` with
  `path.split_once('?')`. Do NOT pull in a URL parsing crate.
- `crates/cli/src/signing.rs:127` — current `sign_request` body. Keep its
  function signature; only change the caller-supplied `path` to be the
  canonical path-with-query and update the format comment.

## Prior art (from wiki)

- `wiki/workspace-identity/keypair-and-signing.md` — current signed payload
  is `METHOD\nPATH\nTIMESTAMP\nBODY`; this chunk changes that to
  `METHOD\nPATH_WITH_QUERY\nTIMESTAMP\nBODY` per the canonicalisation rule.
  Do NOT edit the wiki — the documentation-agent handles that post-merge.
- `wiki/workspace-identity/broker-verification.md` — describes the 5-step
  middleware flow. Step 2 (reconstruct the signed payload) changes shape.
- `wiki/decisions/three-tier-boundary.md` — confirms CLI ↔ broker are
  typically co-deployed, supporting the hard-break compat decision.

## Dependencies on other chunks

- None. Chunks 02, 03, 04 touch disjoint files and may run in parallel.

## Notes for the engineer

- **CRITICAL**: CLI signing change and broker verification change MUST land
  in the SAME commit on the SAME branch. They are paired — splitting them
  would break local round-trip tests during review.
- **Hard break is approved.** No dual-accept window. Old CLI + new broker
  = 401. Old broker + new CLI = 401. Document this in your commit message.
- **DEV BUILDS ONLY.** Never `cargo build --release` or `cargo test
  --release`. Standard verification: `cargo fmt --all`, `cargo clippy
  --workspace -- -D warnings`, `cargo test -p agentcordon-cli`, `cargo test
  -p agentcordon-broker`, `cargo build --workspace`.
- Do NOT touch `wiki/**`, `docs/**`, `input/BUGS.md`, the server crate, the
  Cedar policy bundle, or any of the 13 pre-existing server integration
  test failures (`v311_credential_name_scoping::*`, `credential_bugs::*`).
- Do NOT extract a shared `agentcordon-signing` workspace crate. Two
  identical helpers is the explicit design choice for now.
- Verify byte-identical canonicalisation by writing one shared test data
  table and copying it to both crates' test modules. If a future
  contributor edits one without the other, the round-trip test will catch
  it.
- The root-user bypass at `crates/core/src/policy/cedar/mod.rs:86-95` is
  intentional by design — if you encounter it during review, do not refile.
