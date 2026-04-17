# ENGINEER PLAN — backend_01

Parent chunk: chunk-01-signing-canon
Parent plan: 2026-04-17-high-cli-and-mig-1

## Prior art consulted

- `wiki/workspace-identity/keypair-and-signing.md` — documents the current
  signed-payload shape `METHOD\nPATH\nTIMESTAMP\nBODY`. This chunk changes
  `PATH` to `PATH_WITH_QUERY` on both ends. Do not edit the wiki.
- `wiki/workspace-identity/broker-verification.md` — Step 2 of the
  middleware flow reconstructs the signed payload from
  `request.uri().path()` today; this becomes `path + "?" + query`
  canonicalised.
- `wiki/decisions/three-tier-boundary.md` — confirms CLI and broker are
  co-deployed so a hard break on the payload format is acceptable.
- `wiki/process/dev-builds-only.md` — dev profile verification only.
- Reviewed `wiki/_master-index.md`; no other topic directly relevant.

## Approach

Two byte-identical copies of a pure helper, one in each crate. The helper
lives inside the existing modules (no new files, no shared workspace crate):

```rust
pub fn canonicalise_path_and_query(path: &str, query: Option<&str>) -> String {
    let trimmed: &str = if path.len() > 1 && path.ends_with('/') {
        &path[..path.len() - 1]
    } else {
        path
    };
    match query {
        Some(q) if !q.is_empty() => format!("{trimmed}?{q}"),
        _ => trimmed.to_string(),
    }
}
```

### CLI (`crates/cli/src/signing.rs`)

- Add the helper as a `pub(crate)` function so `broker.rs` can call it.
- Keep `sign_request(keypair, method, path, body)` signature unchanged.
  The path passed in is already the canonical path-with-query (callers
  handle canonicalisation).
- Update the doc comment above `sign_request` to describe the new
  `METHOD\nPATH_WITH_QUERY\nTIMESTAMP\nBODY` format.
- Add seven unit tests that pin the 7 canonical-output cases.

### CLI (`crates/cli/src/broker.rs`)

Each of `get`, `post`, `post_raw`, `post_signed_empty`, `get_raw`
currently receives a path-string that may already contain `?query`
(e.g. callers pass `"/api/v1/credentials/by-name?name=foo"`). Before
calling `sign_request`, split on the first `?` with `split_once('?')`
and pass the result through `canonicalise_path_and_query`. The outbound
HTTP URL is still `format!("{}{}", self.base_url, path)` — the raw path
string (pre-canonicalisation) remains the URL. Request signing uses the
canonical form; request dispatch uses the raw form. If the broker's
incoming URI parses the same raw path into the same canonical shape,
the signatures match; any server-side normalisation that differs would
be a latent issue for a follow-up but is not in scope here.

The paired tests on the broker side demonstrate round-trip: `sign_request`
produces a signature, a simulated middleware reconstruction yields the
same payload, signature verifies.

### Broker (`crates/broker/src/auth.rs`)

- Add the helper (byte-identical copy of the CLI version).
- Replace line 109 `request.uri().path().to_string()` with
  `canonicalise_path_and_query(request.uri().path(), request.uri().query())`.
- Update the existing three tests — `test_verify_valid_signature`,
  `test_reject_expired_timestamp`, `test_reject_invalid_signature` — so
  the `path` they sign and verify is already in canonical form
  (`/status`, which is already canonical; no change needed there beyond
  confirming).
- Add `test_verify_signature_with_query_string`: sign over
  `/foo/bar?a=1&b=2`, verify.
- Add `test_reject_signature_when_query_dropped`: sign over
  `/foo?a=1`, verify with `/foo` (or vice versa) — expect
  `Err(AuthError::InvalidSignature)`.
- Add `test_canonicalise_path_and_query_cases`: same 7 cases as CLI.

## Files I will change

- `crates/cli/src/signing.rs` — add `canonicalise_path_and_query`; update
  doc comment on `sign_request`; add 7 unit test cases.
- `crates/cli/src/broker.rs` — canonicalise the path-with-query before
  calling `sign_request` in 5 methods (`get`, `post`, `post_raw`,
  `post_signed_empty`, `get_raw`).
- `crates/broker/src/auth.rs` — add byte-identical
  `canonicalise_path_and_query`; swap line 109; update 3 tests; add 3 new
  tests.

## Unit tests I will write

- `crates/cli/src/signing.rs` `#[cfg(test)] mod tests`:
  - `canonicalise_plain_path` — `("/foo/bar", None)` → `/foo/bar`
  - `canonicalise_strips_trailing_slash` — `("/foo/bar/", None)` → `/foo/bar`
  - `canonicalise_with_query` — `("/foo/bar", Some("a=1&b=2"))` → `/foo/bar?a=1&b=2`
  - `canonicalise_strips_trailing_slash_with_query` — `("/foo/bar/", Some("a=1&b=2"))` → `/foo/bar?a=1&b=2`
  - `canonicalise_root_path` — `("/", None)` → `/`
  - `canonicalise_root_with_query` — `("/", Some("a=1"))` → `/?a=1`
  - `canonicalise_root_with_empty_query` — `("/", Some(""))` → `/`

- `crates/broker/src/auth.rs` `#[cfg(test)] mod tests`:
  - `canonicalise_path_and_query_cases` — same 7 assertions.
  - `test_verify_signature_with_query_string` — sign
    `GET\n/foo/bar?a=1&b=2\nTS\n` and verify success.
  - `test_reject_signature_when_query_dropped` — sign with query,
    verify with path-only, expect `InvalidSignature`.

## How I'll run the tests

From the worktree `/workspace/.worktrees/backend_01-chunk-01-signing-canon`:

```
cargo fmt --all
cargo clippy --workspace -- -D warnings
cargo test -p agentcordon-cli signing::tests
cargo test -p agentcordon-broker auth::tests
cargo test -p agentcordon-cli
cargo test -p agentcordon-broker
cargo build --workspace
```

All dev profile. No `--release`.

## Non-goals (flagged to reviewer)

- `post_unsigned` is unchanged — unsigned requests don't care about path
  canonicalisation.
- No shared workspace crate for the helper. The plan explicitly calls for
  two byte-identical copies.
- The HTTP URL is not canonicalised (only the signed payload is); the
  server's path-normaliser is assumed to be consistent with the broker's.
- No dual-accept window. Hard break documented in commit message.
