# PLAN — 2026-04-17-high-cli-and-mig-1

## Context

`input/BUGS.md` (2026-04-17 source-code review) recorded 8 High-severity findings. This plan addresses five of them — the four High CLI findings plus MIG-1 — because they cluster cleanly: four touch the CLI crate (and one of those has a paired broker-side half at `crates/broker/src/auth.rs:109`), and MIG-1 is an orthogonal operator-facing fix that can ride in the same plan without coupling.

The three remaining Highs (SRV-1, SRV-2, CORE-1) are server/core changes with different review surfaces and will land in separate plans.

Specifically in scope:

- **CLI-1** — keypair file creation in `agentcordon init` is not TOCTOU-safe; an attacker with write access to `~/.agentcordon/` could race between the existence check and the write.
- **CLI-2 ⇔ BRK-2** (paired defect) — the Ed25519-signed payload at [crates/cli/src/signing.rs:127](crates/cli/src/signing.rs#L127) and the broker-side reconstruction at [crates/broker/src/auth.rs:108-109](crates/broker/src/auth.rs#L108-L109) both use `uri().path()` which drops the query string. Two requests differing only in query params sign identically — latent signature-reuse vector.
- **CLI-3** — trailing-slash ambiguity between CLI signing and server / broker path normalisation produces spurious signature mismatches for any caller that appends or strips a stray `/`.
- **CLI-4** — Windows `HOME` fallback in [crates/cli/src/broker.rs:311](crates/cli/src/broker.rs#L311) (and `crates/cli/src/commands/setup.rs:109`) falls back to `/tmp` when `HOME` is unset, which is wrong on Windows (`USERPROFILE` is the equivalent) and meaningless on any OS where `/tmp` exists but isn't the user's home.
- **MIG-1** — [migrations/007_credential_name_unique.sql](migrations/007_credential_name_unique.sql) installs a `UNIQUE INDEX` on `credentials(name)`. Any deployment that already has duplicate credential names will hit a destructive startup failure with no pre-flight scanner to detect the condition.

User decisions captured during Phase 1:
- **Compat mode:** hard break on the new signed payload. No dual-accept window. Fits the typical per-user-broker deployment where CLI and broker live on the same machine.
- **Path canonicalisation:** strip trailing `/` on both ends at sign time and verify time (except for root `/`).

## Goals

- `agentcordon init` creates `workspace.key` and `workspace.pub` via `OpenOptions::create_new(true)` (Unix) / `CreateFileW + CREATE_NEW` (Windows), so the existence-check and write are atomic. Idempotent behaviour preserved: if the key already exists when `init` runs, the command reuses it (same as today) — only the first-time-create path is hardened.
- The Ed25519-signed payload is `METHOD\nPATH_WITH_QUERY\nTIMESTAMP\nBODY`, where `PATH_WITH_QUERY` is the request's path-and-query as canonicalised by the rule below, on BOTH the CLI (`crates/cli/src/signing.rs::sign_request`) and the broker (`crates/broker/src/auth.rs`). Any old-format CLI fails authentication against the new broker with a clear 401, and vice versa. This is documented as a breaking change in the commit message / RESULT.md.
- Path canonicalisation rule, applied identically on both sides:
  - Input: the raw URI path and optional query string from the outgoing request.
  - Strip a single trailing `/` from the path unless the path is exactly `/`.
  - If a query string is present, append `?` + the query string verbatim (percent-encoding untouched — do NOT re-sort params, do NOT re-encode).
  - If no query string, append nothing.
  - Result shape: `/foo/bar`, `/foo/bar?a=1&b=2`, `/` for root, `/?a=1` for root-with-query. NEVER `/foo/bar/` and NEVER `/foo/bar?`.
  - Fragment component MUST be stripped if present (fragments never reach the server anyway, but belt-and-braces).
- `dirs_or_home()` in `crates/cli/src/broker.rs` and the equivalent in `crates/cli/src/commands/setup.rs` resolve a user home directory via `std::env::home_dir()` equivalents (using the `dirs` crate at `5.0`) that correctly handles Unix (`$HOME`), macOS (`$HOME`), and Windows (`USERPROFILE` → `HOMEDRIVE+HOMEPATH`). No `/tmp` fallback. If no home can be resolved, the function returns an error; the CLI surfaces a clear message and exits non-zero rather than silently writing to a nonsense path.
- A new operator script at `scripts/migration-007-precheck.sh` detects pre-existing duplicate credential names in both SQLite and Postgres deployments, prints a clear "resolve these before upgrading to X.Y.Z" message with the offending names, and exits non-zero if any duplicates are found. The migration file itself gains a comment pointing at the script.
- Every change has a unit or integration test proving the new behaviour; existing tests pass unchanged (with the single exception of the test module for `sign_request` and the broker's signature-verification tests, which MUST be updated to match the new payload format).
- BUGS.md is updated in-place to mark CLI-1, CLI-2, CLI-3, CLI-4, BRK-2, and MIG-1 as **Resolved by plan 2026-04-17-high-cli-and-mig-1** with a merge-commit link. Do NOT remove the rows — mark them. This is the "mark resolved inline" strategy.

## Non-goals

- **SRV-1** (CSP / security headers), **SRV-2** (HTTPS enforcement), **CORE-1** (audit unwrap panics). These are separate plans.
- Any Medium or Low finding from BUGS.md. Bundling them would bloat the chunk set and dilute review.
- Dual-accept / compat window on the signed payload change. User rejected this in Phase 1.
- Changing the Ed25519 signing algorithm, key format, or timestamp-window semantics. Those are orthogonal.
- Reworking CLI command-line parsing, adding new subcommands, or changing existing exit codes beyond what's needed for the home-directory-not-found error path.
- Adding a `dirs` workspace-dep. Add it to `crates/cli/Cargo.toml` directly (the CLI is the only consumer); lift to workspace deps later if broker/core/server need it.
- Changing migration 007's DDL itself. The `UNIQUE INDEX` is correct; only the operator tooling around it needs attention.
- Any change to `crates/core/src/storage/sqlite/credentials/` or the by-name-lookup handler (already correctly maps the UNIQUE error to `StoreError::Conflict`).

## Prior art (from wiki)

- [wiki/workspace-identity/keypair-and-signing.md](wiki/workspace-identity/keypair-and-signing.md) — current signed payload is `METHOD\nPATH\nTIMESTAMP\nBODY`; this plan changes that to `METHOD\nPATH_WITH_QUERY\nTIMESTAMP\nBODY` with the canonicalisation rule above. Update the article post-merge.
- [wiki/workspace-identity/broker-verification.md](wiki/workspace-identity/broker-verification.md) — describes the 5-step middleware flow at `crates/broker/src/auth.rs:88-165`. Step 2 (reconstruct the signed payload) changes shape.
- [wiki/architecture/data-model.md](wiki/architecture/data-model.md) — notes migration 007 is the one that adds `UNIQUE(name, owner_id)` and flags that duplicate-credential-name deployments need manual resolution. Actually the index is on `name` alone (the wiki article over-specifies `owner_id`); MIG-1 is about that gap. Update the article to match the live DDL.
- [wiki/decisions/three-tier-boundary.md](wiki/decisions/three-tier-boundary.md) — the three-tier model. Confirms that CLI ↔ broker are typically co-deployed, supporting the "hard break" compat decision.
- [wiki/process/dev-builds-only.md](wiki/process/dev-builds-only.md) — all verification in this plan is dev profile; no `cargo build --release` anywhere.
- [wiki/process/parallel-agent-spawns.md](wiki/process/parallel-agent-spawns.md) — triage should parallelise independent chunks. The signature change (CLI + broker) is one chunk; CLI-1 is independent; CLI-4 is independent; MIG-1 is independent.
- [wiki/decisions/root-user-is-unrestricted.md](wiki/decisions/root-user-is-unrestricted.md) — unrelated to this plan but worth noting so no engineer refiles CORE-2.

Open known-bugs that overlap this plan's surface:
- `input/BUGS.md` — the source of all five findings. Plan closes the five listed; every other High is out of scope.

## Approach

Triage should emerge roughly these chunks. Parallel where independent; only the signing pair must ship before anything else that depends on signed requests running against the updated broker.

1. **chunk-01 — paired signing canonicalisation (CLI + broker).** A single backend-engineer chunk because CLI and broker must change together. Files: `crates/cli/src/signing.rs`, `crates/cli/src/commands/proxy.rs`, `crates/cli/src/commands/mcp.rs` (if it also signs), `crates/cli/src/broker.rs` (any signed calls), `crates/broker/src/auth.rs`, plus any test module that exercises the payload. Introduces a shared canonicalisation function in both crates (minimum 2 identical copies; do NOT create a workspace-level shared crate for this — too invasive). Adds unit tests that pin the exact canonical output for path, path+query, path+trailing-slash, path+trailing-slash+query, root, root+query, and a fragment-bearing URL.
2. **chunk-02 — CLI-1 TOCTOU-safe keypair create.** Backend-engineer. Files: `crates/cli/src/commands/init.rs`. Use `OpenOptions::new().create_new(true).write(true)` guarded by the existing `if key_path.exists()` idempotent short-circuit. On Unix, set 0o600 via `.mode(0o600)` in the builder. On Windows, use `CreateFileW` with `CREATE_NEW` via the `std::os::windows::fs::OpenOptionsExt` extension. If `create_new` returns `ErrorKind::AlreadyExists` (race loser), emit "keypair appeared concurrently — re-run `agentcordon init`" and exit non-zero.
3. **chunk-03 — CLI-4 Windows-safe home resolution.** Backend-engineer. Files: `crates/cli/Cargo.toml` (add `dirs = "5"` as a direct dep), `crates/cli/src/broker.rs::dirs_or_home`, `crates/cli/src/commands/setup.rs` (the equivalent resolver). Use `dirs::home_dir()`. Error-on-none path; no `/tmp` default. Unit tests mock `HOME` / `USERPROFILE` and verify behaviour on each.
4. **chunk-04 — MIG-1 migration-007 pre-flight scanner.** Test-engineer (this is operator tooling + doc). Files: new `scripts/migration-007-precheck.sh`, edit to `migrations/007_credential_name_unique.sql` (add comment pointing at the script). Script must support SQLite (`.mode csv`, `.mode tabs` etc.) and Postgres (`psql -c`), detect whether the DB is SQLite or Postgres from a `--db-url` flag or `AGTCRDN_DB_URL` env var, and print human-readable output. Smoke-test: create a test DB with two duplicate-named credentials, run the script, verify non-zero exit + both names printed.
5. **chunk-05 — BUGS.md resolution annotations.** Test-engineer (low-code; content change). After all other chunks merge, update [input/BUGS.md](input/BUGS.md) to mark each of CLI-1/2/3/4, BRK-2, MIG-1 as `**Resolved by plan 2026-04-17-high-cli-and-mig-1** (commit <sha>)`. Triage dispatches this LAST so it can cite the final merge SHAs. No other changes to BUGS.md.

Triage has authority to merge chunks 1-4 in parallel since none touch the same files, with chunk-05 sequenced after all four return APPROVED.

## Files affected (anticipated)

- `crates/cli/src/signing.rs` — new `canonicalise_path_and_query()` helper; `sign_request` signature changes to take the raw URI (or path+query separately); tests updated.
- `crates/cli/src/commands/proxy.rs` — pass the full URI's path+query into `sign_request`.
- `crates/cli/src/commands/mcp.rs` and `crates/cli/src/broker.rs` — any other sign-calling site updated to pass path+query.
- `crates/cli/src/commands/init.rs` — atomic keypair creation.
- `crates/cli/src/commands/setup.rs` — home-resolver delegation.
- `crates/cli/Cargo.toml` — add `dirs = "5"`.
- `crates/broker/src/auth.rs` — reconstruct `path_with_query` from `request.uri()` (path and query are available via `uri().path()` + `uri().query()`); apply the same canonicalisation function (or a byte-identical copy).
- `crates/broker/src/auth.rs` tests (the signature-verification test module) — updated fixtures.
- `migrations/007_credential_name_unique.sql` — one-line comment addition pointing at the script.
- `scripts/migration-007-precheck.sh` — new file.
- `input/BUGS.md` — resolution annotations (chunk-05).

Do NOT touch:
- `wiki/**` — knowledge-maintainer handles in Phase 5d.
- Any server-crate code — out of scope.
- The Cedar policy bundle.
- The integration test infrastructure.

## E2E test plan

The architect-reviewer will run these after merge.

1. `cargo fmt --all --check` — clean.
2. `cargo clippy --workspace -- -D warnings` — clean.
3. `cargo test -p agent-cordon-cli` — all CLI tests pass, including new tests for (a) `canonicalise_path_and_query` for the 7 cases listed in Goals, (b) TOCTOU race on init (simulated: create the file between the exists-check and the write; assert the CLI errors cleanly), (c) `dirs_or_home()` on a mocked empty-env harness (assert error rather than `/tmp`), (d) integration with `sign_request`.
4. `cargo test -p agentcordon-broker` — all broker tests pass, including updated fixtures in the signature-verification test module that pin the new payload shape.
5. `cargo test --workspace` — no new failures beyond the 13 pre-existing `agent-cordon-server` integration-test failures documented in the prior plan (`v311_credential_name_scoping::*` and `credential_bugs::*`). These are NOT caused by this plan and must not be fixed here.
6. `cargo build --workspace` (dev profile, per project rule — no `--release`).
7. **Old-CLI vs new-broker smoke test**: check out the pre-merge CLI binary, run it against the new broker, observe a 401 with "signature verification failed" (confirms the hard break works as expected). This can be an informal operator step, not a CI test.
8. `shellcheck scripts/migration-007-precheck.sh` — clean. `bash -n` — syntactically valid. Run the script against a fresh SQLite DB with no duplicates, expect exit 0 and "no duplicates found". Then seed the DB with two duplicate-named credentials via `sqlite3`, re-run, expect exit 1 and both offending names printed.
9. `grep -n 'HOME\|/tmp' crates/cli/src/broker.rs crates/cli/src/commands/setup.rs` — no matches for the `/tmp` fallback anywhere.
10. `grep -n 'uri().path().to_string()' crates/broker/src/auth.rs` — no matches; the line must now also include `uri().query()`.
11. `grep -n 'format!("{method}\\n{path}\\n{timestamp}\\n{body}")' crates/cli/src/signing.rs` — no matches; the format call must now use the canonicalised path-with-query.
12. `input/BUGS.md` contains the string "Resolved by plan 2026-04-17-high-cli-and-mig-1" on each of the six finding rows (CLI-1, CLI-2, CLI-3, CLI-4, BRK-2, MIG-1). Every other row is byte-identical to pre-plan.

## Out of scope / deferred

- SRV-1 (CSP), SRV-2 (HTTPS enforce), CORE-1 (audit unwrap). Separate plans per the user's scoping.
- The 10 "prior audit findings not resurfaced" items in BUGS.md — explicit re-verification is a future task, not this one.
- Adding a `dirs` workspace-dep or sharing path-canonicalisation as a workspace crate. Keep the two duplicates (CLI + broker) until a third consumer appears.
- Making the new CLI emit a helpful "this is a breaking change, re-run `agentcordon setup`" error when it hits a 401 against an old broker. Future nicety.
- Retroactively fixing migrations other than 007.
- Reorganising BUGS.md itself (pruning, re-indexing). Only the six resolution annotations change.
