# CHUNK PLAN — chunk-04-mig-007-precheck

Parent plan: 2026-04-17-high-cli-and-mig-1
Role: test
Engineer: test_01

## Scope

Build an operator-facing pre-flight scanner for migration 007
(`UNIQUE INDEX` on `credentials(name)`) so deployments with pre-existing
duplicate credential names get a clear, non-destructive warning BEFORE
the migration runs and fails.

The migration DDL itself is correct and stays unchanged except for a
one-line comment pointing operators at the script.

Resolves MIG-1.

## Acceptance criteria

- A new file `scripts/migration-007-precheck.sh` exists and is
  executable (`chmod +x`). Bash, not POSIX sh — the project already uses
  bash idioms elsewhere.
- The script accepts a database URL via either:
  - `--db-url <url>` flag, OR
  - `AGTCRDN_DB_URL` env var (the flag wins if both are set).
  - If neither is provided, exit 2 with a usage message that lists both
    options and exits.
- The script auto-detects SQLite vs Postgres from the URL prefix:
  - `sqlite:` or `sqlite3:` or a path ending in `.db` / `.sqlite` /
    `.sqlite3` → SQLite mode (uses `sqlite3` CLI).
  - `postgres://` or `postgresql://` → Postgres mode (uses `psql`).
  - Anything else → exit 2 with "unrecognised db URL scheme" message.
- The duplicate-detection query (run identically in spirit on both
  backends) is:
  ```sql
  SELECT name, COUNT(*) AS dup_count
  FROM credentials
  GROUP BY name
  HAVING COUNT(*) > 1
  ORDER BY name;
  ```
  (NOTE: the parent PLAN's BUGS.md row says "duplicate `(workspace_id,
  owner_id, name)` triples" — that's a stale interpretation. The actual
  migration DDL is `UNIQUE INDEX ... ON credentials(name)` (single
  column). The script must group by `name` only, matching the DDL.)
- Exit codes:
  - `0` — no duplicates; print `"no duplicate credential names found —
    safe to apply migration 007"`.
  - `1` — duplicates found; print a header line, then one line per
    offending name in the form `"  <name>  (<count> rows)"`, then a
    footer telling the operator to dedup before upgrading.
  - `2` — usage / config error (missing URL, unrecognised scheme,
    sqlite3 / psql binary not found).
- The script passes `shellcheck scripts/migration-007-precheck.sh`
  cleanly (no warnings). Use `# shellcheck disable=...` only with a
  comment explaining the disable.
- `bash -n scripts/migration-007-precheck.sh` returns exit 0 (syntactic
  validity).
- `migrations/007_credential_name_unique.sql` gains a one-line comment
  near the top pointing at the script:
  `-- Pre-flight: run scripts/migration-007-precheck.sh to detect
  duplicate names before applying.` Do NOT change the DDL itself.
- Smoke test (run by the engineer, results in RESULT.md):
  - Create a fresh SQLite DB at `/tmp/<unique>/test.db` with a
    `credentials` table (only the `name` column is needed for the
    smoke test; minimal schema is fine).
  - Run the script against it; expect exit 0 and "no duplicate
    credential names found" output.
  - Insert two rows with the same `name = 'aws-readonly'` and one row
    with `name = 'gh-prod'` duplicated three times.
  - Re-run; expect exit 1, both `aws-readonly` and `gh-prod` listed,
    correct counts (2 and 3).
- The Postgres path can be smoke-tested by skeleton invocation only
  (`psql --version` available in the dev container? if not, document
  the manual operator step in RESULT.md and rely on shellcheck for
  static validation of the psql branch).

## Files expected to change

- `scripts/migration-007-precheck.sh` — NEW file. Bash script per spec
  above. ~60-100 lines is reasonable; do NOT bloat with extensive
  argument parsing or colour output.
- `migrations/007_credential_name_unique.sql` — one-line comment
  addition. Do NOT change the DDL.

## Reuse

- The existing `migrations/007_credential_name_unique.sql` comment
  block (lines 1-12) is the right place to insert the pointer comment.
- `sqlite3` and `psql` CLIs are standard. Use them via plain
  invocation, no wrapper crate or library.
- For SQLite, `sqlite3 "$db_path" -bail "SELECT ..."` returns rows on
  stdout; use `wc -l` to detect "any rows present" or use `-csv` /
  `-list` mode and a counter.

## Prior art (from wiki)

- `wiki/architecture/data-model.md` — describes migration 007. The wiki
  notes "duplicate-credential-name deployments need manual resolution"
  but is over-specified about the index columns; trust the DDL in
  `migrations/007_credential_name_unique.sql` (it indexes `name` only).
  Do NOT edit the wiki — the documentation-agent handles that
  post-merge.

## Dependencies on other chunks

- None. Independent of chunks 01, 02, 03.

## Notes for the engineer

- **DEV BUILDS ONLY.** This chunk is shell + SQL; no Cargo work
  required. If you accidentally change Rust files, run the standard
  verification (`cargo fmt --all`, `cargo clippy --workspace -- -D
  warnings`, `cargo test --workspace`) — but you should not need to.
- Do NOT touch `wiki/**`, `docs/**`, `input/BUGS.md`, the server crate,
  the broker crate, the CLI crate, the Cedar policy bundle, or any
  pre-existing server test failures. Do NOT change the migration DDL —
  only add the one-line comment.
- The root-user bypass at `crates/core/src/policy/cedar/mod.rs:86-95`
  is intentional by design — do not refile if encountered during review.
- Smoke tests are part of the engineer's RESULT.md — capture stdout +
  exit code from each invocation so the reviewer can verify.
- If `shellcheck` is not in the dev container, document that and rely
  on `bash -n` plus careful manual review.
- The script should NOT modify the database. Read-only queries only.
  Do not add a `--fix` flag or auto-dedup logic — that's deliberately
  out of scope (operator decision).
