# ENGINEER PLAN — test_01

Parent chunk: chunk-04-mig-007-precheck
Parent plan: 2026-04-17-high-cli-and-mig-1

## Prior art consulted

- `wiki/testing/_index.md` — points at organization/coverage/ci-and-features; no existing harness for shell/operator scripts, so smoke tests will live inline in RESULT.md (captured stdout + exit codes) rather than in a test crate.
- `wiki/process/dev-builds-only.md` — confirms no `cargo --release` anywhere. This chunk is shell + SQL only, so no Cargo work is expected; if I accidentally touch Rust I must run `cargo fmt --all`, `cargo clippy --workspace -- -D warnings`, `cargo test --workspace`.
- `migrations/007_credential_name_unique.sql` — DDL is `CREATE UNIQUE INDEX ... ON credentials(name)` (single column). The duplicate query MUST group by `name` only, matching the DDL. The parent BUGS.md row's "(workspace_id, owner_id, name)" triple is stale — ignore.
- Existing shell scripts (`tools/install.sh`, `docker-entrypoint.sh`) use `#!/usr/bin/env bash` + `set -euo pipefail`. I'll match that style.

No knowledge-maintainer query needed — the chunk scope is clear.

## Test type

scaffolding (operator tooling + smoke-test verification)

The deliverable is an operator-facing bash script; the "tests" are positive and negative smoke invocations captured in RESULT.md. There is no new Rust test code.

## What I will test

Smoke scenarios, all against SQLite (local dev container has `sqlite3`; `psql` is also present but the chunk PLAN permits skeleton-invocation only for Postgres).

- Scenario: **Missing URL** — no flag, no env var. Setup: unset AGTCRDN_DB_URL. Action: `./scripts/migration-007-precheck.sh`. Expected: exit 2, usage message on stderr.
- Scenario: **Unrecognised scheme** — `--db-url mysql://foo`. Expected: exit 2, "unrecognised db URL scheme" message.
- Scenario: **SQLite, no duplicates (positive)** — fresh DB with a `credentials` table containing unique names (or zero rows). Expected: exit 0, "no duplicate credential names found — safe to apply migration 007" on stdout.
- Scenario: **SQLite, duplicates (negative)** — DB seeded with `aws-readonly` x2 and `gh-prod` x3. Expected: exit 1, header line, then `  aws-readonly  (2 rows)` and `  gh-prod  (3 rows)` (alphabetical), then footer telling operator to dedup. Both names present in output.
- Scenario: **Env var vs flag precedence** — both set, flag wins. Validate by pointing env var at a duplicate DB and flag at a clean DB; expect exit 0.
- Scenario: **Sqlite3 binary missing** — simulated by temporarily prepending a PATH with a shim that returns 127 for `sqlite3`. Expected: exit 2 with "sqlite3 not found" message. (Only run if time permits; the PATH munging is the only reliable way to test it locally.)
- Scenario: **Postgres branch — skeleton** — `--db-url postgres://user@nowhere:5432/db` with no real server. We can't hit a live Postgres here, so document that the psql branch is covered by static review + `bash -n` + manual operator verification. A bad host will exit non-zero with a psql connection error; I'll capture that to confirm the psql branch is actually reached.

## Files I will create/change

- `scripts/migration-007-precheck.sh` — NEW. Bash script, ~80-100 lines, `#!/usr/bin/env bash`, `set -euo pipefail`. Arg parser supports `--db-url <url>` and `--help`. Falls back to `AGTCRDN_DB_URL`. Scheme detection (prefix/extension match). Two execution branches: SQLite via `sqlite3 <path> -csv -noheader 'SELECT name, COUNT(*) FROM credentials GROUP BY name HAVING COUNT(*) > 1 ORDER BY name'` and Postgres via `psql "$url" -t -A -F',' -c 'SELECT name, COUNT(*) FROM credentials GROUP BY name HAVING COUNT(*) > 1 ORDER BY name;'`. Parse CSV, count rows, print accordingly. Executable bit set.
- `migrations/007_credential_name_unique.sql` — add ONE line near the top (after the first comment block, before the DDL) pointing at the script. Do NOT change the DDL.

## Test runner & command

No test harness — smoke tests are captured manually in RESULT.md:

```bash
# Positive
TMPDIR=$(mktemp -d)
sqlite3 "$TMPDIR/clean.db" "CREATE TABLE credentials (name TEXT);"
./scripts/migration-007-precheck.sh --db-url "sqlite:$TMPDIR/clean.db"; echo "exit=$?"

# Negative
sqlite3 "$TMPDIR/dirty.db" "CREATE TABLE credentials (name TEXT);
INSERT INTO credentials (name) VALUES
  ('aws-readonly'), ('aws-readonly'),
  ('gh-prod'), ('gh-prod'), ('gh-prod'),
  ('unique-one');"
./scripts/migration-007-precheck.sh --db-url "sqlite:$TMPDIR/dirty.db"; echo "exit=$?"

# Static checks
bash -n scripts/migration-007-precheck.sh
shellcheck scripts/migration-007-precheck.sh   # if available
```

Environment: dev container has `bash`, `sqlite3`, `psql`. `shellcheck` is NOT installed and apt requires root we don't have — the chunk PLAN anticipated this and permits documenting the shortfall + relying on `bash -n` + manual inspection.

## Reuse

- `tools/install.sh` style (bash, set -euo pipefail, `#!/usr/bin/env bash`).
- `sqlite3` and `psql` CLIs directly — no wrapper crate.
- Existing comment block in `migrations/007_credential_name_unique.sql` lines 1-12 is the insertion point for the pointer comment.
