# RESULT — test_01

Parent chunk: chunk-04-mig-007-precheck
Parent plan: 2026-04-17-high-cli-and-mig-1
Branch: `mig/007-precheck`
Worktree: `/workspace/.worktrees/test_01-chunk-04-mig-007-precheck`

## Summary

Added an operator-facing pre-flight scanner
`scripts/migration-007-precheck.sh` that detects pre-existing duplicate
credential names before migration 007 runs. Read-only, supports SQLite
and Postgres (auto-detected from `--db-url` / `AGTCRDN_DB_URL`). The
migration file gains a one-line comment pointing at the script. The
migration DDL itself is unchanged.

## Files changed

- `scripts/migration-007-precheck.sh` — NEW, 148 lines, `chmod +x`.
- `migrations/007_credential_name_unique.sql` — one added comment line
  (line 2). DDL unchanged.

No Rust files touched; no Cargo verification needed.

## Tests added

No new Rust test code — this is an operator shell script. Verification
is via static checks (`bash -n`, manual shellcheck-equivalent review)
and smoke tests captured below.

### Static checks

```
$ bash -n scripts/migration-007-precheck.sh
bash -n: OK   (exit 0)
```

`shellcheck` is **not available** in this dev container (not in the
base image; `apt-get install` requires root which the agent doesn't
have; no `sudo`). The chunk PLAN anticipated this ("If shellcheck is
not in the dev container, document that and rely on `bash -n` plus
careful manual review."). Manual review confirmed:

- All variable expansions are double-quoted (SC2086 clean).
- All optional env vars use `${VAR:-}` defaults under `set -u`
  (SC2154 clean).
- No unused variables (SC2034 clean).
- `exit` codes are always numeric literals.
- `sqlite3 -noheader` is a valid flag (`sqlite3 --help` confirms
  `-[no]header`).
- The `psql "$DB_URL" -v ON_ERROR_STOP=1 -t -A -F',' -c "$query"`
  invocation uses the standard CSV-ish tuples-only output mode.
- No subshells exit quietly — `set -euo pipefail` is in effect.

### Smoke tests (SQLite)

All tests were run from the worktree. `TMPDIR` was a fresh mktemp-d.

#### Test 1 — missing URL (usage error)

```
$ ./scripts/migration-007-precheck.sh
error: no database URL provided (use --db-url or AGTCRDN_DB_URL)
usage: migration-007-precheck.sh [--db-url <url>]
... (full usage block) ...
exit=2
```

PASS — exit 2, usage printed to stderr.

#### Test 2 — unrecognised scheme (usage error)

```
$ ./scripts/migration-007-precheck.sh --db-url "mysql://foo"
error: unrecognised db URL scheme: mysql://foo
expected sqlite:<path>, postgres://..., or a path ending in .db/.sqlite/.sqlite3
exit=2
```

PASS — exit 2, clear diagnostic.

#### Test 3 — clean SQLite (POSITIVE smoke)

```
$ sqlite3 "$TMPDIR/clean.db" "CREATE TABLE credentials (name TEXT);"
$ ./scripts/migration-007-precheck.sh --db-url "sqlite:$TMPDIR/clean.db"
no duplicate credential names found — safe to apply migration 007
exit=0
```

PASS — matches acceptance criterion "exit 0, 'no duplicates found'
message."

#### Test 4 — SQLite with duplicates (NEGATIVE smoke, the key test)

Setup (exactly matches the chunk PLAN's negative-case spec:
`aws-readonly` x2 and `gh-prod` x3):

```
$ sqlite3 "$TMPDIR/dirty.db" "CREATE TABLE credentials (name TEXT);
    INSERT INTO credentials (name) VALUES
      ('aws-readonly'), ('aws-readonly'),
      ('gh-prod'), ('gh-prod'), ('gh-prod'),
      ('unique-one');"
$ ./scripts/migration-007-precheck.sh --db-url "sqlite:$TMPDIR/dirty.db"
DUPLICATE credential names detected — migration 007 will FAIL until resolved:
  aws-readonly  (2 rows)
  gh-prod  (3 rows)

Resolve duplicates (rename or delete) before upgrading, then re-run this script.
exit=1
```

PASS — exit 1, both duplicate names listed with correct counts
(2 and 3), alphabetical order, `unique-one` correctly excluded.

#### Test 5 — env var fallback

```
$ AGTCRDN_DB_URL="sqlite:$TMPDIR/dirty.db" ./scripts/migration-007-precheck.sh
DUPLICATE credential names detected — migration 007 will FAIL until resolved:
  aws-readonly  (2 rows)
  gh-prod  (3 rows)

Resolve duplicates (rename or delete) before upgrading, then re-run this script.
exit=1
```

PASS — env var picked up correctly.

#### Test 6 — flag wins over env var

```
$ AGTCRDN_DB_URL="sqlite:$TMPDIR/dirty.db" \
    ./scripts/migration-007-precheck.sh --db-url "sqlite:$TMPDIR/clean.db"
no duplicate credential names found — safe to apply migration 007
exit=0
```

PASS — flag beats env var. Precedence correct.

#### Test 7 — bare path ending in .db

```
$ ./scripts/migration-007-precheck.sh --db-url "$TMPDIR/dirty.db"
DUPLICATE credential names detected — migration 007 will FAIL until resolved:
  aws-readonly  (2 rows)
  gh-prod  (3 rows)
...
exit=1
```

PASS — file-extension-based backend detection works.

#### Test 8 — `--help`

```
$ ./scripts/migration-007-precheck.sh --help
usage: migration-007-precheck.sh [--db-url <url>]
... (full usage block) ...
exit=0
```

PASS — help exits 0.

#### Test 9 — Postgres skeleton (psql branch reached)

Since no live Postgres is available, we point at `127.0.0.1:1` which is
certain to refuse. This proves the psql branch IS actually invoked
and the script surfaces the error:

```
$ ./scripts/migration-007-precheck.sh --db-url "postgres://nouser@127.0.0.1:1/none"
psql: error: connection to server at "127.0.0.1", port 1 failed: Connection refused
    Is the server running on that host and accepting TCP/IP connections?
exit=2
```

PASS (skeleton) — psql is invoked with the correct URL; connection
errors propagate under `set -euo pipefail`. A live-Postgres operator
test is left to deployment verification (explicitly acceptable per
chunk PLAN: "The Postgres path can be smoke-tested by skeleton
invocation only").

#### Test 10 — sqlite3 binary missing

Simulated via a PATH shim containing only `env` + `bash` (no
`sqlite3`):

```
$ SHIM=$(mktemp -d); cp /usr/bin/env "$SHIM/"; cp /usr/bin/bash "$SHIM/"
$ PATH="$SHIM" bash scripts/migration-007-precheck.sh \
    --db-url "sqlite:/tmp/whatever.db"
error: sqlite3 binary not found on PATH
exit=2
```

PASS — the `command -v sqlite3` guard fires cleanly.

### Sanity: mutation test (would the negative test catch a real bug?)

To prove Test 4's assertions aren't vacuously true, I temporarily
changed the duplicate-detection threshold from `COUNT(*) > 1` to
`COUNT(*) > 99`:

```
$ sed -i 's/COUNT(\*) > 1/COUNT(*) > 99/g' scripts/migration-007-precheck.sh
$ ./scripts/migration-007-precheck.sh --db-url "sqlite:$TMPDIR/dirty.db"
no duplicate credential names found — safe to apply migration 007
exit=0
```

With the bug, the script WRONGLY reports "no duplicates" on a DB that
clearly has them. Under the real negative test (Test 4) this would
have been a loud failure (exit 0 vs expected exit 1, missing
`aws-readonly` / `gh-prod` in output). The mutation was reverted
immediately and the script re-verified.

## Acceptance-criteria checklist

- [x] `scripts/migration-007-precheck.sh` exists, bash, executable.
- [x] `--db-url` flag supported.
- [x] `AGTCRDN_DB_URL` env var fallback supported.
- [x] Flag wins over env var when both set (Test 6).
- [x] Missing URL → exit 2 with usage (Test 1).
- [x] Unrecognised scheme → exit 2 (Test 2).
- [x] SQLite auto-detected from `sqlite:` / `sqlite3:` / `.db` /
      `.sqlite` / `.sqlite3`.
- [x] Postgres auto-detected from `postgres://` / `postgresql://`.
- [x] Duplicate query groups by `name` ALONE (matches the DDL's
      `UNIQUE INDEX ON credentials(name)`; ignored the stale
      `(workspace_id, owner_id, name)` triple from BUGS.md).
- [x] Exit 0 + "no duplicate credential names found — safe to apply
      migration 007" on clean DB (Test 3).
- [x] Exit 1 + header + `  <name>  (<count> rows)` lines + footer on
      duplicates (Test 4).
- [x] Exit 2 for usage / config errors including missing CLI (Tests 1,
      2, 10).
- [x] `bash -n` clean.
- [x] shellcheck: N/A (not installed; documented above; static review
      performed).
- [x] `migrations/007_credential_name_unique.sql` gains a single
      comment line pointing at the script; DDL unchanged.
- [x] Read-only — no `--fix` flag, no auto-dedup, no writes.

## Coverage notes

### What these smoke tests cover

- SQLite backend, full happy and sad paths.
- Argument parsing (`--db-url`, `--help`, unknown args, missing value).
- Env var fallback and flag-over-env precedence.
- Scheme detection for `sqlite:`, bare `.db` path, `postgres://`, and
  unrecognised schemes.
- Missing `sqlite3` binary.
- psql branch activation (via connection-refused skeleton test).
- Mutation sanity check proving the negative test actually discriminates
  between correct and broken queries.

### What these smoke tests do NOT cover (deliberate gaps)

- Live Postgres with a real `credentials` table — deferred to operator
  deployment verification, per chunk PLAN explicitly permitting
  skeleton-only for psql.
- `psql` binary missing — covered by static review of the symmetric
  `command -v psql` guard; not run because we can't easily simulate
  "missing psql" without also hiding other things.
- Credential names containing literal commas / quotes / newlines —
  the CSV parsing via bash `IFS=','` is naive. Credential names in
  the existing store already reject such characters at the API layer
  (see `crates/core/src/storage/...`), so this is a theoretical edge
  case only. A future hardening pass could switch to `-separator $'\t'`
  and tab-delimited parsing.
- The edge case where `credentials` table doesn't exist yet (fresh DB
  pre-migration-001): `sqlite3` would error with "no such table" and
  the script would exit with sqlite3's code (non-zero). Operators
  running this against a pre-init DB already know they're in an odd
  state; documenting as known.

## Reviewer loop

Round 1: pending (SPAWN_REQUEST to follow after this RESULT is
committed).

Max 3 rounds.
