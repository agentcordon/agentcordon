#!/usr/bin/env bash
# migration-007-precheck.sh — Pre-flight scanner for migration 007
# (credentials.name UNIQUE index). Detects pre-existing duplicate
# credential names before the migration runs, so operators can dedup
# manually instead of hitting a destructive startup failure.
#
# Read-only. Does not modify the database. Supports SQLite and Postgres.
#
# Usage:
#   scripts/migration-007-precheck.sh --db-url <url>
#   AGTCRDN_DB_URL=<url> scripts/migration-007-precheck.sh
#
# Exit codes:
#   0 — no duplicates; safe to apply migration 007
#   1 — duplicates found; resolve before upgrading
#   2 — usage/config error (missing URL, bad scheme, missing CLI)

set -euo pipefail

usage() {
    cat <<'EOF' >&2
usage: migration-007-precheck.sh [--db-url <url>]

Detects duplicate credential names before applying migration 007
(UNIQUE INDEX on credentials.name).

The database URL may be provided via:
  --db-url <url>         command-line flag (wins if both are set)
  AGTCRDN_DB_URL env var fallback

Supported URL schemes:
  sqlite:<path>, sqlite3:<path>, or a bare path ending in
  .db / .sqlite / .sqlite3  (uses the sqlite3 CLI)
  postgres://... or postgresql://...  (uses the psql CLI)

Exit codes: 0 clean, 1 duplicates found, 2 usage/config error.
EOF
}

DB_URL=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --db-url)
            if [[ $# -lt 2 ]]; then
                echo "error: --db-url requires a value" >&2
                usage
                exit 2
            fi
            DB_URL="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "error: unknown argument: $1" >&2
            usage
            exit 2
            ;;
    esac
done

if [[ -z "$DB_URL" ]]; then
    DB_URL="${AGTCRDN_DB_URL:-}"
fi

if [[ -z "$DB_URL" ]]; then
    echo "error: no database URL provided (use --db-url or AGTCRDN_DB_URL)" >&2
    usage
    exit 2
fi

# Detect backend from URL prefix / file extension.
backend=""
sqlite_path=""

case "$DB_URL" in
    sqlite3:*)
        backend="sqlite"
        sqlite_path="${DB_URL#sqlite3:}"
        ;;
    sqlite:*)
        backend="sqlite"
        sqlite_path="${DB_URL#sqlite:}"
        ;;
    postgres://*|postgresql://*)
        backend="postgres"
        ;;
    *.db|*.sqlite|*.sqlite3)
        backend="sqlite"
        sqlite_path="$DB_URL"
        ;;
    *)
        echo "error: unrecognised db URL scheme: $DB_URL" >&2
        echo "expected sqlite:<path>, postgres://..., or a path ending in .db/.sqlite/.sqlite3" >&2
        exit 2
        ;;
esac

# sqlite: strip optional //  prefix so sqlite:///tmp/x.db → /tmp/x.db
if [[ "$backend" == "sqlite" ]]; then
    sqlite_path="${sqlite_path#//}"
fi

query="SELECT name, COUNT(*) FROM credentials GROUP BY name HAVING COUNT(*) > 1 ORDER BY name;"

# Run the query, collect "name,count" rows on stdout.
rows=""
case "$backend" in
    sqlite)
        if ! command -v sqlite3 >/dev/null 2>&1; then
            echo "error: sqlite3 binary not found on PATH" >&2
            exit 2
        fi
        # -bail: stop on first error. -csv: comma-separated. -noheader: no
        # column names (we want pure data lines).
        rows="$(sqlite3 -bail -csv -noheader "$sqlite_path" "$query")"
        ;;
    postgres)
        if ! command -v psql >/dev/null 2>&1; then
            echo "error: psql binary not found on PATH" >&2
            exit 2
        fi
        # -t: tuples only (no header/footer). -A: unaligned. -F',': CSV-ish
        # field separator. ON_ERROR_STOP: propagate errors as non-zero exit.
        rows="$(psql "$DB_URL" -v ON_ERROR_STOP=1 -t -A -F',' -c "$query")"
        ;;
esac

# Trim leading/trailing whitespace-only lines so the empty-output case is
# actually empty.
rows="$(printf '%s' "$rows" | sed '/^[[:space:]]*$/d')"

if [[ -z "$rows" ]]; then
    echo "no duplicate credential names found — safe to apply migration 007"
    exit 0
fi

echo "DUPLICATE credential names detected — migration 007 will FAIL until resolved:"
while IFS=',' read -r name count; do
    [[ -z "$name" ]] && continue
    echo "  ${name}  (${count} rows)"
done <<< "$rows"
echo ""
echo "Resolve duplicates (rename or delete) before upgrading, then re-run this script." >&2
exit 1
