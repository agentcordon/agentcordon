#!/usr/bin/env bash
# Small helper for poking the admin API from the host with a real session,
# the way the admin UI does. Used while investigating findings.
#
#   ./uat/admin-api.sh GET /api/v1/mcp-servers
#   ./uat/admin-api.sh POST /api/v1/credentials '{"name":"x", ...}'

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
set -a
# shellcheck disable=SC1091
source "$HERE/uat.env"
set +a

METHOD="${1:-GET}"
PATH_="${2:-/api/v1/mcp-servers}"
BODY="${3:-}"

JAR="$(mktemp)"
trap 'rm -f "$JAR"' EXIT

curl -sS -c "$JAR" -b "$JAR" -o /dev/null \
  -X POST "$UAT_SERVER_URL/api/v1/auth/login" \
  -H 'Content-Type: application/json' \
  -d "{\"username\":\"$UAT_ROOT_USERNAME\",\"password\":\"$UAT_ROOT_PASSWORD\"}"

CSRF="$(grep -i agtcrdn_csrf "$JAR" | awk '{print $7}' | tail -1)"

if [ -n "$BODY" ]; then
  curl -sS -b "$JAR" -X "$METHOD" "$UAT_SERVER_URL$PATH_" \
    -H "X-CSRF-Token: $CSRF" -H 'Content-Type: application/json' -d "$BODY"
else
  curl -sS -b "$JAR" -X "$METHOD" "$UAT_SERVER_URL$PATH_" -H "X-CSRF-Token: $CSRF"
fi
echo
