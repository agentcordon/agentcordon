#!/bin/bash
# Regenerate the v0.3.3 fixture database in this directory.
#
#   ./regenerate.sh [workdir]
#
# Builds the v0.3.3 server from the tagged source, runs it against a fresh
# SQLite file with a known master secret, and populates it through the v0.3.3
# admin API exactly as a v0.3.3 operator would. Nothing is written to the
# database by hand.
#
# Needs: cargo, curl, jq, openssl, xxd, sqlite3, and a git checkout with the
# v0.3.3 tag. Regenerating rewrites fixture.json: every id, token and key in
# it is freshly generated, so the test constants come from that file.
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(git -C "$HERE" rev-parse --show-toplevel)
WORK=${1:-$(mktemp -d)}
PORT=${AGTCRDN_FIXTURE_PORT:-31417}
BASE="http://127.0.0.1:$PORT"
SECRET='fixture-secret-v033!'
ROOT_PW='fixture-root-pw-2026'

mkdir -p "$WORK/data"
echo "workdir: $WORK"

# ---- 1. build the v0.3.3 server from the tag -------------------------------
if [ ! -d "$WORK/src" ]; then
  git -C "$REPO" worktree add --detach "$WORK/src" v0.3.3
fi
( cd "$WORK/src" && CARGO_TARGET_DIR="$WORK/target" cargo build -p agent-cordon-server --bin agent-cordon-server )
SERVER="$WORK/target/debug/agent-cordon-server"

# ---- 2. run it against a fresh database ------------------------------------
rm -f "$WORK/data/agent-cordon.db"*
AGTCRDN_DB_PATH="$WORK/data/agent-cordon.db" \
AGTCRDN_MASTER_SECRET="$SECRET" \
AGTCRDN_ROOT_USERNAME=root \
AGTCRDN_ROOT_PASSWORD="$ROOT_PW" \
AGTCRDN_LISTEN_ADDR="127.0.0.1:$PORT" \
AGTCRDN_BASE_URL="$BASE" \
AGTCRDN_LOG_FORMAT=text \
"$SERVER" > "$WORK/server.log" 2>&1 &
SERVER_PID=$!
trap 'kill "$SERVER_PID" 2>/dev/null || true' EXIT

for _ in $(seq 1 60); do
  if [ "$(curl -s -o /dev/null -w '%{http_code}' "$BASE/health" || true)" = "200" ]; then break; fi
  sleep 1
done

J="$WORK/jar"
api() { # method path [body]
  local m=$1 p=$2 b=${3:-}
  if [ -n "$b" ]; then
    curl -sS -X "$m" "$BASE$p" -b "$J" -H "Content-Type: application/json" -H "X-CSRF-Token: $CSRF" -d "$b"
  else
    curl -sS -X "$m" "$BASE$p" -b "$J" -H "X-CSRF-Token: $CSRF"
  fi
}

# ---- 3. populate through the v0.3.3 admin API ------------------------------
CSRF=$(curl -sS -c "$J" -X POST "$BASE/api/v1/auth/login" -H "Content-Type: application/json" \
  -d "{\"username\":\"root\",\"password\":\"$ROOT_PW\"}" | jq -r '.data.csrf_token')
[ "$CSRF" != "null" ] || { echo "root login failed"; exit 1; }

api POST /api/v1/users '{"username":"fixture-admin","password":"fixture-admin-pw-2026","display_name":"Fixture Admin","role":"admin"}' >/dev/null
api POST /api/v1/users '{"username":"fixture-viewer","password":"fixture-viewer-pw-26","display_name":"Fixture Viewer","role":"viewer"}' >/dev/null

# The workspace's real Ed25519 identity key.
openssl genpkey -algorithm ed25519 -out "$WORK/workspace-ed25519.pem" 2>/dev/null
PUBHEX=$(openssl pkey -in "$WORK/workspace-ed25519.pem" -pubout -outform DER | xxd -p -c 100 | tr -d '\n' | tail -c 64)
SEEDHEX=$(openssl pkey -in "$WORK/workspace-ed25519.pem" -outform DER | xxd -p -c 100 | tr -d '\n' | tail -c 64)
PKHASH=$(printf '%s' "$PUBHEX" | xxd -r -p | sha256sum | cut -d' ' -f1)

# RFC 8628 device flow: the broker asks, root approves, the broker exchanges.
DEV=$(curl -sS -X POST "$BASE/api/v1/oauth/device/code" \
  -d "client_id=agentcordon-broker" \
  -d "scope=credentials:discover credentials:vend mcp:discover mcp:invoke" \
  --data-urlencode "workspace_name=fixture-workspace" \
  -d "public_key_hash=$PKHASH")
DEVICE_CODE=$(printf '%s' "$DEV" | jq -r '.device_code')
USER_CODE=$(printf '%s' "$DEV" | jq -r '.user_code')
api POST /api/v1/oauth/device/approve "{\"user_code\":\"$USER_CODE\",\"public_key_hash\":\"$PKHASH\"}" >/dev/null
TOK=$(curl -sS -X POST "$BASE/api/v1/oauth/token" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:device_code" \
  -d "device_code=$DEVICE_CODE" -d "client_id=agentcordon-broker")
ACCESS=$(printf '%s' "$TOK" | jq -r '.access_token')
REFRESH=$(printf '%s' "$TOK" | jq -r '.refresh_token')
WS_ID=$(api GET /api/v1/workspaces | jq -r '.data[] | select(.name=="fixture-workspace") | .id')

C1_ID=$(api POST /api/v1/credentials '{"name":"fixture-api-key","service":"example","secret_value":"sk-fixture-plain-0001","credential_type":"generic","allowed_url_pattern":"https://api.example.com/*","description":"Fixture credential stored under v0.3.3","tags":["fixture"]}' | jq -r '.data.id')
C2_ID=$(api POST /api/v1/credentials '{"name":"fixture-rotated-key","service":"example","secret_value":"sk-fixture-rotated-v1","credential_type":"generic","description":"Fixture credential with rotation history"}' | jq -r '.data.id')
api PUT "/api/v1/credentials/$C2_ID" '{"secret_value":"sk-fixture-rotated-v2"}' >/dev/null
api PUT "/api/v1/credentials/$C2_ID" '{"secret_value":"sk-fixture-rotated-v3"}' >/dev/null

for CID in "$C1_ID" "$C2_ID"; do
  POLICY=$(printf 'permit(\n  principal == AgentCordon::Workspace::"%s",\n  action == AgentCordon::Action::"vend_credential",\n  resource == AgentCordon::Credential::"%s"\n);' "$WS_ID" "$CID")
  api POST /api/v1/policies "$(jq -nc --arg n "grant-fixture-$CID" --arg p "$POLICY" '{name:$n,description:"Fixture grant",cedar_policy:$p,enabled:true}')" >/dev/null
done

curl -sS -X POST "$BASE/api/v1/mcp-servers/import" -H "Authorization: Bearer $ACCESS" \
  -H "Content-Type: application/json" \
  -d "{\"workspace_id\":\"$WS_ID\",\"servers\":[{\"name\":\"fixture-mcp\",\"transport\":\"http\",\"url\":\"https://mcp.example.com/sse\",\"tools\":[{\"name\":\"search\",\"description\":\"Search things\"}]}]}" >/dev/null

# A real vend, so the audit trail carries one. v0.3.3's vend seals the secret
# to a broker-supplied P-256 key.
openssl ecparam -genkey -name prime256v1 -noout -out "$WORK/broker-p256.pem" 2>/dev/null
BROKER_PUB=$(openssl ec -in "$WORK/broker-p256.pem" -pubout -outform DER 2>/dev/null | tail -c 65 | base64 -w0 | tr '+/' '-_' | tr -d '=')
curl -sS -X POST "$BASE/api/v1/credentials/vend-device/fixture-api-key" \
  -H "Authorization: Bearer $ACCESS" -H "Content-Type: application/json" \
  -d "{\"broker_public_key\":\"$BROKER_PUB\"}" >/dev/null

curl -sS -o /dev/null -X POST "$BASE/api/v1/auth/login" -H "Content-Type: application/json" \
  -d '{"username":"fixture-viewer","password":"fixture-viewer-pw-26"}'

# ---- 4. freeze the file ----------------------------------------------------
kill "$SERVER_PID"; wait "$SERVER_PID" 2>/dev/null || true
DB="$WORK/data/agent-cordon.db"
sqlite3 "$DB" "PRAGMA wal_checkpoint(TRUNCATE); PRAGMA journal_mode=delete; VACUUM;" >/dev/null

# The device-flow approval provisions a per-workspace public client; the
# tokens are bound to it, not to the bootstrap client.
CLIENT_ID=$(sqlite3 "$DB" "SELECT client_id FROM oauth_refresh_tokens LIMIT 1;")
AUDIT=$(sqlite3 "$DB" "SELECT count(*) FROM audit_events;")
AUDIT_LISTABLE=$(sqlite3 "$DB" "SELECT count(*) FROM audit_events WHERE event_type <> 'policy_evaluated';")

cp "$DB" "$HERE/agent-cordon.db"
cp "$WORK/workspace-ed25519.pem" "$HERE/workspace-ed25519.pem"
jq --arg ws "$WS_ID" --arg pk "$PKHASH" --arg seed "$SEEDHEX" --arg pub "$PUBHEX" \
   --arg c1 "$C1_ID" --arg c2 "$C2_ID" --arg at "$ACCESS" --arg rt "$REFRESH" \
   --arg cid "$CLIENT_ID" --argjson audit "$AUDIT" --argjson listable "$AUDIT_LISTABLE" \
   '.workspace.id=$ws | .workspace.pk_hash=$pk | .workspace.ed25519_seed_hex=$seed
    | .workspace.ed25519_public_hex=$pub | .credentials.plain.id=$c1
    | .credentials.rotated.id=$c2 | .oauth.access_token=$at | .oauth.refresh_token=$rt
    | .oauth.client_id=$cid | .row_counts.audit_events=$audit
    | .row_counts.audit_events_excluding_policy_evaluated=$listable' \
   "$HERE/fixture.json" > "$HERE/fixture.json.new"
mv "$HERE/fixture.json.new" "$HERE/fixture.json"

echo "fixture regenerated in $HERE"
echo "remove the temporary v0.3.3 worktree with: git -C $REPO worktree remove $WORK/src"
