#!/usr/bin/env bash
# AgentCordon release UAT — one command: build, up, test, collect, tear down.
#
#   ./uat/run.sh              full run
#   ./uat/run.sh --no-build   reuse existing images
#   ./uat/run.sh --keep       leave containers running after the tests
#   ./uat/run.sh --up-only    build + bring the topology up, then stop
#   ./uat/run.sh --down-only  tear everything down and stop
#   ./uat/run.sh --with-oauth also bring up the OAuth/MCP mocks during --up-only
#                             (the S11-S16 specs do this themselves otherwise)
#   ./uat/run.sh --grep-invert=PATTERN
#                             skip the scenarios whose titles match PATTERN
#                             (uat/prepare-s15.sh uses it to skip the
#                             destructive S5 lifecycle scenario)
#
# Environment flags (see uat/README.md "Environment flags"):
#   UAT_BROWSER=chromium|firefox|webkit
#                             which engine the browser half drives (default
#                             chromium). Installs that browser into
#                             uat/.browsers.
#   UAT_SKIP_NETWORK_INSTALL=1
#                             skip the two S0 steps that run the documented
#                             `curl .../install.sh | sh`, which downloads from
#                             the GitHub "latest" release. Everything else runs
#                             on binaries built from this worktree, so the run
#                             needs no public internet with this set.
#
# Every run writes uat/artifacts/provenance.json: the commit, the working-tree
# state, the id and digest of every image used, the CLI/broker version strings,
# and the node and Playwright versions.
#
# Exit code is the Playwright exit code.

set -uo pipefail

# The topology is one shared resource per worktree (fixed container names, a
# fixed host port, one volume), so two runs at once destroy each other. Run
# from a snapshot of this file so an edit made while a run is in progress
# cannot change the script bash is still reading, then take an exclusive lock.
if [ -z "${UAT_RUN_SNAPSHOT:-}" ]; then
  _origin="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  _snap="$(mktemp "${TMPDIR:-/tmp}/uat-run.XXXXXX")"
  cp "${BASH_SOURCE[0]}" "$_snap"
  UAT_RUN_SNAPSHOT="$_snap" UAT_RUN_ORIGIN="$_origin" exec bash "$_snap" "$@"
fi
HERE="${UAT_RUN_ORIGIN:?}"
exec 9>"$HERE/.run.lock"
if ! flock -n 9; then
  echo "uat/run.sh: another run holds $HERE/.run.lock; wait for it to finish" >&2
  exit 75
fi
trap 'rm -f "$UAT_RUN_SNAPSHOT"' EXIT
ROOT="$(cd "$HERE/.." && pwd)"
ARTIFACTS="$HERE/artifacts"
PW="$HERE/playwright"

# shellcheck disable=SC2046
set -a
source "$HERE/uat.env"
set +a

# UAT_BROWSER selects the Playwright project (see playwright.config.ts) and the
# browser this installs. chromium is the default, so an unset environment runs
# exactly what it always ran.
UAT_BROWSER="${UAT_BROWSER:-chromium}"
case "$UAT_BROWSER" in
  chromium|firefox|webkit) ;;
  *) echo "UAT_BROWSER=$UAT_BROWSER: expected chromium, firefox or webkit" >&2; exit 2 ;;
esac
export UAT_BROWSER

export PLAYWRIGHT_BROWSERS_PATH="$HERE/.browsers"
export UAT_ENV_FILE="$HERE/uat.env"

DO_BUILD=1
DO_TEARDOWN=1
UP_ONLY=0
DOWN_ONLY=0
WITH_OAUTH=0
GREP_INVERT=""
for arg in "$@"; do
  case "$arg" in
    --no-build) DO_BUILD=0 ;;
    --keep)     DO_TEARDOWN=0 ;;
    --up-only)  UP_ONLY=1 ;;
    --down-only) DOWN_ONLY=1 ;;
    --with-oauth) WITH_OAUTH=1 ;;
    --grep-invert=*) GREP_INVERT="${arg#--grep-invert=}" ;;
    *) echo "unknown flag: $arg" >&2; exit 2 ;;
  esac
done

log() { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }

teardown() {
  log "Tearing down"
  for c in "$UAT_CLI" "$UAT_BROKER" "$UAT_CLI_GUARDED" "$UAT_BROKER_GUARDED" "$UAT_SERVER2" "$UAT_MCP" "$UAT_IDP" "$UAT_SERVER" "$UAT_UPSTREAM"; do
    docker rm -f "$c" >/dev/null 2>&1 || true
  done
  docker network rm "$UAT_NETWORK" >/dev/null 2>&1 || true
  docker volume rm "$UAT_VOLUME" >/dev/null 2>&1 || true
}

# Ctrl-C or a killed run must not leave seven containers, the network, and the
# volume behind. --keep and --up-only opt out on purpose.
on_interrupt() {
  trap - INT TERM
  if [ "${DO_TEARDOWN:-1}" = 1 ] && [ "${UP_ONLY:-0}" != 1 ]; then
    teardown
  fi
  exit 130
}
trap on_interrupt INT TERM

collect_logs() {
  log "Collecting container logs into $ARTIFACTS"
  mkdir -p "$ARTIFACTS"
  for c in "$UAT_SERVER" "$UAT_SERVER2" "$UAT_UPSTREAM" "$UAT_BROKER" "$UAT_CLI" "$UAT_BROKER_GUARDED" "$UAT_CLI_GUARDED" "$UAT_IDP" "$UAT_MCP"; do
    if docker inspect "$c" >/dev/null 2>&1; then
      docker logs "$c" > "$ARTIFACTS/$c.log" 2>&1 || true
    fi
  done
  # The CLI container's own files (register transcript, workspace key metadata)
  docker exec "$UAT_CLI" sh -c 'ls -la /home/uat/workspace /home/uat/workspace/.agentcordon 2>/dev/null; echo "--- register.log ---"; cat /home/uat/register.log 2>/dev/null' \
    > "$ARTIFACTS/cli-workspace.txt" 2>&1 || true
  # The mocks' own observation endpoints: every token-endpoint call the IdP saw
  # (with the caller's address) and every request the mock MCP server saw.
  #
  # The mocks live in the server container's network namespace, so S9's
  # `docker restart` of the server leaves them running but unreachable until
  # they are restarted (which would wipe their in-memory log). The S16 spec
  # therefore snapshots these files while the mocks are still up; only
  # overwrite them here if the fetch actually succeeds. `docker logs` of the
  # two mock containers is the durable record either way.
  for pair in "idp-log.json:$UAT_IDP_URL/_uat/log" \
              "idp-tokens.json:$UAT_IDP_URL/_uat/tokens" \
              "mcp-log.json:$UAT_MCP_URL/_uat/log"; do
    name="${pair%%:*}"
    url="${pair#*:}"
    if curl -fsS -o "$ARTIFACTS/.$name.tmp" "$url" 2>/dev/null; then
      mv "$ARTIFACTS/.$name.tmp" "$ARTIFACTS/$name"
    else
      rm -f "$ARTIFACTS/.$name.tmp"
    fi
  done
}

# Provenance for uat/REPORT.md: exactly what this run ran against. Written on
# every run, once the topology is up and again after the tests, so it also
# carries the versions read out of the live containers. Read-only git only.
write_provenance() {
  log "Writing provenance to $ARTIFACTS/provenance.json"
  mkdir -p "$ARTIFACTS"

  local head tree dirty branch
  head="$(git -C "$ROOT" rev-parse HEAD 2>/dev/null || echo unknown)"
  tree="$(git -C "$ROOT" rev-parse 'HEAD^{tree}' 2>/dev/null || echo unknown)"
  dirty="$(git -C "$ROOT" status --porcelain 2>/dev/null | wc -l | tr -d ' ')"
  branch="$(git -C "$ROOT" rev-parse --abbrev-ref HEAD 2>/dev/null || echo unknown)"

  # Image identity: the local id always, plus the RepoDigest for anything
  # pulled from a registry (the two locally built images have none).
  image_json() { # image ref
    local ref="$1" id digest
    id="$(docker image inspect -f '{{.Id}}' "$ref" 2>/dev/null || echo unknown)"
    digest="$(docker image inspect -f '{{if .RepoDigests}}{{index .RepoDigests 0}}{{end}}' "$ref" 2>/dev/null || echo '')"
    printf '{"ref":"%s","id":"%s","repo_digest":"%s"}' "$ref" "$id" "$digest"
  }

  # Version strings, read out of the containers when they are up.
  local cli_version broker_version
  cli_version="$(docker exec "$UAT_CLI" agentcordon --version 2>/dev/null | tr -d '\r\n' || echo unavailable)"
  broker_version="$(docker exec "$UAT_BROKER" agentcordon-broker --version 2>/dev/null | tr -d '\r\n' || echo unavailable)"

  # The server exposes no unauthenticated version endpoint, so the honest
  # answer is the workspace version its image was built from.
  local workspace_version
  workspace_version="$(sed -n 's/^version = "\(.*\)"/\1/p' "$ROOT/Cargo.toml" | head -1)"

  local node_version pw_version docker_version
  node_version="$(node --version 2>/dev/null || echo unavailable)"
  pw_version="$( (cd "$PW" && npx playwright --version 2>/dev/null) | tr -d '\r\n')"
  [ -n "$pw_version" ] || pw_version=unavailable
  docker_version="$(docker --version 2>/dev/null | tr -d '\r\n')"
  [ -n "$docker_version" ] || docker_version=unavailable

  local clean=false; [ "$dirty" = 0 ] && clean=true
  local built=false;  [ "$DO_BUILD" = 1 ] && built=true
  local skipnet=false; [ "${UAT_SKIP_NETWORK_INSTALL:-0}" = 1 ] && skipnet=true

  cat > "$ARTIFACTS/provenance.json" <<EOF
{
  "run_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "host": "$(uname -srm)",
  "git": {
    "commit": "$head",
    "tree": "$tree",
    "branch": "$branch",
    "dirty_paths": $dirty,
    "clean": $clean
  },
  "images": [
    $(image_json "$UAT_SERVER_IMAGE"),
    $(image_json "$UAT_TOOLS_IMAGE"),
    $(image_json "$UAT_PYTHON_IMAGE")
  ],
  "versions": {
    "workspace_cargo_version": "$workspace_version",
    "agentcordon_cli": "$cli_version",
    "agentcordon_broker": "$broker_version",
    "server": "built from workspace_cargo_version; the server exposes no unauthenticated version endpoint",
    "node": "$node_version",
    "playwright": "$pw_version",
    "browser": "$UAT_BROWSER",
    "docker": "$docker_version"
  },
  "flags": {
    "built_images": $built,
    "skip_network_install": $skipnet,
    "grep_invert": "$GREP_INVERT"
  }
}
EOF
}

wait_http() { # url, seconds
  local url="$1" secs="${2:-90}" i=0
  while [ "$i" -lt "$secs" ]; do
    if curl -fsS -o /dev/null "$url" 2>/dev/null; then return 0; fi
    i=$((i+1)); sleep 1
  done
  return 1
}

mkdir -p "$ARTIFACTS"

if [ "$DOWN_ONLY" = 1 ]; then teardown; exit 0; fi

# ---------------------------------------------------------------- teardown any
log "Removing leftovers from a previous run"
teardown
rm -f "$ARTIFACTS/findings.json" "$PW/.state.json"
rm -rf "$ARTIFACTS/screenshots"

# ------------------------------------------------------------------- 1. build
if [ "$DO_BUILD" = 1 ]; then
  log "Building server image from the repo Dockerfile"
  docker build -f "$ROOT/Dockerfile" -t "$UAT_SERVER_IMAGE" "$ROOT" \
    > "$ARTIFACTS/build-server.log" 2>&1 || { tail -40 "$ARTIFACTS/build-server.log"; exit 1; }

  log "Building tools image (broker + CLI) from uat/Dockerfile.tools"
  docker build -f "$HERE/Dockerfile.tools" -t "$UAT_TOOLS_IMAGE" "$ROOT" \
    > "$ARTIFACTS/build-tools.log" 2>&1 || { tail -40 "$ARTIFACTS/build-tools.log"; exit 1; }
fi

# ------------------------------------------------------------------ 2. bring up
log "Creating network $UAT_NETWORK"
docker network create "$UAT_NETWORK" >/dev/null

# The second alias makes a regional-looking AWS hostname resolve to the mock
# inside the harness. S14 uses it to prove the auto-default AWS fence covers a
# regional endpoint without any call leaving the Docker network: the fence
# check is what is measured, the connection that follows is expected to fail
# (the mock speaks plain HTTP on 8080, not TLS on 443).
log "Starting mock upstream"
docker run -d --name "$UAT_UPSTREAM" \
  --network "$UAT_NETWORK" --network-alias upstream \
  --network-alias "$UAT_AWS_REGIONAL_HOST" \
  -v "$HERE/mock_upstream.py:/app/mock_upstream.py:ro" \
  -w /app "$UAT_PYTHON_IMAGE" python3 /app/mock_upstream.py >/dev/null

# docker-compose.yml semantics, reproduced with plain `docker run` because the
# compose plugin is not installed on this host: same image, same
# `agentcordon-data:/data` named volume, same published 3140, and only env
# vars that README.md § "Configuration" and .env.example document.
# AGTCRDN_BASE_URL is deliberately NOT set for S0-S9, so those scenarios
# measure the shipped fallback ("http://" + the listen address). S3 asserts
# both that fallback and the warning README and .env.example now carry about
# it; the OAuth half of the run sets the variable, which is the documented
# compose-file edit.
log "Starting server (docker-compose.yml semantics; published on host port $UAT_HOST_PORT)"
docker volume create "$UAT_VOLUME" >/dev/null
docker run -d --name "$UAT_SERVER" \
  --network "$UAT_NETWORK" --network-alias server \
  -p "127.0.0.1:$UAT_HOST_PORT:3140" \
  -v "$UAT_VOLUME:/data" \
  -e AGTCRDN_ROOT_USERNAME="$UAT_ROOT_USERNAME" \
  -e AGTCRDN_ROOT_PASSWORD="$UAT_ROOT_PASSWORD" \
  -e AGTCRDN_MASTER_SECRET="$UAT_MASTER_SECRET" \
  -e AGTCRDN_LOG_LEVEL=info \
  "$UAT_SERVER_IMAGE" >/dev/null

log "Waiting for the server to answer /health"
if ! wait_http "$UAT_SERVER_URL/health" 120; then
  echo "server never came up" >&2
  docker logs "$UAT_SERVER" | tail -40
  exit 1
fi

# README.md § "Quick Start / 2. Start the broker":
#     agentcordon-broker --server-url http://localhost:3140
# plus, because the broker runs in its own container and must be reachable
# from the CLI container, the flags docs/cli-reference.md § "Broker flags for
# a non-loopback bind" documents: --bind with --shared-secret.
# --proxy-allow-loopback is documented in docs/configuration.md and
# docs/cli-reference.md; the mock upstream is on a private Docker bridge
# address, which the SSRF guard refuses by design. See uat/README.md.
log "Starting broker"
docker run -d --name "$UAT_BROKER" \
  --network "$UAT_NETWORK" --network-alias broker \
  "$UAT_TOOLS_IMAGE" \
  agentcordon-broker \
    --server-url http://server:3140 \
    --bind 0.0.0.0 \
    --port 9876 \
    --shared-secret "$UAT_BROKER_SHARED_SECRET" \
    --proxy-allow-loopback >/dev/null

log "Starting CLI container (shares the broker's network namespace)"
docker run -d --name "$UAT_CLI" \
  --network "container:$UAT_BROKER" \
  -e HOME=/home/uat \
  -e AGTCRDN_BROKER_URL=http://127.0.0.1:9876 \
  -e AGTCRDN_BROKER_SHARED_SECRET="$UAT_BROKER_SHARED_SECRET" \
  -w /home/uat/workspace \
  "$UAT_TOOLS_IMAGE" sleep infinity >/dev/null

log "Waiting for the broker to answer /health"
for i in $(seq 1 60); do
  if docker exec "$UAT_CLI" curl -fsS -o /dev/null http://127.0.0.1:9876/health 2>/dev/null; then
    break
  fi
  sleep 1
done
docker exec "$UAT_CLI" curl -fsS http://127.0.0.1:9876/health > "$ARTIFACTS/broker-health.json" 2>&1 || {
  echo "broker never came up" >&2; docker logs "$UAT_BROKER" | tail -40; exit 1; }

# A second broker the way it ships: no --proxy-allow-loopback, so the SSRF
# guard is on. S21 enrolls a workspace through it and proves that a credential
# fenced to one literal host (http://upstream:8080/*) is forwarded to that
# host's private address without the flag, and that an unfenced credential is
# still refused (ADR-0014). The main broker keeps the flag because the MCP
# path is still guarded unconditionally.
log "Starting guarded broker (no --proxy-allow-loopback)"
docker run -d --name "$UAT_BROKER_GUARDED" \
  --network "$UAT_NETWORK" --network-alias broker-guarded \
  "$UAT_TOOLS_IMAGE" \
  agentcordon-broker \
    --server-url http://server:3140 \
    --bind 0.0.0.0 \
    --port 9876 \
    --shared-secret "$UAT_BROKER_SHARED_SECRET" >/dev/null

log "Starting guarded CLI container (shares the guarded broker's network namespace)"
docker run -d --name "$UAT_CLI_GUARDED" \
  --network "container:$UAT_BROKER_GUARDED" \
  -e HOME=/home/uat \
  -e AGTCRDN_BROKER_URL=http://127.0.0.1:9876 \
  -e AGTCRDN_BROKER_SHARED_SECRET="$UAT_BROKER_SHARED_SECRET" \
  -w /home/uat/workspace \
  "$UAT_TOOLS_IMAGE" sleep infinity >/dev/null

log "Waiting for the guarded broker to answer /health"
for i in $(seq 1 60); do
  if docker exec "$UAT_CLI_GUARDED" curl -fsS -o /dev/null http://127.0.0.1:9876/health 2>/dev/null; then
    break
  fi
  sleep 1
done
docker exec "$UAT_CLI_GUARDED" curl -fsS http://127.0.0.1:9876/health > "$ARTIFACTS/broker-guarded-health.json" 2>&1 || {
  echo "guarded broker never came up" >&2; docker logs "$UAT_BROKER_GUARDED" | tail -40; exit 1; }

log "Topology up"
docker ps --filter "name=agentcordon-uat" --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'

write_provenance

# The OAuth/MCP half of the topology (mock IdP, mock MCP server, and the server
# reconfigured with AGTCRDN_BASE_URL) is brought up by the first S11-S16 spec,
# so that S0-S9 still measure the shipped defaults. --with-oauth does it here
# for someone poking around with --up-only.
if [ "$WITH_OAUTH" = 1 ]; then
  "$HERE/oauth-topology.sh" up || exit 1
fi

if [ "$UP_ONLY" = 1 ]; then exit 0; fi

# --------------------------------------------------------------- 3. playwright
log "Installing Playwright and the $UAT_BROWSER browser (into uat/.browsers)"
( cd "$PW" && npm install --no-audit --no-fund ) >> "$ARTIFACTS/npm-install.log" 2>&1 || {
  tail -30 "$ARTIFACTS/npm-install.log"; exit 1; }
( cd "$PW" && npx playwright install "$UAT_BROWSER" ) >> "$ARTIFACTS/npm-install.log" 2>&1 || {
  tail -30 "$ARTIFACTS/npm-install.log"; exit 1; }

log "Running the UAT scenarios"
if [ -n "$GREP_INVERT" ]; then
  ( cd "$PW" && npx playwright test --grep-invert "$GREP_INVERT" )
else
  ( cd "$PW" && npx playwright test )
fi
TEST_EXIT=$?

# ------------------------------------------------------------------ 4. collect
collect_logs
write_provenance
cp -f "$PW/report/results.json" "$ARTIFACTS/playwright-results.json" 2>/dev/null || true

# Playwright's own tally counts a `test.fail()` test that failed as "expected",
# i.e. alongside the real passes. Break the four outcomes apart so the harness
# never reports a documented defect as a green test, and surface the finding
# ids the test titles carry ([D7], [G3], ...).
log "Results"
node "$HERE/summarize-results.js" "$ARTIFACTS/playwright-results.json" \
  --json "$ARTIFACTS/results-summary.json" || true

# ----------------------------------------------------------------- 5. teardown
if [ "$DO_TEARDOWN" = 1 ]; then
  teardown
else
  log "--keep given: containers left running"
fi

log "Playwright exit code: $TEST_EXIT"
log "HTML report: $PW/report/index.html"
log "Screenshots: $PW/report/screenshots"
exit "$TEST_EXIT"
