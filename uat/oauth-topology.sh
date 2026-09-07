#!/usr/bin/env bash
# Bring up (or tear down) the parts of the UAT topology that only the OAuth and
# MCP scenarios (S11-S16) need.
#
#   ./uat/oauth-topology.sh up     recreate the server with the documented
#                                  OAuth configuration, then start the mock
#                                  IdP and the mock MCP server
#   ./uat/oauth-topology.sh down   remove the mock IdP and the mock MCP server
#
# Why the server is recreated rather than started this way from the start:
# README.md § Configuration and .env.example both say AGTCRDN_BASE_URL is
# "required for OAuth2 MCP flows" and nothing else, so a new user does not set
# it until they reach those flows. uat/run.sh therefore starts the server
# without it (which is what S3 measures), and this script performs the
# documented reconfiguration when the OAuth scenarios need it. In compose terms
# it is "add three lines to .env, then `docker compose up -d`": same image,
# same named volume, so no data is lost.
#
# Every variable it adds is documented:
#   AGTCRDN_BASE_URL             README.md § Configuration, .env.example
#   AGTCRDN_PROXY_ALLOW_LOOPBACK README.md § Configuration, .env.example,
#                                docs/granting-mcp-server-access.md § SSRF
#   AGTCRDN_MCP_TEMPLATES_DIR    *undocumented* — recorded as a finding in
#                                uat/REPORT.md; there is no other way to put a
#                                mock MCP server in the marketplace.

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ARTIFACTS="$HERE/artifacts"

set -a
# shellcheck disable=SC1091
source "$HERE/uat.env"
set +a

log() { printf '\n\033[1;35m--> %s\033[0m\n' "$*"; }

wait_http() { # url, seconds
  local url="$1" secs="${2:-60}" i=0
  while [ "$i" -lt "$secs" ]; do
    if curl -fsS -o /dev/null "$url" 2>/dev/null; then return 0; fi
    i=$((i + 1)); sleep 1
  done
  return 1
}

down() {
  docker rm -f "$UAT_MCP" >/dev/null 2>&1 || true
  docker rm -f "$UAT_IDP" >/dev/null 2>&1 || true
}

start_mocks() {
  log "Starting the mock OAuth provider in the server's network namespace"
  docker run -d --name "$UAT_IDP" \
    --network "container:$UAT_SERVER" \
    -v "$HERE/mock_oauth_provider.py:/app/mock_oauth_provider.py:ro" \
    -e UAT_IDP_PORT="$UAT_IDP_PORT" \
    -e UAT_IDP_NODCR_PORT="$UAT_IDP_NODCR_PORT" \
    -e UAT_IDP_DELEGATED_TTL="$UAT_IDP_DELEGATED_TTL" \
    -e UAT_IDP_SUBJECT="$UAT_IDP_SUBJECT" \
    -w /app "$UAT_PYTHON_IMAGE" python3 /app/mock_oauth_provider.py >/dev/null

  log "Starting the mock MCP server in the server's network namespace"
  docker run -d --name "$UAT_MCP" \
    --network "container:$UAT_SERVER" \
    -v "$HERE/mock_mcp.py:/app/mock_mcp.py:ro" \
    -e UAT_MCP_PORT="$UAT_MCP_PORT" \
    -e UAT_MCP_SELF_URL="$UAT_MCP_URL" \
    -e UAT_MCP_API_KEY="$UAT_MCP_API_KEY" \
    -e UAT_IDP_URL="$UAT_IDP_URL" \
    -e UAT_IDP_ISSUER="$UAT_IDP_URL" \
    -w /app "$UAT_PYTHON_IMAGE" python3 /app/mock_mcp.py >/dev/null

  for url in "$UAT_IDP_URL/_uat/health" "$UAT_IDP_NODCR_URL/_uat/health" "$UAT_MCP_URL/_uat/health"; do
    if ! wait_http "$url" 60; then
      echo "mock never came up: $url" >&2
      docker logs "$UAT_IDP" 2>&1 | tail -20
      docker logs "$UAT_MCP" 2>&1 | tail -20
      return 1
    fi
  done
  return 0
}

up() {
  mkdir -p "$ARTIFACTS"
  down

  log "Recreating the server with the documented OAuth2 configuration"
  docker rm -f "$UAT_SERVER" >/dev/null 2>&1 || true
  docker run -d --name "$UAT_SERVER" \
    --network "$UAT_NETWORK" --network-alias server \
    -p "127.0.0.1:$UAT_HOST_PORT:3140" \
    -p "127.0.0.1:$UAT_IDP_PORT:$UAT_IDP_PORT" \
    -p "127.0.0.1:$UAT_IDP_NODCR_PORT:$UAT_IDP_NODCR_PORT" \
    -p "127.0.0.1:$UAT_MCP_PORT:$UAT_MCP_PORT" \
    -v "$UAT_VOLUME:/data" \
    -v "$HERE/mcp-templates:/uat/mcp-templates:ro" \
    -e AGTCRDN_ROOT_USERNAME="$UAT_ROOT_USERNAME" \
    -e AGTCRDN_ROOT_PASSWORD="$UAT_ROOT_PASSWORD" \
    -e AGTCRDN_MASTER_SECRET="$UAT_MASTER_SECRET" \
    -e AGTCRDN_LOG_LEVEL=info \
    -e AGTCRDN_BASE_URL="$UAT_BASE_URL" \
    -e AGTCRDN_PROXY_ALLOW_LOOPBACK=true \
    -e AGTCRDN_MCP_TEMPLATES_DIR=/uat/mcp-templates \
    "$UAT_SERVER_IMAGE" >/dev/null

  if ! wait_http "$UAT_SERVER_URL/health" 120; then
    echo "server never came back up" >&2
    docker logs "$UAT_SERVER" 2>&1 | tail -40
    return 1
  fi

  start_mocks || return 1

  log "OAuth topology up"
  docker ps --filter "name=agentcordon-uat" --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'
  return 0
}

case "${1:-up}" in
  up)   up ;;
  down) down ;;
  mocks) start_mocks ;;
  *) echo "usage: $0 [up|down|mocks]" >&2; exit 2 ;;
esac
