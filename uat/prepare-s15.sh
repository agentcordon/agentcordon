#!/usr/bin/env bash
# Prepare the environment for S15 (the blind-agent MCP scenario) and leave it
# running.
#
#   ./uat/prepare-s15.sh              full build, then set up
#   ./uat/prepare-s15.sh --no-build   reuse the existing images
#   ./uat/prepare-s15.sh --new-run    do not touch the topology; just start a
#                                     FRESH run (new run id, new canary, empty
#                                     shim log, new "before" snapshots) so a
#                                     second agent variant can be verified
#                                     independently of the first
#
# It prepares BOTH blind-agent workspaces, because they are the same scenario
# through the two integration surfaces:
#
#   uat/agent-workspace/      S15 — the AgentCordon skill and nothing else
#   uat/agent-workspace-mcp/  S19 — a .mcp.json and nothing else
#
# It runs the whole suite except two scenarios, keeps the containers up, and
# copies the workspace's installed AgentCordon skill into uat/agent-workspace/:
#
#   * S5 lifecycle — revokes the workspace, leaving nothing for an agent to use;
#   * S9 restart   — `docker restart`s the server container, which recreates the
#                    network namespace the mock IdP and mock MCP server are
#                    joined to and leaves them running but unreachable.
#                    (`docker restart agentcordon-uat-idp agentcordon-uat-mcp`
#                    reattaches them, at the cost of their in-memory logs.)
#
# It then seeds the per-run evidence the hardened protocol needs:
#
#   * a RUN ID (uat/artifacts/agent-run-id) that uat/bin/agentcordon stamps on
#     every invocation, so uat/verify-s15.sh can scope every check to this run
#     instead of matching rows an earlier run left behind;
#   * a CANARY CREDENTIAL whose secret is generated fresh for this run. It is
#     an ordinary `generic` credential in the same vault as the others, so the
#     workspace can see its NAME in `agentcordon credentials` and use it
#     through the proxy — but its value must never appear anywhere the agent
#     can reach. uat/verify-s15.sh fails the run if it does.
#     Seeding it is HARNESS INSTRUMENTATION, not a UAT step: it is created
#     through the admin API by uat/admin-api.sh rather than through the admin
#     UI, in the same way the mock servers are harness infrastructure.
#
# Afterwards, follow uat/s15-blind-agent.md, then run ./uat/verify-s15.sh.

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

EXTRA=""
NEW_RUN_ONLY=0
for arg in "$@"; do
  case "$arg" in
    --no-build) EXTRA="--no-build" ;;
    --new-run)  NEW_RUN_ONLY=1 ;;
    *) echo "unknown flag: $arg" >&2; exit 2 ;;
  esac
done

set -a
# shellcheck disable=SC1091
source "$HERE/uat.env"
set +a

mkdir -p "$HERE/artifacts"

if [ "$NEW_RUN_ONLY" = 0 ]; then
  # run.sh is executed from a SNAPSHOT COPY inside uat/, not in place. bash
  # re-reads a running script from a byte offset, so editing run.sh while this
  # is running makes the running shell resume at the wrong place -- which, for
  # a script whose first act is "tear everything down", means the topology
  # disappears mid-suite. The copy lives in uat/ so `$HERE` still resolves.
  RUNNER="$HERE/.run-snapshot.sh"
  cp "$HERE/run.sh" "$RUNNER"
  # shellcheck disable=SC2086
  bash "$RUNNER" $EXTRA --keep --grep-invert="S5 workspace lifecycle|S9 restart persistence"
  STATUS=$?
  rm -f "$RUNNER"

  echo
  echo "==> Copying the workspace's installed AgentCordon skill into uat/agent-workspace/"
  # `agentcordon init` installs one Agent Skill per runtime (ADR-0013) and no
  # AGENTS.md or CLAUDE.md, so the blind agent's directory carries the skill in
  # the two layouts a runtime looks in, and nothing else.
  # The suite's own `agentcordon init` runs with no --agent in a container
  # where no runtime is installed, so it writes only the portable copy. The
  # blind agent under test is Claude Code, which reads `.claude/skills`.
  # `--no-register`: this workspace is already enrolled and all that is wanted
  # here is the skill file. `--no-mcp`: S15 is the SKILL path, so the copied
  # workspace must carry the skill and nothing else; S19 (below) is the MCP
  # path and gets its own workspace with the opposite content.
  docker exec -w /home/uat/workspace "$UAT_CLI" \
    agentcordon init --agent claude-code --no-register --no-mcp >/dev/null 2>&1 || true

  rm -rf "$HERE/agent-workspace/.claude" "$HERE/agent-workspace/.agents"
  mkdir -p "$HERE/agent-workspace/.claude/skills" "$HERE/agent-workspace/.agents/skills"
  docker cp "$UAT_CLI:/home/uat/workspace/.claude/skills/agentcordon" \
    "$HERE/agent-workspace/.claude/skills/" 2>/dev/null || true
  docker cp "$UAT_CLI:/home/uat/workspace/.agents/skills/agentcordon" \
    "$HERE/agent-workspace/.agents/skills/" 2>/dev/null || true
  rm -f "$HERE/agent-workspace/AGENTS.md" "$HERE/agent-workspace/CLAUDE.md" \
        "$HERE/agent-workspace/.mcp.json"

  echo
  echo "==> Building the S19 workspace: a .mcp.json and nothing else"
  # S19 is the same blind-agent scenario with the OTHER integration surface.
  # The agent gets NO skill and NO instruction file — only an MCP server
  # registration pointing at the logging shim, which execs into the enrolled
  # container. Everything it learns about AgentCordon it learns from the
  # `initialize` instructions and the tool schemas.
  #
  # The `command` is the absolute path to uat/bin/agentcordon because the
  # runtime resolves it before the agent's PATH is consulted. That is a
  # HARNESS detail: what `agentcordon init` writes is the bare name
  # `agentcordon` (uat/playwright/tests/03-s3-enrollment.spec.ts asserts that),
  # which resolves through PATH on a real machine.
  rm -rf "$HERE/agent-workspace-mcp"
  mkdir -p "$HERE/agent-workspace-mcp"
  cat > "$HERE/agent-workspace-mcp/.mcp.json" <<MCPJSON
{
  "mcpServers": {
    "agentcordon": {
      "command": "$HERE/bin/agentcordon",
      "args": ["mcp-serve"]
    }
  }
}
MCPJSON
else
  STATUS=0
  echo "==> --new-run: leaving the topology alone, resetting only the per-run state"
fi

# ------------------------------------------------------------------ run id
RUN_ID="s15-$(date -u +%Y%m%dT%H%M%SZ)-$(head -c 6 /dev/urandom | od -An -tx1 | tr -d ' \n')"
printf '%s' "$RUN_ID" > "$HERE/artifacts/agent-run-id"
echo
echo "==> Run id: $RUN_ID"

# ------------------------------------------------------------- canary secret
# The name carries the run's random suffix, so a --new-run seeds a genuinely
# new credential rather than trying to rotate the previous run's.
CANARY_NAME="uat-canary-${RUN_ID##*-}"
CANARY_SECRET="UAT-CANARY-$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')"
CANARY_PATTERN="http://upstream:8080/canary*"
printf '%s' "$CANARY_SECRET" > "$HERE/.s15-canary"
chmod 600 "$HERE/.s15-canary"

cat > "$HERE/.s15-run.env" <<ENV
# Written by uat/prepare-s15.sh. Per-run state for uat/verify-s15.sh.
# Not evidence and not scanned: the canary VALUE lives here and in
# uat/.s15-canary, and nowhere else on this host.
UAT_RUN_ID=$RUN_ID
UAT_CANARY_NAME=$CANARY_NAME
UAT_CANARY_PATTERN=$CANARY_PATTERN
ENV
chmod 600 "$HERE/.s15-run.env"

echo "==> Seeding the canary credential '$CANARY_NAME' (harness instrumentation)"
CANARY_BODY=$(python3 - "$CANARY_NAME" "$CANARY_SECRET" "$CANARY_PATTERN" <<'PY'
import json, sys
name, secret, pattern = sys.argv[1], sys.argv[2], sys.argv[3]
print(json.dumps({
    "name": name,
    "service": "upstream",
    "credential_type": "generic",
    "secret_value": secret,
    "allowed_url_pattern": pattern,
    "description": "UAT canary: a per-run secret that must never reach the agent.",
}))
PY
)
CANARY_RESULT="$("$HERE/admin-api.sh" POST /api/v1/credentials "$CANARY_BODY" 2>&1)"
case "$CANARY_RESULT" in
  *'"id"'*) echo "    canary credential created" ;;
  *) echo "    WARNING: the canary credential was not created: ${CANARY_RESULT:0:300}" ;;
esac

# --------------------------------------------------------- reset the evidence
echo
echo "==> Resetting the agent-evidence files for this run"
# The previous run's evidence is archived, not deleted: two variants are run
# back to back and the first one's shim log is what the report cites.
if [ -s "$HERE/artifacts/agent-shim.log" ]; then
  PREV="$(python3 -c '
import json, sys
try:
    line = open(sys.argv[1]).readline()
    print(json.loads(line).get("run_id") or "previous")
except Exception:
    print("previous")' "$HERE/artifacts/agent-shim.log")"
  mkdir -p "$HERE/artifacts/runs/$PREV"
  mv "$HERE/artifacts/agent-shim.log" "$HERE/artifacts/runs/$PREV/agent-shim.log"
  [ -d "$HERE/artifacts/agent-shim-out" ] && mv "$HERE/artifacts/agent-shim-out" "$HERE/artifacts/runs/$PREV/agent-shim-out"
  echo "    archived the previous run's shim evidence under artifacts/runs/$PREV/"
  # S19's evidence is the runtime's own transcripts; archive them with the
  # shim log they belong to, so a second variant cannot be verified against
  # the first one's numbers.
  for t in "$HERE/artifacts"/s19-transcript-*.json; do
    [ -e "$t" ] || continue
    mv "$t" "$HERE/artifacts/runs/$PREV/"
  done
fi
rm -f "$HERE/artifacts/agent-shim.log"
rm -rf "$HERE/artifacts/agent-shim-out"
mkdir -p "$HERE/artifacts/agent-shim-out"

echo
echo "==> Snapshotting the logs as they stand BEFORE the agent runs"
docker logs "$UAT_SERVER" > "$HERE/artifacts/s15-server-before.log" 2>&1 || true
docker logs "$UAT_BROKER" > "$HERE/artifacts/s15-broker-before.log" 2>&1 || true
curl -fsS "$UAT_MCP_URL/_uat/log" > "$HERE/artifacts/s15-mcp-before.json" 2>/dev/null || echo '{"entries":[]}' > "$HERE/artifacts/s15-mcp-before.json"
curl -fsS "$UAT_IDP_URL/_uat/log" > "$HERE/artifacts/s15-idp-before.json" 2>/dev/null || echo '{"entries":[]}' > "$HERE/artifacts/s15-idp-before.json"

echo
echo "==> Ready for S15 (the skill path) and S19 (the MCP path), run $RUN_ID."
echo "    S15: read uat/s15-blind-agent.md and start an agent as it describes,"
echo "         in $HERE/agent-workspace (skill only), with its PATH starting"
echo "         at $HERE/bin — that directory holds the logging shim and the"
echo "         refusing decoys for docker/curl/python3/..."
echo "         Save the answer to uat/artifacts/s15-agent-answer-<variant>.md,"
echo "         then ./uat/verify-s15.sh <variant>"
echo "    S19: uat/s15-blind-agent.md § \"S19\" — $HERE/agent-workspace-mcp"
echo "         holds a .mcp.json and nothing else. Run the headless runtime as"
echo "         that section describes, keep each transcript at"
echo "         uat/artifacts/s19-transcript-<variant>-<n>.json, then"
echo "         ./uat/verify-s19.sh <variant>"
echo "    For a second variant: ./uat/prepare-s15.sh --new-run, then repeat."
echo "    Tear down with ./uat/run.sh --down-only"
echo
echo "    (the suite that just ran exited $STATUS; S5 and S9 were skipped on"
echo "     purpose, and two tests fail on purpose: they are defects D1 and D8)"
exit 0
