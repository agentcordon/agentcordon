#!/usr/bin/env python3
"""Check every bundled MCP template against the server it names.

A template is a URL and an auth method written down months ago. Vendors move
endpoints, retire SSE for streamable HTTP, and change where they publish their
OAuth metadata, and none of that shows up in a unit test: the catalog keeps
loading, the marketplace keeps rendering, and the first person to learn the
template is stale is a user whose Connect button fails.

Two things are checked per template:

1. **The endpoint answers.** An MCP `initialize` is POSTed. `200` means it
   answered, `401`/`403` means it answered and wants credentials -- both prove
   the URL is live. Anything else (a `404`, a `302` to a marketing page, no
   response at all) means the template points at nothing.

2. **OAuth discovery can find the metadata.** `oauth2_resource_url` is turned
   into a metadata URL by appending `/.well-known/oauth-protected-resource`,
   and naming the field skips the `401` probe entirely -- so a field that
   resolves to a `404` fails the connect with no fallback. RFC 9728 also allows
   the path-insertion form (`https://host/.well-known/oauth-protected-resource/mcp`
   for the resource `https://host/mcp`), which this field cannot express; a
   server that uses it must leave the field out and let its own `401` hint say
   where the document lives. Either shape is fine, neither is not.

This talks to the public internet and depends on other people's uptime, so it
is deliberately NOT wired into CI: a vendor's bad afternoon is not a reason to
fail a pull request. Run it by hand when adding a template, and periodically
against the whole catalog.

    python3 scripts/check-mcp-templates.py            # every bundled template
    python3 scripts/check-mcp-templates.py neon slack # just these keys

Exit code is 1 when any template has a problem, so it can gate a release check
if you want it to.
"""

import json
import pathlib
import re
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor

ROOT = pathlib.Path(__file__).resolve().parent.parent
TEMPLATE_DIR = ROOT / "data" / "mcp-templates"

WELL_KNOWN = "/.well-known/oauth-protected-resource"
TIMEOUT = "20"

INITIALIZE = json.dumps(
    {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "agentcordon-template-check", "version": "1"},
        },
    }
)

# A server that answers at all proves its URL is live; whether it then wants a
# token is the template's business, not this check's.
LIVE_STATUSES = {"200", "401", "403"}


def curl(*args):
    """Run curl, returning stdout. A failure is an empty string, not a raise."""
    return subprocess.run(
        ["curl", "-s", "--max-time", TIMEOUT, *args],
        capture_output=True,
        text=True,
    ).stdout


def status_of(url):
    return curl("-o", "/dev/null", "-w", "%{http_code}", url) or "---"


def initialize(url):
    """POST an MCP initialize. Returns (status code, has a 401 metadata hint)."""
    out = curl(
        "-i",
        "-X",
        "POST",
        url,
        "-H",
        "Content-Type: application/json",
        "-H",
        "Accept: application/json, text/event-stream",
        "-d",
        INITIALIZE,
    )
    first = out.split("\n", 1)[0] if out else ""
    code = re.search(r"\b(\d{3})\b", first)
    return (code.group(1) if code else "---"), bool(
        re.search(r"resource_metadata", out, re.I)
    )


def check(path):
    template = json.loads(path.read_text())
    key = template["key"]
    code, hinted = initialize(template["upstream_url"])

    resource = template.get("oauth2_resource_url")
    metadata = status_of(resource.rstrip("/") + WELL_KNOWN) if resource else None

    problems = []
    if code not in LIVE_STATUSES:
        problems.append(f"endpoint answered {code}")
    if template["auth_method"] == "oauth2":
        if resource and metadata != "200":
            problems.append(
                f"oauth2_resource_url metadata is {metadata}; either the origin "
                f"serves the document (leave the field) or it does not (drop it)"
            )
        if not resource and not hinted:
            problems.append(
                "no oauth2_resource_url and no resource_metadata hint on the "
                "401, so discovery has nowhere to start"
            )
    return key, code, resource, metadata, problems


def main():
    wanted = set(sys.argv[1:])
    paths = sorted(TEMPLATE_DIR.glob("*.json"))
    if wanted:
        paths = [p for p in paths if json.loads(p.read_text())["key"] in wanted]
        missing = wanted - {json.loads(p.read_text())["key"] for p in paths}
        if missing:
            sys.exit(f"no such template: {', '.join(sorted(missing))}")
    if not paths:
        sys.exit(f"no templates found in {TEMPLATE_DIR}")

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = sorted(pool.map(check, paths))

    failed = 0
    for key, code, resource, metadata, problems in results:
        mark = "FAIL" if problems else "ok  "
        print(f"{mark} {key:<14} http={code:<4} meta={metadata or '-':<4} {resource or ''}")
        for problem in problems:
            failed += 1
            print(f"       {problem}")

    noun = "problem" if failed == 1 else "problems"
    print(f"\n{len(results)} templates checked, {failed} {noun}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
