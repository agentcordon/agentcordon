#!/usr/bin/env python3
"""
E2E test runner for the broker flow.

Usage:
    python3 tests/e2e/run_broker_e2e.py [--base-url URL] [--skip-build]

Runs the critical-path DAG:
    setup.login → broker.start → workspace.oauth_register
    → credential.discover_via_broker → proxy.via_broker
    + security nodes
"""

import argparse
import os
import sys
import tempfile

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from tests.e2e.dag_runner import DagRunner
from tests.e2e.helpers import stop_broker
from tests.e2e.nodes.broker import get_nodes as broker_nodes
from tests.e2e.nodes.oauth_flow import get_nodes as oauth_nodes
from tests.e2e.nodes.broker_proxy import get_nodes as proxy_nodes
from tests.e2e.nodes.oauth_security import get_nodes as security_nodes


def main():
    parser = argparse.ArgumentParser(description="Run broker E2E tests")
    parser.add_argument(
        "--base-url", default="http://localhost:3140",
        help="AgentCordon server URL (default: http://localhost:3140)",
    )
    parser.add_argument(
        "--skip-build", action="store_true",
        help="Skip cargo build step",
    )
    args = parser.parse_args()

    runner = DagRunner()

    # Register all nodes
    for node in broker_nodes():
        runner.add_node(node)
    for node in oauth_nodes():
        runner.add_node(node)
    for node in proxy_nodes():
        runner.add_node(node)
    for node in security_nodes():
        runner.add_node(node)

    # Pre-populate context with base setup values
    # In a full E2E run, setup.login, workspace.create, credential.create,
    # and permission.grant nodes would populate these. For standalone broker
    # testing, these can be provided via environment or pre-seeded.
    ctx = {
        "base_url": args.base_url,
    }

    # Allow environment overrides for pre-seeded values
    env_map = {
        "AC_E2E_ADMIN_COOKIE": "admin_session_cookie",
        "AC_E2E_WORKSPACE_ID": "ws_workspace_id",
        "AC_E2E_WORKSPACE_NAME": "ws_workspace_name",
        "AC_E2E_CREDENTIAL_NAME": "credential_name",
    }
    for env_key, ctx_key in env_map.items():
        val = os.environ.get(env_key)
        if val:
            ctx[ctx_key] = val

    print("=" * 60)
    print("AgentCordon Broker E2E Tests")
    print(f"Server: {args.base_url}")
    print("=" * 60)

    try:
        results = runner.run(ctx)
    finally:
        # Always clean up broker process
        proc = ctx.get("broker_process")
        if proc:
            print("\nCleaning up broker process...")
            stop_broker(proc)

    print(runner.summary())

    # Exit with failure if any critical nodes failed
    failed = any(r.status == "failed" for r in results)
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
