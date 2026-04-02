#!/usr/bin/env python3
"""
Main E2E test runner for AgentCordon.

Usage:
    python3 tests/e2e/run.py [FLAGS]

Flags:
    --base-url URL    Server URL (default: http://localhost:3140)
    --skip-build      Skip cargo build step
    --dag             Print DAG visualization and exit
    --node NAME       Run a single node and its dependencies
    --no-cleanup      Don't delete temp files on exit
    --keep-running    Leave processes running after tests

All test nodes use the broker architecture (OAuth consent, signed requests,
broker-mediated credential discovery and proxy).
"""

import argparse
import os
import sys

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from tests.e2e.dag_runner import DagRunner
from tests.e2e.helpers import stop_broker
from tests.e2e.nodes import all_nodes


def print_dag(runner: DagRunner):
    """Print a text visualization of the DAG."""
    order = runner._topo_sort()

    print("E2E Test DAG")
    print("=" * 60)

    for name in order:
        node = runner.nodes[name]
        deps = ", ".join(node.depends_on) if node.depends_on else "(none)"
        crit = " [CRITICAL]" if node.critical else ""
        print(f"  {name}{crit}")
        print(f"    depends_on: {deps}")
        if node.produces:
            print(f"    produces:   {', '.join(node.produces)}")
        if node.consumes:
            print(f"    consumes:   {', '.join(node.consumes)}")
        print()

    print(f"Total nodes: {len(order)}")


def main():
    parser = argparse.ArgumentParser(description="Run AgentCordon E2E tests")
    parser.add_argument(
        "--base-url", default="http://localhost:3140",
        help="AgentCordon server URL (default: http://localhost:3140)",
    )
    parser.add_argument(
        "--skip-build", action="store_true",
        help="Skip cargo build step",
    )
    parser.add_argument(
        "--dag", action="store_true",
        help="Print DAG visualization and exit",
    )
    parser.add_argument(
        "--node", type=str, default=None,
        help="Run a single node and its dependencies",
    )
    parser.add_argument(
        "--no-cleanup", action="store_true",
        help="Don't delete temp files on exit",
    )
    parser.add_argument(
        "--keep-running", action="store_true",
        help="Leave processes running after tests",
    )
    args = parser.parse_args()

    runner = DagRunner()

    # Register all nodes
    for node in all_nodes():
        runner.add_node(node)

    # DAG visualization mode
    if args.dag:
        print_dag(runner)
        sys.exit(0)

    # Pre-populate context
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
    print("AgentCordon E2E Tests")
    print(f"Server: {args.base_url}")
    print("=" * 60)

    try:
        results = runner.run(ctx)
    finally:
        if not args.keep_running:
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
