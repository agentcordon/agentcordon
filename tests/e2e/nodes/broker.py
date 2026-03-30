"""
DAG nodes for broker lifecycle: broker.start, broker.health.
"""

import json
import os
import tempfile
import urllib.request
import urllib.error

from tests.e2e.dag_runner import DagNode
from tests.e2e.helpers import (
    find_free_port,
    start_broker,
    stop_broker,
)


# ---------------------------------------------------------------------------
# broker.start
# ---------------------------------------------------------------------------

def broker_start(ctx: dict) -> dict:
    """
    Start the broker daemon, wait for health, store broker_url in context.

    Consumes: base_url
    Produces: broker_url, broker_port, broker_process, broker_data_dir, broker_pem_key_path
    """
    base_url = ctx["base_url"]

    # Create a temp directory for broker data
    broker_data_dir = tempfile.mkdtemp(prefix="ac_broker_e2e_")
    ctx["broker_data_dir"] = broker_data_dir

    # Determine broker binary location
    cargo_target = os.environ.get(
        "CARGO_TARGET_DIR",
        os.path.join(os.environ.get("AC_PROJECT_ROOT", "."), "target"),
    )
    broker_binary = os.path.join(cargo_target, "debug", "agentcordon-broker")

    if not os.path.isfile(broker_binary):
        # Try relative to working directory
        broker_binary = os.path.join("target", "debug", "agentcordon-broker")
    if not os.path.isfile(broker_binary):
        raise FileNotFoundError(
            f"Broker binary not found. Build with: cargo build -p agentcordon-broker"
        )

    proc, port, broker_url = start_broker(
        server_url=base_url,
        data_dir=broker_data_dir,
        broker_binary=broker_binary,
        timeout=15.0,
    )

    ctx["broker_url"] = broker_url
    ctx["broker_port"] = port
    ctx["broker_process"] = proc

    return ctx


BROKER_START_NODE = DagNode(
    name="broker.start",
    fn=broker_start,
    depends_on=["setup.login"],
    produces=["broker_url", "broker_port", "broker_process", "broker_data_dir"],
    consumes=["base_url"],
    critical=True,
    timeout=15.0,
)


# ---------------------------------------------------------------------------
# broker.health
# ---------------------------------------------------------------------------

def broker_health(ctx: dict) -> dict:
    """
    Verify broker /health endpoint returns 200 with {"status": "ok"}.

    Consumes: broker_url
    Produces: (none — validation only)
    """
    broker_url = ctx["broker_url"]

    req = urllib.request.Request(f"{broker_url}/health")
    with urllib.request.urlopen(req, timeout=5) as resp:
        assert resp.status == 200, f"Expected 200, got {resp.status}"
        body = json.loads(resp.read())
        assert body.get("status") == "ok", f"Expected status 'ok', got {body}"

    # Verify version field is present
    assert "version" in body, "Health response missing 'version' field"

    return ctx


BROKER_HEALTH_NODE = DagNode(
    name="broker.health",
    fn=broker_health,
    depends_on=["broker.start"],
    produces=[],
    consumes=["broker_url"],
    critical=True,
    timeout=10.0,
)


# ---------------------------------------------------------------------------
# Cleanup helper (registered as a finally-node or called in teardown)
# ---------------------------------------------------------------------------

def broker_stop(ctx: dict) -> dict:
    """Stop the broker process if running."""
    proc = ctx.get("broker_process")
    if proc:
        stop_broker(proc)
        ctx.pop("broker_process", None)
    return ctx


BROKER_STOP_NODE = DagNode(
    name="broker.stop",
    fn=broker_stop,
    depends_on=[],  # Run unconditionally in teardown
    produces=[],
    consumes=[],
    critical=False,
    timeout=5.0,
)


def get_nodes():
    """Return all broker DAG nodes."""
    return [BROKER_START_NODE, BROKER_HEALTH_NODE, BROKER_STOP_NODE]
