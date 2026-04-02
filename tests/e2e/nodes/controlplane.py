"""
DAG nodes for control plane testing: controlplane.health, controlplane.workspace_list.
"""

import json

from tests.e2e.dag_runner import DagNode
from tests.e2e.helpers import server_request


# ---------------------------------------------------------------------------
# controlplane.health
# ---------------------------------------------------------------------------

def controlplane_health(ctx: dict) -> dict:
    """
    Verify the server health endpoint returns 200.

    Consumes: base_url
    """
    base_url = ctx["base_url"]

    status, _, body = server_request(base_url, "GET", "/health")

    assert status == 200, f"Health check failed with {status}: {body}"

    data = json.loads(body)
    assert data.get("status") == "ok", f"Health status not ok: {data}"

    return ctx


CONTROLPLANE_HEALTH_NODE = DagNode(
    name="controlplane.health",
    fn=controlplane_health,
    depends_on=[],
    produces=[],
    consumes=["base_url"],
    critical=True,
    timeout=5.0,
)


# ---------------------------------------------------------------------------
# controlplane.workspace_list
# ---------------------------------------------------------------------------

def controlplane_workspace_list(ctx: dict) -> dict:
    """
    List workspaces via admin API after OAuth registration.

    Consumes: base_url, admin_session_cookie, ws_workspace_name
    """
    base_url = ctx["base_url"]
    admin_cookie = ctx["admin_session_cookie"]

    status, _, body = server_request(
        base_url, "GET", "/api/v1/workspaces",
        cookies=admin_cookie,
    )

    assert status == 200, f"Workspace list failed with {status}: {body}"

    data = json.loads(body)
    workspaces = data.get("data", data)
    if isinstance(workspaces, dict):
        workspaces = workspaces.get("workspaces", workspaces.get("items", []))

    assert isinstance(workspaces, list), f"Expected workspace list: {type(workspaces)}"

    # After OAuth registration, our workspace should exist
    ws_name = ctx.get("ws_workspace_name")
    if ws_name:
        names = [w.get("name", "") for w in workspaces]
        assert ws_name in names, (
            f"Workspace '{ws_name}' not found after registration. Available: {names}"
        )

    return ctx


CONTROLPLANE_WORKSPACE_LIST_NODE = DagNode(
    name="controlplane.workspace_list",
    fn=controlplane_workspace_list,
    depends_on=["workspace.oauth_register"],
    produces=[],
    consumes=["base_url", "admin_session_cookie"],
    critical=False,
    timeout=10.0,
)


def get_nodes():
    """Return all control plane DAG nodes."""
    return [CONTROLPLANE_HEALTH_NODE, CONTROLPLANE_WORKSPACE_LIST_NODE]
