"""
DAG nodes for Windows installer assets: windows.install_script_served.
"""

from tests.e2e.dag_runner import DagNode
from tests.e2e.helpers import server_request


def windows_install_script_served(ctx: dict) -> dict:
    """
    Verify that GET /install.ps1 serves the Windows PowerShell installer.

    Consumes: base_url
    Produces: install_ps1_served
    """
    base_url = ctx["base_url"]

    status, headers, body = server_request(base_url, "GET", "/install.ps1")
    assert status == 200, f"GET /install.ps1 failed {status}: {body[:200]}"

    content_type = ""
    for k, v in headers.items():
        if k.lower() == "content-type":
            content_type = v.lower()
            break
    assert (
        "powershell" in content_type or "text/plain" in content_type
    ), f"Unexpected Content-Type for install.ps1: {content_type}"

    # The script should begin with a PowerShell requires/header and mention
    # the install target directory.
    head = body.lstrip()[:200]
    assert head.startswith("#Requires") or head.startswith("#"), (
        f"install.ps1 body does not start with PowerShell header: {head!r}"
    )
    assert "LOCALAPPDATA" in body and "AgentCordon" in body, (
        "install.ps1 body missing LOCALAPPDATA\\AgentCordon target reference"
    )

    ctx["install_ps1_served"] = True
    return ctx


WINDOWS_INSTALL_SCRIPT_SERVED_NODE = DagNode(
    name="windows.install_script_served",
    fn=windows_install_script_served,
    depends_on=["setup.login"],
    produces=["install_ps1_served"],
    consumes=["base_url"],
    critical=False,
    timeout=10.0,
)


def get_nodes():
    """Return all Windows-installer DAG nodes."""
    return [WINDOWS_INSTALL_SCRIPT_SERVED_NODE]
