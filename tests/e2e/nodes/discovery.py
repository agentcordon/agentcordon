"""
DAG nodes for credential discovery testing via broker:
discovery.by_name, discovery.no_secrets_in_list.
"""

import json

from tests.e2e.dag_runner import DagNode
from tests.e2e.helpers import broker_request, server_request


# ---------------------------------------------------------------------------
# discovery.by_name
# ---------------------------------------------------------------------------

def discovery_by_name(ctx: dict) -> dict:
    """
    Discover a specific credential by name via the admin API.

    Consumes: base_url, admin_session_cookie, credential_name
    """
    base_url = ctx["base_url"]
    admin_cookie = ctx["admin_session_cookie"]
    credential_name = ctx["credential_name"]

    status, _, body = server_request(
        base_url, "GET", f"/api/v1/credentials/by-name/{credential_name}",
        cookies=admin_cookie,
    )

    assert status == 200, (
        f"Credential by-name lookup failed with {status}: {body}"
    )

    data = json.loads(body)
    cred = data.get("data", data)
    assert cred.get("name") == credential_name, (
        f"Name mismatch: {cred.get('name')} != {credential_name}"
    )

    return ctx


DISCOVERY_BY_NAME_NODE = DagNode(
    name="discovery.by_name",
    fn=discovery_by_name,
    depends_on=["credential.create"],
    produces=[],
    consumes=["base_url", "admin_session_cookie", "credential_name"],
    critical=False,
    timeout=10.0,
)


# ---------------------------------------------------------------------------
# discovery.no_secrets_in_list
# ---------------------------------------------------------------------------

def discovery_no_secrets_in_list(ctx: dict) -> dict:
    """
    Verify that credential list responses never include secret values.

    Consumes: base_url, admin_session_cookie
    """
    base_url = ctx["base_url"]
    admin_cookie = ctx["admin_session_cookie"]

    status, _, body = server_request(
        base_url, "GET", "/api/v1/credentials",
        cookies=admin_cookie,
    )

    assert status == 200, f"Credential list failed: {status}"

    # Check that no secret patterns appear
    body_lower = body.lower()
    forbidden = [
        "e2e-test-secret-value",
        "secret_value",
        "-----begin",
        "private_key",
    ]

    for pattern in forbidden:
        assert pattern not in body_lower, (
            f"Secret pattern '{pattern}' found in credential list response"
        )

    return ctx


DISCOVERY_NO_SECRETS_NODE = DagNode(
    name="discovery.no_secrets_in_list",
    fn=discovery_no_secrets_in_list,
    depends_on=["credential.create"],
    produces=[],
    consumes=["base_url", "admin_session_cookie"],
    critical=True,
    timeout=10.0,
)


def get_nodes():
    """Return all discovery DAG nodes."""
    return [DISCOVERY_BY_NAME_NODE, DISCOVERY_NO_SECRETS_NODE]
