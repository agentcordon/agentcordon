"""
DAG nodes for grant/permission flow testing: grant.verify_access_via_broker.
"""

import json

from tests.e2e.dag_runner import DagNode
from tests.e2e.helpers import broker_request


# ---------------------------------------------------------------------------
# grant.verify_access_via_broker
# ---------------------------------------------------------------------------

def grant_verify_access_via_broker(ctx: dict) -> dict:
    """
    After permissions are granted, verify the workspace can discover
    credentials through the broker (the granted permissions are effective).

    Consumes: broker_url, broker_pem_key_path, credential_name, permission_granted
    """
    broker_url = ctx["broker_url"]
    pem_key_path = ctx["broker_pem_key_path"]
    credential_name = ctx["credential_name"]

    status, _, body = broker_request(
        broker_url, pem_key_path, "GET", "/credentials"
    )

    assert status == 200, (
        f"Broker credential discovery failed after grant: {status}: {body}"
    )

    data = json.loads(body)
    creds = data.get("data", data)
    if isinstance(creds, dict):
        creds = creds.get("credentials", [])

    assert isinstance(creds, list), f"Expected list: {type(creds)}"

    cred_names = [c.get("name", "") for c in creds]
    assert credential_name in cred_names, (
        f"Granted credential '{credential_name}' not discoverable via broker. "
        f"Available: {cred_names}"
    )

    return ctx


GRANT_VERIFY_ACCESS_NODE = DagNode(
    name="grant.verify_access_via_broker",
    fn=grant_verify_access_via_broker,
    depends_on=["permission.grant"],
    produces=[],
    consumes=["broker_url", "broker_pem_key_path", "credential_name"],
    critical=False,
    timeout=15.0,
)



# ---------------------------------------------------------------------------
# grant.permission_check
# ---------------------------------------------------------------------------

def grant_permission_check(ctx: dict) -> dict:
    """
    Verify grant-based access respects Cedar policies: after granting access,
    broker can proxy; credential without grant is not accessible.

    Consumes: broker_url, broker_pem_key_path, credential_name, base_url
    """
    broker_url = ctx["broker_url"]
    pem_key_path = ctx["broker_pem_key_path"]
    credential_name = ctx["credential_name"]
    base_url = ctx.get("base_url", "http://localhost:3140")

    # Granted credential should proxy successfully
    upstream_url = ctx.get("proxy_upstream_url", f"{base_url}/health")
    proxy_body = json.dumps({
        "method": "GET",
        "url": upstream_url,
        "credential": credential_name,
        "headers": {"Accept": "application/json"},
    })

    status, _, body = broker_request(
        broker_url, pem_key_path, "POST", "/proxy", body=proxy_body,
    )

    assert status == 200, (
        f"Proxy with granted credential failed: {status}: {body}"
    )

    # Non-existent credential should fail
    proxy_body2 = json.dumps({
        "method": "GET",
        "url": upstream_url,
        "credential": "nonexistent-credential-xyz-12345",
    })

    status, _, body = broker_request(
        broker_url, pem_key_path, "POST", "/proxy", body=proxy_body2,
    )

    assert status in (403, 404), (
        f"Expected 403/404 for nonexistent credential, got {status}"
    )

    return ctx


GRANT_PERMISSION_CHECK_NODE = DagNode(
    name="grant.permission_check",
    fn=grant_permission_check,
    depends_on=["grant.verify_access_via_broker"],
    produces=[],
    consumes=["broker_url", "broker_pem_key_path", "credential_name"],
    critical=False,
    timeout=30.0,
)


def get_nodes():
    """Return all grant DAG nodes."""
    return [GRANT_VERIFY_ACCESS_NODE, GRANT_PERMISSION_CHECK_NODE]
