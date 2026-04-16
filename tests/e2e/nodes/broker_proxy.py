"""
DAG nodes for broker-mediated credential discovery and proxy:
  - credential.discover_via_broker
  - proxy.via_broker
  - proxy.via_broker_denied
"""

import json
import urllib.request
import urllib.error

from tests.e2e.dag_runner import DagNode
from tests.e2e.helpers import broker_request


# ---------------------------------------------------------------------------
# credential.discover_via_broker
# ---------------------------------------------------------------------------

def credential_discover_via_broker(ctx: dict) -> dict:
    """
    List credentials through the broker using a signed request.

    The CLI signs a GET /credentials request → broker uses its stored OAuth
    token to query the server → returns the credential list.

    Consumes: broker_url, broker_pem_key_path
    Produces: broker_discovered_credentials
    """
    broker_url = ctx["broker_url"]
    pem_key_path = ctx["broker_pem_key_path"]

    status, headers, body = broker_request(
        broker_url, pem_key_path, "GET", "/credentials"
    )

    assert status == 200, (
        f"Expected 200 from broker /credentials, got {status}: {body}"
    )

    data = json.loads(body)
    credentials = data.get("data", data)

    # Should be a list
    assert isinstance(credentials, list), (
        f"Expected credential list, got {type(credentials)}: {credentials}"
    )

    # Verify we got at least one credential (credential.create should have run)
    assert len(credentials) > 0, (
        "No credentials returned from broker. "
        "Did credential.create run before this node?"
    )

    # Extract credential names for downstream nodes
    cred_names = [c.get("name", c.get("id", "unknown")) for c in credentials]
    ctx["broker_discovered_credentials"] = credentials
    ctx["broker_credential_names"] = cred_names

    # Verify the credential we created is in the list
    created_cred_name = ctx.get("credential_name")
    if created_cred_name:
        assert created_cred_name in cred_names, (
            f"Created credential '{created_cred_name}' not found in "
            f"broker-discovered credentials: {cred_names}"
        )

    return ctx


CREDENTIAL_DISCOVER_VIA_BROKER_NODE = DagNode(
    name="credential.discover_via_broker",
    fn=credential_discover_via_broker,
    depends_on=["workspace.device_code_exchange", "credential.create"],
    produces=["broker_discovered_credentials"],
    consumes=["broker_url", "broker_pem_key_path"],
    critical=True,
    timeout=20.0,
)


# ---------------------------------------------------------------------------
# proxy.via_broker
# ---------------------------------------------------------------------------

def proxy_via_broker(ctx: dict) -> dict:
    """
    Proxy an HTTP request through the broker.

    The CLI signs a POST /proxy request → broker vends the credential from
    the server → ECIES-decrypts → applies transform → proxies to the upstream
    target → returns the response.

    Consumes: broker_url, broker_pem_key_path, broker_discovered_credentials
    Produces: broker_proxy_success
    """
    broker_url = ctx["broker_url"]
    pem_key_path = ctx["broker_pem_key_path"]

    # Use the first discovered credential, or the one we created
    credential_name = ctx.get("credential_name")
    if not credential_name:
        creds = ctx.get("broker_discovered_credentials", [])
        if creds:
            credential_name = creds[0].get("name", creds[0].get("id"))
    assert credential_name, "No credential available for proxy test"

    # Use a mock upstream URL — in E2E we need a real target.
    # Use the server's own /health as a safe upstream target, or
    # use httpbin if available. For E2E tests, we proxy to the server itself.
    upstream_url = ctx.get(
        "proxy_upstream_url",
        f"{ctx.get('base_url', 'http://localhost:3140')}/health"
    )

    proxy_body = json.dumps({
        "method": "GET",
        "url": upstream_url,
        "credential": credential_name,
        "headers": {
            "Accept": "application/json",
        },
    })

    status, headers, body = broker_request(
        broker_url, pem_key_path, "POST", "/proxy", body=proxy_body,
    )

    assert status == 200, (
        f"Expected 200 from broker /proxy, got {status}: {body}"
    )

    data = json.loads(body)
    proxy_result = data.get("data", data)

    # Verify the proxy response contains upstream data
    upstream_status = proxy_result.get("status_code")
    assert upstream_status is not None, (
        f"Proxy response missing status_code: {proxy_result}"
    )

    upstream_body = proxy_result.get("body", "")
    assert upstream_body, f"Proxy response has empty body: {proxy_result}"

    # Verify no credential material leaked into the proxy response
    # The response should contain the upstream's response, not any secrets
    assert "ECIES" not in body, "ECIES reference leaked into proxy response"
    assert "private_key" not in body.lower(), "Private key reference in proxy response"

    ctx["broker_proxy_success"] = True
    ctx["broker_proxy_response"] = proxy_result

    return ctx


PROXY_VIA_BROKER_NODE = DagNode(
    name="proxy.via_broker",
    fn=proxy_via_broker,
    depends_on=["credential.discover_via_broker", "permission.grant"],
    produces=["broker_proxy_success"],
    consumes=["broker_url", "broker_pem_key_path"],
    critical=True,
    timeout=45.0,
)


# ---------------------------------------------------------------------------
# proxy.via_broker_denied
# ---------------------------------------------------------------------------

def proxy_via_broker_denied(ctx: dict) -> dict:
    """
    Verify that a workspace with OAuth tokens but no Cedar permission
    for a credential gets 403 when attempting to proxy.

    The upstream target should never receive the request.

    Consumes: broker_url, broker_pem_key_path
    Produces: (none — validation only)
    """
    broker_url = ctx["broker_url"]
    pem_key_path = ctx["broker_pem_key_path"]

    # Use a credential name that the workspace has no Cedar permission for.
    # We use a non-existent credential to ensure no grant covers it.
    unpermitted_credential = "nonexistent-credential-no-permission"

    proxy_body = json.dumps({
        "method": "GET",
        "url": f"{ctx.get('base_url', 'http://localhost:3140')}/health",
        "credential": unpermitted_credential,
        "headers": {"Accept": "application/json"},
    })

    status, headers, body = broker_request(
        broker_url, pem_key_path, "POST", "/proxy", body=proxy_body,
    )

    assert status in (403, 404), (
        f"Expected 403/404 for proxy without permission, got {status}: {body}"
    )

    return ctx


PROXY_VIA_BROKER_DENIED_NODE = DagNode(
    name="proxy.via_broker_denied",
    fn=proxy_via_broker_denied,
    depends_on=["workspace.device_code_exchange"],
    produces=[],
    consumes=["broker_url", "broker_pem_key_path"],
    critical=False,
    timeout=20.0,
)


def get_nodes():
    """Return all broker proxy DAG nodes."""
    return [
        CREDENTIAL_DISCOVER_VIA_BROKER_NODE,
        PROXY_VIA_BROKER_NODE,
        PROXY_VIA_BROKER_DENIED_NODE,
    ]
