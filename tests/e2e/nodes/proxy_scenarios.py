"""
DAG nodes for proxy edge case scenarios.

Scenarios:
  proxy.consecutive_reuse
  proxy.no_credential_in_response
  proxy.invalid_method_rejected
"""

import json

from tests.e2e.dag_runner import DagNode
from tests.e2e.helpers import broker_request


# ---------------------------------------------------------------------------
# proxy.consecutive_reuse
# ---------------------------------------------------------------------------

def proxy_consecutive_reuse(ctx: dict) -> dict:
    """
    Two proxy calls with same credential → both succeed (token not consumed).

    Consumes: broker_url, broker_pem_key_path, credential_name, base_url
    """
    broker_url = ctx["broker_url"]
    pem_key_path = ctx["broker_pem_key_path"]
    credential_name = ctx["credential_name"]
    base_url = ctx.get("base_url", "http://localhost:3140")
    upstream_url = ctx.get("proxy_upstream_url", f"{base_url}/health")

    results = []
    for i in range(2):
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
            f"Consecutive proxy call #{i+1} failed with {status}: {body}"
        )
        results.append(status)

    # Both should have succeeded
    assert all(s == 200 for s in results), (
        f"Not all consecutive proxy calls succeeded: {results}"
    )

    return ctx


PROXY_CONSECUTIVE_REUSE_NODE = DagNode(
    name="proxy.consecutive_reuse",
    fn=proxy_consecutive_reuse,
    depends_on=["proxy.via_broker"],
    produces=[],
    consumes=["broker_url", "broker_pem_key_path", "credential_name"],
    critical=False,
    timeout=30.0,
)


# ---------------------------------------------------------------------------
# proxy.no_credential_in_response
# ---------------------------------------------------------------------------

def proxy_no_credential_in_response(ctx: dict) -> dict:
    """
    After proxy, verify the response body doesn't contain the raw credential secret.

    Consumes: broker_url, broker_pem_key_path, credential_name, base_url
    """
    broker_url = ctx["broker_url"]
    pem_key_path = ctx["broker_pem_key_path"]
    credential_name = ctx["credential_name"]
    base_url = ctx.get("base_url", "http://localhost:3140")
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

    assert status == 200, f"Proxy call failed: {status}: {body}"

    # Check response doesn't contain credential material
    body_lower = body.lower()
    forbidden = [
        "e2e-test-secret-value",
        "secret_value",
        "client_secret",
        "private_key",
        "-----begin",
    ]

    for pattern in forbidden:
        assert pattern not in body_lower, (
            f"Credential pattern '{pattern}' found in proxy response body"
        )

    return ctx


PROXY_NO_CREDENTIAL_IN_RESPONSE_NODE = DagNode(
    name="proxy.no_credential_in_response",
    fn=proxy_no_credential_in_response,
    depends_on=["proxy.via_broker"],
    produces=[],
    consumes=["broker_url", "broker_pem_key_path", "credential_name"],
    critical=False,
    timeout=15.0,
)


# ---------------------------------------------------------------------------
# proxy.invalid_method_rejected
# ---------------------------------------------------------------------------

def proxy_invalid_method_rejected(ctx: dict) -> dict:
    """
    Proxy with invalid HTTP method (e.g., "HACK") → 400.

    Consumes: broker_url, broker_pem_key_path, credential_name, base_url
    """
    broker_url = ctx["broker_url"]
    pem_key_path = ctx["broker_pem_key_path"]
    credential_name = ctx["credential_name"]
    base_url = ctx.get("base_url", "http://localhost:3140")

    proxy_body = json.dumps({
        "method": "HACK",
        "url": f"{base_url}/health",
        "credential": credential_name,
    })

    status, _, body = broker_request(
        broker_url, pem_key_path, "POST", "/proxy", body=proxy_body,
    )

    # The proxy may:
    # - Reject the method itself (400/405)
    # - Forward it to upstream which returns an error (wrapped as 200 with error status_code)
    # - Return a server error (500/502)
    # All are acceptable. If proxy returns 200, check if upstream rejected it.
    if status == 200:
        data = json.loads(body)
        result = data.get("data", data)
        upstream_status = result.get("status_code", 0)
        assert upstream_status in (400, 405, 501), (
            f"Upstream should reject 'HACK' method, got status_code={upstream_status}"
        )
    else:
        assert status in (400, 405, 500, 502), (
            f"Invalid HTTP method 'HACK' returned unexpected {status}: {body}"
        )

    return ctx


PROXY_INVALID_METHOD_NODE = DagNode(
    name="proxy.invalid_method_rejected",
    fn=proxy_invalid_method_rejected,
    depends_on=["proxy.via_broker"],
    produces=[],
    consumes=["broker_url", "broker_pem_key_path", "credential_name"],
    critical=False,
    timeout=15.0,
)


def get_nodes():
    """Return all proxy scenario DAG nodes."""
    return [
        PROXY_CONSECUTIVE_REUSE_NODE,
        PROXY_NO_CREDENTIAL_IN_RESPONSE_NODE,
        PROXY_INVALID_METHOD_NODE,
    ]
