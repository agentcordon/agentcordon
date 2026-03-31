"""
DAG nodes for OAuth/broker security validation:
  - security.broker_unsigned_rejected
  - security.cli_no_credential_material
  - security.oauth_token_revocation
"""

import json
import urllib.request
import urllib.error

from tests.e2e.dag_runner import DagNode
from tests.e2e.helpers import broker_request, server_request


# ---------------------------------------------------------------------------
# security.broker_unsigned_rejected
# ---------------------------------------------------------------------------

def security_broker_unsigned_rejected(ctx: dict) -> dict:
    """
    Verify that an unsigned request to the broker is rejected with 401.

    Consumes: broker_url
    Produces: (none — validation only)
    """
    broker_url = ctx["broker_url"]

    # Send request WITHOUT Ed25519 signature headers
    req = urllib.request.Request(
        f"{broker_url}/credentials",
        method="GET",
    )

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            raise AssertionError(
                f"Expected 401 for unsigned request, got {resp.status}"
            )
    except urllib.error.HTTPError as e:
        assert e.code == 401, (
            f"Expected 401 for unsigned request, got {e.code}: "
            f"{e.read().decode() if e.fp else ''}"
        )

    # Also test with garbage signature
    bad_headers = {
        "X-AC-PublicKey": "00" * 32,
        "X-AC-Timestamp": "9999999999",
        "X-AC-Signature": "ff" * 64,
    }
    req2 = urllib.request.Request(
        f"{broker_url}/credentials",
        headers=bad_headers,
        method="GET",
    )

    try:
        with urllib.request.urlopen(req2, timeout=10) as resp:
            raise AssertionError(
                f"Expected 401 for bad signature, got {resp.status}"
            )
    except urllib.error.HTTPError as e:
        assert e.code == 401, (
            f"Expected 401 for bad signature, got {e.code}"
        )

    return ctx


SECURITY_BROKER_UNSIGNED_NODE = DagNode(
    name="security.broker_unsigned_rejected",
    fn=security_broker_unsigned_rejected,
    depends_on=["broker.start"],
    produces=[],
    consumes=["broker_url"],
    critical=False,
    timeout=10.0,
)


# ---------------------------------------------------------------------------
# security.cli_no_credential_material
# ---------------------------------------------------------------------------

def security_cli_no_credential_material(ctx: dict) -> dict:
    """
    After broker proxy completes, verify no credential material appears
    in CLI-accessible outputs.

    Inspects the proxy response returned to the "CLI" (our test harness)
    and verifies no secret values, OAuth tokens, or decrypted ECIES content
    leaked through.

    Consumes: broker_url, broker_pem_key_path, broker_proxy_response
    Produces: (none — validation only)
    """
    proxy_response = ctx.get("broker_proxy_response", {})
    proxy_body_str = json.dumps(proxy_response)

    # Patterns that should NEVER appear in CLI-side output
    forbidden_patterns = [
        "access_token",
        "refresh_token",
        "client_secret",
        "private_key",
        "-----BEGIN",
        "ECIES",
        "decrypted",
    ]

    for pattern in forbidden_patterns:
        assert pattern.lower() not in proxy_body_str.lower(), (
            f"Credential material pattern '{pattern}' found in proxy response "
            f"returned to CLI: {proxy_body_str[:200]}..."
        )

    # The proxy response should only contain upstream response fields
    allowed_top_keys = {"status_code", "headers", "body"}
    actual_keys = set(proxy_response.keys())
    unexpected = actual_keys - allowed_top_keys
    # Allow extra metadata keys but flag credential-looking ones
    for key in unexpected:
        assert "token" not in key.lower(), (
            f"Suspicious key '{key}' in proxy response (may contain token data)"
        )
        assert "secret" not in key.lower(), (
            f"Suspicious key '{key}' in proxy response (may contain secret data)"
        )
        assert "credential" not in key.lower() or key == "credential_name", (
            f"Suspicious key '{key}' in proxy response (may contain credential data)"
        )

    return ctx


SECURITY_CLI_NO_CREDENTIAL_NODE = DagNode(
    name="security.cli_no_credential_material",
    fn=security_cli_no_credential_material,
    depends_on=["proxy.via_broker"],
    produces=[],
    consumes=["broker_url", "broker_pem_key_path"],
    critical=True,
    timeout=20.0,
)


# ---------------------------------------------------------------------------
# security.oauth_token_revocation
# ---------------------------------------------------------------------------

def security_oauth_token_revocation(ctx: dict) -> dict:
    """
    Verify that revoking OAuth tokens causes subsequent broker requests to fail.

    Admin revokes workspace's OAuth tokens via server API. Next request
    through broker should return 401 from the server. Broker surfaces the
    error to the CLI.

    Consumes: oauth_client_id, admin_session_cookie, broker_url, broker_pem_key_path, base_url
    Produces: (none — validation only)
    """
    oauth_client_id = ctx["oauth_client_id"]
    admin_cookie = ctx.get("admin_session_cookie", "")
    broker_url = ctx["broker_url"]
    pem_key_path = ctx["broker_pem_key_path"]
    base_url = ctx["base_url"]

    # Step 1: Revoke OAuth tokens via server admin API
    revoke_body = json.dumps({"client_id": oauth_client_id})
    status, _, body = server_request(
        base_url, "POST", "/api/v1/oauth/revoke",
        body=revoke_body,
        cookies=admin_cookie,
    )

    assert status in (200, 204), (
        f"Expected 200/204 from token revocation, got {status}: {body}"
    )

    # Step 2: Attempt a signed request through broker — should fail
    # The broker's stored OAuth token is now revoked, so the server should
    # reject it when the broker tries to use it.
    status, _, body = broker_request(
        broker_url, pem_key_path, "GET", "/credentials"
    )

    assert status == 401, (
        f"Expected 401 after token revocation, got {status}: {body}"
    )

    return ctx


SECURITY_OAUTH_TOKEN_REVOCATION_NODE = DagNode(
    name="security.oauth_token_revocation",
    fn=security_oauth_token_revocation,
    depends_on=["proxy.via_broker"],
    produces=[],
    consumes=[
        "oauth_client_id", "admin_session_cookie",
        "broker_url", "broker_pem_key_path", "base_url",
    ],
    critical=False,
    timeout=30.0,
)


def get_nodes():
    """Return all OAuth security DAG nodes."""
    return [
        SECURITY_BROKER_UNSIGNED_NODE,
        SECURITY_CLI_NO_CREDENTIAL_NODE,
        SECURITY_OAUTH_TOKEN_REVOCATION_NODE,
    ]
