"""
DAG node for verifying old auth endpoints are removed: removal.old_endpoints_gone.
"""

import json
import urllib.request
import urllib.error

from tests.e2e.dag_runner import DagNode
from tests.e2e.helpers import server_request


# ---------------------------------------------------------------------------
# removal.old_endpoints_gone
# ---------------------------------------------------------------------------

def removal_old_endpoints_gone(ctx: dict) -> dict:
    """
    Verify all deleted challenge-response and identity JWT endpoints return 404.

    Tests:
      - POST /api/v1/workspaces/identify → 404
      - POST /api/v1/workspaces/verify → 404
      - POST /api/v1/agents/identify → 404
      - POST /api/v1/agents/verify → 404
      - GET /api/v1/credentials with forged old-style workspace JWT → 401

    Consumes: base_url
    Produces: (none — validation only)
    """
    base_url = ctx["base_url"]

    # Verify removed endpoints return 404
    removed_endpoints = [
        ("POST", "/api/v1/workspaces/identify"),
        ("POST", "/api/v1/workspaces/verify"),
        ("POST", "/api/v1/agents/identify"),
        ("POST", "/api/v1/agents/verify"),
    ]

    for method, path in removed_endpoints:
        status, _, body = server_request(
            base_url, method, path,
            body=json.dumps({"dummy": "payload"}),
        )
        assert status in (404, 405), (
            f"Expected 404/405 for removed endpoint {method} {path}, "
            f"got {status}: {body}"
        )

    # Verify that a forged old-style workspace identity JWT is rejected
    # Craft a fake JWT (header.payload.signature with dummy data)
    import base64

    fake_header = base64.urlsafe_b64encode(
        json.dumps({"alg": "EdDSA", "typ": "JWT"}).encode()
    ).rstrip(b"=").decode()
    fake_payload = base64.urlsafe_b64encode(
        json.dumps({
            "sub": "workspace:fake-id",
            "aud": "agentcordon:workspace",  # Old audience format
            "iss": "agentcordon",
            "exp": 9999999999,
            "iat": 1700000000,
        }).encode()
    ).rstrip(b"=").decode()
    fake_sig = base64.urlsafe_b64encode(b"\x00" * 64).rstrip(b"=").decode()
    forged_jwt = f"{fake_header}.{fake_payload}.{fake_sig}"

    status, _, body = server_request(
        base_url, "GET", "/api/v1/credentials",
        headers={"Authorization": f"Bearer {forged_jwt}"},
    )
    assert status == 401, (
        f"Expected 401 for forged old workspace JWT on /api/v1/credentials, "
        f"got {status}: {body}"
    )

    return ctx


REMOVAL_OLD_ENDPOINTS_GONE_NODE = DagNode(
    name="removal.old_endpoints_gone",
    fn=removal_old_endpoints_gone,
    depends_on=["setup.login"],
    produces=[],
    consumes=["base_url"],
    critical=True,
    timeout=10.0,
)


def get_nodes():
    """Return all removal verification DAG nodes."""
    return [REMOVAL_OLD_ENDPOINTS_GONE_NODE]
