"""
DAG nodes for security testing: security.no_auth_rejected,
security.csrf_required, security.expired_session.
"""

import json
import urllib.request
import urllib.error

from tests.e2e.dag_runner import DagNode
from tests.e2e.helpers import server_request


# ---------------------------------------------------------------------------
# security.no_auth_rejected
# ---------------------------------------------------------------------------

def security_no_auth_rejected(ctx: dict) -> dict:
    """
    Verify that unauthenticated requests to protected endpoints return 401.

    Consumes: base_url
    """
    base_url = ctx["base_url"]

    protected_endpoints = [
        ("GET", "/api/v1/credentials"),
        ("GET", "/api/v1/workspaces"),
        ("GET", "/api/v1/policies"),
        ("GET", "/api/v1/users"),
        ("GET", "/api/v1/audit"),
        ("GET", "/api/v1/stats"),
    ]

    for method, path in protected_endpoints:
        status, _, body = server_request(base_url, method, path)
        assert status == 401, (
            f"Expected 401 for unauthenticated {method} {path}, got {status}"
        )

    return ctx


SECURITY_NO_AUTH_NODE = DagNode(
    name="security.no_auth_rejected",
    fn=security_no_auth_rejected,
    depends_on=["setup.login"],
    produces=[],
    consumes=["base_url"],
    critical=False,
    timeout=10.0,
)


# ---------------------------------------------------------------------------
# security.csrf_required
# ---------------------------------------------------------------------------

def security_csrf_required(ctx: dict) -> dict:
    """
    Verify that state-changing requests without CSRF token are rejected.

    Consumes: base_url, admin_session_cookie
    """
    base_url = ctx["base_url"]
    admin_cookie = ctx["admin_session_cookie"]

    # POST without CSRF token should be rejected
    create_body = json.dumps({
        "name": "csrf-test",
        "service": "csrf-test",
        "secret_value": "csrf-test",
    })

    status, _, body = server_request(
        base_url, "POST", "/api/v1/credentials",
        body=create_body,
        cookies=admin_cookie,
        # Deliberately omit X-CSRF-Token
    )

    assert status in (401, 403), (
        f"Expected 401/403 for missing CSRF, got {status}: {body}"
    )

    return ctx


SECURITY_CSRF_REQUIRED_NODE = DagNode(
    name="security.csrf_required",
    fn=security_csrf_required,
    depends_on=["setup.login"],
    produces=[],
    consumes=["base_url", "admin_session_cookie"],
    critical=False,
    timeout=10.0,
)


# ---------------------------------------------------------------------------
# security.expired_session
# ---------------------------------------------------------------------------

def security_expired_session(ctx: dict) -> dict:
    """
    Verify that a garbage session cookie returns 401.

    Consumes: base_url
    """
    base_url = ctx["base_url"]

    status, _, body = server_request(
        base_url, "GET", "/api/v1/credentials",
        cookies="agtcrdn_session=invalid-garbage-token-12345",
    )

    assert status == 401, (
        f"Expected 401 for invalid session, got {status}: {body}"
    )

    return ctx


SECURITY_EXPIRED_SESSION_NODE = DagNode(
    name="security.expired_session",
    fn=security_expired_session,
    depends_on=["setup.login"],
    produces=[],
    consumes=["base_url"],
    critical=False,
    timeout=10.0,
)


def get_nodes():
    """Return all security DAG nodes."""
    return [
        SECURITY_NO_AUTH_NODE,
        SECURITY_CSRF_REQUIRED_NODE,
        SECURITY_EXPIRED_SESSION_NODE,
    ]
