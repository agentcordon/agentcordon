"""
DAG nodes for auth edge case scenarios.

Scenarios:
  auth.rate_limiting
  auth.session_cookie_required
  auth.wrong_csrf_rejected
  auth.password_minimum_length
"""

import json
import os

from tests.e2e.dag_runner import DagNode
from tests.e2e.helpers import server_request


# ---------------------------------------------------------------------------
# auth.rate_limiting
# ---------------------------------------------------------------------------

def auth_rate_limiting(ctx: dict) -> dict:
    """
    Rapid failed logins (5+) with the same username → 429 response.

    The server rate-limits per username (default: 5 failures per window).
    Sending 8 failures with the same username should trigger 429.

    Consumes: base_url
    """
    base_url = ctx["base_url"]

    # Use the SAME username for all attempts so the per-username rate
    # limiter accumulates failures and triggers after the threshold.
    target_username = f"ratelimit-user-{os.urandom(4).hex()}"

    got_429 = False
    for i in range(8):
        login_body = json.dumps({
            "username": target_username,
            "password": "wrong-password-attempt",
        })

        status, _, body = server_request(
            base_url, "POST", "/api/v1/auth/login",
            body=login_body,
        )

        if status == 429:
            got_429 = True
            break

        # 401 is expected for bad credentials
        assert status in (401, 429), (
            f"Login attempt #{i+1} returned unexpected {status}: {body}"
        )

    assert got_429, (
        "Expected 429 after repeated failed logins with the same username, "
        "but never received it after 8 attempts"
    )
    return ctx


AUTH_RATE_LIMITING_NODE = DagNode(
    name="auth.rate_limiting",
    fn=auth_rate_limiting,
    depends_on=["setup.login"],
    produces=[],
    consumes=["base_url"],
    critical=False,
    timeout=15.0,
)


# ---------------------------------------------------------------------------
# auth.session_cookie_required
# ---------------------------------------------------------------------------

def auth_session_cookie_required(ctx: dict) -> dict:
    """
    API call without any cookie → 401.

    Consumes: base_url
    """
    base_url = ctx["base_url"]

    # Try accessing protected endpoints with NO cookies at all
    endpoints = [
        ("GET", "/api/v1/credentials"),
        ("GET", "/api/v1/workspaces"),
        ("GET", "/api/v1/auth/me"),
    ]

    for method, path in endpoints:
        status, _, body = server_request(
            base_url, method, path,
            # No cookies!
        )

        assert status == 401, (
            f"Expected 401 for {method} {path} without cookie, got {status}"
        )

    return ctx


AUTH_SESSION_COOKIE_REQUIRED_NODE = DagNode(
    name="auth.session_cookie_required",
    fn=auth_session_cookie_required,
    depends_on=["setup.login"],
    produces=[],
    consumes=["base_url"],
    critical=False,
    timeout=10.0,
)


# ---------------------------------------------------------------------------
# auth.wrong_csrf_rejected
# ---------------------------------------------------------------------------

def auth_wrong_csrf_rejected(ctx: dict) -> dict:
    """
    POST with wrong X-CSRF-Token value → 403.

    Consumes: base_url, admin_session_cookie
    """
    base_url = ctx["base_url"]
    admin_cookie = ctx["admin_session_cookie"]

    create_body = json.dumps({
        "name": f"csrf-wrong-{os.urandom(4).hex()}",
        "service": "csrf-wrong-test",
        "secret_value": "csrf-test-secret",
    })

    status, _, body = server_request(
        base_url, "POST", "/api/v1/credentials",
        body=create_body,
        headers={"X-CSRF-Token": "completely-wrong-csrf-token-value"},
        cookies=admin_cookie,
    )

    assert status in (401, 403), (
        f"Wrong CSRF token should return 401/403, got {status}: {body}"
    )

    return ctx


AUTH_WRONG_CSRF_NODE = DagNode(
    name="auth.wrong_csrf_rejected",
    fn=auth_wrong_csrf_rejected,
    depends_on=["setup.login"],
    produces=[],
    consumes=["base_url", "admin_session_cookie"],
    critical=False,
    timeout=10.0,
)


# ---------------------------------------------------------------------------
# auth.password_minimum_length
# ---------------------------------------------------------------------------

def auth_password_minimum_length(ctx: dict) -> dict:
    """
    Create user with short password (<12 chars) → 400.

    Consumes: base_url, admin_session_cookie, csrf_token
    """
    base_url = ctx["base_url"]
    admin_cookie = ctx["admin_session_cookie"]
    csrf_token = ctx["csrf_token"]

    create_body = json.dumps({
        "username": f"short-pw-{os.urandom(4).hex()}",
        "password": "short",  # Way too short
        "role": "viewer",
        "display_name": "Short Password Test",
    })

    status, _, body = server_request(
        base_url, "POST", "/api/v1/users",
        body=create_body,
        headers={"X-CSRF-Token": csrf_token},
        cookies=admin_cookie,
    )

    # Should be rejected for password policy violation
    assert status in (400, 422), (
        f"Short password should be rejected, got {status}: {body}"
    )

    # If it somehow succeeded, clean up
    if status in (200, 201):
        user_id = json.loads(body).get("data", json.loads(body)).get("id")
        if user_id:
            server_request(
                base_url, "DELETE", f"/api/v1/users/{user_id}",
                headers={"X-CSRF-Token": csrf_token},
                cookies=admin_cookie,
            )

    return ctx


AUTH_PASSWORD_MIN_LENGTH_NODE = DagNode(
    name="auth.password_minimum_length",
    fn=auth_password_minimum_length,
    depends_on=["setup.login"],
    produces=[],
    consumes=["base_url", "admin_session_cookie", "csrf_token"],
    critical=False,
    timeout=10.0,
)


def get_nodes():
    """Return all auth scenario DAG nodes."""
    return [
        AUTH_RATE_LIMITING_NODE,
        AUTH_SESSION_COOKIE_REQUIRED_NODE,
        AUTH_WRONG_CSRF_NODE,
        AUTH_PASSWORD_MIN_LENGTH_NODE,
    ]
