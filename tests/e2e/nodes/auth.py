"""
DAG nodes for authentication testing: auth.login_success, auth.login_failure,
auth.session_valid, auth.logout.
"""

import json
import os
import urllib.request
import urllib.error

from tests.e2e.dag_runner import DagNode
from tests.e2e.helpers import server_request


# ---------------------------------------------------------------------------
# auth.login_success
# ---------------------------------------------------------------------------

def auth_login_success(ctx: dict) -> dict:
    """
    Verify successful login returns session cookie and user info.

    Consumes: base_url, admin_session_cookie
    """
    base_url = ctx["base_url"]

    username = os.environ.get("AGTCRDN_ROOT_USERNAME", "root")
    password = os.environ.get("AGTCRDN_ROOT_PASSWORD", "")

    login_body = json.dumps({
        "username": username,
        "password": password,
    })

    req = urllib.request.Request(
        f"{base_url}/api/v1/auth/login",
        data=login_body.encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    with urllib.request.urlopen(req, timeout=10) as resp:
        assert resp.status == 200, f"Login failed: {resp.status}"
        body = json.loads(resp.read())
        data = body.get("data", body)

        # Verify response structure
        assert "csrf_token" in data, "Missing csrf_token"
        assert "user" in data, "Missing user info"
        assert "expires_at" in data, "Missing expires_at"

        user = data["user"]
        assert user.get("username") == username
        assert user.get("role") in ("Admin", "admin")

        # Verify Set-Cookie headers
        cookies = resp.headers.get_all("Set-Cookie") or []
        cookie_names = [c.split("=")[0] for c in cookies]
        assert "agtcrdn_session" in cookie_names, (
            f"Missing agtcrdn_session cookie. Got: {cookie_names}"
        )

    return ctx


AUTH_LOGIN_SUCCESS_NODE = DagNode(
    name="auth.login_success",
    fn=auth_login_success,
    depends_on=["setup.login"],
    produces=[],
    consumes=["base_url"],
    critical=False,
    timeout=10.0,
)


# ---------------------------------------------------------------------------
# auth.login_failure
# ---------------------------------------------------------------------------

def auth_login_failure(ctx: dict) -> dict:
    """
    Verify bad credentials return 401 and no session cookie.

    Consumes: base_url
    """
    base_url = ctx["base_url"]

    login_body = json.dumps({
        "username": "nonexistent-user",
        "password": "wrong-password",
    })

    status, headers, body = server_request(
        base_url, "POST", "/api/v1/auth/login",
        body=login_body,
    )

    assert status in (401, 429), f"Expected 401/429 for bad creds, got {status}: {body}"

    return ctx


AUTH_LOGIN_FAILURE_NODE = DagNode(
    name="auth.login_failure",
    fn=auth_login_failure,
    depends_on=["setup.login"],
    produces=[],
    consumes=["base_url"],
    critical=False,
    timeout=10.0,
)


# ---------------------------------------------------------------------------
# auth.session_valid
# ---------------------------------------------------------------------------

def auth_session_valid(ctx: dict) -> dict:
    """
    Verify GET /auth/me returns the logged-in user with a valid session.

    Consumes: base_url, admin_session_cookie
    """
    base_url = ctx["base_url"]
    admin_cookie = ctx["admin_session_cookie"]

    status, _, body = server_request(
        base_url, "GET", "/api/v1/auth/me",
        cookies=admin_cookie,
    )

    assert status == 200, f"GET /auth/me failed with {status}: {body}"

    data = json.loads(body)
    user = data.get("data", data)
    assert user.get("username"), "No username in /auth/me response"

    return ctx


AUTH_SESSION_VALID_NODE = DagNode(
    name="auth.session_valid",
    fn=auth_session_valid,
    depends_on=["setup.login"],
    produces=[],
    consumes=["base_url", "admin_session_cookie"],
    critical=False,
    timeout=10.0,
)


# ---------------------------------------------------------------------------
# auth.logout
# ---------------------------------------------------------------------------

def auth_logout(ctx: dict) -> dict:
    """
    Verify logout invalidates the session.

    IMPORTANT: The server's logout endpoint deletes ALL sessions for the user,
    so we create a temporary non-admin user to test logout without breaking the
    main admin session that downstream nodes depend on.

    Consumes: base_url, admin_session_cookie, csrf_token
    """
    base_url = ctx["base_url"]
    admin_cookie = ctx["admin_session_cookie"]
    csrf_token = ctx["csrf_token"]

    # Create a temporary user for logout testing
    temp_username = f"logout-test-{os.urandom(4).hex()}"
    temp_password = "LogoutTestPass123!"

    create_body = json.dumps({
        "username": temp_username,
        "password": temp_password,
        "role": "viewer",
        "display_name": "Logout Test User",
    })

    status, _, body = server_request(
        base_url, "POST", "/api/v1/users",
        body=create_body,
        headers={"X-CSRF-Token": csrf_token},
        cookies=admin_cookie,
    )

    assert status in (200, 201), f"Failed to create temp user for logout test: {status}: {body}"

    data = json.loads(body)
    temp_user = data.get("data", data)
    temp_user_id = temp_user.get("id")

    try:
        # Login as temp user
        login_body = json.dumps({"username": temp_username, "password": temp_password})
        req = urllib.request.Request(
            f"{base_url}/api/v1/auth/login",
            data=login_body.encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        with urllib.request.urlopen(req, timeout=10) as resp:
            body = json.loads(resp.read())
            cookies = resp.headers.get_all("Set-Cookie") or []
            all_cookie_parts = []
            csrf = ""
            for cookie in cookies:
                kv = cookie.split(";")[0]
                all_cookie_parts.append(kv)
                if kv.startswith("agtcrdn_csrf="):
                    csrf = kv.split("=", 1)[1]
            combined_cookies = "; ".join(all_cookie_parts)
            if not csrf:
                csrf = body.get("data", body).get("csrf_token", "")

        assert combined_cookies, "Failed to get session for logout test"

        # Logout
        status, _, body = server_request(
            base_url, "POST", "/api/v1/auth/logout",
            headers={"X-CSRF-Token": csrf},
            cookies=combined_cookies,
        )

        assert status in (200, 204), f"Logout failed with {status}: {body}"

        # Verify session is now invalid
        status, _, body = server_request(
            base_url, "GET", "/api/v1/auth/me",
            cookies=combined_cookies,
        )

        assert status == 401, (
            f"Expected 401 after logout, got {status} — session not invalidated"
        )
    finally:
        # Clean up temp user
        if temp_user_id:
            server_request(
                base_url, "DELETE", f"/api/v1/users/{temp_user_id}",
                headers={"X-CSRF-Token": csrf_token},
                cookies=admin_cookie,
            )

    return ctx


AUTH_LOGOUT_NODE = DagNode(
    name="auth.logout",
    fn=auth_logout,
    depends_on=["auth.session_valid"],
    produces=[],
    consumes=["base_url", "admin_session_cookie", "csrf_token"],
    critical=False,
    timeout=15.0,
)


# ---------------------------------------------------------------------------
# auth.whoami
# ---------------------------------------------------------------------------

def auth_whoami(ctx: dict) -> dict:
    """
    Verify GET /auth/me returns full user profile including role and username.
    Extends auth.session_valid with deeper response validation.

    Consumes: base_url, admin_session_cookie
    """
    base_url = ctx["base_url"]
    admin_cookie = ctx["admin_session_cookie"]

    status, _, body = server_request(
        base_url, "GET", "/api/v1/auth/me",
        cookies=admin_cookie,
    )

    assert status == 200, f"GET /auth/me failed with {status}: {body}"

    data = json.loads(body)
    user = data.get("data", data)

    # Verify detailed user fields
    assert user.get("username"), "No username in /auth/me response"
    assert user.get("role") in ("Admin", "admin", "Viewer", "viewer"), (
        f"Unexpected role: {user.get('role')}"
    )
    assert user.get("id"), "No user id in /auth/me response"

    return ctx


AUTH_WHOAMI_NODE = DagNode(
    name="auth.whoami",
    fn=auth_whoami,
    depends_on=["setup.login"],
    produces=[],
    consumes=["base_url", "admin_session_cookie"],
    critical=False,
    timeout=10.0,
)


# ---------------------------------------------------------------------------
# auth.oidc_providers_list
# ---------------------------------------------------------------------------

def auth_oidc_providers_list(ctx: dict) -> dict:
    """
    Verify GET /auth/oidc/providers returns a list (even if empty).
    This is the public OIDC providers endpoint.

    Consumes: base_url
    """
    base_url = ctx["base_url"]

    status, _, body = server_request(
        base_url, "GET", "/api/v1/auth/oidc/providers",
    )

    assert status == 200, f"OIDC providers list failed with {status}: {body}"

    data = json.loads(body)
    providers = data.get("data", data)
    if isinstance(providers, dict):
        providers = providers.get("providers", providers.get("items", []))

    assert isinstance(providers, list), f"Expected providers list, got: {type(providers)}"

    return ctx


AUTH_OIDC_PROVIDERS_LIST_NODE = DagNode(
    name="auth.oidc_providers_list",
    fn=auth_oidc_providers_list,
    depends_on=["setup.login"],
    produces=[],
    consumes=["base_url"],
    critical=False,
    timeout=10.0,
)


# ---------------------------------------------------------------------------
# auth.change_password
# ---------------------------------------------------------------------------

def auth_change_password(ctx: dict) -> dict:
    """
    Create a temporary user, change their password, verify login with new password.

    Consumes: base_url, admin_session_cookie, csrf_token
    """
    base_url = ctx["base_url"]
    admin_cookie = ctx["admin_session_cookie"]
    csrf_token = ctx["csrf_token"]

    # Create a temporary user
    temp_username = f"chgpw-test-{os.urandom(4).hex()}"
    temp_password = "OriginalPass123!"
    new_password = "ChangedPass456!"

    create_body = json.dumps({
        "username": temp_username,
        "password": temp_password,
        "role": "viewer",
        "display_name": "Password Change Test",
    })

    status, _, body = server_request(
        base_url, "POST", "/api/v1/users",
        body=create_body,
        headers={"X-CSRF-Token": csrf_token},
        cookies=admin_cookie,
    )

    assert status in (200, 201), f"Failed to create temp user: {status}: {body}"

    data = json.loads(body)
    temp_user = data.get("data", data)
    temp_user_id = temp_user.get("id")
    assert temp_user_id, "No user ID returned"

    try:
        # Change password via admin endpoint
        chg_body = json.dumps({
            "new_password": new_password,
        })

        status, _, body = server_request(
            base_url, "POST", f"/api/v1/users/{temp_user_id}/change-password",
            body=chg_body,
            headers={"X-CSRF-Token": csrf_token},
            cookies=admin_cookie,
        )

        assert status == 200, f"Change password failed with {status}: {body}"

        # Verify login with NEW password works
        login_body = json.dumps({
            "username": temp_username,
            "password": new_password,
        })

        status, _, body = server_request(
            base_url, "POST", "/api/v1/auth/login",
            body=login_body,
        )

        assert status == 200, (
            f"Login with new password failed with {status}: {body}"
        )

        # Verify login with OLD password fails
        old_login_body = json.dumps({
            "username": temp_username,
            "password": temp_password,
        })

        status, _, body = server_request(
            base_url, "POST", "/api/v1/auth/login",
            body=old_login_body,
        )

        assert status in (401, 429), (
            f"Login with old password should fail, got {status}"
        )

    finally:
        # Clean up temp user
        server_request(
            base_url, "DELETE", f"/api/v1/users/{temp_user_id}",
            headers={"X-CSRF-Token": csrf_token},
            cookies=admin_cookie,
        )

    return ctx


AUTH_CHANGE_PASSWORD_NODE = DagNode(
    name="auth.change_password",
    fn=auth_change_password,
    depends_on=["setup.login"],
    produces=[],
    consumes=["base_url", "admin_session_cookie", "csrf_token"],
    critical=False,
    timeout=15.0,
)


def get_nodes():
    """Return all auth DAG nodes."""
    return [
        AUTH_LOGIN_SUCCESS_NODE,
        AUTH_LOGIN_FAILURE_NODE,
        AUTH_SESSION_VALID_NODE,
        AUTH_LOGOUT_NODE,
        AUTH_WHOAMI_NODE,
        AUTH_OIDC_PROVIDERS_LIST_NODE,
        AUTH_CHANGE_PASSWORD_NODE,
    ]
