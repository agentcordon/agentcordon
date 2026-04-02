"""
DAG nodes for test setup: setup.login, workspace.create, credential.create, permission.grant.

These are prerequisite nodes that establish admin session auth, create a workspace,
store a credential, and grant permissions — everything downstream nodes need.
"""

import json
import os
import urllib.request
import urllib.error

from tests.e2e.dag_runner import DagNode
from tests.e2e.helpers import server_request


# ---------------------------------------------------------------------------
# setup.login
# ---------------------------------------------------------------------------

def setup_login(ctx: dict) -> dict:
    """
    Log in as the root admin user and store session cookie + CSRF token.

    The server must be running and the root user must exist.
    Reads credentials from environment: AGTCRDN_ROOT_USERNAME, AGTCRDN_ROOT_PASSWORD.

    Consumes: base_url
    Produces: admin_session_cookie, csrf_token, admin_user_id
    """
    base_url = ctx["base_url"]

    username = os.environ.get("AGTCRDN_ROOT_USERNAME", "root")
    password = os.environ.get("AGTCRDN_ROOT_PASSWORD", "")

    assert password, (
        "AGTCRDN_ROOT_PASSWORD must be set for E2E tests. "
        "Set it in the environment before running."
    )

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

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            assert resp.status == 200, f"Login failed with {resp.status}"
            body = json.loads(resp.read())

            # Extract ALL cookies from Set-Cookie headers
            # The CSRF middleware uses double-submit cookie pattern:
            # both agtcrdn_csrf cookie AND X-CSRF-Token header must be present.
            cookies = resp.headers.get_all("Set-Cookie") or []
            all_cookie_parts = []
            csrf_cookie_value = ""
            has_session = False
            for cookie in cookies:
                kv = cookie.split(";")[0]
                all_cookie_parts.append(kv)
                if kv.startswith("agtcrdn_session="):
                    has_session = True
                if kv.startswith("agtcrdn_csrf="):
                    csrf_cookie_value = kv.split("=", 1)[1]

            assert has_session, (
                f"No agtcrdn_session cookie in login response. "
                f"Set-Cookie headers: {cookies}"
            )

            # Session cookie string includes ALL cookies (session + CSRF)
            combined_cookies = "; ".join(all_cookie_parts)

            # CSRF token: prefer cookie value, fall back to response body
            data = body.get("data", body)
            csrf_token = csrf_cookie_value or data.get("csrf_token", "")
            assert csrf_token, "No csrf_token in login response or cookies"

            # Extract user ID
            user_info = data.get("user", {})
            admin_user_id = user_info.get("id", "")

            ctx["admin_session_cookie"] = combined_cookies
            ctx["csrf_token"] = csrf_token
            ctx["admin_user_id"] = admin_user_id

    except urllib.error.HTTPError as e:
        resp_text = e.read().decode("utf-8") if e.fp else ""
        raise AssertionError(f"Login failed with {e.code}: {resp_text}")

    return ctx


SETUP_LOGIN_NODE = DagNode(
    name="setup.login",
    fn=setup_login,
    depends_on=[],
    produces=["admin_session_cookie", "csrf_token", "admin_user_id"],
    consumes=["base_url"],
    critical=True,
    timeout=10.0,
)


# ---------------------------------------------------------------------------
# workspace.create
# ---------------------------------------------------------------------------

def workspace_create(ctx: dict) -> dict:
    """
    Establish workspace identity in the context for downstream nodes.

    The actual workspace DB record is created during the OAuth consent flow
    (workspace.oauth_register). This node sets up the workspace name and
    a placeholder ID in context.

    Consumes: base_url, admin_session_cookie
    Produces: ws_workspace_id, ws_workspace_name
    """
    import uuid

    workspace_name = ctx.get("ws_workspace_name", "e2e-test-workspace")
    workspace_id = ctx.get("ws_workspace_id", str(uuid.uuid4()))

    ctx["ws_workspace_id"] = workspace_id
    ctx["ws_workspace_name"] = workspace_name

    return ctx


WORKSPACE_CREATE_NODE = DagNode(
    name="workspace.create",
    fn=workspace_create,
    depends_on=["setup.login"],
    produces=["ws_workspace_id", "ws_workspace_name"],
    consumes=["base_url", "admin_session_cookie"],
    critical=True,
    timeout=5.0,
)


# ---------------------------------------------------------------------------
# credential.create
# ---------------------------------------------------------------------------

def credential_create(ctx: dict) -> dict:
    """
    Create a test credential via the admin API.

    Consumes: base_url, admin_session_cookie, csrf_token
    Produces: credential_id, credential_name
    """
    base_url = ctx["base_url"]
    admin_cookie = ctx["admin_session_cookie"]
    csrf_token = ctx["csrf_token"]

    credential_name = f"e2e-test-cred-{os.urandom(4).hex()}"
    create_body = json.dumps({
        "name": credential_name,
        "service": "e2e-mock-api",
        "secret_value": "e2e-test-secret-value-12345",
        "scopes": ["read", "write"],
        "description": "E2E test credential for proxy and discovery tests",
        "tags": ["e2e", "test"],
    })

    status, resp_headers, body = server_request(
        base_url, "POST", "/api/v1/credentials",
        body=create_body,
        headers={"X-CSRF-Token": csrf_token},
        cookies=admin_cookie,
    )

    assert status in (200, 201), (
        f"Credential creation failed with {status}: {body}"
    )

    data = json.loads(body)
    cred = data.get("data", data)
    credential_id = cred.get("id", "")
    assert credential_id, f"No credential ID in response: {cred}"

    # Use the name from the response in case it was normalized
    ctx["credential_id"] = credential_id
    ctx["credential_name"] = cred.get("name", credential_name)

    return ctx


CREDENTIAL_CREATE_NODE = DagNode(
    name="credential.create",
    fn=credential_create,
    depends_on=["setup.login"],
    produces=["credential_id", "credential_name"],
    consumes=["base_url", "admin_session_cookie", "csrf_token"],
    critical=True,
    timeout=10.0,
)


# ---------------------------------------------------------------------------
# permission.grant
# ---------------------------------------------------------------------------

def permission_grant(ctx: dict) -> dict:
    """
    Grant the E2E workspace permission to vend/access the test credential.

    Must run after workspace.oauth_register (workspace exists in DB)
    and credential.create (credential exists).

    Consumes: base_url, admin_session_cookie, csrf_token, credential_id
    Produces: permission_granted
    """
    base_url = ctx["base_url"]
    admin_cookie = ctx["admin_session_cookie"]
    csrf_token = ctx["csrf_token"]
    credential_id = ctx["credential_id"]

    # We need the workspace UUID from the DB. After oauth_register, the workspace
    # is created. List workspaces to find it.
    status, _, body = server_request(
        base_url, "GET", "/api/v1/workspaces",
        cookies=admin_cookie,
    )

    assert status == 200, f"Failed to list workspaces: {status}: {body}"

    data = json.loads(body)
    workspaces = data.get("data", data)
    if isinstance(workspaces, dict):
        workspaces = workspaces.get("workspaces", [])

    # Find the E2E workspace — use the LAST match (most recently created,
    # which is the one from OAuth consent, not the placeholder from workspace.create)
    ws_name = ctx.get("ws_workspace_name", "e2e-test-workspace")
    target_ws = None
    for ws in workspaces:
        if ws.get("name") == ws_name:
            target_ws = ws  # keep overwriting to get the last match

    assert target_ws, (
        f"Workspace '{ws_name}' not found in workspace list. "
        f"Available: {[w.get('name') for w in workspaces]}"
    )

    workspace_uuid = target_ws.get("id")
    assert workspace_uuid, f"Workspace has no ID: {target_ws}"
    ctx["ws_db_id"] = workspace_uuid

    # Grant vend_credential and access permissions
    for perm in ["vend_credential", "access", "read", "list"]:
        grant_body = json.dumps({
            "workspace_id": workspace_uuid,
            "permission": perm,
        })

        status, _, body = server_request(
            base_url, "POST", f"/api/v1/credentials/{credential_id}/permissions",
            body=grant_body,
            headers={"X-CSRF-Token": csrf_token},
            cookies=admin_cookie,
        )

        assert status in (200, 201, 409), (
            f"Permission grant '{perm}' failed with {status}: {body}"
        )

    ctx["permission_granted"] = True
    return ctx


PERMISSION_GRANT_NODE = DagNode(
    name="permission.grant",
    fn=permission_grant,
    depends_on=["workspace.oauth_register", "credential.create"],
    produces=["permission_granted"],
    consumes=[
        "base_url", "admin_session_cookie", "csrf_token", "credential_id",
    ],
    critical=True,
    timeout=15.0,
)


def get_nodes():
    """Return all setup DAG nodes."""
    return [
        SETUP_LOGIN_NODE,
        WORKSPACE_CREATE_NODE,
        CREDENTIAL_CREATE_NODE,
        PERMISSION_GRANT_NODE,
    ]
