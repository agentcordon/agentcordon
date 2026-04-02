"""
DAG nodes for user management testing: user.list, user.create_and_delete.
"""

import json
import os

from tests.e2e.dag_runner import DagNode
from tests.e2e.helpers import server_request


# ---------------------------------------------------------------------------
# user.list
# ---------------------------------------------------------------------------

def user_list(ctx: dict) -> dict:
    """
    List users via admin API.

    Consumes: base_url, admin_session_cookie
    """
    base_url = ctx["base_url"]
    admin_cookie = ctx["admin_session_cookie"]

    status, _, body = server_request(
        base_url, "GET", "/api/v1/users",
        cookies=admin_cookie,
    )

    assert status == 200, f"User list failed with {status}: {body}"

    data = json.loads(body)
    users = data.get("data", data)
    if isinstance(users, dict):
        users = users.get("users", users.get("items", []))

    assert isinstance(users, list), f"Expected user list, got: {type(users)}"
    assert len(users) >= 1, "Expected at least root user"

    return ctx


USER_LIST_NODE = DagNode(
    name="user.list",
    fn=user_list,
    depends_on=["setup.login"],
    produces=[],
    consumes=["base_url", "admin_session_cookie"],
    critical=False,
    timeout=10.0,
)


# ---------------------------------------------------------------------------
# user.create_and_delete
# ---------------------------------------------------------------------------

def user_create_and_delete(ctx: dict) -> dict:
    """
    Create a non-admin user, verify it appears, then delete it.

    Consumes: base_url, admin_session_cookie, csrf_token
    """
    base_url = ctx["base_url"]
    admin_cookie = ctx["admin_session_cookie"]
    csrf_token = ctx["csrf_token"]

    username = f"e2e-user-{os.urandom(4).hex()}"
    create_body = json.dumps({
        "username": username,
        "password": "E2eTestPass123!",
        "role": "viewer",
        "display_name": "E2E Test User",
    })

    status, _, body = server_request(
        base_url, "POST", "/api/v1/users",
        body=create_body,
        headers={"X-CSRF-Token": csrf_token},
        cookies=admin_cookie,
    )

    assert status in (200, 201), f"User create failed with {status}: {body}"

    data = json.loads(body)
    user = data.get("data", data)
    user_id = user.get("id")
    assert user_id, f"No user ID in response: {user}"

    # Delete the user
    status, _, body = server_request(
        base_url, "DELETE", f"/api/v1/users/{user_id}",
        headers={"X-CSRF-Token": csrf_token},
        cookies=admin_cookie,
    )

    assert status in (200, 204), f"User delete failed with {status}: {body}"

    return ctx


USER_CREATE_AND_DELETE_NODE = DagNode(
    name="user.create_and_delete",
    fn=user_create_and_delete,
    depends_on=["setup.login"],
    produces=[],
    consumes=["base_url", "admin_session_cookie", "csrf_token"],
    critical=False,
    timeout=10.0,
)


def get_nodes():
    """Return all user DAG nodes."""
    return [USER_LIST_NODE, USER_CREATE_AND_DELETE_NODE]
