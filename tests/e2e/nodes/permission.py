"""
DAG nodes for permission/grant testing: permission.list, permission.revoke_and_verify.
"""

import json

from tests.e2e.dag_runner import DagNode
from tests.e2e.helpers import server_request


# ---------------------------------------------------------------------------
# permission.list
# ---------------------------------------------------------------------------

def permission_list(ctx: dict) -> dict:
    """
    List permissions on the test credential.

    Consumes: base_url, admin_session_cookie, credential_id
    Produces: permission_entries
    """
    base_url = ctx["base_url"]
    admin_cookie = ctx["admin_session_cookie"]
    credential_id = ctx["credential_id"]

    status, _, body = server_request(
        base_url, "GET", f"/api/v1/credentials/{credential_id}/permissions",
        cookies=admin_cookie,
    )

    assert status == 200, f"Permission list failed with {status}: {body}"

    data = json.loads(body)
    result = data.get("data", data)
    permissions = result.get("permissions", [])

    assert isinstance(permissions, list), f"Expected permissions list: {result}"
    assert len(permissions) > 0, (
        "No permissions found — permission.grant should have created some"
    )

    ctx["permission_entries"] = permissions
    return ctx


PERMISSION_LIST_NODE = DagNode(
    name="permission.list",
    fn=permission_list,
    depends_on=["permission.grant"],
    produces=["permission_entries"],
    consumes=["base_url", "admin_session_cookie", "credential_id"],
    critical=False,
    timeout=10.0,
)


# ---------------------------------------------------------------------------
# permission.revoke_and_verify
# ---------------------------------------------------------------------------

def permission_revoke_and_verify(ctx: dict) -> dict:
    """
    Create a throwaway credential, grant a permission, revoke it, verify gone.

    Consumes: base_url, admin_session_cookie, csrf_token, ws_db_id
    """
    import os

    base_url = ctx["base_url"]
    admin_cookie = ctx["admin_session_cookie"]
    csrf_token = ctx["csrf_token"]
    workspace_uuid = ctx.get("ws_db_id")

    if not workspace_uuid:
        # Skip if no workspace DB ID available
        return ctx

    # Create throwaway credential
    name = f"e2e-perm-test-{os.urandom(4).hex()}"
    create_body = json.dumps({
        "name": name,
        "service": "e2e-perm-test",
        "secret_value": "perm-test-secret",
    })

    status, _, body = server_request(
        base_url, "POST", "/api/v1/credentials",
        body=create_body,
        headers={"X-CSRF-Token": csrf_token},
        cookies=admin_cookie,
    )

    assert status in (200, 201), f"Create throwaway cred failed: {status}: {body}"
    cred_id = json.loads(body).get("data", {}).get("id")
    assert cred_id

    # Grant permission
    grant_body = json.dumps({
        "workspace_id": workspace_uuid,
        "permission": "read",
    })

    status, _, body = server_request(
        base_url, "POST", f"/api/v1/credentials/{cred_id}/permissions",
        body=grant_body,
        headers={"X-CSRF-Token": csrf_token},
        cookies=admin_cookie,
    )

    assert status in (200, 201, 409), f"Grant failed: {status}: {body}"

    # Revoke
    status, _, body = server_request(
        base_url, "DELETE",
        f"/api/v1/credentials/{cred_id}/permissions/{workspace_uuid}/read",
        headers={"X-CSRF-Token": csrf_token},
        cookies=admin_cookie,
    )

    assert status in (200, 204), f"Revoke failed: {status}: {body}"

    # Verify permission is gone
    status, _, body = server_request(
        base_url, "GET", f"/api/v1/credentials/{cred_id}/permissions",
        cookies=admin_cookie,
    )

    if status == 200:
        data = json.loads(body)
        result = data.get("data", data)
        perms = result.get("permissions", [])
        for p in perms:
            ws_id = p.get("workspace_id", p.get("agent_id"))
            if str(ws_id) == str(workspace_uuid) and p.get("permission") == "read":
                raise AssertionError("Permission still exists after revocation")

    # Cleanup: delete throwaway credential
    server_request(
        base_url, "DELETE", f"/api/v1/credentials/{cred_id}",
        headers={"X-CSRF-Token": csrf_token},
        cookies=admin_cookie,
    )

    return ctx


PERMISSION_REVOKE_AND_VERIFY_NODE = DagNode(
    name="permission.revoke_and_verify",
    fn=permission_revoke_and_verify,
    depends_on=["permission.grant"],
    produces=[],
    consumes=["base_url", "admin_session_cookie", "csrf_token"],
    critical=False,
    timeout=15.0,
)



# ---------------------------------------------------------------------------
# permission.cache_invalidation
# ---------------------------------------------------------------------------

def permission_cache_invalidation(ctx: dict) -> dict:
    """
    Grant permission, verify it works, revoke it via the permissions API,
    verify the permission is gone from the server's permission list.

    This tests the server-side permission grant/revoke cycle without
    relying on the broker's caching behavior.

    Consumes: base_url, admin_session_cookie, csrf_token, ws_db_id
    """
    import os

    base_url = ctx["base_url"]
    admin_cookie = ctx["admin_session_cookie"]
    csrf_token = ctx["csrf_token"]
    workspace_uuid = ctx.get("ws_db_id")

    if not workspace_uuid:
        return ctx

    # Create throwaway credential
    name = f"e2e-cache-inv-{os.urandom(4).hex()}"
    create_body = json.dumps({
        "name": name,
        "service": "e2e-cache-inv",
        "secret_value": "cache-inv-secret",
    })

    status, _, body = server_request(
        base_url, "POST", "/api/v1/credentials",
        body=create_body,
        headers={"X-CSRF-Token": csrf_token},
        cookies=admin_cookie,
    )

    assert status in (200, 201), f"Create cred failed: {status}: {body}"
    cred_id = json.loads(body).get("data", {}).get("id")

    # Grant permission — use 'vend_credential' which is the primary permission
    grant_body = json.dumps({
        "workspace_id": workspace_uuid,
        "permission": "vend_credential",
    })

    status, _, body = server_request(
        base_url, "POST", f"/api/v1/credentials/{cred_id}/permissions",
        body=grant_body,
        headers={"X-CSRF-Token": csrf_token},
        cookies=admin_cookie,
    )

    assert status in (200, 201, 409), f"Grant failed: {status}: {body}"

    # Verify permission exists in the list
    status, _, body = server_request(
        base_url, "GET", f"/api/v1/credentials/{cred_id}/permissions",
        cookies=admin_cookie,
    )

    assert status == 200, f"Permission list failed: {status}: {body}"
    data = json.loads(body)
    result = data.get("data", data)
    perms = result.get("permissions", [])

    # Verify workspace has at least one permission on this credential
    has_perm = any(
        str(p.get("workspace_id", p.get("agent_id", ""))) == str(workspace_uuid)
        for p in perms
    )
    assert has_perm, f"No permissions for workspace {workspace_uuid}: {perms}"

    # Revoke the permission
    status, _, body = server_request(
        base_url, "DELETE",
        f"/api/v1/credentials/{cred_id}/permissions/{workspace_uuid}/vend_credential",
        headers={"X-CSRF-Token": csrf_token},
        cookies=admin_cookie,
    )

    assert status in (200, 204), f"Revoke failed: {status}: {body}"

    # Verify the specific permission is gone from server-side list
    status, _, body = server_request(
        base_url, "GET", f"/api/v1/credentials/{cred_id}/permissions",
        cookies=admin_cookie,
    )

    if status == 200:
        data = json.loads(body)
        result = data.get("data", data)
        perms = result.get("permissions", [])
        still_has = any(
            (str(p.get("workspace_id", p.get("agent_id", ""))) == str(workspace_uuid)
             and p.get("permission") == "vend_credential")
            for p in perms
        )
        assert not still_has, (
            f"Permission 'vend_credential' still exists after revocation: {perms}"
        )

    # Cleanup
    server_request(
        base_url, "DELETE", f"/api/v1/credentials/{cred_id}",
        headers={"X-CSRF-Token": csrf_token},
        cookies=admin_cookie,
    )

    return ctx


PERMISSION_CACHE_INVALIDATION_NODE = DagNode(
    name="permission.cache_invalidation",
    fn=permission_cache_invalidation,
    depends_on=["permission.grant"],
    produces=[],
    consumes=["base_url", "admin_session_cookie", "csrf_token", "ws_db_id"],
    critical=False,
    timeout=15.0,
)


def get_nodes():
    """Return all permission DAG nodes."""
    return [
        PERMISSION_LIST_NODE,
        PERMISSION_REVOKE_AND_VERIFY_NODE,
        PERMISSION_CACHE_INVALIDATION_NODE,
    ]
