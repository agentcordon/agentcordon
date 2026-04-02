"""
DAG nodes for negative/error path testing: negative.invalid_credential_id,
negative.duplicate_credential_name, negative.nonexistent_resource.
"""

import json
import os
import uuid

from tests.e2e.dag_runner import DagNode
from tests.e2e.helpers import server_request


# ---------------------------------------------------------------------------
# negative.invalid_credential_id
# ---------------------------------------------------------------------------

def negative_invalid_credential_id(ctx: dict) -> dict:
    """
    Verify requests with a nonexistent credential UUID return 404.

    Consumes: base_url, admin_session_cookie
    """
    base_url = ctx["base_url"]
    admin_cookie = ctx["admin_session_cookie"]

    fake_id = str(uuid.uuid4())

    status, _, body = server_request(
        base_url, "GET", f"/api/v1/credentials/{fake_id}",
        cookies=admin_cookie,
    )

    assert status == 404, (
        f"Expected 404 for nonexistent credential, got {status}: {body}"
    )

    return ctx


NEGATIVE_INVALID_CREDENTIAL_ID_NODE = DagNode(
    name="negative.invalid_credential_id",
    fn=negative_invalid_credential_id,
    depends_on=["setup.login"],
    produces=[],
    consumes=["base_url", "admin_session_cookie"],
    critical=False,
    timeout=10.0,
)


# ---------------------------------------------------------------------------
# negative.duplicate_credential_name
# ---------------------------------------------------------------------------

def negative_duplicate_credential_name(ctx: dict) -> dict:
    """
    Verify creating a credential with a duplicate name fails.

    Consumes: base_url, admin_session_cookie, csrf_token, credential_name
    """
    base_url = ctx["base_url"]
    admin_cookie = ctx["admin_session_cookie"]
    csrf_token = ctx["csrf_token"]
    existing_name = ctx["credential_name"]

    create_body = json.dumps({
        "name": existing_name,
        "service": "duplicate-test",
        "secret_value": "dup-secret",
    })

    status, _, body = server_request(
        base_url, "POST", "/api/v1/credentials",
        body=create_body,
        headers={"X-CSRF-Token": csrf_token},
        cookies=admin_cookie,
    )

    assert status in (400, 409, 422), (
        f"Expected 400/409/422 for duplicate name, got {status}: {body}"
    )

    return ctx


NEGATIVE_DUPLICATE_CREDENTIAL_NAME_NODE = DagNode(
    name="negative.duplicate_credential_name",
    fn=negative_duplicate_credential_name,
    depends_on=["credential.create"],
    produces=[],
    consumes=["base_url", "admin_session_cookie", "csrf_token", "credential_name"],
    critical=False,
    timeout=10.0,
)


# ---------------------------------------------------------------------------
# negative.nonexistent_resource
# ---------------------------------------------------------------------------

def negative_nonexistent_resource(ctx: dict) -> dict:
    """
    Verify 404s for various nonexistent resources.

    Consumes: base_url, admin_session_cookie
    """
    base_url = ctx["base_url"]
    admin_cookie = ctx["admin_session_cookie"]

    fake_id = str(uuid.uuid4())

    endpoints = [
        ("GET", f"/api/v1/workspaces/{fake_id}"),
        ("GET", f"/api/v1/policies/{fake_id}"),
        ("GET", f"/api/v1/users/{fake_id}"),
    ]

    for method, path in endpoints:
        status, _, body = server_request(
            base_url, method, path,
            cookies=admin_cookie,
        )

        assert status in (404, 403), (
            f"Expected 404/403 for {method} {path}, got {status}"
        )

    return ctx


NEGATIVE_NONEXISTENT_RESOURCE_NODE = DagNode(
    name="negative.nonexistent_resource",
    fn=negative_nonexistent_resource,
    depends_on=["setup.login"],
    produces=[],
    consumes=["base_url", "admin_session_cookie"],
    critical=False,
    timeout=10.0,
)


def get_nodes():
    """Return all negative test DAG nodes."""
    return [
        NEGATIVE_INVALID_CREDENTIAL_ID_NODE,
        NEGATIVE_DUPLICATE_CREDENTIAL_NAME_NODE,
        NEGATIVE_NONEXISTENT_RESOURCE_NODE,
    ]
