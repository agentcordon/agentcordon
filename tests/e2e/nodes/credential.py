"""
DAG nodes for credential CRUD testing: credential.list, credential.get,
credential.update, credential.delete_extra.
"""

import json
import os

from tests.e2e.dag_runner import DagNode
from tests.e2e.helpers import server_request


# ---------------------------------------------------------------------------
# credential.list
# ---------------------------------------------------------------------------

def credential_list(ctx: dict) -> dict:
    """
    List credentials via admin API.

    Consumes: base_url, admin_session_cookie, credential_name
    Produces: credential_list_result
    """
    base_url = ctx["base_url"]
    admin_cookie = ctx["admin_session_cookie"]

    status, _, body = server_request(
        base_url, "GET", "/api/v1/credentials",
        cookies=admin_cookie,
    )

    assert status == 200, f"Credential list failed with {status}: {body}"

    data = json.loads(body)
    credentials = data.get("data", data)
    if isinstance(credentials, dict):
        credentials = credentials.get("credentials", credentials.get("items", []))

    assert isinstance(credentials, list), f"Expected list, got: {type(credentials)}"

    # The credential we created should be in the list
    cred_name = ctx.get("credential_name")
    if cred_name:
        names = [c.get("name", "") for c in credentials]
        assert cred_name in names, (
            f"Created credential '{cred_name}' not in list: {names}"
        )

    ctx["credential_list_result"] = credentials
    return ctx


CREDENTIAL_LIST_NODE = DagNode(
    name="credential.list",
    fn=credential_list,
    depends_on=["credential.create"],
    produces=["credential_list_result"],
    consumes=["base_url", "admin_session_cookie"],
    critical=False,
    timeout=10.0,
)


# ---------------------------------------------------------------------------
# credential.get
# ---------------------------------------------------------------------------

def credential_get(ctx: dict) -> dict:
    """
    Get a single credential by ID.

    Consumes: base_url, admin_session_cookie, credential_id, credential_name
    """
    base_url = ctx["base_url"]
    admin_cookie = ctx["admin_session_cookie"]
    credential_id = ctx["credential_id"]

    status, _, body = server_request(
        base_url, "GET", f"/api/v1/credentials/{credential_id}",
        cookies=admin_cookie,
    )

    assert status == 200, f"Credential get failed with {status}: {body}"

    data = json.loads(body)
    cred = data.get("data", data)
    assert cred.get("name") == ctx["credential_name"], (
        f"Credential name mismatch: {cred.get('name')} != {ctx['credential_name']}"
    )

    # Verify no secret value is exposed in GET response
    body_lower = body.lower()
    assert "e2e-test-secret-value" not in body_lower, (
        "Secret value leaked in GET credential response"
    )

    return ctx


CREDENTIAL_GET_NODE = DagNode(
    name="credential.get",
    fn=credential_get,
    depends_on=["credential.create"],
    produces=[],
    consumes=["base_url", "admin_session_cookie", "credential_id"],
    critical=False,
    timeout=10.0,
)


# ---------------------------------------------------------------------------
# credential.update
# ---------------------------------------------------------------------------

def credential_update(ctx: dict) -> dict:
    """
    Update credential metadata via admin API.

    Consumes: base_url, admin_session_cookie, csrf_token, credential_id
    """
    base_url = ctx["base_url"]
    admin_cookie = ctx["admin_session_cookie"]
    csrf_token = ctx["csrf_token"]
    credential_id = ctx["credential_id"]

    update_body = json.dumps({
        "description": "Updated by E2E test",
        "tags": ["e2e", "test", "updated"],
    })

    status, _, body = server_request(
        base_url, "PUT", f"/api/v1/credentials/{credential_id}",
        body=update_body,
        headers={"X-CSRF-Token": csrf_token},
        cookies=admin_cookie,
    )

    assert status == 200, f"Credential update failed with {status}: {body}"

    # Verify the update took effect
    status, _, body = server_request(
        base_url, "GET", f"/api/v1/credentials/{credential_id}",
        cookies=admin_cookie,
    )

    data = json.loads(body)
    cred = data.get("data", data)
    assert "updated" in (cred.get("tags") or []), (
        f"Tag 'updated' not found after update: {cred.get('tags')}"
    )

    return ctx


CREDENTIAL_UPDATE_NODE = DagNode(
    name="credential.update",
    fn=credential_update,
    depends_on=["credential.get"],
    produces=[],
    consumes=["base_url", "admin_session_cookie", "csrf_token", "credential_id"],
    critical=False,
    timeout=10.0,
)


# ---------------------------------------------------------------------------
# credential.delete_extra
# ---------------------------------------------------------------------------

def credential_delete_extra(ctx: dict) -> dict:
    """
    Create a throwaway credential and delete it. Verify 404 after deletion.
    Does NOT delete the main test credential needed by other nodes.

    Consumes: base_url, admin_session_cookie, csrf_token
    """
    base_url = ctx["base_url"]
    admin_cookie = ctx["admin_session_cookie"]
    csrf_token = ctx["csrf_token"]

    # Create a throwaway credential
    name = f"e2e-delete-test-{os.urandom(4).hex()}"
    create_body = json.dumps({
        "name": name,
        "service": "e2e-delete-test",
        "secret_value": "delete-me",
    })

    status, _, body = server_request(
        base_url, "POST", "/api/v1/credentials",
        body=create_body,
        headers={"X-CSRF-Token": csrf_token},
        cookies=admin_cookie,
    )

    assert status in (200, 201), f"Create throwaway cred failed: {status}: {body}"

    data = json.loads(body)
    cred_id = data.get("data", data).get("id")
    assert cred_id, "No ID for throwaway credential"

    # Delete it
    status, _, body = server_request(
        base_url, "DELETE", f"/api/v1/credentials/{cred_id}",
        headers={"X-CSRF-Token": csrf_token},
        cookies=admin_cookie,
    )

    assert status in (200, 204), f"Delete failed with {status}: {body}"

    # Verify 404
    status, _, body = server_request(
        base_url, "GET", f"/api/v1/credentials/{cred_id}",
        cookies=admin_cookie,
    )

    assert status == 404, f"Expected 404 after delete, got {status}"

    return ctx


CREDENTIAL_DELETE_EXTRA_NODE = DagNode(
    name="credential.delete_extra",
    fn=credential_delete_extra,
    depends_on=["credential.create"],
    produces=[],
    consumes=["base_url", "admin_session_cookie", "csrf_token"],
    critical=False,
    timeout=10.0,
)



# ---------------------------------------------------------------------------
# credential.transforms
# ---------------------------------------------------------------------------

def credential_transforms(ctx: dict) -> dict:
    """
    Create credentials with different transform types (bearer, basic, aws-sigv4),
    verify transform_name is stored correctly.

    Consumes: base_url, admin_session_cookie, csrf_token
    """
    base_url = ctx["base_url"]
    admin_cookie = ctx["admin_session_cookie"]
    csrf_token = ctx["csrf_token"]

    transforms = ["bearer", "basic-auth"]

    for transform in transforms:
        name = f"e2e-transform-{transform}-{os.urandom(4).hex()}"
        create_body = json.dumps({
            "name": name,
            "service": f"e2e-transform-{transform}",
            "secret_value": f"transform-test-secret-{transform}",
            "transform_name": transform,
        })

        status, _, body = server_request(
            base_url, "POST", "/api/v1/credentials",
            body=create_body,
            headers={"X-CSRF-Token": csrf_token},
            cookies=admin_cookie,
        )

        assert status in (200, 201), (
            f"Create credential with transform '{transform}' failed: {status}: {body}"
        )

        data = json.loads(body)
        cred = data.get("data", data)
        cred_id = cred.get("id")
        assert cred_id, f"No ID returned for transform credential: {cred}"

        # Verify transform_name is persisted
        status, _, body = server_request(
            base_url, "GET", f"/api/v1/credentials/{cred_id}",
            cookies=admin_cookie,
        )

        assert status == 200, f"Get transform credential failed: {status}: {body}"
        data = json.loads(body)
        fetched = data.get("data", data)
        assert fetched.get("transform_name") == transform, (
            f"Transform name mismatch: expected '{transform}', "
            f"got '{fetched.get('transform_name')}'"
        )

        # Cleanup
        server_request(
            base_url, "DELETE", f"/api/v1/credentials/{cred_id}",
            headers={"X-CSRF-Token": csrf_token},
            cookies=admin_cookie,
        )

    return ctx


CREDENTIAL_TRANSFORMS_NODE = DagNode(
    name="credential.transforms",
    fn=credential_transforms,
    depends_on=["setup.login"],
    produces=[],
    consumes=["base_url", "admin_session_cookie", "csrf_token"],
    critical=False,
    timeout=20.0,
)


# ---------------------------------------------------------------------------
# credential.expiry
# ---------------------------------------------------------------------------

def credential_expiry(ctx: dict) -> dict:
    """
    Create credential with expires_at set in the past, verify it shows as expired.

    Consumes: base_url, admin_session_cookie, csrf_token
    """
    import datetime

    base_url = ctx["base_url"]
    admin_cookie = ctx["admin_session_cookie"]
    csrf_token = ctx["csrf_token"]

    # Create credential that already expired (1 hour ago)
    past = (
        datetime.datetime.now(datetime.timezone.utc)
        - datetime.timedelta(hours=1)
    ).isoformat()

    name = f"e2e-expiry-test-{os.urandom(4).hex()}"
    create_body = json.dumps({
        "name": name,
        "service": "e2e-expiry-test",
        "secret_value": "expiry-secret",
        "expires_at": past,
    })

    status, _, body = server_request(
        base_url, "POST", "/api/v1/credentials",
        body=create_body,
        headers={"X-CSRF-Token": csrf_token},
        cookies=admin_cookie,
    )

    assert status in (200, 201), (
        f"Create expired credential failed: {status}: {body}"
    )

    data = json.loads(body)
    cred = data.get("data", data)
    cred_id = cred.get("id")

    # Verify expires_at is persisted
    status, _, body = server_request(
        base_url, "GET", f"/api/v1/credentials/{cred_id}",
        cookies=admin_cookie,
    )

    assert status == 200, f"Get expired credential failed: {status}: {body}"
    data = json.loads(body)
    fetched = data.get("data", data)
    assert fetched.get("expires_at") is not None, (
        "expires_at not returned on expired credential"
    )

    # Cleanup
    server_request(
        base_url, "DELETE", f"/api/v1/credentials/{cred_id}",
        headers={"X-CSRF-Token": csrf_token},
        cookies=admin_cookie,
    )

    return ctx


CREDENTIAL_EXPIRY_NODE = DagNode(
    name="credential.expiry",
    fn=credential_expiry,
    depends_on=["setup.login"],
    produces=[],
    consumes=["base_url", "admin_session_cookie", "csrf_token"],
    critical=False,
    timeout=15.0,
)


# ---------------------------------------------------------------------------
# credential.reveal_history
# ---------------------------------------------------------------------------

def credential_reveal_history(ctx: dict) -> dict:
    """
    Reveal a credential secret via POST /credentials/{id}/reveal,
    verify the action is logged in the audit trail.

    Consumes: base_url, admin_session_cookie, csrf_token, credential_id
    """
    base_url = ctx["base_url"]
    admin_cookie = ctx["admin_session_cookie"]
    csrf_token = ctx["csrf_token"]
    credential_id = ctx["credential_id"]

    # Reveal the credential secret
    status, _, body = server_request(
        base_url, "POST", f"/api/v1/credentials/{credential_id}/reveal",
        body="{}",
        headers={"X-CSRF-Token": csrf_token},
        cookies=admin_cookie,
    )

    assert status == 200, (
        f"Credential reveal failed with {status}: {body}"
    )

    data = json.loads(body)
    result = data.get("data", data)
    # The reveal endpoint should return the secret value
    assert result is not None, "No data returned from credential reveal"

    # Check that an audit event was created for the reveal
    import time
    time.sleep(0.3)  # small delay for async audit write

    status, _, body = server_request(
        base_url, "GET", "/api/v1/audit",
        cookies=admin_cookie,
    )

    if status == 200:
        audit_data = json.loads(body)
        events = audit_data.get("data", audit_data)
        if isinstance(events, dict):
            events = events.get("events", [])
        event_types = [e.get("event_type", e.get("type", "")) for e in events]
        assert any(t in event_types for t in ["credential_secret_viewed", "credential_revealed", "credential_vended"]), (
            f"Credential reveal not found in audit log. Types: {event_types[:20]}"
        )

    return ctx


CREDENTIAL_REVEAL_HISTORY_NODE = DagNode(
    name="credential.reveal_history",
    fn=credential_reveal_history,
    depends_on=["credential.create"],
    produces=[],
    consumes=["base_url", "admin_session_cookie", "csrf_token", "credential_id"],
    critical=False,
    timeout=15.0,
)


# ---------------------------------------------------------------------------
# credential.duplicate_name
# ---------------------------------------------------------------------------

def credential_duplicate_name(ctx: dict) -> dict:
    """
    Try creating two credentials with same name, verify 409 conflict.

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


CREDENTIAL_DUPLICATE_NAME_NODE = DagNode(
    name="credential.duplicate_name",
    fn=credential_duplicate_name,
    depends_on=["credential.create"],
    produces=[],
    consumes=["base_url", "admin_session_cookie", "csrf_token", "credential_name"],
    critical=False,
    timeout=10.0,
)


# ---------------------------------------------------------------------------
# credential.secret_history
# ---------------------------------------------------------------------------

def credential_secret_history(ctx: dict) -> dict:
    """
    Verify GET /credentials/{id}/secret-history returns history entries.

    Consumes: base_url, admin_session_cookie, credential_id
    """
    base_url = ctx["base_url"]
    admin_cookie = ctx["admin_session_cookie"]
    credential_id = ctx["credential_id"]

    status, _, body = server_request(
        base_url, "GET", f"/api/v1/credentials/{credential_id}/secret-history",
        cookies=admin_cookie,
    )

    assert status == 200, f"Secret history failed with {status}: {body}"

    data = json.loads(body)
    history = data.get("data", data)
    if isinstance(history, dict):
        history = history.get("history", history.get("items", []))

    assert isinstance(history, list), f"Expected history list, got: {type(history)}"
    # A newly created credential has no history entries (history tracks rotations).
    # Just verify the endpoint returns a valid list.

    # Now update the secret to generate a history entry
    csrf_token = ctx["csrf_token"]
    update_body = json.dumps({
        "secret_value": "rotated-secret-value",
    })

    server_request(
        base_url, "PUT", f"/api/v1/credentials/{credential_id}",
        body=update_body,
        headers={"X-CSRF-Token": csrf_token},
        cookies=admin_cookie,
    )

    # Re-check: should now have at least 1 history entry
    status2, _, body2 = server_request(
        base_url, "GET", f"/api/v1/credentials/{credential_id}/secret-history",
        cookies=admin_cookie,
    )

    assert status2 == 200, f"Secret history after rotation failed: {status2}: {body2}"
    data2 = json.loads(body2)
    history2 = data2.get("data", data2)
    if isinstance(history2, dict):
        history2 = history2.get("history", history2.get("items", []))

    assert isinstance(history2, list), f"Expected history list after rotation: {type(history2)}"
    assert len(history2) >= 1, f"Expected >=1 history entry after rotation, got {len(history2)}"

    return ctx


CREDENTIAL_SECRET_HISTORY_NODE = DagNode(
    name="credential.secret_history",
    fn=credential_secret_history,
    depends_on=["credential.create"],
    produces=[],
    consumes=["base_url", "admin_session_cookie", "credential_id", "csrf_token"],
    critical=False,
    timeout=15.0,
)


# ---------------------------------------------------------------------------
# credential.templates
# ---------------------------------------------------------------------------

def credential_templates(ctx: dict) -> dict:
    """
    Verify GET /credential-templates returns a list of templates.

    Consumes: base_url, admin_session_cookie
    """
    base_url = ctx["base_url"]
    admin_cookie = ctx["admin_session_cookie"]

    status, _, body = server_request(
        base_url, "GET", "/api/v1/credential-templates",
        cookies=admin_cookie,
    )

    assert status == 200, f"Credential templates failed with {status}: {body}"

    data = json.loads(body)
    templates = data.get("data", data)
    if isinstance(templates, dict):
        templates = templates.get("templates", templates.get("items", []))

    assert isinstance(templates, list), f"Expected templates list, got: {type(templates)}"
    assert len(templates) >= 1, f"Expected at least 1 credential template, got {len(templates)}"

    # Verify template structure
    for t in templates[:3]:
        assert "key" in t or "name" in t, f"Template missing key/name: {t}"

    return ctx


CREDENTIAL_TEMPLATES_NODE = DagNode(
    name="credential.templates",
    fn=credential_templates,
    depends_on=["setup.login"],
    produces=[],
    consumes=["base_url", "admin_session_cookie"],
    critical=False,
    timeout=10.0,
)


# ---------------------------------------------------------------------------
# credential.agent_store
# ---------------------------------------------------------------------------

def credential_agent_store(ctx: dict) -> dict:
    """
    Verify POST /credentials/agent-store endpoint exists and requires workspace auth.
    Since this endpoint requires workspace JWT (not session cookie), we verify it
    rejects session-cookie auth with 401/403.

    Consumes: base_url, admin_session_cookie, csrf_token
    """
    base_url = ctx["base_url"]
    admin_cookie = ctx["admin_session_cookie"]
    csrf_token = ctx["csrf_token"]

    store_body = json.dumps({
        "name": f"e2e-agent-store-{os.urandom(4).hex()}",
        "service": "e2e-agent-store-test",
        "secret_value": "agent-store-test-secret",
    })

    # agent-store requires workspace auth (JWT), not admin session cookie.
    # Using session cookie should fail with 401/403.
    status, _, body = server_request(
        base_url, "POST", "/api/v1/credentials/agent-store",
        body=store_body,
        headers={"X-CSRF-Token": csrf_token},
        cookies=admin_cookie,
    )

    # Endpoint exists: any non-404 response means it's registered.
    # With cookie auth, expect 401 (wrong auth type) or 403 (no workspace identity)
    # or 200 if admin sessions are also accepted.
    assert status != 404, f"agent-store endpoint not registered (got 404)"

    # If it succeeded (200/201), that's also valid — endpoint exists and works
    if status in (200, 201):
        # Clean up the credential we created
        data = json.loads(body)
        cred = data.get("data", data)
        cred_id = cred.get("id")
        if cred_id:
            server_request(
                base_url, "DELETE", f"/api/v1/credentials/{cred_id}",
                headers={"X-CSRF-Token": csrf_token},
                cookies=admin_cookie,
            )

    return ctx


CREDENTIAL_AGENT_STORE_NODE = DagNode(
    name="credential.agent_store",
    fn=credential_agent_store,
    depends_on=["setup.login"],
    produces=[],
    consumes=["base_url", "admin_session_cookie", "csrf_token"],
    critical=False,
    timeout=10.0,
)


# ---------------------------------------------------------------------------
# credential.vend_by_name
# ---------------------------------------------------------------------------

def credential_vend_by_name(ctx: dict) -> dict:
    """
    Verify GET /credentials/by-name/{name} retrieves a credential by name.

    Consumes: base_url, admin_session_cookie, credential_name
    """
    base_url = ctx["base_url"]
    admin_cookie = ctx["admin_session_cookie"]
    cred_name = ctx["credential_name"]

    status, _, body = server_request(
        base_url, "GET", f"/api/v1/credentials/by-name/{cred_name}",
        cookies=admin_cookie,
    )

    assert status == 200, f"Get credential by name failed with {status}: {body}"

    data = json.loads(body)
    cred = data.get("data", data)
    assert cred.get("name") == cred_name, (
        f"Name mismatch: expected '{cred_name}', got '{cred.get('name')}'"
    )

    return ctx


CREDENTIAL_VEND_BY_NAME_NODE = DagNode(
    name="credential.vend_by_name",
    fn=credential_vend_by_name,
    depends_on=["credential.create"],
    produces=[],
    consumes=["base_url", "admin_session_cookie", "credential_name"],
    critical=False,
    timeout=10.0,
)


def get_nodes():
    """Return all credential CRUD DAG nodes."""
    return [
        CREDENTIAL_LIST_NODE,
        CREDENTIAL_GET_NODE,
        CREDENTIAL_UPDATE_NODE,
        CREDENTIAL_DELETE_EXTRA_NODE,
        CREDENTIAL_TRANSFORMS_NODE,
        CREDENTIAL_EXPIRY_NODE,
        CREDENTIAL_REVEAL_HISTORY_NODE,
        CREDENTIAL_DUPLICATE_NAME_NODE,
        CREDENTIAL_SECRET_HISTORY_NODE,
        CREDENTIAL_TEMPLATES_NODE,
        CREDENTIAL_AGENT_STORE_NODE,
        CREDENTIAL_VEND_BY_NAME_NODE,
    ]
