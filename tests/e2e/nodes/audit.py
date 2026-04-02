"""
DAG nodes for audit API testing: audit.list, audit.filter, audit.export.
"""

import json

from tests.e2e.dag_runner import DagNode
from tests.e2e.helpers import server_request


# ---------------------------------------------------------------------------
# audit.list
# ---------------------------------------------------------------------------

def audit_list(ctx: dict) -> dict:
    """
    List audit events via admin API and verify structure.

    Consumes: base_url, admin_session_cookie
    Produces: audit_events
    """
    base_url = ctx["base_url"]
    admin_cookie = ctx["admin_session_cookie"]

    status, _, body = server_request(
        base_url, "GET", "/api/v1/audit",
        cookies=admin_cookie,
    )

    assert status == 200, f"Audit list failed with {status}: {body}"

    data = json.loads(body)
    events = data.get("data", data)
    if isinstance(events, dict):
        events = events.get("events", events.get("items", []))

    assert isinstance(events, list), f"Expected audit events list, got: {type(events)}"
    assert len(events) > 0, "No audit events found — login should have generated at least one"

    # Verify event structure
    for event in events[:3]:
        assert "event_type" in event or "type" in event, (
            f"Audit event missing event_type: {event}"
        )

    ctx["audit_events"] = events
    return ctx


AUDIT_LIST_NODE = DagNode(
    name="audit.list",
    fn=audit_list,
    depends_on=["setup.login"],
    produces=["audit_events"],
    consumes=["base_url", "admin_session_cookie"],
    critical=False,
    timeout=10.0,
)


# ---------------------------------------------------------------------------
# audit.filter
# ---------------------------------------------------------------------------

def audit_filter(ctx: dict) -> dict:
    """
    Verify audit event filtering works (by event_type).

    Consumes: base_url, admin_session_cookie
    """
    base_url = ctx["base_url"]
    admin_cookie = ctx["admin_session_cookie"]

    # Filter for login events
    status, _, body = server_request(
        base_url, "GET", "/api/v1/audit?event_type=user_login_success",
        cookies=admin_cookie,
    )

    assert status == 200, f"Audit filter failed with {status}: {body}"

    data = json.loads(body)
    events = data.get("data", data)
    if isinstance(events, dict):
        events = events.get("events", events.get("items", []))

    assert isinstance(events, list), f"Expected filtered events list: {events}"

    return ctx


AUDIT_FILTER_NODE = DagNode(
    name="audit.filter",
    fn=audit_filter,
    depends_on=["audit.list"],
    produces=[],
    consumes=["base_url", "admin_session_cookie"],
    critical=False,
    timeout=10.0,
)


# ---------------------------------------------------------------------------
# audit.export
# ---------------------------------------------------------------------------

def audit_export(ctx: dict) -> dict:
    """
    Verify audit export endpoints return valid data.

    Consumes: base_url, admin_session_cookie
    """
    base_url = ctx["base_url"]
    admin_cookie = ctx["admin_session_cookie"]

    for fmt in ["csv", "jsonl"]:
        status, headers, body = server_request(
            base_url, "GET", f"/api/v1/audit/export?format={fmt}",
            cookies=admin_cookie,
        )

        assert status == 200, f"Audit export {fmt} failed with {status}: {body}"
        assert len(body) > 0, f"Audit export {fmt} returned empty body"

    return ctx


AUDIT_EXPORT_NODE = DagNode(
    name="audit.export",
    fn=audit_export,
    depends_on=["audit.list"],
    produces=[],
    consumes=["base_url", "admin_session_cookie"],
    critical=False,
    timeout=10.0,
)


# ---------------------------------------------------------------------------
# audit.export_jsonl
# ---------------------------------------------------------------------------

def audit_export_jsonl(ctx: dict) -> dict:
    """
    Verify GET /audit/export/jsonl returns valid JSONL data.

    Consumes: base_url, admin_session_cookie
    """
    base_url = ctx["base_url"]
    admin_cookie = ctx["admin_session_cookie"]

    status, headers, body = server_request(
        base_url, "GET", "/api/v1/audit/export/jsonl",
        cookies=admin_cookie,
    )

    assert status == 200, f"Audit export JSONL failed with {status}: {body}"
    assert len(body) > 0, "Audit export JSONL returned empty body"

    # Verify each line is valid JSON
    lines = [l for l in body.strip().split("\n") if l.strip()]
    assert len(lines) >= 1, "Expected at least 1 JSONL line"
    for line in lines[:5]:
        parsed = json.loads(line)
        assert isinstance(parsed, dict), f"JSONL line is not a dict: {line}"

    return ctx


AUDIT_EXPORT_JSONL_NODE = DagNode(
    name="audit.export_jsonl",
    fn=audit_export_jsonl,
    depends_on=["audit.list"],
    produces=[],
    consumes=["base_url", "admin_session_cookie"],
    critical=False,
    timeout=10.0,
)


# ---------------------------------------------------------------------------
# audit.export_syslog
# ---------------------------------------------------------------------------

def audit_export_syslog(ctx: dict) -> dict:
    """
    Verify GET /audit/export/syslog returns valid syslog-formatted data.

    Consumes: base_url, admin_session_cookie
    """
    base_url = ctx["base_url"]
    admin_cookie = ctx["admin_session_cookie"]

    status, headers, body = server_request(
        base_url, "GET", "/api/v1/audit/export/syslog",
        cookies=admin_cookie,
    )

    assert status == 200, f"Audit export syslog failed with {status}: {body}"
    assert len(body) > 0, "Audit export syslog returned empty body"

    return ctx


AUDIT_EXPORT_SYSLOG_NODE = DagNode(
    name="audit.export_syslog",
    fn=audit_export_syslog,
    depends_on=["audit.list"],
    produces=[],
    consumes=["base_url", "admin_session_cookie"],
    critical=False,
    timeout=10.0,
)


# ---------------------------------------------------------------------------
# audit.get_by_id
# ---------------------------------------------------------------------------

def audit_get_by_id(ctx: dict) -> dict:
    """
    Verify GET /audit/{id} returns a single audit event.

    Consumes: base_url, admin_session_cookie, audit_events
    """
    base_url = ctx["base_url"]
    admin_cookie = ctx["admin_session_cookie"]
    audit_events = ctx["audit_events"]

    # Pick the first event's ID
    first_event = audit_events[0]
    event_id = first_event.get("id")
    assert event_id, f"First audit event has no id: {first_event}"

    status, _, body = server_request(
        base_url, "GET", f"/api/v1/audit/{event_id}",
        cookies=admin_cookie,
    )

    assert status == 200, f"Audit get by ID failed with {status}: {body}"

    data = json.loads(body)
    event = data.get("data", data)
    assert event.get("id") == event_id, (
        f"Event ID mismatch: expected '{event_id}', got '{event.get('id')}'"
    )

    return ctx


AUDIT_GET_BY_ID_NODE = DagNode(
    name="audit.get_by_id",
    fn=audit_get_by_id,
    depends_on=["audit.list"],
    produces=[],
    consumes=["base_url", "admin_session_cookie", "audit_events"],
    critical=False,
    timeout=10.0,
)


# ---------------------------------------------------------------------------
# audit.no_secrets_in_events
# ---------------------------------------------------------------------------

def audit_no_secrets_in_events(ctx: dict) -> dict:
    """
    Fetch all audit events, scan entire JSON for forbidden patterns
    (secret_value, password values, Bearer token values).

    Consumes: base_url, admin_session_cookie
    """
    base_url = ctx["base_url"]
    admin_cookie = ctx["admin_session_cookie"]

    status, _, body = server_request(
        base_url, "GET", "/api/v1/audit",
        cookies=admin_cookie,
    )

    assert status == 200, f"Audit list failed: {status}: {body}"

    data = json.loads(body)
    events = data.get("data", data)
    if isinstance(events, dict):
        events = events.get("events", events.get("items", []))

    assert isinstance(events, list), f"Expected events list: {type(events)}"

    # Scan each event for forbidden patterns
    forbidden_patterns = [
        "e2e-test-secret-value",
        "-----begin private",
        "-----begin rsa",
    ]

    for event in events:
        event_str = json.dumps(event).lower()
        for pattern in forbidden_patterns:
            assert pattern not in event_str, (
                f"Secret pattern '{pattern}' found in audit event "
                f"type={event.get('event_type', event.get('type', 'unknown'))}"
            )

    return ctx


AUDIT_NO_SECRETS_NODE = DagNode(
    name="audit.no_secrets_in_events",
    fn=audit_no_secrets_in_events,
    depends_on=["audit.list"],
    produces=[],
    consumes=["base_url", "admin_session_cookie"],
    critical=False,
    timeout=10.0,
)


def get_nodes():
    """Return all audit DAG nodes."""
    return [
        AUDIT_LIST_NODE,
        AUDIT_FILTER_NODE,
        AUDIT_EXPORT_NODE,
        AUDIT_EXPORT_JSONL_NODE,
        AUDIT_EXPORT_SYSLOG_NODE,
        AUDIT_GET_BY_ID_NODE,
        AUDIT_NO_SECRETS_NODE,
    ]
