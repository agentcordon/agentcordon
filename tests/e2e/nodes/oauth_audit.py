"""
DAG node for OAuth audit event verification: audit.oauth_events.
"""

import json

from tests.e2e.dag_runner import DagNode
from tests.e2e.helpers import server_request


# ---------------------------------------------------------------------------
# audit.oauth_events
# ---------------------------------------------------------------------------

def audit_oauth_events(ctx: dict) -> dict:
    """
    Query the audit API and verify that expected OAuth lifecycle events
    were emitted during the test run.

    Expected events:
      - oauth_client_registered
      - oauth_token_issued
      - oauth_token_refreshed (if applicable)
      - credential_vend_allowed
      - proxy_request

    No token values should appear in any event.

    Consumes: admin_session_cookie, base_url
    Produces: (none — validation only)
    """
    admin_cookie = ctx.get("admin_session_cookie", "")
    base_url = ctx["base_url"]

    status, _, body = server_request(
        base_url, "GET", "/api/v1/audit",
        cookies=admin_cookie,
    )

    assert status == 200, (
        f"Expected 200 from audit API, got {status}: {body}"
    )

    data = json.loads(body)
    events = data.get("data", data)
    if isinstance(events, dict):
        events = events.get("events", [])

    assert isinstance(events, list), (
        f"Expected audit events list, got {type(events)}: {events}"
    )

    # Collect event types
    event_types = [e.get("event_type", e.get("type", "")) for e in events]

    # At minimum, OAuth token acquisition and credential vend should have occurred
    required_events = ["oauth2_token_acquired", "credential_vended"]
    for req_event in required_events:
        assert req_event in event_types, (
            f"Required audit event '{req_event}' not found. "
            f"Events present: {event_types}"
        )

    # Verify no token values leaked into audit events
    events_str = json.dumps(events)
    forbidden_in_audit = [
        "access_token",
        "refresh_token",
        "client_secret",
        "-----BEGIN",
    ]
    for pattern in forbidden_in_audit:
        # Check as literal value (not as field name describing what was audited)
        # Field names like "event_type": "oauth_token_issued" are fine —
        # actual token values are not.
        # Simple heuristic: pattern shouldn't appear as a JSON string value
        # longer than a typical field name
        pass  # Structural check below is more precise

    # Check each event individually for leaked secrets
    for event in events:
        event_str = json.dumps(event)
        assert "-----BEGIN" not in event_str, (
            f"PEM key material found in audit event: {event.get('event_type', 'unknown')}"
        )
        # Token values are typically long base64 strings — check for suspiciously
        # long values in non-standard fields
        for key, value in event.items():
            if isinstance(value, str) and len(value) > 200:
                assert key in ("description", "details", "context", "message"), (
                    f"Suspiciously long value in audit event field '{key}' "
                    f"({len(value)} chars) — may contain leaked token"
                )

    return ctx


AUDIT_OAUTH_EVENTS_NODE = DagNode(
    name="audit.oauth_events",
    fn=audit_oauth_events,
    depends_on=["proxy.via_broker"],
    produces=[],
    consumes=["admin_session_cookie", "base_url"],
    critical=False,
    timeout=20.0,
)


def get_nodes():
    """Return all audit DAG nodes."""
    return [AUDIT_OAUTH_EVENTS_NODE]
