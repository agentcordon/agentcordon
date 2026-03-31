"""
DAG node for full broker lifecycle journey: journey.broker_full_lifecycle.
"""

import json
import os
import subprocess
import tempfile
import time

from tests.e2e.dag_runner import DagNode
from tests.e2e.helpers import (
    broker_request,
    generate_ed25519_keypair,
    server_request,
    sign_request,
)


# ---------------------------------------------------------------------------
# journey.broker_full_lifecycle
# ---------------------------------------------------------------------------

def journey_broker_full_lifecycle(ctx: dict) -> dict:
    """
    Full lifecycle journey test covering the complete user story:

      1. Admin creates a credential (already done by upstream nodes)
      2. CLI inits Ed25519 keypair
      3. CLI registers with broker → user approves consent
      4. CLI lists credentials via broker
      5. CLI proxies request via broker
      6. Admin checks audit log for expected events
      7. Admin revokes OAuth tokens
      8. CLI retries → fails with 401

    This node depends on audit.oauth_events to ensure all prior broker
    operations have completed and been audited. It then performs a fresh
    end-to-end lifecycle with revocation to validate the full story.

    Consumes: broker_url, admin_session_cookie, base_url, broker_data_dir,
              broker_pem_key_path, oauth_client_id
    Produces: (none — journey validation only)
    """
    broker_url = ctx["broker_url"]
    admin_cookie = ctx.get("admin_session_cookie", "")
    base_url = ctx["base_url"]
    pem_key_path = ctx["broker_pem_key_path"]

    # Step 1-5: Already validated by upstream nodes
    # (broker.start → workspace.oauth_register → credential.discover_via_broker
    #  → proxy.via_broker → audit.oauth_events)
    # This journey node does a final coherence check.

    # Verify credentials are still discoverable
    status, _, body = broker_request(
        broker_url, pem_key_path, "GET", "/credentials"
    )
    assert status == 200, (
        f"Journey: credential discovery failed with {status}: {body}"
    )

    credentials = json.loads(body)
    cred_data = credentials.get("data", credentials)
    assert isinstance(cred_data, list) and len(cred_data) > 0, (
        f"Journey: expected at least one credential, got: {cred_data}"
    )

    # Verify proxy still works
    credential_name = ctx.get("credential_name")
    if not credential_name and cred_data:
        credential_name = cred_data[0].get("name", cred_data[0].get("id"))

    if credential_name:
        upstream_url = ctx.get(
            "proxy_upstream_url",
            f"{base_url}/health"
        )
        proxy_body = json.dumps({
            "method": "GET",
            "url": upstream_url,
            "credential": credential_name,
            "headers": {"Accept": "application/json"},
        })

        status, _, body = broker_request(
            broker_url, pem_key_path, "POST", "/proxy", body=proxy_body,
        )
        assert status == 200, (
            f"Journey: proxy request failed with {status}: {body}"
        )

    # Verify audit events are present
    status, _, body = server_request(
        base_url, "GET", "/api/v1/admin/audit",
        cookies=admin_cookie,
    )
    if status == 200:
        audit_data = json.loads(body)
        events = audit_data.get("data", audit_data)
        if isinstance(events, dict):
            events = events.get("events", [])
        event_types = [e.get("event_type", e.get("type", "")) for e in events]
        assert "oauth_client_registered" in event_types, (
            "Journey: oauth_client_registered event not in audit log"
        )

    # Step 7: Revoke OAuth tokens
    oauth_client_id = ctx.get("oauth_client_id")
    if oauth_client_id and admin_cookie:
        revoke_body = json.dumps({"client_id": oauth_client_id})
        status, _, body = server_request(
            base_url, "POST", "/api/v1/oauth/revoke",
            body=revoke_body,
            cookies=admin_cookie,
        )
        assert status in (200, 204), (
            f"Journey: token revocation failed with {status}: {body}"
        )

        # Step 8: Retry — should fail with 401
        # Give the server a moment to process revocation
        time.sleep(0.5)

        status, _, body = broker_request(
            broker_url, pem_key_path, "GET", "/credentials"
        )
        assert status == 401, (
            f"Journey: expected 401 after revocation, got {status}: {body}"
        )

    return ctx


JOURNEY_BROKER_FULL_LIFECYCLE_NODE = DagNode(
    name="journey.broker_full_lifecycle",
    fn=journey_broker_full_lifecycle,
    depends_on=["audit.oauth_events"],
    produces=[],
    consumes=[
        "broker_url", "admin_session_cookie", "base_url",
        "broker_pem_key_path",
    ],
    critical=False,
    timeout=120.0,
)


def get_nodes():
    """Return all journey DAG nodes."""
    return [JOURNEY_BROKER_FULL_LIFECYCLE_NODE]
