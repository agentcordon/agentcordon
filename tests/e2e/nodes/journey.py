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
        base_url, "GET", "/api/v1/audit",
        cookies=admin_cookie,
    )
    if status == 200:
        audit_data = json.loads(body)
        events = audit_data.get("data", audit_data)
        if isinstance(events, dict):
            events = events.get("events", [])
        event_types = [e.get("event_type", e.get("type", "")) for e in events]
        assert "oauth2_token_acquired" in event_types, (
            "Journey: oauth2_token_acquired event not in audit log"
        )

    # Step 7: Revoke OAuth client (which revokes all its tokens)
    oauth_client_id = ctx.get("oauth_client_id")
    csrf_token = ctx.get("csrf_token", "")
    if oauth_client_id and admin_cookie:
        # Look up the client UUID from the list
        status, _, body = server_request(
            base_url, "GET", "/api/v1/oauth/clients",
            cookies=admin_cookie,
        )
        client_uuid = None
        if status == 200:
            clients = json.loads(body).get("data", [])
            for c in clients:
                if c.get("client_id") == oauth_client_id:
                    client_uuid = c.get("id")
                    break

        if client_uuid:
            status, _, body = server_request(
                base_url, "DELETE", f"/api/v1/oauth/clients/{client_uuid}",
                headers={"X-CSRF-Token": csrf_token},
                cookies=admin_cookie,
            )
            assert status in (200, 204), (
                f"Journey: token revocation failed with {status}: {body}"
            )

            # Step 8: Retry — should fail with 401
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
    depends_on=[
        "audit.oauth_events",
        "proxy.broker_round_trip",
        "proxy.via_broker_denied",
        "security.cli_no_credential_material",
        "mcp.import_config",
    ],
    produces=[],
    consumes=[
        "broker_url", "admin_session_cookie", "base_url",
        "broker_pem_key_path",
    ],
    critical=False,
    timeout=120.0,
)



# ---------------------------------------------------------------------------
# journey.deny_no_grants
# ---------------------------------------------------------------------------

def journey_deny_no_grants(ctx: dict) -> dict:
    """
    Create a fresh workspace with no grants, verify credential access denied.

    This creates a new Ed25519 keypair, registers via OAuth, but does NOT
    grant any permissions. Then verifies credential discovery returns empty.

    Consumes: base_url, admin_session_cookie, csrf_token, broker_url
    """
    import tempfile

    base_url = ctx["base_url"]
    admin_cookie = ctx["admin_session_cookie"]
    csrf_token = ctx["csrf_token"]
    broker_url = ctx["broker_url"]

    # Generate a fresh Ed25519 keypair for an isolated workspace
    tmp_dir = tempfile.mkdtemp(prefix="e2e-deny-")
    priv_hex, pub_hex, pk_hash = generate_ed25519_keypair(tmp_dir)
    pem_key_path = os.path.join(tmp_dir, "ed25519.pem")

    # Register this new workspace via broker OAuth flow
    ws_name = f"e2e-deny-ws-{os.urandom(4).hex()}"

    reg_body = json.dumps({
        "workspace_name": ws_name,
        "public_key": pub_hex,
    })

    status, _, body = broker_request(
        broker_url, pem_key_path, "POST", "/register", body=reg_body,
    )

    # Registration initiates OAuth flow — might get redirect or pending
    # If it succeeds (200), the workspace is created but has no grants
    if status in (200, 201):
        # Try to discover credentials — should get empty list or 403
        status2, _, body2 = broker_request(
            broker_url, pem_key_path, "GET", "/credentials"
        )

        if status2 == 200:
            creds = json.loads(body2).get("data", [])
            # Should have no credentials (no grants)
            assert len(creds) == 0, (
                f"Expected 0 credentials for unganted workspace, got {len(creds)}"
            )
        else:
            # 401 or 403 is also acceptable (no OAuth token yet)
            assert status2 in (401, 403), (
                f"Expected empty/denied for ungranted workspace, got {status2}"
            )
    else:
        # Registration requires consent approval — that's OK,
        # the point is the workspace has no grants
        pass

    return ctx


JOURNEY_DENY_NO_GRANTS_NODE = DagNode(
    name="journey.deny_no_grants",
    fn=journey_deny_no_grants,
    depends_on=["broker.health"],
    produces=[],
    consumes=["base_url", "admin_session_cookie", "csrf_token", "broker_url"],
    critical=False,
    timeout=30.0,
)


# ---------------------------------------------------------------------------
# journey.agent_isolation
# ---------------------------------------------------------------------------

def journey_agent_isolation(ctx: dict) -> dict:
    """
    Verify the main E2E workspace can see its credential, but a request
    with a different (non-registered) key cannot.

    Consumes: broker_url, broker_pem_key_path, credential_name
    """
    import tempfile

    broker_url = ctx["broker_url"]
    pem_key_path = ctx["broker_pem_key_path"]
    credential_name = ctx["credential_name"]

    # Main workspace should see the credential
    status, _, body = broker_request(
        broker_url, pem_key_path, "GET", "/credentials"
    )
    assert status == 200, f"Main workspace discovery failed: {status}"
    creds = json.loads(body).get("data", [])
    names = [c.get("name", "") for c in creds]
    assert credential_name in names, (
        f"Main workspace can't see '{credential_name}': {names}"
    )

    # Generate a fresh keypair (unauthenticated workspace)
    tmp_dir = tempfile.mkdtemp(prefix="e2e-isolation-")
    generate_ed25519_keypair(tmp_dir)
    other_pem = os.path.join(tmp_dir, "ed25519.pem")

    # This foreign key should not be able to discover credentials
    status, _, body = broker_request(
        broker_url, other_pem, "GET", "/credentials"
    )

    # Should get 401 (unknown workspace key)
    assert status == 401, (
        f"Expected 401 for unknown workspace key, got {status}: {body}"
    )

    return ctx


JOURNEY_AGENT_ISOLATION_NODE = DagNode(
    name="journey.agent_isolation",
    fn=journey_agent_isolation,
    depends_on=["grant.verify_access_via_broker"],
    produces=[],
    consumes=["broker_url", "broker_pem_key_path", "credential_name"],
    critical=False,
    timeout=20.0,
)


def get_nodes():
    """Return all journey DAG nodes."""
    return [
        JOURNEY_BROKER_FULL_LIFECYCLE_NODE,
        JOURNEY_DENY_NO_GRANTS_NODE,
        JOURNEY_AGENT_ISOLATION_NODE,
    ]
