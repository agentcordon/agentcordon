"""
DAG nodes for RFC 8628 Device Authorization Grant workspace registration flow.

Replaces the legacy OAuth authorization-code + loopback flow. These nodes
cover: device_code_request, poll_pending, approve, exchange, deny, expiry,
and csrf_reject.
"""

import json
import os
import re
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

from tests.e2e.dag_runner import DagNode
from tests.e2e.helpers import (
    broker_request,
    generate_ed25519_keypair,
    server_request,
)


DEVICE_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:device_code"
BOOTSTRAP_CLIENT_ID = "agentcordon-broker"


def _parse_hidden_fields(html: str) -> dict:
    return dict(re.findall(
        r'<input\s+type="hidden"\s+name="([^"]+)"\s+value="([^"]*)"', html
    ))


def _device_code_request(base_url: str, client_id: str, scope: str) -> tuple:
    body = urllib.parse.urlencode({
        "client_id": client_id,
        "scope": scope,
    })
    status, _, resp = server_request(
        base_url, "POST", "/oauth/device/code",
        body=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    return status, resp


def _token_poll(base_url: str, device_code: str, client_id: str) -> tuple:
    body = urllib.parse.urlencode({
        "grant_type": DEVICE_GRANT_TYPE,
        "device_code": device_code,
        "client_id": client_id,
    })
    status, _, resp = server_request(
        base_url, "POST", "/oauth/token",
        body=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    return status, resp


# ---------------------------------------------------------------------------
# workspace.device_code_request
# ---------------------------------------------------------------------------

def workspace_device_code_request(ctx: dict) -> dict:
    """
    Initiate a device authorization grant and verify RFC 8628 response shape.

    Consumes: broker_url, base_url, ws_workspace_name, broker_data_dir
    Produces: device_code, user_code, verification_uri,
              verification_uri_complete, device_code_expires_at,
              ws_ed25519_key, ws_pk_hash, broker_pem_key_path
    """
    base_url = ctx["base_url"]
    broker_data_dir = ctx["broker_data_dir"]

    # Generate a workspace keypair (used later by broker-signed requests).
    private_key_hex, public_key_hex, pk_hash = generate_ed25519_keypair(broker_data_dir)
    ctx["ws_ed25519_key"] = private_key_hex
    ctx["ws_public_key_hex"] = public_key_hex
    ctx["ws_pk_hash"] = pk_hash
    ctx["broker_pem_key_path"] = os.path.join(broker_data_dir, "ed25519.pem")

    client_id = ctx.get("bootstrap_client_id", BOOTSTRAP_CLIENT_ID)
    scope = "credentials:discover credentials:vend mcp:discover mcp:invoke"

    status, resp = _device_code_request(base_url, client_id, scope)
    assert status == 200, f"POST /oauth/device/code failed {status}: {resp}"

    data = json.loads(resp)
    for field in (
        "device_code", "user_code", "verification_uri",
        "verification_uri_complete", "expires_in", "interval",
    ):
        assert field in data, f"Missing RFC 8628 field '{field}' in {data}"

    ctx["device_code"] = data["device_code"]
    ctx["user_code"] = data["user_code"]
    ctx["verification_uri"] = data["verification_uri"]
    ctx["verification_uri_complete"] = data["verification_uri_complete"]
    ctx["device_code_expires_at"] = time.time() + int(data["expires_in"])
    ctx["bootstrap_client_id"] = client_id
    return ctx


WORKSPACE_DEVICE_CODE_REQUEST_NODE = DagNode(
    name="workspace.device_code_request",
    fn=workspace_device_code_request,
    depends_on=["broker.start", "workspace.create"],
    produces=[
        "device_code", "user_code", "verification_uri",
        "verification_uri_complete", "device_code_expires_at",
        "ws_ed25519_key", "ws_pk_hash", "broker_pem_key_path",
    ],
    consumes=["broker_url", "base_url", "ws_workspace_name", "broker_data_dir"],
    critical=True,
    timeout=20.0,
)


# ---------------------------------------------------------------------------
# workspace.device_code_poll_pending
# ---------------------------------------------------------------------------

def workspace_device_code_poll_pending(ctx: dict) -> dict:
    """
    Poll /oauth/token immediately: assert authorization_pending, then
    slow_down on a too-fast second poll, then authorization_pending after
    honouring the interval.

    Consumes: base_url, device_code, bootstrap_client_id
    Produces: poll_pending_verified
    """
    base_url = ctx["base_url"]
    device_code = ctx["device_code"]
    client_id = ctx.get("bootstrap_client_id", BOOTSTRAP_CLIENT_ID)

    status, resp = _token_poll(base_url, device_code, client_id)
    assert status == 400, f"Expected 400 on first poll, got {status}: {resp}"
    body = json.loads(resp)
    assert body.get("error") == "authorization_pending", (
        f"Expected authorization_pending, got {body}"
    )

    # Immediately poll again — should return slow_down
    status, resp = _token_poll(base_url, device_code, client_id)
    assert status == 400, f"Expected 400 on second poll, got {status}: {resp}"
    body = json.loads(resp)
    assert body.get("error") == "slow_down", (
        f"Expected slow_down on rapid re-poll, got {body}"
    )

    # Wait interval (10s after a doubled slow_down) and poll again
    time.sleep(10.5)
    status, resp = _token_poll(base_url, device_code, client_id)
    assert status == 400, f"Expected 400 after interval wait, got {status}"
    body = json.loads(resp)
    assert body.get("error") == "authorization_pending", (
        f"Expected authorization_pending after interval, got {body}"
    )

    ctx["poll_pending_verified"] = True
    return ctx


WORKSPACE_DEVICE_CODE_POLL_PENDING_NODE = DagNode(
    name="workspace.device_code_poll_pending",
    fn=workspace_device_code_poll_pending,
    depends_on=["workspace.device_code_request"],
    produces=["poll_pending_verified"],
    consumes=["base_url", "device_code", "bootstrap_client_id"],
    critical=True,
    timeout=30.0,
)


# ---------------------------------------------------------------------------
# workspace.device_code_approve
# ---------------------------------------------------------------------------

def workspace_device_code_approve(ctx: dict) -> dict:
    """
    Approve the pending device code via the /activate web form.

    Consumes: base_url, user_code, admin_session_cookie
    Produces: device_code_approved
    """
    base_url = ctx["base_url"]
    user_code = ctx["user_code"]
    admin_cookie = ctx["admin_session_cookie"]

    # GET /activate?user_code=<code> to obtain the form + csrf_token
    status, _, body = server_request(
        base_url, "GET",
        f"/activate?user_code={urllib.parse.quote(user_code)}",
        cookies=admin_cookie,
    )
    assert status == 200, f"GET /activate failed {status}: {body}"
    hidden = _parse_hidden_fields(body)
    assert hidden.get("csrf_token"), f"No csrf_token in /activate form: {hidden}"

    # Make sure the user_code field is included (the form may pre-fill it)
    hidden.setdefault("user_code", user_code)
    hidden["decision"] = "approve"

    form_body = urllib.parse.urlencode(hidden)
    status, _, body = server_request(
        base_url, "POST", "/activate",
        body=form_body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        cookies=admin_cookie,
    )
    assert status == 200, f"POST /activate approve failed {status}: {body}"
    body_lower = body.lower()
    assert "success" in body_lower or "approved" in body_lower or "close" in body_lower, (
        f"Expected success marker in activate response: {body[:300]}"
    )

    ctx["device_code_approved"] = True
    return ctx


WORKSPACE_DEVICE_CODE_APPROVE_NODE = DagNode(
    name="workspace.device_code_approve",
    fn=workspace_device_code_approve,
    depends_on=["workspace.device_code_request", "setup.login"],
    produces=["device_code_approved"],
    consumes=["base_url", "user_code", "admin_session_cookie"],
    critical=True,
    timeout=15.0,
)


# ---------------------------------------------------------------------------
# workspace.device_code_exchange
# ---------------------------------------------------------------------------

def workspace_device_code_exchange(ctx: dict) -> dict:
    """
    Exchange the approved device code for tokens; verify single-use replay.

    Consumes: base_url, broker_url, device_code, bootstrap_client_id,
              broker_pem_key_path
    Produces: oauth_client_id, oauth_tokens_stored
    """
    base_url = ctx["base_url"]
    broker_url = ctx["broker_url"]
    device_code = ctx["device_code"]
    client_id = ctx.get("bootstrap_client_id", BOOTSTRAP_CLIENT_ID)
    pem_key_path = ctx.get("broker_pem_key_path")

    deadline = time.time() + 15
    tokens = None
    last_status = None
    last_body = None
    while time.time() < deadline:
        status, resp = _token_poll(base_url, device_code, client_id)
        last_status, last_body = status, resp
        if status == 200:
            tokens = json.loads(resp)
            break
        # Still pending or slow_down — wait and retry
        time.sleep(5.5)

    assert tokens is not None, (
        f"Device code exchange did not succeed in time: "
        f"last status={last_status} body={last_body}"
    )

    assert tokens.get("access_token"), f"Missing access_token: {tokens}"
    assert tokens.get("token_type", "").lower() == "bearer", (
        f"Expected token_type=Bearer, got {tokens.get('token_type')}"
    )
    oauth_client_id = tokens.get("client_id") or client_id
    ctx["oauth_client_id"] = oauth_client_id

    # Single-use replay: second poll must now return invalid_grant
    status, resp = _token_poll(base_url, device_code, client_id)
    assert status == 400, f"Expected 400 on replay, got {status}: {resp}"
    body = json.loads(resp)
    assert body.get("error") == "invalid_grant", (
        f"Expected invalid_grant on replay, got {body}"
    )

    # If broker has a keypair, sanity-check broker /status reports registered.
    if pem_key_path and os.path.exists(pem_key_path):
        try:
            status_code, _, status_body = broker_request(
                broker_url, pem_key_path, "GET", "/status"
            )
            if status_code == 200:
                inner = json.loads(status_body).get("data", {})
                # Not fatal if broker didn't independently register — the
                # server-side token exchange is authoritative for this test.
                ctx["broker_status_registered"] = bool(inner.get("registered"))
        except Exception:
            pass

    ctx["oauth_tokens_stored"] = True
    return ctx


WORKSPACE_DEVICE_CODE_EXCHANGE_NODE = DagNode(
    name="workspace.device_code_exchange",
    fn=workspace_device_code_exchange,
    depends_on=[
        "workspace.device_code_approve",
        "workspace.device_code_poll_pending",
    ],
    produces=["oauth_client_id", "oauth_tokens_stored"],
    consumes=[
        "base_url", "broker_url", "device_code",
        "bootstrap_client_id", "broker_pem_key_path",
    ],
    critical=True,
    timeout=30.0,
)


# ---------------------------------------------------------------------------
# workspace.device_code_deny
# ---------------------------------------------------------------------------

def workspace_device_code_deny(ctx: dict) -> dict:
    """
    Start a fresh device flow, deny consent, assert access_denied on poll.

    Consumes: base_url, admin_session_cookie
    Produces: device_code_deny_verified
    """
    base_url = ctx["base_url"]
    admin_cookie = ctx["admin_session_cookie"]
    client_id = ctx.get("bootstrap_client_id", BOOTSTRAP_CLIENT_ID)

    status, resp = _device_code_request(
        base_url, client_id, "credentials:discover"
    )
    assert status == 200, f"POST /oauth/device/code failed {status}: {resp}"
    data = json.loads(resp)
    device_code = data["device_code"]
    user_code = data["user_code"]

    # GET /activate form
    status, _, body = server_request(
        base_url, "GET",
        f"/activate?user_code={urllib.parse.quote(user_code)}",
        cookies=admin_cookie,
    )
    assert status == 200, f"GET /activate failed {status}: {body}"
    hidden = _parse_hidden_fields(body)
    assert hidden.get("csrf_token"), f"No csrf_token in form"
    hidden.setdefault("user_code", user_code)
    hidden["decision"] = "deny"

    form_body = urllib.parse.urlencode(hidden)
    status, _, body = server_request(
        base_url, "POST", "/activate",
        body=form_body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        cookies=admin_cookie,
    )
    assert status == 200, f"POST /activate deny failed {status}: {body}"

    status, resp = _token_poll(base_url, device_code, client_id)
    assert status == 400, f"Expected 400 after deny, got {status}: {resp}"
    body = json.loads(resp)
    assert body.get("error") == "access_denied", (
        f"Expected access_denied, got {body}"
    )

    ctx["device_code_deny_verified"] = True
    return ctx


WORKSPACE_DEVICE_CODE_DENY_NODE = DagNode(
    name="workspace.device_code_deny",
    fn=workspace_device_code_deny,
    depends_on=["broker.start", "setup.login"],
    produces=["device_code_deny_verified"],
    consumes=["broker_url", "base_url", "admin_session_cookie", "broker_data_dir"],
    critical=False,
    timeout=20.0,
)


# ---------------------------------------------------------------------------
# workspace.device_code_expiry
# ---------------------------------------------------------------------------

def workspace_device_code_expiry(ctx: dict) -> dict:
    """
    Verify that polling a device code past its TTL yields expired_token.

    Requires the server to have been started with a short TTL
    (e.g. AGTCRDN_DEVICE_CODE_TTL_SECS=2). If unavailable, skip softly.

    Consumes: base_url, broker_url
    Produces: device_code_expiry_verified
    """
    base_url = ctx["base_url"]
    client_id = ctx.get("bootstrap_client_id", BOOTSTRAP_CLIENT_ID)

    status, resp = _device_code_request(
        base_url, client_id, "credentials:discover"
    )
    assert status == 200, f"POST /oauth/device/code failed {status}: {resp}"
    data = json.loads(resp)
    device_code = data["device_code"]
    expires_in = int(data.get("expires_in", 600))

    if expires_in > 5:
        # Server not running with a short TTL — mark as verified-skipped so
        # that the DAG does not block on a 10-minute real-time wait.
        ctx["device_code_expiry_verified"] = "skipped-long-ttl"
        return ctx

    time.sleep(expires_in + 1.5)
    status, resp = _token_poll(base_url, device_code, client_id)
    assert status == 400, f"Expected 400 after expiry, got {status}: {resp}"
    body = json.loads(resp)
    assert body.get("error") == "expired_token", (
        f"Expected expired_token, got {body}"
    )

    ctx["device_code_expiry_verified"] = True
    return ctx


WORKSPACE_DEVICE_CODE_EXPIRY_NODE = DagNode(
    name="workspace.device_code_expiry",
    fn=workspace_device_code_expiry,
    depends_on=["broker.start"],
    produces=["device_code_expiry_verified"],
    consumes=["base_url", "broker_url", "broker_data_dir"],
    critical=False,
    timeout=15.0,
)


# ---------------------------------------------------------------------------
# workspace.device_code_csrf_reject
# ---------------------------------------------------------------------------

def workspace_device_code_csrf_reject(ctx: dict) -> dict:
    """
    POST /activate with a tampered csrf_token must be rejected with 403.

    Consumes: base_url, user_code, admin_session_cookie
    Produces: csrf_reject_verified
    """
    base_url = ctx["base_url"]
    user_code = ctx["user_code"]
    admin_cookie = ctx["admin_session_cookie"]

    form = {
        "user_code": user_code,
        "csrf_token": "tampered-csrf-value-0000",
        "decision": "approve",
    }
    form_body = urllib.parse.urlencode(form)
    status, _, body = server_request(
        base_url, "POST", "/activate",
        body=form_body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        cookies=admin_cookie,
    )
    assert status == 403, (
        f"Expected 403 for tampered CSRF, got {status}: {body[:200]}"
    )

    ctx["csrf_reject_verified"] = True
    return ctx


WORKSPACE_DEVICE_CODE_CSRF_REJECT_NODE = DagNode(
    name="workspace.device_code_csrf_reject",
    fn=workspace_device_code_csrf_reject,
    depends_on=["workspace.device_code_request"],
    produces=["csrf_reject_verified"],
    consumes=["base_url", "user_code", "admin_session_cookie"],
    critical=False,
    timeout=10.0,
)


def get_nodes():
    """Return all device-flow DAG nodes."""
    return [
        WORKSPACE_DEVICE_CODE_REQUEST_NODE,
        WORKSPACE_DEVICE_CODE_POLL_PENDING_NODE,
        WORKSPACE_DEVICE_CODE_APPROVE_NODE,
        WORKSPACE_DEVICE_CODE_EXCHANGE_NODE,
        WORKSPACE_DEVICE_CODE_DENY_NODE,
        WORKSPACE_DEVICE_CODE_EXPIRY_NODE,
        WORKSPACE_DEVICE_CODE_CSRF_REJECT_NODE,
    ]
