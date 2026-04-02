"""
DAG node for workspace OAuth registration flow: workspace.oauth_register.
"""

import hashlib
import json
import os
import re
import time
import urllib.request
import urllib.error
import urllib.parse

from tests.e2e.dag_runner import DagNode
from tests.e2e.helpers import (
    broker_request,
    generate_ed25519_keypair,
    server_request,
    sign_request,
)


def _parse_hidden_fields(html: str) -> dict:
    """Extract all hidden input field name/value pairs from HTML."""
    return dict(re.findall(r'<input\s+type="hidden"\s+name="([^"]+)"\s+value="([^"]*)"', html))


def _no_redirect_opener():
    """Build a urllib opener that does NOT follow redirects."""

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            raise urllib.error.HTTPError(
                newurl, code, msg, headers, fp
            )

    return urllib.request.build_opener(NoRedirect)


# ---------------------------------------------------------------------------
# workspace.oauth_register
# ---------------------------------------------------------------------------

def workspace_oauth_register(ctx: dict) -> dict:
    """
    Full OAuth registration flow:
      1. Generate Ed25519 keypair for the workspace
      2. POST /register to broker with workspace name + public key + scopes
      3. Broker returns authorization_url (with workspace_name + public_key_hash, NO client_id)
      4. GET consent page, parse hidden fields, POST approval
      5. Extract client_id from redirect Location header
      6. Follow redirect to broker callback
      7. Verify registration is complete

    Consumes: broker_url, ws_workspace_id, base_url, admin_session_cookie
    Produces: oauth_client_id, ws_ed25519_key, ws_pk_hash, broker_pem_key_path
    """
    broker_url = ctx["broker_url"]
    workspace_id = ctx["ws_workspace_id"]
    workspace_name = ctx.get("ws_workspace_name", "e2e-test-workspace")
    base_url = ctx["base_url"]
    admin_cookie = ctx.get("admin_session_cookie", "")

    # Step 1: Generate Ed25519 keypair
    broker_data_dir = ctx["broker_data_dir"]
    private_key_hex, public_key_hex, pk_hash = generate_ed25519_keypair(broker_data_dir)
    pem_key_path = os.path.join(broker_data_dir, "ed25519.pem")

    ctx["ws_ed25519_key"] = private_key_hex
    ctx["ws_pk_hash"] = pk_hash
    ctx["ws_public_key_hex"] = public_key_hex
    ctx["broker_pem_key_path"] = pem_key_path

    # Step 2: POST /register to broker
    # The register endpoint takes a self-signed body (not the standard
    # header-based auth, since the workspace isn't registered yet).
    scopes = ["credentials:discover", "credentials:vend", "mcp:discover", "mcp:invoke"]

    # Sign the registration payload: workspace_name \n public_key \n scopes_joined
    # Field separators prevent boundary manipulation attacks.
    scopes_joined = " ".join(scopes)
    reg_payload_to_sign = f"{workspace_name}\n{public_key_hex}\n{scopes_joined}"

    import subprocess
    import tempfile

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write(reg_payload_to_sign)
        payload_file = f.name

    try:
        result = subprocess.run(
            [
                "openssl", "pkeyutl", "-sign",
                "-inkey", pem_key_path,
                "-rawin",
                "-in", payload_file,
            ],
            check=True, capture_output=True,
        )
        reg_signature_hex = result.stdout.hex()
    finally:
        os.unlink(payload_file)

    register_body = json.dumps({
        "workspace_name": workspace_name,
        "public_key": public_key_hex,
        "scopes": scopes,
        "signature": reg_signature_hex,
    })

    # POST /register (no auth headers needed — self-signed body)
    req = urllib.request.Request(
        f"{broker_url}/register",
        data=register_body.encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            status = resp.status
            resp_body = json.loads(resp.read())
    except urllib.error.HTTPError as e:
        resp_text = e.read().decode("utf-8") if e.fp else ""
        raise AssertionError(
            f"POST /register failed with {e.code}: {resp_text}"
        )

    assert status == 200, f"Expected 200 from /register, got {status}"
    data = resp_body.get("data", resp_body)
    auth_url = data.get("authorization_url")
    assert auth_url, f"No authorization_url in register response: {resp_body}"
    assert data.get("status") == "awaiting_consent", (
        f"Expected status 'awaiting_consent', got {data.get('status')}"
    )

    # Step 3: GET the consent page with session cookie to retrieve hidden fields
    consent_headers = {}
    if admin_cookie:
        consent_headers["Cookie"] = admin_cookie

    consent_get_req = urllib.request.Request(auth_url, headers=consent_headers)
    try:
        with urllib.request.urlopen(consent_get_req, timeout=30) as resp:
            consent_html = resp.read().decode("utf-8")
    except urllib.error.HTTPError as e:
        resp_text = e.read().decode("utf-8") if e.fp else ""
        raise AssertionError(
            f"GET consent page failed with {e.code}: {resp_text}"
        )

    # Parse all hidden form fields from the consent HTML
    hidden_fields = _parse_hidden_fields(consent_html)
    assert hidden_fields, f"No hidden fields found in consent HTML"

    # Step 4: POST consent approval with all hidden fields + decision=approve
    hidden_fields["decision"] = "approve"

    consent_body = urllib.parse.urlencode(hidden_fields).encode("utf-8")

    consent_post_headers = {
        "Content-Type": "application/x-www-form-urlencoded",
    }
    if admin_cookie:
        consent_post_headers["Cookie"] = admin_cookie

    consent_post_req = urllib.request.Request(
        f"{base_url}/api/v1/oauth/authorize",
        data=consent_body,
        headers=consent_post_headers,
        method="POST",
    )

    # Use no-redirect opener to capture the Location header
    opener = _no_redirect_opener()
    redirect_location = None
    try:
        consent_resp = opener.open(consent_post_req, timeout=30)
        # If server returned 200 instead of redirect, check for location
        redirect_location = consent_resp.headers.get("Location")
    except urllib.error.HTTPError as e:
        if e.code in (301, 302, 303, 307):
            redirect_location = e.headers.get("Location", "")
        else:
            resp_text = e.read().decode("utf-8") if e.fp else ""
            raise AssertionError(
                f"Consent approval failed with {e.code}: {resp_text}"
            )

    assert redirect_location, "No redirect Location after consent approval"

    # Step 5: Extract client_id from the redirect URL
    parsed_redirect = urllib.parse.urlparse(redirect_location)
    redirect_query = urllib.parse.parse_qs(parsed_redirect.query)
    client_id = redirect_query.get("client_id", [None])[0]
    assert client_id, f"No client_id in redirect URL: {redirect_location}"
    ctx["oauth_client_id"] = client_id

    # Step 6: Follow the redirect to the broker callback
    try:
        callback_req = urllib.request.Request(redirect_location)
        with urllib.request.urlopen(callback_req, timeout=30) as cb_resp:
            pass  # Callback processed
    except urllib.error.HTTPError:
        pass  # Callback may return HTML or error status, that's fine

    # Step 7: Wait for broker to complete token exchange
    deadline = time.time() + 30
    registration_complete = False

    while time.time() < deadline:
        try:
            status_code, _, status_body = broker_request(
                broker_url, pem_key_path, "GET", "/status"
            )
            if status_code == 200:
                status_data = json.loads(status_body)
                inner = status_data.get("data", status_data)
                if inner.get("registered") is True:
                    registration_complete = True
                    break
                token_status = inner.get("token_status", "")
                if token_status == "valid":
                    registration_complete = True
                    break
        except Exception:
            pass
        time.sleep(0.5)

    assert registration_complete, (
        "Broker registration did not complete within 30s. "
        "Tokens may not have been exchanged."
    )

    ctx["oauth_tokens_stored"] = True
    return ctx


WORKSPACE_OAUTH_REGISTER_NODE = DagNode(
    name="workspace.oauth_register",
    fn=workspace_oauth_register,
    depends_on=["broker.start", "workspace.create"],
    produces=["oauth_client_id", "ws_ed25519_key", "ws_pk_hash", "broker_pem_key_path"],
    consumes=[
        "broker_url", "ws_workspace_id", "base_url",
        "broker_data_dir",
    ],
    critical=True,
    timeout=45.0,
)


# ---------------------------------------------------------------------------
# workspace.oauth_consent_deny
# ---------------------------------------------------------------------------

def workspace_oauth_consent_deny(ctx: dict) -> dict:
    """
    Verify that denying OAuth consent returns a clear error to the broker.

    Initiates an OAuth registration flow for a second workspace, navigates
    to the consent page, clicks "Deny", and verifies the broker receives
    an error callback and surfaces a clear error.

    Consumes: broker_url, base_url, admin_session_cookie
    Produces: oauth_deny_verified
    """
    import subprocess
    import tempfile

    broker_url = ctx["broker_url"]
    base_url = ctx["base_url"]
    admin_cookie = ctx.get("admin_session_cookie", "")
    broker_data_dir = ctx["broker_data_dir"]

    # Generate a separate keypair for the deny-test workspace
    deny_data_dir = tempfile.mkdtemp(prefix="ac_deny_e2e_")
    _, public_key_hex, _ = generate_ed25519_keypair(deny_data_dir)
    pem_key_path = os.path.join(deny_data_dir, "ed25519.pem")

    # Sign the registration payload
    workspace_name = "e2e-deny-workspace"
    scopes = ["credentials:discover"]
    scopes_joined = " ".join(scopes)
    reg_payload_to_sign = f"{workspace_name}\n{public_key_hex}\n{scopes_joined}"

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write(reg_payload_to_sign)
        payload_file = f.name

    try:
        result = subprocess.run(
            [
                "openssl", "pkeyutl", "-sign",
                "-inkey", pem_key_path,
                "-rawin",
                "-in", payload_file,
            ],
            check=True, capture_output=True,
        )
        reg_signature_hex = result.stdout.hex()
    finally:
        os.unlink(payload_file)

    register_body = json.dumps({
        "workspace_name": workspace_name,
        "public_key": public_key_hex,
        "scopes": scopes,
        "signature": reg_signature_hex,
    })

    # POST /register to start OAuth flow
    req = urllib.request.Request(
        f"{broker_url}/register",
        data=register_body.encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            resp_body = json.loads(resp.read())
    except urllib.error.HTTPError as e:
        resp_text = e.read().decode("utf-8") if e.fp else ""
        raise AssertionError(
            f"POST /register failed with {e.code}: {resp_text}"
        )

    data = resp_body.get("data", resp_body)
    auth_url = data.get("authorization_url")
    assert auth_url, f"No authorization_url in register response: {resp_body}"

    # GET the consent page with session cookie to retrieve hidden fields
    consent_headers = {}
    if admin_cookie:
        consent_headers["Cookie"] = admin_cookie

    consent_get_req = urllib.request.Request(auth_url, headers=consent_headers)
    try:
        with urllib.request.urlopen(consent_get_req, timeout=30) as resp:
            consent_html = resp.read().decode("utf-8")
    except urllib.error.HTTPError as e:
        resp_text = e.read().decode("utf-8") if e.fp else ""
        raise AssertionError(
            f"GET consent page failed with {e.code}: {resp_text}"
        )

    # Parse all hidden form fields from the consent HTML
    hidden_fields = _parse_hidden_fields(consent_html)
    assert hidden_fields, "No hidden fields found in consent HTML"

    # Submit consent denial
    hidden_fields["decision"] = "deny"

    deny_body = urllib.parse.urlencode(hidden_fields).encode("utf-8")

    deny_headers = {
        "Content-Type": "application/x-www-form-urlencoded",
    }
    if admin_cookie:
        deny_headers["Cookie"] = admin_cookie

    deny_req = urllib.request.Request(
        f"{base_url}/api/v1/oauth/authorize",
        data=deny_body,
        headers=deny_headers,
        method="POST",
    )

    # The deny should redirect to broker callback with error parameter
    deny_error_received = False
    opener = _no_redirect_opener()
    try:
        deny_resp = opener.open(deny_req, timeout=30)
        # If we get a 200 with error info, that's also valid
        deny_body_text = deny_resp.read().decode("utf-8")
        if "error" in deny_body_text or "denied" in deny_body_text.lower():
            deny_error_received = True
    except urllib.error.HTTPError as e:
        if e.code in (301, 302, 303, 307):
            location = e.headers.get("Location", "")
            if "error=" in location:
                deny_error_received = True
                # Follow the redirect to broker callback
                try:
                    callback_req = urllib.request.Request(location)
                    with urllib.request.urlopen(callback_req, timeout=10) as cb_resp:
                        pass
                except urllib.error.HTTPError:
                    pass  # Broker callback may return error status, that's expected
        elif e.code in (400, 403):
            # Server rejected the deny action directly — also valid
            deny_error_received = True

    assert deny_error_received, (
        "Consent denial did not produce an error response. "
        "The broker should receive an error callback when consent is denied."
    )

    # Verify broker status shows NOT registered for this workspace
    status_code, _, status_body = broker_request(
        broker_url, pem_key_path, "GET", "/status"
    )
    if status_code == 200:
        status_data = json.loads(status_body)
        inner = status_data.get("data", status_data)
        assert inner.get("registered") is not True, (
            "Broker shows registered after consent denial — should not be registered"
        )

    ctx["oauth_deny_verified"] = True
    return ctx


WORKSPACE_OAUTH_CONSENT_DENY_NODE = DagNode(
    name="workspace.oauth_consent_deny",
    fn=workspace_oauth_consent_deny,
    depends_on=["broker.start"],
    produces=["oauth_deny_verified"],
    consumes=["broker_url", "base_url", "broker_data_dir"],
    critical=False,
    timeout=30.0,
)


def get_nodes():
    """Return all OAuth flow DAG nodes."""
    return [WORKSPACE_OAUTH_REGISTER_NODE, WORKSPACE_OAUTH_CONSENT_DENY_NODE]
