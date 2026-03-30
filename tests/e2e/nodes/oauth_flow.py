"""
DAG node for workspace OAuth registration flow: workspace.oauth_register.
"""

import hashlib
import json
import os
import time
import urllib.request
import urllib.error

from tests.e2e.dag_runner import DagNode
from tests.e2e.helpers import (
    broker_request,
    generate_ed25519_keypair,
    server_request,
    sign_request,
)


# ---------------------------------------------------------------------------
# workspace.oauth_register
# ---------------------------------------------------------------------------

def workspace_oauth_register(ctx: dict) -> dict:
    """
    Full OAuth registration flow:
      1. Generate Ed25519 keypair for the workspace
      2. POST /register to broker with workspace name + public key + scopes
      3. Broker registers OAuth client with server, returns authorization_url
      4. Programmatically approve consent via server admin API
      5. Broker receives callback, exchanges code for tokens
      6. Verify registration is complete

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
    # The register endpoint is special: it takes a self-signed body (not the
    # standard header-based auth, since the workspace isn't registered yet).
    scopes = ["credentials:discover", "credentials:vend"]

    # Sign the registration payload: workspace_name || public_key || scopes_joined
    scopes_joined = " ".join(scopes)
    reg_payload_to_sign = f"{workspace_name}{public_key_hex}{scopes_joined}"

    # Sign using openssl
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

    # Step 3: Extract OAuth parameters from the authorization URL
    from urllib.parse import urlparse, parse_qs
    parsed = urlparse(auth_url)
    query = parse_qs(parsed.query)

    client_id = query.get("client_id", [None])[0]
    state = query.get("state", [None])[0]
    scope = query.get("scope", [None])[0]
    code_challenge = query.get("code_challenge", [None])[0]
    redirect_uri = query.get("redirect_uri", [None])[0]

    assert client_id, f"No client_id in auth URL: {auth_url}"
    ctx["oauth_client_id"] = client_id

    # Step 4: Programmatically approve consent via server admin API
    # POST to the server's authorize endpoint to simulate user clicking "Approve"
    consent_body = urllib.parse.urlencode({
        "client_id": client_id,
        "scope": scope or scopes_joined,
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "action": "approve",
    }).encode("utf-8")

    consent_headers = {
        "Content-Type": "application/x-www-form-urlencoded",
    }
    if admin_cookie:
        consent_headers["Cookie"] = admin_cookie

    # Use the admin storage state / session to approve
    consent_req = urllib.request.Request(
        f"{base_url}/api/v1/oauth/authorize",
        data=consent_body,
        headers=consent_headers,
        method="POST",
    )

    # The consent approval should redirect to the broker's callback
    # We follow the redirect chain or handle the 302
    import urllib.parse

    opener = urllib.request.build_opener(
        urllib.request.HTTPRedirectHandler()
    )

    try:
        consent_resp = opener.open(consent_req, timeout=30)
        consent_status = consent_resp.status
    except urllib.error.HTTPError as e:
        # A 302 redirect is expected — follow it
        if e.code in (301, 302, 303, 307):
            location = e.headers.get("Location", "")
            # The redirect should go to broker's callback with ?code=...&state=...
            if "code=" in location:
                # Make the callback request to the broker
                callback_req = urllib.request.Request(location)
                try:
                    with urllib.request.urlopen(callback_req, timeout=30) as cb_resp:
                        pass  # Callback processed
                except urllib.error.HTTPError:
                    pass  # Callback may return HTML, that's fine
            consent_status = 200  # Consider redirect as success
        else:
            resp_text = e.read().decode("utf-8") if e.fp else ""
            raise AssertionError(
                f"Consent approval failed with {e.code}: {resp_text}"
            )

    # Step 5: Wait for broker to complete token exchange
    # Poll broker's /status endpoint for this workspace
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


def get_nodes():
    """Return all OAuth flow DAG nodes."""
    return [WORKSPACE_OAUTH_REGISTER_NODE]
