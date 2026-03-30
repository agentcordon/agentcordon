"""
E2E test helpers for AgentCordon.

Provides Ed25519 signing, broker lifecycle management, and signed HTTP requests.
Uses openssl CLI for Ed25519 operations (no Python crypto library dependency).
"""

import json
import os
import signal
import socket
import subprocess
import tempfile
import time
import urllib.request
import urllib.error
from typing import Dict, Optional, Tuple


# ---------------------------------------------------------------------------
# Ed25519 key management (via openssl CLI)
# ---------------------------------------------------------------------------

def generate_ed25519_keypair(data_dir: str) -> Tuple[str, str, str]:
    """
    Generate an Ed25519 keypair using openssl.

    Returns (private_key_hex, public_key_hex, pk_hash) where:
      - private_key_hex: 64-char hex of the 32-byte Ed25519 seed
      - public_key_hex: 64-char hex of the 32-byte Ed25519 public key
      - pk_hash: sha256 hex digest of the public key bytes
    """
    import hashlib

    key_path = os.path.join(data_dir, "ed25519.pem")
    pub_path = os.path.join(data_dir, "ed25519.pub.pem")

    # Generate private key in PEM
    subprocess.run(
        ["openssl", "genpkey", "-algorithm", "ed25519", "-out", key_path],
        check=True, capture_output=True,
    )
    # Extract public key PEM
    subprocess.run(
        ["openssl", "pkey", "-in", key_path, "-pubout", "-out", pub_path],
        check=True, capture_output=True,
    )

    # Extract raw private key bytes (seed) from DER
    result = subprocess.run(
        ["openssl", "pkey", "-in", key_path, "-outform", "DER"],
        check=True, capture_output=True,
    )
    # Ed25519 private key DER: 48 bytes total, last 32 bytes are the seed
    der_bytes = result.stdout
    private_seed = der_bytes[-32:]
    private_key_hex = private_seed.hex()

    # Extract raw public key bytes from DER
    result = subprocess.run(
        ["openssl", "pkey", "-in", key_path, "-pubout", "-outform", "DER"],
        check=True, capture_output=True,
    )
    # Ed25519 public key DER: 44 bytes total, last 32 bytes are the key
    pub_der_bytes = result.stdout
    public_key_bytes = pub_der_bytes[-32:]
    public_key_hex = public_key_bytes.hex()

    pk_hash = "sha256:" + hashlib.sha256(public_key_bytes).hexdigest()

    return private_key_hex, public_key_hex, pk_hash


def sign_request(
    pem_key_path: str,
    method: str,
    path: str,
    body: str = "",
    timestamp: Optional[str] = None,
) -> Dict[str, str]:
    """
    Sign a request per the CLI protocol spec using openssl.

    Signed payload: METHOD\\nPATH\\nTIMESTAMP\\nBODY

    Returns dict with X-AC-PublicKey, X-AC-Timestamp, X-AC-Signature headers.
    """
    if timestamp is None:
        timestamp = str(int(time.time()))

    payload = f"{method}\n{path}\n{timestamp}\n{body}"

    # Sign with openssl
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write(payload)
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
        signature_bytes = result.stdout
        signature_hex = signature_bytes.hex()
    finally:
        os.unlink(payload_file)

    # Extract public key hex
    result = subprocess.run(
        ["openssl", "pkey", "-in", pem_key_path, "-pubout", "-outform", "DER"],
        check=True, capture_output=True,
    )
    public_key_hex = result.stdout[-32:].hex()

    return {
        "X-AC-PublicKey": public_key_hex,
        "X-AC-Timestamp": timestamp,
        "X-AC-Signature": signature_hex,
    }


# ---------------------------------------------------------------------------
# Broker lifecycle
# ---------------------------------------------------------------------------

def find_free_port() -> int:
    """Find an available TCP port on localhost."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def start_broker(
    server_url: str,
    data_dir: str,
    broker_binary: Optional[str] = None,
    port: Optional[int] = None,
    timeout: float = 10.0,
) -> Tuple[subprocess.Popen, int, str]:
    """
    Start the broker daemon and wait for it to become healthy.

    Returns (process, port, broker_url).
    """
    if broker_binary is None:
        broker_binary = os.path.join(
            os.environ.get("CARGO_TARGET_DIR", "target"),
            "debug", "agentcordon-broker"
        )

    if port is None:
        port = find_free_port()

    broker_url = f"http://127.0.0.1:{port}"

    env = os.environ.copy()
    env["AGTCRDN_SERVER_URL"] = server_url
    env["AGTCRDN_BROKER_PORT"] = str(port)
    env["AGTCRDN_BROKER_DATA_DIR"] = data_dir
    env["RUST_LOG"] = "info"

    proc = subprocess.Popen(
        [broker_binary, "start", "--port", str(port)],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    # Wait for health check
    deadline = time.time() + timeout
    last_error = None
    while time.time() < deadline:
        try:
            req = urllib.request.Request(f"{broker_url}/health")
            with urllib.request.urlopen(req, timeout=2) as resp:
                if resp.status == 200:
                    body = json.loads(resp.read())
                    if body.get("status") == "ok":
                        return proc, port, broker_url
        except Exception as e:
            last_error = e
            # Check if process died
            if proc.poll() is not None:
                stdout = proc.stdout.read().decode() if proc.stdout else ""
                stderr = proc.stderr.read().decode() if proc.stderr else ""
                raise RuntimeError(
                    f"Broker exited with code {proc.returncode}\n"
                    f"stdout: {stdout}\nstderr: {stderr}"
                )
        time.sleep(0.3)

    # Timed out
    proc.terminate()
    raise TimeoutError(
        f"Broker did not become healthy within {timeout}s. Last error: {last_error}"
    )


def stop_broker(proc: subprocess.Popen, timeout: float = 5.0):
    """Gracefully stop the broker daemon."""
    if proc.poll() is not None:
        return  # Already exited
    proc.send_signal(signal.SIGTERM)
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=2)


# ---------------------------------------------------------------------------
# Signed HTTP requests to broker
# ---------------------------------------------------------------------------

def broker_request(
    broker_url: str,
    pem_key_path: str,
    method: str,
    path: str,
    body: Optional[str] = None,
    extra_headers: Optional[Dict[str, str]] = None,
) -> Tuple[int, dict, str]:
    """
    Make a signed HTTP request to the broker.

    Returns (status_code, response_headers_dict, response_body_str).
    """
    body_str = body if body else ""

    sig_headers = sign_request(pem_key_path, method, path, body=body_str)

    headers = dict(sig_headers)
    if body:
        headers["Content-Type"] = "application/json"
    if extra_headers:
        headers.update(extra_headers)

    url = f"{broker_url}{path}"
    data = body_str.encode("utf-8") if body else None

    req = urllib.request.Request(url, data=data, headers=headers, method=method)

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            resp_body = resp.read().decode("utf-8")
            resp_headers = dict(resp.headers)
            return resp.status, resp_headers, resp_body
    except urllib.error.HTTPError as e:
        resp_body = e.read().decode("utf-8") if e.fp else ""
        resp_headers = dict(e.headers) if e.headers else {}
        return e.code, resp_headers, resp_body


# ---------------------------------------------------------------------------
# Server HTTP helpers
# ---------------------------------------------------------------------------

def server_request(
    base_url: str,
    method: str,
    path: str,
    body: Optional[str] = None,
    headers: Optional[Dict[str, str]] = None,
    cookies: Optional[str] = None,
) -> Tuple[int, dict, str]:
    """
    Make an HTTP request to the AgentCordon server.

    Returns (status_code, response_headers_dict, response_body_str).
    """
    url = f"{base_url}{path}"
    data = body.encode("utf-8") if body else None

    req_headers = headers or {}
    if body and "Content-Type" not in req_headers:
        req_headers["Content-Type"] = "application/json"
    if cookies:
        req_headers["Cookie"] = cookies

    req = urllib.request.Request(url, data=data, headers=req_headers, method=method)

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            resp_body = resp.read().decode("utf-8")
            resp_headers = dict(resp.headers)
            return resp.status, resp_headers, resp_body
    except urllib.error.HTTPError as e:
        resp_body = e.read().decode("utf-8") if e.fp else ""
        resp_headers = dict(e.headers) if e.headers else {}
        return e.code, resp_headers, resp_body


def wait_for_server(base_url: str, timeout: float = 15.0):
    """Wait for the server to be reachable."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            req = urllib.request.Request(f"{base_url}/health")
            with urllib.request.urlopen(req, timeout=2) as resp:
                if resp.status == 200:
                    return
        except Exception:
            time.sleep(0.3)
    raise TimeoutError(f"Server at {base_url} not reachable within {timeout}s")
