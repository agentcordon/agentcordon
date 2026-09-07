#!/usr/bin/env python3
"""Mock upstream for the AgentCordon UAT harness.

Serves on UAT_BIND:UAT_UPSTREAM_PORT (default 0.0.0.0:8080).

Environment:
  UAT_UPSTREAM_PORT  listen port (default 8080)
  UAT_BIND           bind address (default 0.0.0.0, so the containerised harness
                     is reachable from the other containers; set 127.0.0.1 to
                     keep it off a shared host's interfaces)
  UAT_UPSTREAM_HOST  host:port the /redirect Location header points back at
                     (default upstream:<UAT_UPSTREAM_PORT>, the Docker network
                     alias uat/run.sh gives this container)

  /redirect  -> 302 to /secret (Location header set)
  /secret    -> the "secret page" a redirect-follower would leak to
  /sigv4     -> verifies an AWS SigV4 signature (S14)
  /oauth-api -> requires a bearer issued by the mock IdP (S11)
  anything   -> 200 JSON echo of {method, path, headers, body}

The echo deliberately reflects every request header (including the injected
Authorization header) so the broker's leak scanner can be observed at work.

Harness infrastructure only: nothing here is a product claim.
"""

import hashlib
import hmac
import json
import os
import urllib.request
import urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# ---------------------------------------------------------------- SigV4 config
#
# Fixed test credential. The UAT admin stores exactly these values through the
# admin UI; this file is the verifying "AWS".
SIGV4_ACCESS_KEY_ID = os.environ.get("UAT_AWS_ACCESS_KEY_ID", "AKIAUATEXAMPLE")
SIGV4_SECRET_ACCESS_KEY = os.environ.get(
    "UAT_AWS_SECRET_ACCESS_KEY", "uat-aws-secret-key-value"
)
SIGV4_REGION = os.environ.get("UAT_AWS_REGION", "us-east-1")
SIGV4_SERVICE = os.environ.get("UAT_AWS_SERVICE", "execute-api")

# ---------------------------------------------------------------- listen config
PORT = int(os.environ.get("UAT_UPSTREAM_PORT", "8080"))
BIND = os.environ.get("UAT_BIND", "0.0.0.0")
# host:port the /redirect Location points at. Defaults to this container's
# Docker network alias so a redirect-follower lands back here.
REDIRECT_HOST = os.environ.get("UAT_UPSTREAM_HOST", "upstream:%d" % PORT)

# Where /oauth-api validates bearer tokens. The mock IdP shares the server
# container's network namespace, so from this container it is `server:9000`.
IDP_URL = os.environ.get("UAT_IDP_URL", "http://server:9000")

# Services that follow the S3 signing conventions (single-encoded canonical
# URI). Mirrors crates/core/src/transform/builtins/aws_sigv4.rs.
S3_SERVICES = {"s3", "s3express", "s3-object-lambda", "s3-outposts"}

UNRESERVED = set(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.~"
)


def uri_encode(value, encode_slash):
    out = []
    for byte in value.encode("utf-8"):
        ch = chr(byte)
        if ch in UNRESERVED:
            out.append(ch)
        elif ch == "/" and not encode_slash:
            out.append("/")
        else:
            out.append("%%%02X" % byte)
    return "".join(out)


def percent_decode(value):
    raw = bytearray()
    data = value.encode("utf-8")
    i = 0
    while i < len(data):
        if data[i:i + 1] == b"%" and i + 2 < len(data):
            try:
                raw.append(int(data[i + 1:i + 3].decode("ascii"), 16))
                i += 3
                continue
            except ValueError:
                pass
        raw.append(data[i])
        i += 1
    return raw.decode("utf-8", "replace")


def canonical_uri_path(path, double_encode):
    if not path or path == "/":
        return "/"
    segments = []
    for segment in path.split("/"):
        once = uri_encode(percent_decode(segment), False)
        segments.append(uri_encode(once, False) if double_encode else once)
    return "/".join(segments)


def canonical_query_string(query):
    if not query:
        return ""
    params = []
    for pair in query.split("&"):
        key, sep, value = pair.partition("=")
        params.append(
            (
                uri_encode(percent_decode(key), True),
                uri_encode(percent_decode(value), True),
            )
        )
    params.sort()
    return "&".join("%s=%s" % (k, v) for k, v in params)


def canonical_header_value(value):
    return " ".join(value.split())


def hmac_sha256(key, data):
    return hmac.new(key, data.encode("utf-8"), hashlib.sha256).digest()


def parse_authorization(header):
    """Parse an `AWS4-HMAC-SHA256 Credential=..., SignedHeaders=..., Signature=...`
    header into a dict, or return None."""
    if not header or not header.startswith("AWS4-HMAC-SHA256 "):
        return None
    parts = {}
    for chunk in header[len("AWS4-HMAC-SHA256 "):].split(","):
        key, sep, value = chunk.strip().partition("=")
        if sep:
            parts[key.strip()] = value.strip()
    if not {"Credential", "SignedHeaders", "Signature"} <= set(parts):
        return None
    cred = parts["Credential"].split("/")
    if len(cred) != 5:
        return None
    return {
        "access_key_id": cred[0],
        "date_stamp": cred[1],
        "region": cred[2],
        "service": cred[3],
        "terminator": cred[4],
        "credential_scope": "/".join(cred[1:]),
        "signed_headers": parts["SignedHeaders"].split(";"),
        "signature": parts["Signature"],
    }


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        print("upstream %s - %s" % (self.address_string(), fmt % args), flush=True)

    def _body(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            return ""
        return self.rfile.read(length).decode("utf-8", "replace")

    def _send(self, code, payload, extra_headers=None, content_type="application/json"):
        raw = payload.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("X-Uat-Upstream", "mock")
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(raw)

    # ------------------------------------------------------------- /sigv4
    def handle_sigv4(self, path, query, body):
        auth = parse_authorization(self.headers.get("Authorization"))
        if auth is None:
            self._send(
                403,
                json.dumps(
                    {
                        "ok": False,
                        "error": "missing or malformed AWS4-HMAC-SHA256 Authorization header",
                        "received_authorization": self.headers.get("Authorization"),
                    }
                ),
            )
            return

        if auth["access_key_id"] != SIGV4_ACCESS_KEY_ID:
            self._send(
                403,
                json.dumps(
                    {
                        "ok": False,
                        "error": "unknown access key id",
                        "access_key_id": auth["access_key_id"],
                    }
                ),
            )
            return
        if auth["region"] != SIGV4_REGION or auth["service"] != SIGV4_SERVICE:
            self._send(
                403,
                json.dumps(
                    {
                        "ok": False,
                        "error": "credential scope does not match this endpoint",
                        "expected": "%s/%s" % (SIGV4_REGION, SIGV4_SERVICE),
                        "received": "%s/%s" % (auth["region"], auth["service"]),
                    }
                ),
            )
            return

        amz_date = self.headers.get("X-Amz-Date") or ""
        if not amz_date:
            self._send(403, json.dumps({"ok": False, "error": "missing x-amz-date"}))
            return

        # Rebuild the canonical request from the headers the signer listed.
        header_lines = []
        missing = []
        for name in auth["signed_headers"]:
            value = self.headers.get(name)
            if value is None and name == "host":
                value = self.headers.get("Host")
            if value is None:
                missing.append(name)
                continue
            header_lines.append("%s:%s\n" % (name, canonical_header_value(value)))
        if missing:
            self._send(
                403,
                json.dumps(
                    {
                        "ok": False,
                        "error": "signed header absent from the request",
                        "missing": missing,
                        "signed_headers": auth["signed_headers"],
                    }
                ),
            )
            return

        payload_hash = hashlib.sha256(body.encode("utf-8")).hexdigest()
        double_encode = auth["service"] not in S3_SERVICES
        # Canonical request: the header block's own trailing newline plus the
        # separator newline produce the blank line AWS requires before
        # SignedHeaders.
        canonical_request = "%s\n%s\n%s\n%s\n%s\n%s" % (
            self.command.upper(),
            canonical_uri_path(path, double_encode),
            canonical_query_string(query),
            "".join(header_lines),
            ";".join(auth["signed_headers"]),
            payload_hash,
        )

        string_to_sign = "\n".join(
            [
                "AWS4-HMAC-SHA256",
                amz_date,
                auth["credential_scope"],
                hashlib.sha256(canonical_request.encode("utf-8")).hexdigest(),
            ]
        )

        k_date = hmac_sha256(
            ("AWS4" + SIGV4_SECRET_ACCESS_KEY).encode("utf-8"), auth["date_stamp"]
        )
        k_region = hmac_sha256(k_date, auth["region"])
        k_service = hmac_sha256(k_region, auth["service"])
        k_signing = hmac_sha256(k_service, "aws4_request")
        expected = hmac.new(
            k_signing, string_to_sign.encode("utf-8"), hashlib.sha256
        ).hexdigest()

        if not hmac.compare_digest(expected, auth["signature"]):
            self._send(
                403,
                json.dumps(
                    {
                        "ok": False,
                        "error": "signature mismatch",
                        "canonical_request": canonical_request,
                        "string_to_sign": string_to_sign,
                        "expected_signature": expected,
                        "received_signature": auth["signature"],
                    }
                ),
            )
            return

        self._send(
            200,
            json.dumps(
                {
                    "ok": True,
                    "sigv4_verified": True,
                    "access_key_id": auth["access_key_id"],
                    "credential_scope": auth["credential_scope"],
                    "signed_headers": auth["signed_headers"],
                    "canonical_uri": canonical_uri_path(path, double_encode),
                    "canonical_query_string": canonical_query_string(query),
                    "amz_date": amz_date,
                    "method": self.command,
                    "path": self.path,
                }
            ),
        )

    # --------------------------------------------------------- /oauth-api
    def handle_oauth_api(self):
        auth = self.headers.get("Authorization") or ""
        if not auth.lower().startswith("bearer "):
            self._send(
                401,
                json.dumps({"error": "missing bearer token"}),
                extra_headers={"WWW-Authenticate": 'Bearer realm="uat-upstream"'},
            )
            return
        token = auth.split(None, 1)[1].strip()
        try:
            req = urllib.request.Request(
                IDP_URL + "/_uat/validate",
                data=json.dumps({"token": token}).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                info = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            self._send(
                401,
                json.dumps(
                    {
                        "error": "token rejected by the issuer",
                        "issuer_status": e.code,
                        "token_fingerprint": hashlib.sha256(
                            token.encode("utf-8")
                        ).hexdigest()[:16],
                    }
                ),
                extra_headers={"WWW-Authenticate": 'Bearer error="invalid_token"'},
            )
            return
        except Exception as e:  # network problem talking to the mock IdP
            self._send(502, json.dumps({"error": "cannot reach the mock IdP: %s" % e}))
            return

        self._send(
            200,
            json.dumps(
                {
                    "ok": True,
                    "subject": info.get("subject"),
                    "grant": info.get("grant"),
                    "client_id": info.get("client_id"),
                    "scope": info.get("scope"),
                    "token_fingerprint": hashlib.sha256(
                        token.encode("utf-8")
                    ).hexdigest()[:16],
                }
            ),
        )

    def handle_any(self):
        path, _, query = self.path.partition("?")
        body = self._body()

        if path == "/redirect":
            self._send(
                302,
                json.dumps({"redirect": "/secret"}),
                extra_headers={"Location": "http://%s/secret" % REDIRECT_HOST},
            )
            return

        if path == "/secret":
            self._send(
                200,
                json.dumps({"secret_page": True, "message": "you followed the redirect"}),
            )
            return

        if path == "/sigv4" or path.startswith("/sigv4/"):
            self.handle_sigv4(path, query, body)
            return

        if path == "/oauth-api" or path.startswith("/oauth-api/"):
            self.handle_oauth_api()
            return

        echo = {
            "method": self.command,
            "path": self.path,
            "headers": {k: v for k, v in self.headers.items()},
            "body": body,
        }
        self._send(200, json.dumps(echo))

    do_GET = handle_any
    do_POST = handle_any
    do_PUT = handle_any
    do_DELETE = handle_any
    do_PATCH = handle_any
    do_HEAD = handle_any


if __name__ == "__main__":
    print("mock_upstream listening on %s:%d" % (BIND, PORT), flush=True)
    ThreadingHTTPServer((BIND, PORT), Handler).serve_forever()
