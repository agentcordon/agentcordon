#!/usr/bin/env python3
"""Mock OAuth 2.0 authorization server for the AgentCordon UAT harness.

Harness infrastructure. It stands in for a real identity provider; nothing
here is a product claim.

It is started in the *server container's network namespace*, so the
AgentCordon server reaches it at `http://127.0.0.1:<port>` and the host
browser reaches it on the port the server container publishes. That matters
twice over:

  * `POST /api/v1/credentials` refuses a plain-HTTP `oauth2_token_endpoint`
    on any host other than `localhost`/`127.0.0.1`/`::1`
    (`crates/server/src/routes/admin_api/credentials/create.rs`), and
  * `crates/server/src/oauth_discovery` refuses plain HTTP to any host other
    than `localhost`/`127.0.0.1`.

TWO LISTENERS, because AgentCordon keys a provider client on the
authorization server's *origin* (scheme://host:port, path discarded), so the
DCR and the manual-provider-client paths cannot share a port:

  :9000  issuer http://127.0.0.1:9000  -- publishes `registration_endpoint`,
         so `oauth_discovery::ensure_provider_client` registers dynamically
         (RFC 7591).
  :9001  issuer http://127.0.0.1:9001  -- no `registration_endpoint`, so
         discovery returns `NoDcrSupport` and an admin has to add the client
         by hand under Settings > OAuth Provider Clients.

Endpoints on each listener:

  GET  /.well-known/oauth-authorization-server   RFC 8414 metadata
  GET  /.well-known/oauth-protected-resource     RFC 9728 (this origin is
                                                 also its own resource, see
                                                 uat/REPORT.md)
  GET  /authorize          minimal HTML consent page with an Approve button
  POST /authorize/decision the Approve button's target
  POST /token              authorization_code (PKCE S256),
                           refresh_token (rotating), client_credentials
  POST /register           RFC 7591 -- :9000 only

Environment:
  UAT_IDP_PORT           DCR listener port (default 9000)
  UAT_IDP_NODCR_PORT     no-DCR listener port (default 9001)
  UAT_IDP_HOST           host the issuer URLs name (default 127.0.0.1)
  UAT_BIND               bind address for both listeners (default 0.0.0.0, so
                         the containerised harness is reachable from the other
                         containers; set 127.0.0.1 to keep it off a shared
                         host's interfaces)
  UAT_IDP_DELEGATED_TTL  delegated access-token lifetime, seconds (default 100)
  UAT_IDP_SUBJECT        subject for the delegated grants

Observation endpoints (not part of any standard, prefixed `_uat`):

  POST /_uat/validate   {"token": "..."} -> 200 token facts, 401 if unknown
  GET  /_uat/log        every authorize / token / register call, with the
                        caller's address, so a test can assert that the
                        BROKER never called the token endpoint
  GET  /_uat/tokens     issued tokens (fingerprints only)
  GET  /_uat/clients    registered clients (no secrets)
  POST /_uat/reset      clear the log and the issued tokens
  GET  /_uat/health
"""

import base64
import hashlib
import json
import os
import secrets
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

DCR_PORT = int(os.environ.get("UAT_IDP_PORT", "9000"))
NODCR_PORT = int(os.environ.get("UAT_IDP_NODCR_PORT", "9001"))
HOST_FOR_ISSUER = os.environ.get("UAT_IDP_HOST", "127.0.0.1")
# Bind address for both listeners. 0.0.0.0 by default so the containerised
# harness stays reachable; 127.0.0.1 keeps it off a shared host's interfaces.
# Mirrors uat/mock_upstream.py.
BIND = os.environ.get("UAT_BIND", "0.0.0.0")

# Access-token lifetime for the delegated grants. Deliberately short so a UAT
# run can watch the server refresh and the provider rotate the refresh token
# without waiting minutes. The broker re-syncs when a cached upstream token is
# within 60s of expiry, so anything above ~70s produces one refresh per wait.
DELEGATED_TTL = int(os.environ.get("UAT_IDP_DELEGATED_TTL", "100"))

SUBJECT = os.environ.get("UAT_IDP_SUBJECT", "uat-delegated-user@example.test")

LOCK = threading.Lock()

CLIENTS = {}         # (port, client_id) -> record
AUTH_CODES = {}      # code -> record
ACCESS_TOKENS = {}   # token -> record
REFRESH_TOKENS = {}  # token -> record
PENDING = {}         # request_id -> authorize request
LOG = []


def register_static_clients():
    static = [
        # S11: the application credential. The admin stores the client id and
        # secret as an `oauth2_client_credentials` credential; the SERVER
        # exchanges them here.
        (
            DCR_PORT,
            {
                "client_id": "uat-app-client",
                "client_secret": "uat-app-client-secret",
                "grant_types": ["client_credentials"],
                "token_endpoint_auth_method": "client_secret_post",
                "access_token_ttl": 120,
                "client_name": "UAT application client",
            },
        ),
        # The same thing with a lifetime short enough that a UAT step can
        # observe the server's token cache expiring and re-exchanging. The
        # server treats a cached token as expired 30s early
        # (EXPIRY_BUFFER_SECS, crates/core/src/oauth2/token_manager.rs), so a
        # 40s lifetime caches for about 10s.
        (
            DCR_PORT,
            {
                "client_id": "uat-app-client-short",
                "client_secret": "uat-app-client-short-secret",
                "grant_types": ["client_credentials"],
                "token_endpoint_auth_method": "client_secret_post",
                "access_token_ttl": 40,
                "client_name": "UAT application client (short-lived tokens)",
            },
        ),
        # S12b: the manual provider client. :9001 publishes no registration
        # endpoint, so these two values have to be typed into the admin UI.
        (
            NODCR_PORT,
            {
                "client_id": "uat-manual-client",
                "client_secret": "uat-manual-client-secret",
                "grant_types": ["authorization_code", "refresh_token"],
                "token_endpoint_auth_method": "client_secret_post",
                "access_token_ttl": DELEGATED_TTL,
                "client_name": "UAT manual provider client",
            },
        ),
    ]
    for port, record in static:
        record = dict(record, static=True, port=port)
        CLIENTS[(port, record["client_id"])] = record


register_static_clients()


def now():
    return time.time()


def issuer(port):
    return "http://%s:%d" % (HOST_FOR_ISSUER, port)


def log_call(kind, port, **fields):
    with LOCK:
        entry = {"seq": len(LOG) + 1, "at": round(now(), 3), "kind": kind, "port": port}
        entry.update(fields)
        LOG.append(entry)
    print("idp:%d %s %s" % (port, kind, json.dumps(fields)), flush=True)


def fingerprint(value):
    if not value:
        return None
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


def issue_access_token(port, client_id, grant, subject, scope, ttl):
    token = "uat_at_" + secrets.token_urlsafe(24)
    with LOCK:
        ACCESS_TOKENS[token] = {
            "port": port,
            "client_id": client_id,
            "grant": grant,
            "subject": subject,
            "scope": scope,
            "issued_at": now(),
            "expires_at": now() + ttl,
        }
    return token


def issue_refresh_token(port, client_id, subject, scope, generation):
    token = "uat_rt_" + secrets.token_urlsafe(24)
    with LOCK:
        REFRESH_TOKENS[token] = {
            "port": port,
            "client_id": client_id,
            "subject": subject,
            "scope": scope,
            "generation": generation,
            "used": False,
            "issued_at": now(),
        }
    return token


def as_metadata(port, dcr):
    base = issuer(port)
    doc = {
        "issuer": base,
        "authorization_endpoint": base + "/authorize",
        "token_endpoint": base + "/token",
        "scopes_supported": ["openid", "profile", "uat.read", "uat.write"],
        "response_types_supported": ["code"],
        "response_modes_supported": ["query"],
        "grant_types_supported": [
            "authorization_code",
            "refresh_token",
            "client_credentials",
        ],
        "token_endpoint_auth_methods_supported": [
            "client_secret_post",
            "client_secret_basic",
        ],
        "code_challenge_methods_supported": ["S256"],
        "service_documentation": "https://example.test/uat-mock-idp",
    }
    if dcr:
        doc["registration_endpoint"] = base + "/register"
    return doc


def protected_resource_metadata(port):
    """This origin doubles as its own protected resource.

    AgentCordon's discovery requires the authorization, token and registration
    endpoints to share an origin with `oauth2_resource_url`
    (`validate_endpoint_origin`, crates/server/src/oauth_discovery/client.rs),
    so a UAT template whose resource URL is the MCP server's own origin cannot
    be provisioned. See uat/REPORT.md.
    """
    base = issuer(port)
    return {
        "resource": base,
        "authorization_servers": [base],
        "bearer_methods_supported": ["header"],
        "resource_documentation": "https://example.test/uat-mock-idp",
    }


CONSENT_PAGE = """<!doctype html>
<html><head><meta charset="utf-8"><title>UAT IdP - Authorize</title>
<style>
 body {{ font-family: system-ui, sans-serif; max-width: 36rem; margin: 4rem auto; }}
 .card {{ border: 1px solid #ccc; border-radius: 8px; padding: 1.5rem 2rem; }}
 dt {{ font-weight: 600; margin-top: .6rem; }}
 dd {{ margin: 0; font-family: ui-monospace, monospace; word-break: break-all; }}
 button {{ font-size: 1rem; padding: .6rem 1.4rem; margin-right: .8rem; }}
 #approve {{ background: #1a7f37; color: #fff; border: 0; border-radius: 6px; }}
 #deny {{ background: #eee; border: 1px solid #bbb; border-radius: 6px; }}
</style></head>
<body>
<div class="card">
  <h1 id="consent-heading">Authorize {client_name}</h1>
  <p id="consent-subject">Signed in as <strong>{subject}</strong></p>
  <dl>
    <dt>Issuer</dt><dd id="consent-issuer">{issuer}</dd>
    <dt>Client ID</dt><dd id="consent-client-id">{client_id}</dd>
    <dt>Redirect URI</dt><dd id="consent-redirect-uri">{redirect_uri}</dd>
    <dt>Scopes</dt><dd id="consent-scope">{scope}</dd>
    <dt>PKCE</dt><dd id="consent-pkce">{pkce}</dd>
  </dl>
  <form method="POST" action="/authorize/decision">
    <input type="hidden" name="request_id" value="{request_id}">
    <button id="approve" name="decision" value="approve" type="submit">Approve</button>
    <button id="deny" name="decision" value="deny" type="submit">Deny</button>
  </form>
</div>
</body></html>
"""


def make_handler(port, dcr):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = "uat-mock-idp/1.0"

        # ---------------------------------------------------------- plumbing
        def log_message(self, fmt, *args):
            print("idp:%d %s - %s" % (port, self.address_string(), fmt % args), flush=True)

        def _read_body(self):
            length = int(self.headers.get("Content-Length") or 0)
            if length <= 0:
                return b""
            return self.rfile.read(length)

        def _form(self):
            ctype = (self.headers.get("Content-Type") or "").split(";")[0].strip()
            raw = self._read_body()
            if ctype == "application/json":
                try:
                    return json.loads(raw.decode("utf-8")), raw
                except Exception:
                    return {}, raw
            parsed = urllib.parse.parse_qs(raw.decode("utf-8"), keep_blank_values=True)
            return {k: v[0] for k, v in parsed.items()}, raw

        def _json(self, code, payload, extra_headers=None):
            raw = json.dumps(payload).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(raw)))
            for k, v in (extra_headers or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(raw)

        def _html(self, code, body):
            raw = body.encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def _redirect(self, location):
            self.send_response(302)
            self.send_header("Location", location)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def _error(self, code, err, description):
            self._json(code, {"error": err, "error_description": description})

        def _peer(self):
            try:
                return self.client_address[0]
            except Exception:
                return "?"

        # ----------------------------------------------------------- routing
        def do_GET(self):
            path, _, query = self.path.partition("?")
            params = {
                k: v[0]
                for k, v in urllib.parse.parse_qs(query, keep_blank_values=True).items()
            }

            if path in (
                "/.well-known/oauth-authorization-server",
                "/.well-known/openid-configuration",
            ):
                self._json(200, as_metadata(port, dcr))
                return
            if path == "/.well-known/oauth-protected-resource":
                self._json(200, protected_resource_metadata(port))
                return
            if path == "/authorize":
                self.handle_authorize(params)
                return
            if path == "/_uat/health":
                self._json(200, {"ok": True, "issuer": issuer(port), "dcr": dcr})
                return
            if path == "/_uat/log":
                with LOCK:
                    self._json(200, {"entries": list(LOG)})
                return
            if path == "/_uat/clients":
                with LOCK:
                    self._json(
                        200,
                        {
                            "clients": [
                                {k: v for k, v in c.items() if k != "client_secret"}
                                for c in CLIENTS.values()
                            ]
                        },
                    )
                return
            if path == "/_uat/tokens":
                with LOCK:
                    self._json(
                        200,
                        {
                            "access_tokens": [
                                dict(v, fingerprint=fingerprint(k))
                                for k, v in ACCESS_TOKENS.items()
                            ],
                            "refresh_tokens": [
                                dict(v, fingerprint=fingerprint(k))
                                for k, v in REFRESH_TOKENS.items()
                            ],
                        },
                    )
                return
            self._error(404, "not_found", "no such endpoint: %s" % path)

        def do_POST(self):
            path, _, _q = self.path.partition("?")
            if path == "/token":
                self.handle_token()
                return
            if path == "/authorize/decision":
                self.handle_decision()
                return
            if path == "/register":
                if not dcr:
                    self._error(
                        404,
                        "not_found",
                        "this authorization server does not support dynamic client registration",
                    )
                    return
                self.handle_register()
                return
            if path == "/_uat/validate":
                body, _ = self._form()
                self.handle_validate(body.get("token"))
                return
            if path == "/_uat/reset":
                with LOCK:
                    LOG.clear()
                    ACCESS_TOKENS.clear()
                    REFRESH_TOKENS.clear()
                    AUTH_CODES.clear()
                    PENDING.clear()
                    for key in [k for k, v in CLIENTS.items() if not v.get("static")]:
                        del CLIENTS[key]
                self._json(200, {"ok": True})
                return
            self._error(404, "not_found", "no such endpoint: %s" % path)

        # -------------------------------------------------------- /authorize
        def handle_authorize(self, params):
            client_id = params.get("client_id", "")
            redirect_uri = params.get("redirect_uri", "")
            state = params.get("state", "")
            scope = params.get("scope", "")
            challenge = params.get("code_challenge", "")
            method = params.get("code_challenge_method", "")

            log_call(
                "authorize",
                port,
                client_id=client_id,
                redirect_uri=redirect_uri,
                scope=scope,
                code_challenge_method=method or None,
                remote_addr=self._peer(),
            )

            client = CLIENTS.get((port, client_id))
            if client is None:
                self._html(
                    400,
                    "<h1>unknown client</h1><p>client_id=%s is not registered at %s</p>"
                    % (client_id, issuer(port)),
                )
                return
            if not redirect_uri:
                self._html(400, "<h1>missing redirect_uri</h1>")
                return
            if challenge and method != "S256":
                self._html(
                    400,
                    "<h1>unsupported code_challenge_method</h1><p>only S256 is supported</p>",
                )
                return

            request_id = secrets.token_urlsafe(16)
            with LOCK:
                PENDING[request_id] = {
                    "port": port,
                    "client_id": client_id,
                    "redirect_uri": redirect_uri,
                    "state": state,
                    "scope": scope,
                    "code_challenge": challenge,
                    "created_at": now(),
                }
            self._html(
                200,
                CONSENT_PAGE.format(
                    client_name=client.get("client_name", client_id),
                    client_id=client_id,
                    redirect_uri=redirect_uri,
                    scope=scope or "(none requested)",
                    pkce="S256" if challenge else "none",
                    subject=SUBJECT,
                    request_id=request_id,
                    issuer=issuer(port),
                ),
            )

        def handle_decision(self):
            body, _ = self._form()
            request_id = body.get("request_id", "")
            decision = body.get("decision", "deny")
            with LOCK:
                pending = PENDING.pop(request_id, None)
            if pending is None:
                self._html(400, "<h1>unknown or expired authorization request</h1>")
                return

            sep = "&" if "?" in pending["redirect_uri"] else "?"
            if decision != "approve":
                self._redirect(
                    pending["redirect_uri"]
                    + sep
                    + urllib.parse.urlencode(
                        {"error": "access_denied", "state": pending["state"]}
                    )
                )
                return

            code = "uat_code_" + secrets.token_urlsafe(20)
            with LOCK:
                AUTH_CODES[code] = dict(pending, subject=SUBJECT, expires_at=now() + 300)
            log_call(
                "authorize_approved",
                port,
                client_id=pending["client_id"],
                subject=SUBJECT,
                remote_addr=self._peer(),
            )
            self._redirect(
                pending["redirect_uri"]
                + sep
                + urllib.parse.urlencode({"code": code, "state": pending["state"]})
            )

        # ------------------------------------------------------------ /token
        def _client_auth(self, form):
            client_id = form.get("client_id")
            client_secret = form.get("client_secret")
            header = self.headers.get("Authorization") or ""
            if header.lower().startswith("basic "):
                try:
                    decoded = base64.b64decode(header.split(None, 1)[1]).decode("utf-8")
                    basic_id, _, basic_secret = decoded.partition(":")
                    client_id = client_id or urllib.parse.unquote(basic_id)
                    client_secret = client_secret or urllib.parse.unquote(basic_secret)
                except Exception:
                    return None, "invalid_client", "malformed Basic authorization header"
            if not client_id:
                return None, "invalid_client", "no client_id presented"
            client = CLIENTS.get((port, client_id))
            if client is None:
                return None, "invalid_client", "unknown client_id"
            if client.get("token_endpoint_auth_method") == "none":
                return client, None, None
            if client_secret != client.get("client_secret"):
                return None, "invalid_client", "client authentication failed"
            return client, None, None

        def handle_token(self):
            form, _ = self._form()
            grant = form.get("grant_type", "")
            presented_refresh = form.get("refresh_token")
            log_call(
                "token",
                port,
                grant_type=grant,
                client_id=form.get("client_id"),
                has_client_secret=bool(form.get("client_secret"))
                or (self.headers.get("Authorization") or "")
                .lower()
                .startswith("basic "),
                refresh_token_presented=fingerprint(presented_refresh),
                code_verifier_presented=bool(form.get("code_verifier")),
                remote_addr=self._peer(),
                user_agent=self.headers.get("User-Agent"),
            )

            client, err, desc = self._client_auth(form)
            if err:
                self._error(401, err, desc)
                return

            if grant == "client_credentials":
                scope = form.get("scope", "")
                ttl = client.get("access_token_ttl", 120)
                token = issue_access_token(
                    port,
                    client["client_id"],
                    "client_credentials",
                    client["client_id"],
                    scope,
                    ttl,
                )
                self._json(
                    200,
                    {
                        "access_token": token,
                        "token_type": "Bearer",
                        "expires_in": ttl,
                        "scope": scope,
                    },
                )
                return

            if grant == "authorization_code":
                code = form.get("code", "")
                with LOCK:
                    entry = AUTH_CODES.pop(code, None)
                if entry is None or entry["expires_at"] < now():
                    self._error(
                        400, "invalid_grant", "unknown or expired authorization code"
                    )
                    return
                if entry["client_id"] != client["client_id"]:
                    self._error(400, "invalid_grant", "code was issued to another client")
                    return
                if entry.get("code_challenge"):
                    verifier = form.get("code_verifier", "")
                    digest = hashlib.sha256(verifier.encode("ascii")).digest()
                    expected = (
                        base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
                    )
                    if expected != entry["code_challenge"]:
                        self._error(400, "invalid_grant", "PKCE verification failed")
                        return
                scope = entry.get("scope", "")
                ttl = client.get("access_token_ttl", DELEGATED_TTL)
                access = issue_access_token(
                    port, client["client_id"], "authorization_code", entry["subject"], scope, ttl
                )
                refresh = issue_refresh_token(
                    port, client["client_id"], entry["subject"], scope, 1
                )
                self._json(
                    200,
                    {
                        "access_token": access,
                        "token_type": "Bearer",
                        "expires_in": ttl,
                        "refresh_token": refresh,
                        "scope": scope,
                    },
                )
                return

            if grant == "refresh_token":
                if not presented_refresh:
                    self._error(400, "invalid_request", "refresh_token is required")
                    return
                with LOCK:
                    entry = REFRESH_TOKENS.get(presented_refresh)
                if entry is None:
                    self._error(400, "invalid_grant", "unknown refresh token")
                    return
                if entry["used"]:
                    self._error(
                        400,
                        "invalid_grant",
                        "refresh token already used; this provider rotates refresh tokens",
                    )
                    return
                if entry["client_id"] != client["client_id"]:
                    self._error(
                        400, "invalid_grant", "refresh token belongs to another client"
                    )
                    return
                with LOCK:
                    entry["used"] = True
                scope = entry.get("scope", "")
                ttl = client.get("access_token_ttl", DELEGATED_TTL)
                access = issue_access_token(
                    port, client["client_id"], "refresh_token", entry["subject"], scope, ttl
                )
                rotated = issue_refresh_token(
                    port,
                    client["client_id"],
                    entry["subject"],
                    scope,
                    entry["generation"] + 1,
                )
                log_call(
                    "refresh_rotated",
                    port,
                    client_id=client["client_id"],
                    old_refresh_token=fingerprint(presented_refresh),
                    new_refresh_token=fingerprint(rotated),
                    generation=entry["generation"] + 1,
                    remote_addr=self._peer(),
                )
                self._json(
                    200,
                    {
                        "access_token": access,
                        "token_type": "Bearer",
                        "expires_in": ttl,
                        "refresh_token": rotated,
                        "scope": scope,
                    },
                )
                return

            self._error(400, "unsupported_grant_type", "grant_type=%s" % grant)

        # --------------------------------------------------------- /register
        def handle_register(self):
            body, raw = self._form()
            if not isinstance(body, dict):
                self._error(400, "invalid_client_metadata", "body must be a JSON object")
                return
            client_id = "uat-dcr-" + secrets.token_hex(6)
            auth_method = body.get("token_endpoint_auth_method") or "client_secret_basic"
            record = {
                "client_id": client_id,
                "client_secret": None
                if auth_method == "none"
                else "uat-dcr-secret-" + secrets.token_hex(10),
                "grant_types": body.get("grant_types")
                or ["authorization_code", "refresh_token"],
                "token_endpoint_auth_method": auth_method,
                "redirect_uris": body.get("redirect_uris") or [],
                "client_name": body.get("client_name")
                or "UAT dynamically registered client",
                "scope": body.get("scope", ""),
                "access_token_ttl": DELEGATED_TTL,
                "static": False,
                "port": port,
            }
            with LOCK:
                CLIENTS[(port, client_id)] = record
            log_call(
                "register",
                port,
                client_id=client_id,
                client_name=record["client_name"],
                redirect_uris=record["redirect_uris"],
                token_endpoint_auth_method=auth_method,
                remote_addr=self._peer(),
                request_body=raw.decode("utf-8", "replace")[:2000],
            )
            response = {
                "client_id": client_id,
                "client_id_issued_at": int(now()),
                "grant_types": record["grant_types"],
                "token_endpoint_auth_method": auth_method,
                "redirect_uris": record["redirect_uris"],
                "client_name": record["client_name"],
                "response_types": body.get("response_types") or ["code"],
            }
            if record["client_secret"]:
                response["client_secret"] = record["client_secret"]
                response["client_secret_expires_at"] = 0
            if record["scope"]:
                response["scope"] = record["scope"]
            self._json(201, response)

        # ---------------------------------------------------------- /_uat/*
        def handle_validate(self, token):
            if not token:
                self._error(400, "invalid_request", "token is required")
                return
            with LOCK:
                entry = ACCESS_TOKENS.get(token)
            if entry is None:
                self._error(401, "invalid_token", "unknown access token")
                return
            if entry["expires_at"] < now():
                self._error(401, "invalid_token", "access token expired")
                return
            self._json(
                200,
                {
                    "active": True,
                    "client_id": entry["client_id"],
                    "grant": entry["grant"],
                    "subject": entry["subject"],
                    "scope": entry["scope"],
                    "expires_at": entry["expires_at"],
                    "fingerprint": fingerprint(token),
                },
            )

    return Handler


def serve(port, dcr):
    ThreadingHTTPServer((BIND, port), make_handler(port, dcr)).serve_forever()


if __name__ == "__main__":
    print(
        "mock IdP on %s: :%d (DCR) and :%d (no DCR), delegated ttl %ds"
        % (BIND, DCR_PORT, NODCR_PORT, DELEGATED_TTL),
        flush=True,
    )
    threading.Thread(target=serve, args=(NODCR_PORT, False), daemon=True).start()
    serve(DCR_PORT, True)
