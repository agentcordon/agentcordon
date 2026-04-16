"""
DAG nodes for OAuth proxy flow testing: oauth_proxy.token_endpoint,
oauth_proxy.client_list.
"""

import json

from tests.e2e.dag_runner import DagNode
from tests.e2e.helpers import server_request


# ---------------------------------------------------------------------------
# oauth_proxy.client_list
# ---------------------------------------------------------------------------

def oauth_proxy_client_list(ctx: dict) -> dict:
    """
    List OAuth clients via admin API after registration.

    Consumes: base_url, admin_session_cookie, oauth_client_id
    """
    base_url = ctx["base_url"]
    admin_cookie = ctx["admin_session_cookie"]

    status, _, body = server_request(
        base_url, "GET", "/api/v1/oauth/clients",
        cookies=admin_cookie,
    )

    assert status == 200, f"OAuth client list failed with {status}: {body}"

    data = json.loads(body)
    clients = data.get("data", data)
    if isinstance(clients, dict):
        clients = clients.get("clients", clients.get("items", []))

    assert isinstance(clients, list), f"Expected client list: {type(clients)}"

    # Our registered client should be in the list
    oauth_client_id = ctx.get("oauth_client_id")
    if oauth_client_id:
        client_ids = [c.get("client_id", c.get("id", "")) for c in clients]
        assert oauth_client_id in client_ids, (
            f"OAuth client '{oauth_client_id}' not in list: {client_ids}"
        )

    return ctx


OAUTH_PROXY_CLIENT_LIST_NODE = DagNode(
    name="oauth_proxy.client_list",
    fn=oauth_proxy_client_list,
    depends_on=["workspace.device_code_exchange"],
    produces=[],
    consumes=["base_url", "admin_session_cookie"],
    critical=False,
    timeout=10.0,
)


# ---------------------------------------------------------------------------
# oauth_proxy.no_token_in_response
# ---------------------------------------------------------------------------

def oauth_proxy_no_token_in_response(ctx: dict) -> dict:
    """
    Verify that OAuth client list does not expose access/refresh tokens.

    Consumes: base_url, admin_session_cookie
    """
    base_url = ctx["base_url"]
    admin_cookie = ctx["admin_session_cookie"]

    status, _, body = server_request(
        base_url, "GET", "/api/v1/oauth/clients",
        cookies=admin_cookie,
    )

    assert status == 200, f"Client list failed: {status}"

    body_lower = body.lower()
    forbidden = ["access_token", "refresh_token", "client_secret"]

    for pattern in forbidden:
        # Check for actual token values (long strings), not field labels
        assert f'"{pattern}": "ey' not in body_lower, (
            f"Token value pattern '{pattern}' found in client list"
        )

    return ctx


OAUTH_PROXY_NO_TOKEN_NODE = DagNode(
    name="oauth_proxy.no_token_in_response",
    fn=oauth_proxy_no_token_in_response,
    depends_on=["oauth_proxy.client_list"],
    produces=[],
    consumes=["base_url", "admin_session_cookie"],
    critical=False,
    timeout=10.0,
)


def get_nodes():
    """Return all OAuth proxy DAG nodes."""
    return [OAUTH_PROXY_CLIENT_LIST_NODE, OAUTH_PROXY_NO_TOKEN_NODE]
