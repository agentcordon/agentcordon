"""
DAG nodes for settings testing: settings.stats.
"""

import json

from tests.e2e.dag_runner import DagNode
from tests.e2e.helpers import server_request


# ---------------------------------------------------------------------------
# settings.stats
# ---------------------------------------------------------------------------

def settings_stats(ctx: dict) -> dict:
    """
    Verify the stats/dashboard endpoint returns valid data.

    Consumes: base_url, admin_session_cookie
    """
    base_url = ctx["base_url"]
    admin_cookie = ctx["admin_session_cookie"]

    status, _, body = server_request(
        base_url, "GET", "/api/v1/stats",
        cookies=admin_cookie,
    )

    assert status == 200, f"Stats endpoint failed with {status}: {body}"

    data = json.loads(body)
    stats = data.get("data", data)

    # Should contain count fields
    assert isinstance(stats, dict), f"Expected stats dict, got: {type(stats)}"

    return ctx


SETTINGS_STATS_NODE = DagNode(
    name="settings.stats",
    fn=settings_stats,
    depends_on=["setup.login"],
    produces=[],
    consumes=["base_url", "admin_session_cookie"],
    critical=False,
    timeout=10.0,
)


# ---------------------------------------------------------------------------
# settings.dashboard
# ---------------------------------------------------------------------------

def settings_dashboard(ctx: dict) -> dict:
    """
    Verify settings page shows system stats (workspace count, credential count).

    Consumes: base_url, admin_session_cookie
    """
    base_url = ctx["base_url"]
    admin_cookie = ctx["admin_session_cookie"]

    # Check settings HTML page has stats
    status, _, body = server_request(
        base_url, "GET", "/settings",
        cookies=admin_cookie,
    )

    assert status == 200, f"Settings page failed with {status}"

    body_lower = body.lower()
    assert "<html" in body_lower or "<!doctype" in body_lower, (
        "Settings page did not return HTML"
    )

    # Also verify the stats API returns counts
    status, _, body = server_request(
        base_url, "GET", "/api/v1/stats",
        cookies=admin_cookie,
    )

    assert status == 200, f"Stats API failed with {status}: {body}"
    data = json.loads(body)
    stats = data.get("data", data)

    # Stats should have at least some count fields
    assert isinstance(stats, dict), f"Expected stats dict: {type(stats)}"

    # Stats may have nested structure like {"workspaces": {"total": N}, ...}
    # Verify at least one top-level key exists with data
    assert "workspaces" in stats or "credentials" in stats, (
        f"Stats missing expected keys: {list(stats.keys())}"
    )

    # Verify workspace and credential counts are present
    ws = stats.get("workspaces", {})
    creds = stats.get("credentials", {})
    if isinstance(ws, dict):
        assert ws.get("total", 0) >= 1, f"Expected >=1 workspace, got {ws}"
    if isinstance(creds, dict):
        assert creds.get("total", 0) >= 1, f"Expected >=1 credential, got {creds}"

    return ctx


SETTINGS_DASHBOARD_NODE = DagNode(
    name="settings.dashboard",
    fn=settings_dashboard,
    depends_on=["credential.create"],
    produces=[],
    consumes=["base_url", "admin_session_cookie"],
    critical=False,
    timeout=10.0,
)


# ---------------------------------------------------------------------------
# admin.rotate_key
# ---------------------------------------------------------------------------

def admin_rotate_key(ctx: dict) -> dict:
    """
    Verify POST /admin/rotate-key endpoint works.
    This re-encrypts credentials under the current key.

    Consumes: base_url, admin_session_cookie, csrf_token
    """
    base_url = ctx["base_url"]
    admin_cookie = ctx["admin_session_cookie"]
    csrf_token = ctx["csrf_token"]

    status, _, body = server_request(
        base_url, "POST", "/api/v1/admin/rotate-key",
        body="{}",
        headers={"X-CSRF-Token": csrf_token},
        cookies=admin_cookie,
    )

    assert status == 200, f"Admin rotate-key failed with {status}: {body}"

    data = json.loads(body)
    result = data.get("data", data)
    assert isinstance(result, dict), f"Expected dict result, got: {type(result)}"

    return ctx


ADMIN_ROTATE_KEY_NODE = DagNode(
    name="admin.rotate_key",
    fn=admin_rotate_key,
    depends_on=["credential.create"],
    produces=[],
    consumes=["base_url", "admin_session_cookie", "csrf_token"],
    critical=False,
    timeout=30.0,
)


# ---------------------------------------------------------------------------
# admin.oidc_providers
# ---------------------------------------------------------------------------

def admin_oidc_providers(ctx: dict) -> dict:
    """
    Verify GET /oidc-providers returns the admin OIDC providers list.

    Consumes: base_url, admin_session_cookie
    """
    base_url = ctx["base_url"]
    admin_cookie = ctx["admin_session_cookie"]

    status, _, body = server_request(
        base_url, "GET", "/api/v1/oidc-providers",
        cookies=admin_cookie,
    )

    assert status == 200, f"Admin OIDC providers list failed with {status}: {body}"

    data = json.loads(body)
    providers = data.get("data", data)
    if isinstance(providers, dict):
        providers = providers.get("providers", providers.get("items", []))

    assert isinstance(providers, list), f"Expected providers list, got: {type(providers)}"

    return ctx


ADMIN_OIDC_PROVIDERS_NODE = DagNode(
    name="admin.oidc_providers",
    fn=admin_oidc_providers,
    depends_on=["setup.login"],
    produces=[],
    consumes=["base_url", "admin_session_cookie"],
    critical=False,
    timeout=10.0,
)


# ---------------------------------------------------------------------------
# settings.workspace_count_accurate
# ---------------------------------------------------------------------------

def settings_workspace_count_accurate(ctx: dict) -> dict:
    """
    Get workspace count from stats, create a workspace (if we can),
    verify the count increased.

    Since workspace creation happens via OAuth flow (complex), we instead
    verify the stats count is consistent with the workspace list.

    Consumes: base_url, admin_session_cookie
    """
    base_url = ctx["base_url"]
    admin_cookie = ctx["admin_session_cookie"]

    # Get stats
    status, _, body = server_request(
        base_url, "GET", "/api/v1/stats",
        cookies=admin_cookie,
    )
    assert status == 200, f"Stats endpoint failed: {status}: {body}"

    stats = json.loads(body).get("data", json.loads(body))

    # Get workspace list
    status2, _, body2 = server_request(
        base_url, "GET", "/api/v1/workspaces",
        cookies=admin_cookie,
    )
    assert status2 == 200, f"Workspace list failed: {status2}: {body2}"

    ws_data = json.loads(body2).get("data", json.loads(body2))
    if isinstance(ws_data, dict):
        ws_list = ws_data.get("workspaces", ws_data.get("items", []))
    elif isinstance(ws_data, list):
        ws_list = ws_data
    else:
        ws_list = []

    actual_count = len(ws_list)

    # Check stats workspace count matches
    ws_stats = stats.get("workspaces", {})
    if isinstance(ws_stats, dict):
        stats_count = ws_stats.get("total", ws_stats.get("count", -1))
    elif isinstance(ws_stats, (int, float)):
        stats_count = int(ws_stats)
    else:
        stats_count = -1

    if stats_count >= 0:
        assert stats_count == actual_count, (
            f"Stats workspace count ({stats_count}) doesn't match "
            f"actual workspace list ({actual_count})"
        )

    return ctx


SETTINGS_WORKSPACE_COUNT_NODE = DagNode(
    name="settings.workspace_count_accurate",
    fn=settings_workspace_count_accurate,
    depends_on=["workspace.device_code_exchange"],
    produces=[],
    consumes=["base_url", "admin_session_cookie"],
    critical=False,
    timeout=10.0,
)


def get_nodes():
    """Return all settings DAG nodes."""
    return [
        SETTINGS_STATS_NODE,
        SETTINGS_DASHBOARD_NODE,
        ADMIN_ROTATE_KEY_NODE,
        ADMIN_OIDC_PROVIDERS_NODE,
        SETTINGS_WORKSPACE_COUNT_NODE,
    ]
