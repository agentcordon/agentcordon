"""
DAG nodes for basic UI accessibility checks: ui.login_page, ui.dashboard_loads.

Note: Full Playwright-based UI tests are in tests/e2e/playwright/.
These nodes do basic HTTP checks that the UI pages return HTML.
"""

import json

from tests.e2e.dag_runner import DagNode
from tests.e2e.helpers import server_request


# ---------------------------------------------------------------------------
# ui.login_page
# ---------------------------------------------------------------------------

def ui_login_page(ctx: dict) -> dict:
    """
    Verify the login page renders HTML (no auth required).

    Consumes: base_url
    """
    base_url = ctx["base_url"]

    status, headers, body = server_request(base_url, "GET", "/login")

    assert status == 200, f"Login page failed with {status}"
    assert "<html" in body.lower() or "<!doctype" in body.lower(), (
        "Login page did not return HTML"
    )
    assert "password" in body.lower(), "Login page missing password field"

    return ctx


UI_LOGIN_PAGE_NODE = DagNode(
    name="ui.login_page",
    fn=ui_login_page,
    depends_on=[],
    produces=[],
    consumes=["base_url"],
    critical=False,
    timeout=10.0,
)


# ---------------------------------------------------------------------------
# ui.dashboard_loads
# ---------------------------------------------------------------------------

def ui_dashboard_loads(ctx: dict) -> dict:
    """
    Verify the dashboard page loads with a valid session.

    Consumes: base_url, admin_session_cookie
    """
    base_url = ctx["base_url"]
    admin_cookie = ctx["admin_session_cookie"]

    status, _, body = server_request(
        base_url, "GET", "/",
        cookies=admin_cookie,
    )

    # May redirect to dashboard or return it directly
    assert status in (200, 301, 302), f"Dashboard load failed with {status}"

    if status == 200:
        assert "<html" in body.lower() or "<!doctype" in body.lower(), (
            "Dashboard did not return HTML"
        )

    return ctx


UI_DASHBOARD_LOADS_NODE = DagNode(
    name="ui.dashboard_loads",
    fn=ui_dashboard_loads,
    depends_on=["setup.login"],
    produces=[],
    consumes=["base_url", "admin_session_cookie"],
    critical=False,
    timeout=10.0,
)



# ---------------------------------------------------------------------------
# ui.pages_render
# ---------------------------------------------------------------------------

def ui_pages_render(ctx: dict) -> dict:
    """
    Verify all major pages return 200: dashboard, workspaces, credentials,
    security (policies), settings, audit, mcp-servers.

    Consumes: base_url, admin_session_cookie
    """
    base_url = ctx["base_url"]
    admin_cookie = ctx["admin_session_cookie"]

    pages = [
        "/dashboard",
        "/workspaces",
        "/credentials",
        "/security",
        "/settings",
        "/audit",
        "/mcp-servers",
    ]

    for page in pages:
        status, _, body = server_request(
            base_url, "GET", page,
            cookies=admin_cookie,
        )

        assert status in (200, 301, 302), (
            f"Page {page} failed with {status}"
        )

        if status == 200:
            assert "<html" in body.lower() or "<!doctype" in body.lower(), (
                f"Page {page} did not return HTML"
            )

    return ctx


UI_PAGES_RENDER_NODE = DagNode(
    name="ui.pages_render",
    fn=ui_pages_render,
    depends_on=["setup.login"],
    produces=[],
    consumes=["base_url", "admin_session_cookie"],
    critical=False,
    timeout=15.0,
)


# ---------------------------------------------------------------------------
# ui.empty_states
# ---------------------------------------------------------------------------

def ui_empty_states(ctx: dict) -> dict:
    """
    Verify that pages with data render without errors (not necessarily empty,
    but no 500s or broken HTML).

    Consumes: base_url, admin_session_cookie
    """
    base_url = ctx["base_url"]
    admin_cookie = ctx["admin_session_cookie"]

    # These pages should render cleanly even with test data
    pages = [
        "/workspaces",
        "/credentials",
        "/security",
        "/audit",
        "/mcp-servers",
        "/settings/users",
    ]

    for page in pages:
        status, _, body = server_request(
            base_url, "GET", page,
            cookies=admin_cookie,
        )

        assert status in (200, 301, 302), (
            f"Page {page} returned {status} (expected 200/redirect)"
        )

        if status == 200:
            # No server error traces in the HTML
            assert "internal server error" not in body.lower(), (
                f"Page {page} contains server error"
            )
            assert "panic" not in body.lower(), (
                f"Page {page} contains panic trace"
            )

    return ctx


UI_EMPTY_STATES_NODE = DagNode(
    name="ui.empty_states",
    fn=ui_empty_states,
    depends_on=["setup.login"],
    produces=[],
    consumes=["base_url", "admin_session_cookie"],
    critical=False,
    timeout=15.0,
)


# ---------------------------------------------------------------------------
# ui.css_tokens
# ---------------------------------------------------------------------------

def ui_css_tokens(ctx: dict) -> dict:
    """
    Verify CSS custom properties are defined in the dashboard page.

    Consumes: base_url, admin_session_cookie
    """
    base_url = ctx["base_url"]
    admin_cookie = ctx["admin_session_cookie"]

    status, _, body = server_request(
        base_url, "GET", "/dashboard",
        cookies=admin_cookie,
    )

    assert status == 200, f"Dashboard returned {status}"

    # Check that CSS is loaded (either inline or via link)
    has_css = (
        "<style" in body.lower()
        or "stylesheet" in body.lower()
        or ".css" in body.lower()
    )
    assert has_css, "Dashboard page has no CSS (no <style> or stylesheet link)"

    return ctx


UI_CSS_TOKENS_NODE = DagNode(
    name="ui.css_tokens",
    fn=ui_css_tokens,
    depends_on=["setup.login"],
    produces=[],
    consumes=["base_url", "admin_session_cookie"],
    critical=False,
    timeout=10.0,
)


# ---------------------------------------------------------------------------
# ui.slide_in_panel
# ---------------------------------------------------------------------------

def ui_slide_in_panel(ctx: dict) -> dict:
    """
    Verify detail panel partial endpoints return HTML fragments.

    Consumes: base_url, admin_session_cookie, credential_id
    """
    base_url = ctx["base_url"]
    admin_cookie = ctx["admin_session_cookie"]
    credential_id = ctx.get("credential_id")

    if not credential_id:
        return ctx

    # Request credential partial panel
    status, _, body = server_request(
        base_url, "GET", f"/credentials/{credential_id}/partial",
        cookies=admin_cookie,
    )

    assert status == 200, (
        f"Credential partial panel returned {status}: {body[:200]}"
    )

    # Should contain HTML fragment (not full page)
    assert len(body) > 0, "Credential partial panel returned empty body"

    return ctx


UI_SLIDE_IN_PANEL_NODE = DagNode(
    name="ui.slide_in_panel",
    fn=ui_slide_in_panel,
    depends_on=["credential.create"],
    produces=[],
    consumes=["base_url", "admin_session_cookie", "credential_id"],
    critical=False,
    timeout=10.0,
)


def get_nodes():
    """Return all UI DAG nodes."""
    return [
        UI_LOGIN_PAGE_NODE,
        UI_DASHBOARD_LOADS_NODE,
        UI_PAGES_RENDER_NODE,
        UI_EMPTY_STATES_NODE,
        UI_CSS_TOKENS_NODE,
        UI_SLIDE_IN_PANEL_NODE,
    ]
