//! Every route the consolidation removed stays removed.
//!
//! A deleted handler is easy to bring back by accident — a `git revert`, a
//! merge that resurrects a `.route(...)` line, a module re-added to a
//! router. Each row below is a path that a released server answered and
//! this one must not. The caller is a root user, who bypasses Cedar
//! entirely, so a route that still existed would answer `2xx`: nothing
//! here can pass because the request was merely unauthorized.
//!
//! The expected status is not always 404. Axum matches path segments, so a
//! removed sibling of a `{id}` route is captured by that route and answers
//! 400 (the id does not parse as a UUID) or 405 (no handler for the
//! method). Those are recorded per row; a `2xx` fails whatever the row says.

use axum::http::{Method, StatusCode};
use serde_json::json;

use agent_cordon_server::test_helpers::TestAppBuilder;

use crate::common::{create_root_user, login_user_combined, send_json_auto_csrf, TEST_PASSWORD};

/// A removed route: the method and path a released server served, the
/// status this server must answer, and why it is that status.
struct Gone {
    method: Method,
    path: &'static str,
    /// What the router answers now that the route is gone.
    status: StatusCode,
    /// Why this path is gone, and why the status is what it is.
    why: &'static str,
}

fn gone(method: Method, path: &'static str, status: StatusCode, why: &'static str) -> Gone {
    Gone {
        method,
        path,
        status,
        why,
    }
}

fn removed() -> Vec<Gone> {
    use Method as M;
    vec![
        // --- ES256 JWT issuer, JWKS, and the permissions token endpoint ---
        gone(
            M::GET,
            "/.well-known/jwks.json",
            StatusCode::NOT_FOUND,
            "no signing key is derived at startup; bearer credentials are opaque OAuth tokens",
        ),
        gone(
            M::GET,
            "/api/v1/workspaces/11111111-1111-1111-1111-111111111111/permissions",
            StatusCode::NOT_FOUND,
            "the permissions token endpoint is gone; no workspace sub-route named `permissions` \
             is registered",
        ),
        // --- the broker never calls a token endpoint ---
        gone(
            M::POST,
            "/api/v1/workspaces/mcp/rotate-refresh-token",
            StatusCode::NOT_FOUND,
            "the server runs the refresh exchange itself; no three-segment workspace route \
             matches `mcp/rotate-refresh-token`",
        ),
        // --- dormant control-plane endpoints ---
        gone(
            M::GET,
            "/api/v1/workspaces/policies",
            StatusCode::BAD_REQUEST,
            "policy sync had no caller; `/workspaces/{id}` now captures the path and refuses \
             `policies` as a workspace id",
        ),
        gone(
            M::GET,
            "/api/v1/workspaces/audit-stream",
            StatusCode::BAD_REQUEST,
            "the audit-stream WebSocket had no caller (the server no longer enables axum's `ws` \
             feature); `/workspaces/{id}` captures the path",
        ),
        gone(
            M::POST,
            "/api/v1/workspaces/audit-events",
            StatusCode::METHOD_NOT_ALLOWED,
            "audit ingest had no caller; `/workspaces/{id}` captures the path and serves no POST",
        ),
        gone(
            M::POST,
            "/api/v1/workspaces/mcp-report-tools",
            StatusCode::METHOD_NOT_ALLOWED,
            "the tool-report route had no caller; `/workspaces/{id}` captures the path and \
             serves no POST",
        ),
        // --- workspace revocation moved to the admin API ---
        gone(
            M::GET,
            "/api/v1/workspace-identities",
            StatusCode::NOT_FOUND,
            "listing moved to `GET /api/v1/workspaces`",
        ),
        gone(
            M::GET,
            "/api/v1/workspace-identities/11111111-1111-1111-1111-111111111111",
            StatusCode::NOT_FOUND,
            "the workspace-identity list is what handed out other tenants' key hashes",
        ),
        gone(
            M::DELETE,
            "/api/v1/workspace-identities/11111111-1111-1111-1111-111111111111",
            StatusCode::NOT_FOUND,
            "revocation moved to `POST /api/v1/workspaces/{id}/revoke`",
        ),
        gone(
            M::POST,
            "/api/v1/workspace-identities/11111111-1111-1111-1111-111111111111/approve",
            StatusCode::NOT_FOUND,
            "approval stays on the device flow",
        ),
        // --- MCP proxy stub and the device event bus ---
        gone(
            M::POST,
            "/api/v1/mcp/proxy",
            StatusCode::NOT_FOUND,
            "the stub only returned a `moved` error",
        ),
        gone(
            M::GET,
            "/api/v1/devices/events",
            StatusCode::NOT_FOUND,
            "`DeviceEvent`/`EventBus` had no subscriber; the browser `UiEventBus` and \
             `/api/v1/events/ui` remain",
        ),
        // --- admin UI slide-in panel fragments ---
        gone(
            M::GET,
            "/credentials/11111111-1111-1111-1111-111111111111/partial",
            StatusCode::NOT_FOUND,
            "no page fetched it; the admin API detail endpoint carries the Cedar gate",
        ),
        gone(
            M::GET,
            "/workspaces/11111111-1111-1111-1111-111111111111/partial",
            StatusCode::NOT_FOUND,
            "no page fetched it; the admin API detail endpoint carries the Cedar gate",
        ),
        gone(
            M::GET,
            "/security/11111111-1111-1111-1111-111111111111/partial",
            StatusCode::NOT_FOUND,
            "no page fetched it; the admin API detail endpoint carries the Cedar gate",
        ),
        // --- the split-pane detail fragments ---
        gone(
            M::GET,
            "/credentials/11111111-1111-1111-1111-111111111111/detail-partial",
            StatusCode::NOT_FOUND,
            "the credentials list is a table of links to `/credentials/{id}`; no page loads \
             a detail fragment over AJAX any more",
        ),
        gone(
            M::GET,
            "/workspaces/11111111-1111-1111-1111-111111111111/detail-partial",
            StatusCode::NOT_FOUND,
            "the workspaces list is a table of links to `/workspaces/{id}`; no page loads \
             a detail fragment over AJAX any more",
        ),
        // --- the standalone Users pages ---
        //
        // `/users` was a New User button over the same `GET /api/v1/users`
        // table Settings > User Management already showed, with one column
        // fewer, and nothing linked to it (uat/artifacts/reviews/DESIGN-REVIEW.md 1.16). Its
        // replacement at `/settings/users` was the same page one path further
        // in: still a full page, still no Settings rail, and its "New User"
        // button sat beside the section's "Add User" — three surfaces for one
        // function and two labels for one action
        // (uat/artifacts/fresh-user-docker-2.md F5). Both paths stay as
        // redirects to the section itself so a bookmark still lands on the
        // table.
        gone(
            M::GET,
            "/users",
            StatusCode::PERMANENT_REDIRECT,
            "the user table is a Settings section; /users redirects to /settings#users-section",
        ),
        gone(
            M::GET,
            "/settings/users",
            StatusCode::PERMANENT_REDIRECT,
            "and so does the standalone page that replaced it; the section is the table",
        ),
        gone(
            M::GET,
            "/users/new",
            StatusCode::PERMANENT_REDIRECT,
            "the form is framed as 'Settings / New User' and lives at /settings/users/new",
        ),
        // --- the audit detail pane nothing ever loaded ---
        gone(
            M::GET,
            "/audit/11111111-1111-1111-1111-111111111111/detail-partial",
            StatusCode::NOT_FOUND,
            "the audit page expands a row in place and reads `GET /api/v1/audit/{id}` itself; \
             `partials/audit_detail_pane.html` and its handler were never fetched \
             (uat/artifacts/reviews/UI-REVIEW-static.md T1)",
        ),
    ]
}

#[tokio::test]
async fn removed_routes_are_not_served() {
    let ctx = TestAppBuilder::new().build().await;
    create_root_user(&*ctx.store, "gone-root", TEST_PASSWORD).await;
    let cookie = login_user_combined(&ctx.app, "gone-root", TEST_PASSWORD).await;
    let mut failures = Vec::new();
    for row in removed() {
        let body = match row.method {
            Method::POST | Method::PUT | Method::PATCH => Some(json!({})),
            _ => None,
        };
        let (status, resp) = send_json_auto_csrf(
            &ctx.app,
            row.method.clone(),
            row.path,
            None,
            Some(&cookie),
            body,
        )
        .await;
        if status.is_success() {
            failures.push(format!(
                "{} {} is served again (status {status}): {}",
                row.method, row.path, row.why
            ));
        } else if status != row.status {
            failures.push(format!(
                "{} {} answered {status}, expected {} ({}): {resp}",
                row.method, row.path, row.status, row.why
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "routes the consolidation removed:\n{}",
        failures.join("\n")
    );
}
