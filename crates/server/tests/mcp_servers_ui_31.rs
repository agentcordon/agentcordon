//! Issue #31 — drop the right-side slide-in panel preview on the MCP servers
//! list page. Row click should navigate straight to `/mcp-servers/{id}` and
//! the `/mcp-servers/{id}/partial` route should be gone.

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

use agent_cordon_core::domain::user::UserRole;
use agent_cordon_server::test_helpers::TestAppBuilder;

use crate::common::*;

/// Render the rendered HTML of `/mcp-servers` for an admin and return it.
async fn render_list_page(ctx: &agent_cordon_server::test_helpers::TestContext) -> String {
    let _admin = create_test_user(&*ctx.store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let (cookie, csrf) = login_user(&ctx.app, "admin", TEST_PASSWORD).await;
    let full_cookie = combined_cookie(&cookie, &csrf);

    let resp = ctx
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/mcp-servers")
                .header(header::COOKIE, &full_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    String::from_utf8(
        resp.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap()
}

/// #31 — RED: the list page no longer dispatches the `slide-panel-open` event.
#[tokio::test]
async fn mcp_servers_list_does_not_dispatch_slide_panel_open() {
    let ctx = TestAppBuilder::new().build().await;
    let body = render_list_page(&ctx).await;
    // The dispatch side lives inside the list page's Alpine component.
    // The receiver lives in base.html (slidePanel container) and is harmless
    // when nothing fires the event — removing the receiver is a separable
    // cleanup tracked outside #31.
    assert!(
        !body.contains("dispatchEvent(new CustomEvent('slide-panel-open'"),
        "list page must not dispatch slide-panel-open after #31",
    );
    assert!(
        !body.contains("openServerPanel"),
        "openServerPanel handler should be removed after #31",
    );
}

/// #31 — RED: row click navigates directly to the full detail page via a
/// `window.location.href` assignment in the click handler (not a slide-panel
/// dispatch).
#[tokio::test]
async fn mcp_servers_list_row_navigates_directly_to_detail_page() {
    let ctx = TestAppBuilder::new().build().await;
    let body = render_list_page(&ctx).await;
    assert!(
        body.contains("window.location.href = '/mcp-servers/' + server.id")
            || body.contains("window.location.href='/mcp-servers/' + server.id"),
        "row click must assign window.location.href to /mcp-servers/{{id}}",
    );
}

/// #31 — RED: the `/mcp-servers/{id}/partial` route is removed. Seed a real
/// MCP server so the test can distinguish between a router-level 404 (route
/// gone) and a handler-level 404 (server-not-found). Currently the handler
/// renders 200 with HTML for a real server; after #31 the route returns 404.
#[tokio::test]
async fn mcp_servers_partial_route_is_gone() {
    use agent_cordon_core::domain::mcp::{McpAuthMethod, McpServer, McpServerId, McpTransport};
    use agent_cordon_core::domain::workspace::{Workspace, WorkspaceId, WorkspaceStatus};

    let ctx = TestAppBuilder::new().build().await;
    let admin = create_test_user(&*ctx.store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let (cookie, csrf) = login_user(&ctx.app, "admin", TEST_PASSWORD).await;
    let full_cookie = combined_cookie(&cookie, &csrf);

    let now = chrono::Utc::now();
    let ws = Workspace {
        id: WorkspaceId(uuid::Uuid::new_v4()),
        name: "ws-31".to_string(),
        enabled: true,
        status: WorkspaceStatus::Active,
        pk_hash: None,
        encryption_public_key: None,
        tags: vec![],
        owner_id: Some(admin.id.clone()),
        parent_id: None,
        tool_name: None,
        created_at: now,
        updated_at: now,
    };
    ctx.store.create_workspace(&ws).await.expect("ws");
    let mcp = McpServer {
        id: McpServerId(uuid::Uuid::new_v4()),
        workspace_id: Some(ws.id.clone()),
        name: "mcp-31".to_string(),
        upstream_url: "https://example.test/mcp-31".to_string(),
        transport: McpTransport::Http,
        allowed_tools: None,
        enabled: true,
        created_by: None,
        created_at: now,
        updated_at: now,
        tags: vec![],
        required_credentials: None,
        auth_method: McpAuthMethod::None,
        template_key: None,
        discovered_tools: None,
        created_by_user: Some(admin.id.clone()),
    };
    ctx.store.create_mcp_server(&mcp).await.expect("mcp");

    let resp = ctx
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(format!("/mcp-servers/{}/partial", mcp.id.0))
                .header(header::COOKIE, &full_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "/mcp-servers/{{id}}/partial must be removed after #31; got {} for a real MCP server",
        resp.status()
    );
}
