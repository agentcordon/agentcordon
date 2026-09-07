//! Admin UI pages render a shell — user context, CSRF token, and the entity
//! id when the URL names one — and no entity data. Every list the page shows
//! is fetched by its JavaScript from the admin API, so the UI can never show
//! something the (Cedar-filtered) API would not.
//!
//! Each test seeds an entity with a distinctive name, renders the page, and
//! asserts the name is absent from the HTML but present in the API list the
//! page's script fetches.

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;
use uuid::Uuid;

use agent_cordon_core::domain::audit::{AuditDecision, AuditEvent, AuditEventType};
use agent_cordon_core::domain::mcp::{McpAuthMethod, McpServer, McpServerId, McpTransport};
use agent_cordon_core::domain::oidc::{OidcProvider, OidcProviderId};
use agent_cordon_core::domain::user::{User, UserRole};
use agent_cordon_core::domain::workspace::WorkspaceId;
use agent_cordon_core::storage::Store;
use agent_cordon_server::test_helpers::{TestAppBuilder, TestContext};

use crate::common;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

struct Session {
    cookie: String,
    user: User,
}

async fn setup() -> (TestContext, Session) {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let user = common::create_test_user(
        &*ctx.store,
        "shell-admin",
        common::TEST_PASSWORD,
        UserRole::Admin,
    )
    .await;
    let (session, csrf) = common::login_user(&ctx.app, "shell-admin", common::TEST_PASSWORD).await;
    let cookie = common::combined_cookie(&session, &csrf);
    (ctx, Session { cookie, user })
}

async fn get_page(app: &axum::Router, uri: &str, cookie: &str) -> (StatusCode, String) {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(uri)
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let content_type = resp
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let body = String::from_utf8(
        resp.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert!(
        content_type.contains("text/html"),
        "{uri} is a page: content-type {content_type}"
    );
    (status, body)
}

async fn api_get(app: &axum::Router, uri: &str, cookie: &str) -> (StatusCode, Value) {
    common::send_json_auto_csrf(app, Method::GET, uri, None, Some(cookie), None).await
}

/// A legacy path that is now an alias: it answers a redirect to `expected`
/// rather than rendering a second copy of the page.
async fn assert_redirects_to(app: &axum::Router, uri: &str, expected: &str, cookie: &str) {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(uri)
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(
        resp.status().is_redirection(),
        "{uri}: the alias must redirect, got {}",
        resp.status()
    );
    let location = resp
        .headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert_eq!(location, expected, "{uri} redirects to the canonical page");
}

/// The shell every authenticated page renders: a full document carrying the
/// signed-in user's name (nav) and a way for its scripts to reach the CSRF
/// token.
///
/// That way is the `agtcrdn_csrf` double-submit cookie, read by
/// `getCsrfToken()`. Every page also used to emit a `<meta name="csrf-token">`
/// carrying the same value, which no script has ever read
/// (uat/artifacts/reviews/UI-REVIEW-static.md T6); this assertion is why it survived, so it now
/// names the mechanism that is real.
fn assert_shell(body: &str, uri: &str, session: &Session) {
    assert!(body.contains("<!DOCTYPE html>"), "{uri}: full document");
    let shown_name = session
        .user
        .display_name
        .clone()
        .unwrap_or_else(|| session.user.username.clone());
    assert!(
        body.contains(&shown_name),
        "{uri}: shell carries the user context ({shown_name})"
    );
    assert!(
        body.contains("getCsrfToken") || body.contains("csrfToken"),
        "{uri}: shell gives its scripts a way to read the CSRF cookie"
    );
    assert!(
        !body.contains(r#"<meta name="csrf-token""#),
        "{uri}: the CSRF meta tag is gone — nothing read it"
    );
}

fn assert_absent(body: &str, uri: &str, needle: &str) {
    assert!(
        !body.contains(needle),
        "{uri}: page HTML must not embed entity data, found {needle:?}"
    );
}

fn api_names(body: &Value, field: &str) -> Vec<String> {
    body["data"]
        .as_array()
        .unwrap_or_else(|| panic!("data must be a list: {body}"))
        .iter()
        .filter_map(|v| v[field].as_str().map(String::from))
        .collect()
}

async fn seed_credential(app: &axum::Router, cookie: &str, name: &str) -> String {
    let (status, body) = common::send_json_auto_csrf(
        app,
        Method::POST,
        "/api/v1/credentials",
        None,
        Some(cookie),
        Some(json!({ "name": name, "service": "svc", "secret_value": "s3cret-value" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "create credential: {body}");
    body["data"]["id"].as_str().unwrap().to_string()
}

async fn seed_policy(app: &axum::Router, cookie: &str, name: &str) -> String {
    let (status, body) = common::send_json_auto_csrf(
        app,
        Method::POST,
        "/api/v1/policies",
        None,
        Some(cookie),
        Some(json!({
            "name": name,
            "description": format!("{name} description"),
            "cedar_policy": "permit(principal, action, resource);",
        })),
    )
    .await;
    assert!(
        status == StatusCode::OK || status == StatusCode::CREATED,
        "create policy: {body}"
    );
    body["data"]["id"].as_str().unwrap().to_string()
}

async fn seed_vend_event(store: &(dyn Store + Send + Sync), credential_name: &str, ws_name: &str) {
    let event = AuditEvent::builder(AuditEventType::CredentialVended)
        .action("vend_credential")
        .resource("credential", &Uuid::new_v4().to_string())
        .workspace_actor(&WorkspaceId(Uuid::new_v4()), ws_name)
        .details(json!({ "credential_name": credential_name }))
        .decision(AuditDecision::Permit, None)
        .build();
    store.append_audit_event(&event).await.expect("seed event");
}

async fn seed_mcp_server(store: &(dyn Store + Send + Sync), name: &str) -> McpServer {
    let now = chrono::Utc::now();
    let server = McpServer {
        id: McpServerId(Uuid::new_v4()),
        workspace_id: None,
        name: name.to_string(),
        upstream_url: format!("https://{name}.example.test/mcp"),
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
        created_by_user: None,
    };
    store.create_mcp_server(&server).await.expect("seed mcp");
    server
}

async fn seed_oidc_provider(store: &(dyn Store + Send + Sync), name: &str) {
    let now = chrono::Utc::now();
    let provider = OidcProvider {
        id: OidcProviderId(Uuid::new_v4()),
        name: name.to_string(),
        issuer_url: format!("https://{name}.example.test"),
        client_id: format!("{name}-client"),
        encrypted_client_secret: vec![1, 2, 3],
        nonce: vec![0; 12],
        scopes: vec!["openid".to_string()],
        role_mapping: json!({}),
        auto_provision: false,
        enabled: true,
        username_claim: "preferred_username".to_string(),
        created_at: now,
        updated_at: now,
    };
    store
        .create_oidc_provider(&provider)
        .await
        .expect("seed oidc provider");
}

// ---------------------------------------------------------------------------
// Dashboard
// ---------------------------------------------------------------------------

#[tokio::test]
async fn dashboard_renders_shell_and_fetches_activity_from_api() {
    let (ctx, session) = setup().await;
    seed_vend_event(&*ctx.store, "dash-seeded-cred", "dash-seeded-ws").await;

    let (status, body) = get_page(&ctx.app, "/dashboard", &session.cookie).await;
    assert_eq!(status, StatusCode::OK);
    assert_shell(&body, "/dashboard", &session);
    assert_absent(&body, "/dashboard", "dash-seeded-cred");
    assert_absent(&body, "/dashboard", "dash-seeded-ws");
    assert!(
        body.contains("/api/v1/stats"),
        "counts come from the stats API"
    );
    assert!(
        body.contains("/api/v1/audit"),
        "activity comes from the audit API"
    );

    let (status, api) = api_get(
        &ctx.app,
        "/api/v1/audit?event_type=credential_vended&limit=5",
        &session.cookie,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{api}");
    let names: Vec<String> = api["data"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|e| e["metadata"]["credential_name"].as_str().map(String::from))
        .collect();
    assert!(names.contains(&"dash-seeded-cred".to_string()), "{api}");
}

// ---------------------------------------------------------------------------
// Credentials
// ---------------------------------------------------------------------------

#[tokio::test]
async fn credentials_list_renders_shell_and_fetches_list_from_api() {
    let (ctx, session) = setup().await;
    seed_credential(&ctx.app, &session.cookie, "shell-seeded-cred").await;

    let (status, body) = get_page(&ctx.app, "/credentials", &session.cookie).await;
    assert_eq!(status, StatusCode::OK);
    assert_shell(&body, "/credentials", &session);
    assert_absent(&body, "/credentials", "shell-seeded-cred");
    assert!(body.contains("/api/v1/credentials"));

    let (status, api) = api_get(&ctx.app, "/api/v1/credentials", &session.cookie).await;
    assert_eq!(status, StatusCode::OK);
    assert!(api_names(&api, "name").contains(&"shell-seeded-cred".to_string()));
}

#[tokio::test]
async fn credential_detail_pages_render_shell_with_entity_id() {
    let (ctx, session) = setup().await;
    let id = seed_credential(&ctx.app, &session.cookie, "shell-seeded-cred").await;

    // One surface: `/credentials/{id}` is the credential's page. The split
    // pane is gone, so the list no longer carries a second copy of it and
    // `/view` is an alias that redirects here.
    let uri = format!("/credentials/{id}");
    let (status, body) = get_page(&ctx.app, &uri, &session.cookie).await;
    assert_eq!(status, StatusCode::OK, "{uri}");
    assert_shell(&body, &uri, &session);
    assert!(body.contains(&id), "{uri}: shell carries the entity id");
    assert_absent(&body, &uri, "shell-seeded-cred");
    assert!(
        body.contains(r#"href="/credentials" class="back-link""#),
        "{uri}: the detail page has a back link to the list"
    );

    assert_redirects_to(
        &ctx.app,
        &format!("/credentials/{id}/view"),
        &format!("/credentials/{id}"),
        &session.cookie,
    )
    .await;
}

// ---------------------------------------------------------------------------
// Workspaces
// ---------------------------------------------------------------------------

#[tokio::test]
async fn workspaces_list_renders_shell_and_fetches_list_from_api() {
    let (ctx, session) = setup().await;
    common::create_agent_in_db(
        &*ctx.store,
        "shell-seeded-ws",
        vec!["shell-seeded-tag"],
        true,
        Some(session.user.id.clone()),
    )
    .await;

    let (status, body) = get_page(&ctx.app, "/workspaces", &session.cookie).await;
    assert_eq!(status, StatusCode::OK);
    assert_shell(&body, "/workspaces", &session);
    assert_absent(&body, "/workspaces", "shell-seeded-ws");
    assert_absent(&body, "/workspaces", "shell-seeded-tag");
    assert!(body.contains("/api/v1/workspaces"));

    let (status, api) = api_get(&ctx.app, "/api/v1/workspaces", &session.cookie).await;
    assert_eq!(status, StatusCode::OK);
    assert!(api_names(&api, "name").contains(&"shell-seeded-ws".to_string()));
}

#[tokio::test]
async fn workspace_detail_pages_render_shell_with_entity_id() {
    let (ctx, session) = setup().await;
    let (ws, _) = common::create_agent_in_db(
        &*ctx.store,
        "shell-seeded-ws",
        vec![],
        true,
        Some(session.user.id.clone()),
    )
    .await;
    let id = ws.id.0.to_string();

    let uri = format!("/workspaces/{id}");
    let (status, body) = get_page(&ctx.app, &uri, &session.cookie).await;
    assert_eq!(status, StatusCode::OK, "{uri}");
    assert_shell(&body, &uri, &session);
    assert!(body.contains(&id), "{uri}: shell carries the entity id");
    assert_absent(&body, &uri, "shell-seeded-ws");
    assert!(
        body.contains(r#"href="/workspaces" class="back-link""#),
        "{uri}: the detail page has a back link to the list"
    );

    assert_redirects_to(
        &ctx.app,
        &format!("/workspaces/{id}/view"),
        &format!("/workspaces/{id}"),
        &session.cookie,
    )
    .await;
}

// ---------------------------------------------------------------------------
// MCP servers
// ---------------------------------------------------------------------------

#[tokio::test]
async fn mcp_servers_list_renders_shell_and_fetches_list_from_api() {
    let (ctx, session) = setup().await;
    common::create_agent_in_db(
        &*ctx.store,
        "shell-seeded-mcp-ws",
        vec![],
        true,
        Some(session.user.id.clone()),
    )
    .await;
    seed_mcp_server(&*ctx.store, "shell-seeded-mcp").await;

    let (status, body) = get_page(&ctx.app, "/mcp-servers", &session.cookie).await;
    assert_eq!(status, StatusCode::OK);
    assert_shell(&body, "/mcp-servers", &session);
    assert_absent(&body, "/mcp-servers", "shell-seeded-mcp");
    assert_absent(&body, "/mcp-servers", "shell-seeded-mcp-ws");
    assert!(body.contains("/api/v1/mcp-servers"));
    // The marketplace is its own page now: the list neither fetches the
    // template catalog nor carries a second search over the same list.
    assert!(
        !body.contains("/api/v1/mcp-templates"),
        "/mcp-servers: the template catalog belongs to /mcp-servers/marketplace"
    );
    assert_eq!(
        body.matches(r#"class="search-input""#).count(),
        1,
        "/mcp-servers: one search, not two"
    );
    assert!(
        body.contains(r#"href="/mcp-servers/marketplace""#),
        "/mcp-servers: Add server links to the marketplace page"
    );

    let (status, api) = api_get(&ctx.app, "/api/v1/mcp-servers", &session.cookie).await;
    assert_eq!(status, StatusCode::OK);
    assert!(api_names(&api, "name").contains(&"shell-seeded-mcp".to_string()));
}

/// The marketplace is a page of its own -- `/mcp-servers/marketplace` -- and
/// the two aliases that used to point at the list's `#marketplace` anchor
/// point at it instead.
#[tokio::test]
async fn mcp_marketplace_renders_shell_and_fetches_templates_from_api() {
    let (ctx, session) = setup().await;
    seed_mcp_server(&*ctx.store, "shell-seeded-mcp").await;

    let uri = "/mcp-servers/marketplace";
    let (status, body) = get_page(&ctx.app, uri, &session.cookie).await;
    assert_eq!(status, StatusCode::OK);
    assert_shell(&body, uri, &session);
    assert_absent(&body, uri, "shell-seeded-mcp");
    assert!(
        body.contains("/api/v1/mcp-templates"),
        "the catalog comes from the templates API"
    );
    assert!(
        body.contains("/api/v1/workspaces"),
        "the install picker's workspaces come from the API"
    );
    assert!(
        body.contains(r#"href="/mcp-servers" class="back-link""#),
        "the marketplace page links back to the list"
    );

    for alias in ["/marketplace", "/mcp-marketplace"] {
        assert_redirects_to(&ctx.app, alias, uri, &session.cookie).await;
    }
}

#[tokio::test]
async fn mcp_server_detail_renders_shell_with_entity_id() {
    let (ctx, session) = setup().await;
    let server = seed_mcp_server(&*ctx.store, "shell-seeded-mcp").await;
    let id = server.id.0.to_string();
    let uri = format!("/mcp-servers/{id}");

    let (status, body) = get_page(&ctx.app, &uri, &session.cookie).await;
    assert_eq!(status, StatusCode::OK);
    assert_shell(&body, &uri, &session);
    assert!(body.contains(&id));
    assert_absent(&body, &uri, "shell-seeded-mcp");
}

// ---------------------------------------------------------------------------
// Policies
// ---------------------------------------------------------------------------

#[tokio::test]
async fn policies_list_renders_shell_and_fetches_list_from_api() {
    let (ctx, session) = setup().await;
    seed_policy(&ctx.app, &session.cookie, "shell-seeded-policy").await;

    let (status, body) = get_page(&ctx.app, "/security", &session.cookie).await;
    assert_eq!(status, StatusCode::OK);
    assert_shell(&body, "/security", &session);
    assert_absent(&body, "/security", "shell-seeded-policy");
    assert!(body.contains("/api/v1/policies"));

    let (status, api) = api_get(&ctx.app, "/api/v1/policies", &session.cookie).await;
    assert_eq!(status, StatusCode::OK);
    assert!(api_names(&api, "name").contains(&"shell-seeded-policy".to_string()));
}

#[tokio::test]
async fn policy_detail_renders_shell_with_entity_id() {
    let (ctx, session) = setup().await;
    let id = seed_policy(&ctx.app, &session.cookie, "shell-seeded-policy").await;
    let uri = format!("/security/{id}");

    let (status, body) = get_page(&ctx.app, &uri, &session.cookie).await;
    assert_eq!(status, StatusCode::OK);
    assert_shell(&body, &uri, &session);
    assert!(body.contains(&id));
    assert_absent(&body, &uri, "shell-seeded-policy");
}

// ---------------------------------------------------------------------------
// Users
// ---------------------------------------------------------------------------

#[tokio::test]
async fn users_list_renders_shell_and_fetches_list_from_api() {
    let (ctx, session) = setup().await;
    common::create_test_user(
        &*ctx.store,
        "shell-seeded-user",
        common::TEST_PASSWORD,
        UserRole::Viewer,
    )
    .await;

    // The user table is a Settings section and nothing else: the top-level
    // page went first (uat/artifacts/reviews/DESIGN-REVIEW.md §1.16), and the standalone page at
    // `/settings/users` — no rail, its own "New User" button beside Settings'
    // "Add User" — went with it (uat/artifacts/fresh-user-docker-2.md F5).
    // Both paths land on the section.
    for uri in ["/users", "/settings/users"] {
        let resp = ctx
            .app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri(uri)
                    .header(header::COOKIE, &session.cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::PERMANENT_REDIRECT, "{uri}");
        assert_eq!(
            resp.headers()
                .get(header::LOCATION)
                .and_then(|v| v.to_str().ok()),
            Some("/settings#users-section"),
            "{uri} lands on the Settings section that shows the table"
        );
    }

    // The section is a shell like every other list: the rows come from the API.
    let (status, body) = get_page(&ctx.app, "/settings", &session.cookie).await;
    assert_eq!(status, StatusCode::OK);
    assert_shell(&body, "/settings", &session);
    assert_absent(&body, "/settings", "shell-seeded-user");
    assert!(body.contains("/api/v1/users"));

    let (status, api) = api_get(&ctx.app, "/api/v1/users", &session.cookie).await;
    assert_eq!(status, StatusCode::OK);
    assert!(api_names(&api, "username").contains(&"shell-seeded-user".to_string()));
}

// ---------------------------------------------------------------------------
// Audit
// ---------------------------------------------------------------------------

#[tokio::test]
async fn audit_renders_shell_and_fetches_events_from_api() {
    let (ctx, session) = setup().await;
    seed_vend_event(&*ctx.store, "audit-seeded-cred", "audit-seeded-ws").await;

    for uri in ["/audit".to_string(), format!("/audit/{}", Uuid::new_v4())] {
        let (status, body) = get_page(&ctx.app, &uri, &session.cookie).await;
        assert_eq!(status, StatusCode::OK, "{uri}");
        assert_shell(&body, &uri, &session);
        assert_absent(&body, &uri, "audit-seeded-cred");
        assert_absent(&body, &uri, "audit-seeded-ws");
        assert!(body.contains("/api/v1/audit"));
    }

    let (status, api) = api_get(&ctx.app, "/api/v1/audit?limit=50", &session.cookie).await;
    assert_eq!(status, StatusCode::OK);
    let events = api["data"].as_array().unwrap();
    assert!(
        events
            .iter()
            .any(|e| e["metadata"]["credential_name"] == "audit-seeded-cred"
                && e["workspace_name"] == "audit-seeded-ws"),
        "{api}"
    );
}

// ---------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------

#[tokio::test]
async fn settings_renders_shell_and_fetches_providers_from_api() {
    let (ctx, session) = setup().await;
    seed_oidc_provider(&*ctx.store, "shell-seeded-oidc").await;

    let (status, body) = get_page(&ctx.app, "/settings", &session.cookie).await;
    assert_eq!(status, StatusCode::OK);
    assert_shell(&body, "/settings", &session);
    assert_absent(&body, "/settings", "shell-seeded-oidc");
    assert!(body.contains("/api/v1/oidc-providers"));

    let (status, api) = api_get(&ctx.app, "/api/v1/oidc-providers", &session.cookie).await;
    assert_eq!(status, StatusCode::OK);
    assert!(api_names(&api, "name").contains(&"shell-seeded-oidc".to_string()));
}

// ---------------------------------------------------------------------------
// The list a page shows is exactly the Cedar-filtered API list
// ---------------------------------------------------------------------------

/// A viewer with no grant on a root user's credential gets an empty list
/// from the endpoint the credentials page fetches, while root sees it.
/// Workspace-principal scoping of the same endpoint is covered by
/// `v154_ownership` and `v191_credential_list`.
#[tokio::test]
async fn viewer_credentials_api_returns_only_what_cedar_allows() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    common::create_root_user(&*ctx.store, "list-root", common::TEST_PASSWORD).await;
    common::create_test_user(
        &*ctx.store,
        "list-viewer",
        common::TEST_PASSWORD,
        UserRole::Viewer,
    )
    .await;
    let root_cookie =
        common::login_user_combined(&ctx.app, "list-root", common::TEST_PASSWORD).await;
    let viewer_cookie =
        common::login_user_combined(&ctx.app, "list-viewer", common::TEST_PASSWORD).await;
    seed_credential(&ctx.app, &root_cookie, "root-only-cred").await;

    let (status, root_list) = api_get(&ctx.app, "/api/v1/credentials", &root_cookie).await;
    assert_eq!(status, StatusCode::OK);
    assert!(api_names(&root_list, "name").contains(&"root-only-cred".to_string()));

    let (status, viewer_list) = api_get(&ctx.app, "/api/v1/credentials", &viewer_cookie).await;
    assert_eq!(status, StatusCode::OK, "{viewer_list}");
    assert!(
        api_names(&viewer_list, "name").is_empty(),
        "viewer sees nothing Cedar does not permit: {viewer_list}"
    );

    // The page the viewer loads is the same shell root gets: nothing to leak.
    let (status, body) = get_page(&ctx.app, "/credentials", &viewer_cookie).await;
    assert_eq!(status, StatusCode::OK);
    assert_absent(&body, "/credentials", "root-only-cred");
}
