//! The gaps two fresh-user walkthroughs found in the MCP marketplace path.
//!
//! 1. The template schema the docs give is not the schema the loader wants,
//!    and the loader reports one missing field per server restart.
//! 2. `GET /api/v1/mcp-servers` reports no workspaces for a server that is
//!    bound to one, and there is no way to read the bindings back.
//! 3. An install whose tool discovery fails reports success and says
//!    nothing, and nothing retries it.

use axum::http::{Method, StatusCode};
use serde_json::{json, Value};
use wiremock::matchers::{body_string_contains, method as http_method};
use wiremock::{Mock, MockServer, ResponseTemplate};

use agent_cordon_core::domain::user::UserRole;
use agent_cordon_core::storage::AuditFilter;
use agent_cordon_server::templates::{load_mcp_templates_reporting, McpServerTemplate};
use agent_cordon_server::test_helpers::{TestAppBuilder, TestContext};

use crate::common::{
    create_test_user, login_user_combined, send_json, send_json_auto_csrf, TEST_PASSWORD,
};

// ---------------------------------------------------------------------------
// 1. The documented template schema
// ---------------------------------------------------------------------------

/// The complete example from `docs/granting-mcp-server-access.md`
/// § "Adding your own server to the marketplace", byte for byte.
const DOCUMENTED_EXAMPLE: &str = r#"{
  "key": "acme-internal",
  "name": "Acme Internal",
  "upstream_url": "https://mcp.acme.internal/",
  "transport": "http",
  "auth_method": "api_key",
  "api_key_header": "X-API-Key"
}"#;

/// Write `files` into a fresh directory and hand back the directory (kept
/// alive by the returned `TempDir`).
fn templates_dir(files: &[(&str, &str)]) -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    for (name, body) in files {
        std::fs::write(dir.path().join(name), body).expect("write template");
    }
    dir
}

/// The one example the docs give for the only supported way to put your own
/// server in the marketplace has to load.
#[tokio::test]
async fn the_documented_marketplace_template_example_loads() {
    let dir = templates_dir(&[("acme-internal.json", DOCUMENTED_EXAMPLE)]);
    let path = dir.path().to_string_lossy().to_string();

    let ctx = TestAppBuilder::new()
        .with_admin()
        .with_config(move |c| c.mcp_templates_dir = Some(path))
        .build()
        .await;
    create_test_user(&*ctx.store, "tpl-admin", TEST_PASSWORD, UserRole::Admin).await;
    let cookie = login_user_combined(&ctx.app, "tpl-admin", TEST_PASSWORD).await;

    let (status, body) = send_json(
        &ctx.app,
        Method::GET,
        "/api/v1/mcp-templates",
        None,
        Some(&cookie),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let acme = body["data"]
        .as_array()
        .expect("templates array")
        .iter()
        .find(|t| t["key"] == "acme-internal")
        .unwrap_or_else(|| panic!("the documented example must load: {body}"));

    assert_eq!(acme["name"], "Acme Internal");
    assert_eq!(acme["auth_method"], "api_key");
    assert_eq!(acme["api_key_header"], "X-API-Key");
    // The four fields the walkthroughs had to discover one restart at a time
    // are defaulted, not required.
    assert_eq!(
        acme["category"], "custom",
        "an unclassified template lands in `custom`: {acme}"
    );
    assert_eq!(
        acme["tags"],
        json!([]),
        "tags default to none, not to a load failure: {acme}"
    );
    assert_eq!(
        acme["icon"], "acme-internal",
        "icon defaults to the key, which is what the marketplace card already falls back to: {acme}"
    );
    assert!(
        acme["sort_order"].as_u64().expect("sort_order") > 120,
        "an operator's own template sorts after the built-ins: {acme}"
    );
}

/// A template with two problems names both, once, with the legal values —
/// not one per server restart.
#[test]
fn a_template_with_two_problems_reports_both_at_once() {
    let dir = templates_dir(&[(
        "broken.json",
        r#"{
          "key": "broken",
          "name": "Broken",
          "upstream_url": "https://mcp.example.internal/",
          "transport": "grpc",
          "auth_method": "token"
        }"#,
    )]);

    let loaded = load_mcp_templates_reporting(Some(&dir.path().to_string_lossy()));
    let (templates, problems) = (loaded.templates, loaded.problems);

    assert!(
        !templates.iter().any(|t| t.key == "broken"),
        "an invalid template is still skipped"
    );
    let reported = problems
        .iter()
        .find(|p| p.file.contains("broken.json"))
        .unwrap_or_else(|| panic!("the file must be named: {problems:?}"));
    assert_eq!(
        reported.problems.len(),
        2,
        "both problems in one report, not one per restart: {reported:?}"
    );
    let joined = reported.problems.join(" | ");
    assert!(
        joined.contains("transport") && joined.contains("http") && joined.contains("sse"),
        "the transport problem names the legal values: {joined}"
    );
    assert!(
        joined.contains("auth_method")
            && joined.contains("none")
            && joined.contains("api_key")
            && joined.contains("oauth2"),
        "the auth_method problem names the legal values: {joined}"
    );
}

/// A file missing every required field names all of them at once too.
#[test]
fn a_template_missing_required_fields_names_all_of_them() {
    let dir = templates_dir(&[("empty.json", "{}")]);
    let problems = load_mcp_templates_reporting(Some(&dir.path().to_string_lossy())).problems;

    let reported = problems
        .iter()
        .find(|p| p.file.contains("empty.json"))
        .unwrap_or_else(|| panic!("the file must be named: {problems:?}"));
    let joined = reported.problems.join(" | ");
    for field in ["key", "name", "upstream_url", "auth_method"] {
        assert!(
            joined.contains(field),
            "{field} is required and must be reported: {joined}"
        );
    }
}

// ---------------------------------------------------------------------------
// 2. Bound workspaces on the list endpoint
// ---------------------------------------------------------------------------

fn no_auth_template(upstream_url: &str) -> McpServerTemplate {
    McpServerTemplate {
        key: "gaps-mcp".to_string(),
        name: "Gaps MCP".to_string(),
        description: "Synthetic template for the marketplace-gap tests.".to_string(),
        upstream_url: upstream_url.to_string(),
        transport: "http".to_string(),
        auth_method: "none".to_string(),
        credential_template_key: None,
        api_key_header: None,
        api_key_query: None,
        category: "testing".to_string(),
        tags: vec!["test".to_string()],
        icon: "beaker".to_string(),
        sort_order: 9999,
        oauth2_authorize_url: None,
        oauth2_token_url: None,
        oauth2_scopes: None,
        oauth2_app_credential_template_key: None,
        oauth2_resource_url: None,
        oauth2_prefer_dcr: None,
    }
}

/// An MCP server that speaks the full handshake and answers `tools/list`.
async fn mock_mcp_upstream() -> MockServer {
    let server = MockServer::start().await;
    mount_mcp_handshake(&server).await;
    server
}

/// Mount the `initialize` → `notifications/initialized` → `tools/list`
/// handshake on `server`.
async fn mount_mcp_handshake(server: &MockServer) {
    Mock::given(http_method("POST"))
        .and(body_string_contains("\"method\":\"initialize\""))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "protocolVersion": "2025-06-18",
                "capabilities": { "tools": {} },
                "serverInfo": { "name": "mock-mcp", "version": "1.0" },
            }
        })))
        .mount(server)
        .await;
    Mock::given(http_method("POST"))
        .and(body_string_contains("notifications/initialized"))
        .respond_with(ResponseTemplate::new(202))
        .mount(server)
        .await;
    Mock::given(http_method("POST"))
        .and(body_string_contains("\"method\":\"tools/list\""))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0",
            "id": 2,
            "result": { "tools": [ { "name": "echo", "description": "Echo" } ] }
        })))
        .mount(server)
        .await;
}

/// Build an app around `template`, sign an admin in, and provision it for
/// the admin workspace. Returns `(ctx, cookie, workspace id, server id)`.
async fn provision(
    template: McpServerTemplate,
    allow_loopback: bool,
) -> (TestContext, String, String, String, Value) {
    let ctx = TestAppBuilder::new()
        .with_admin()
        .with_mcp_template(template)
        .with_config(move |c| c.proxy_allow_loopback = allow_loopback)
        .build()
        .await;
    create_test_user(&*ctx.store, "gaps-admin", TEST_PASSWORD, UserRole::Admin).await;
    let cookie = login_user_combined(&ctx.app, "gaps-admin", TEST_PASSWORD).await;
    let ws_id = ctx
        .admin_agent
        .as_ref()
        .expect("admin workspace")
        .id
        .0
        .to_string();

    let (status, body) = send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        "/api/v1/mcp-servers/provision",
        None,
        Some(&cookie),
        Some(json!({ "template_key": "gaps-mcp", "workspace_id": ws_id })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "provision: {body}");
    let id = body["data"]["id"].as_str().expect("server id").to_string();
    (ctx, cookie, ws_id, id, body)
}

/// The list endpoint reports the workspaces bound through the junction, the
/// same way the detail endpoint does. The list page's Workspaces column is
/// rendered from this, and it read "No workspaces" for every bound server.
#[tokio::test]
async fn mcp_server_list_reports_the_bound_workspaces() {
    let upstream = mock_mcp_upstream().await;
    let (ctx, cookie, ws_id, id, _) = provision(no_auth_template(&upstream.uri()), true).await;

    let (status, body) = send_json(
        &ctx.app,
        Method::GET,
        "/api/v1/mcp-servers",
        None,
        Some(&cookie),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let row = body["data"]
        .as_array()
        .expect("servers array")
        .iter()
        .find(|s| s["id"] == id.as_str())
        .unwrap_or_else(|| panic!("the provisioned server: {body}"));

    let bound = row["installed_workspaces"]
        .as_array()
        .unwrap_or_else(|| panic!("the list must report bound workspaces: {row}"));
    assert_eq!(bound.len(), 1, "one binding: {row}");
    assert_eq!(bound[0]["id"], ws_id.as_str());
    assert!(
        bound[0]["name"].as_str().is_some_and(|n| !n.is_empty()),
        "the column renders the name: {row}"
    );
}

/// `GET /api/v1/mcp-servers/{id}/workspaces` answers the bindings. It used
/// to answer `405 Allow: POST`, so there was no way to read back what the
/// share endpoints had written.
#[tokio::test]
async fn mcp_server_workspaces_endpoint_lists_the_bindings() {
    let upstream = mock_mcp_upstream().await;
    let (ctx, cookie, ws_id, id, _) = provision(no_auth_template(&upstream.uri()), true).await;

    let (status, body) = send_json(
        &ctx.app,
        Method::GET,
        &format!("/api/v1/mcp-servers/{id}/workspaces"),
        None,
        Some(&cookie),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let bound = body["data"].as_array().expect("bindings array");
    assert_eq!(bound.len(), 1, "one binding: {body}");
    assert_eq!(bound[0]["id"], ws_id.as_str());
}

// ---------------------------------------------------------------------------
// 3. A failed tool discovery is visible, and retryable
// ---------------------------------------------------------------------------

/// Discovery is best-effort, but a failure must be visible: the install
/// response says so and an audit row records the reason. With the SSRF guard
/// at its default, a loopback upstream is refused before a request is made —
/// exactly the walkthrough's failure.
#[tokio::test]
async fn a_failed_tool_discovery_is_reported_in_the_install_and_audited() {
    let upstream = mock_mcp_upstream().await;
    let (ctx, _cookie, _ws, id, body) = provision(no_auth_template(&upstream.uri()), false).await;

    let reason = body["data"]["tool_discovery_error"]
        .as_str()
        .unwrap_or_else(|| panic!("the install response must name the failure: {body}"));
    assert!(
        !reason.is_empty(),
        "the reason is the SSRF refusal, not an empty string: {body}"
    );

    let events = ctx
        .store
        .list_audit_events_filtered(&AuditFilter {
            limit: 100,
            event_type: Some("mcp_tool_discovery_failed".to_string()),
            ..Default::default()
        })
        .await
        .expect("audit list");
    let row = events
        .iter()
        .find(|e| e.resource_id.as_deref() == Some(id.as_str()))
        .unwrap_or_else(|| panic!("an audit row for the failed probe: {events:?}"));
    assert!(
        row.metadata["reason"]
            .as_str()
            .is_some_and(|r| !r.is_empty()),
        "the audit row carries the reason: {}",
        row.metadata
    );
}

/// The detail page's Rediscover tools button posts here, and it repopulates
/// the tool list once the upstream answers.
#[tokio::test]
async fn rediscover_tools_repopulates_the_tool_list() {
    // An upstream that is down at install time: every probe gets a 500.
    let upstream = MockServer::start().await;
    Mock::given(http_method("POST"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&upstream)
        .await;

    let (ctx, cookie, _ws, id, install) = provision(no_auth_template(&upstream.uri()), true).await;
    assert!(
        install["data"]["tool_discovery_error"].as_str().is_some(),
        "the install says discovery failed: {install}"
    );

    let (status, before) = send_json(
        &ctx.app,
        Method::GET,
        &format!("/api/v1/mcp-servers/{id}"),
        None,
        Some(&cookie),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{before}");
    assert_eq!(
        before["data"]["tools"].as_array().map(|t| t.len()),
        Some(0),
        "the failed install left no tools: {before}"
    );

    // The upstream comes up.
    upstream.reset().await;
    mount_mcp_handshake(&upstream).await;

    let (status, body) = send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        &format!("/api/v1/mcp-servers/{id}/discover-tools"),
        None,
        Some(&cookie),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "rediscover: {body}");
    assert_eq!(
        body["data"]["tool_count"], 1,
        "the probe found the upstream's tool: {body}"
    );

    let (status, after) = send_json(
        &ctx.app,
        Method::GET,
        &format!("/api/v1/mcp-servers/{id}"),
        None,
        Some(&cookie),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{after}");
    let tools = after["data"]["tools"].as_array().expect("tools");
    assert_eq!(tools.len(), 1, "the tool is on the record now: {after}");
    assert_eq!(tools[0]["name"], "echo");
}

// ---------------------------------------------------------------------------
// 4. The loader says what a template directory contributed
// ---------------------------------------------------------------------------

/// "The directory is read once, at startup" — and nothing said whether it
/// was read at all. An operator who mistyped the mount path or the variable
/// got a silent no-op and found out only by hunting the marketplace grid.
///
/// The load reports the directory, the keys it took from it and the number
/// of files it skipped, which is what `load_mcp_templates` logs as one INFO
/// line at startup.
#[test]
fn a_template_directory_reports_the_keys_it_contributed() {
    let dir = templates_dir(&[
        ("acme-internal.json", DOCUMENTED_EXAMPLE),
        ("broken.json", r#"{"key": "broken"}"#),
    ]);

    let loaded = load_mcp_templates_reporting(Some(&dir.path().to_string_lossy()));

    let from_dir = loaded
        .directory
        .as_ref()
        .expect("a configured directory is reported");
    assert!(
        from_dir.dir.contains(dir.path().to_string_lossy().as_ref()),
        "the summary names the directory: {from_dir:?}"
    );
    assert_eq!(
        from_dir.loaded,
        vec!["acme-internal".to_string()],
        "the summary names the keys the directory contributed: {from_dir:?}"
    );
    assert_eq!(
        from_dir.skipped, 1,
        "the summary counts the files that did not load: {from_dir:?}"
    );
}

/// With no directory configured there is nothing to confirm, so there is no
/// summary and no startup line.
#[test]
fn no_template_directory_reports_nothing() {
    let loaded = load_mcp_templates_reporting(None);

    assert!(loaded.directory.is_none());
    assert!(
        !loaded.templates.is_empty(),
        "the embedded templates still load"
    );
}
