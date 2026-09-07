//! S20 — per-tool MCP gating: what an operator can narrow, what a refusal
//! records, and what the two reference lists must name.
//!
//! Server HTTP seam (`TestAppBuilder` + `tower::ServiceExt::oneshot`) for the
//! behaviour, and the template sources for the two prose action references.
//! The UAT scenario that found these is
//! `uat/playwright/tests/22-s20-mcp-gating.spec.ts`.

use axum::http::{Method, StatusCode};
use serde_json::json;
use uuid::Uuid;

use agent_cordon_core::domain::audit::{AuditEvent, AuditEventType};
use agent_cordon_core::domain::mcp::{
    McpAuthMethod, McpServer, McpServerId, McpTool, McpTransport,
};
use agent_cordon_core::domain::user::UserRole;
use agent_cordon_core::domain::workspace::WorkspaceId;
use agent_cordon_core::storage::{AuditFilter, Store};
use wiremock::matchers::{body_string_contains, method as wm_method};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::common::*;
use agent_cordon_server::test_helpers::{TestAppBuilder, TestContext};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn tool(name: &str) -> McpTool {
    McpTool {
        name: name.to_string(),
        description: Some(format!("the {name} tool")),
        input_schema: Some(json!({ "type": "object" })),
    }
}

/// An MCP server bound to `workspace_id` through the junction, with the four
/// tools the UAT scenario's mock server publishes.
async fn create_bound_mcp_server(
    store: &(dyn Store + Send + Sync),
    workspace_id: &WorkspaceId,
    name: &str,
) -> McpServerId {
    let now = chrono::Utc::now();
    let tools = vec![tool("echo"), tool("whoami"), tool("team_notice")];
    let server = McpServer {
        id: McpServerId(Uuid::new_v4()),
        workspace_id: Some(workspace_id.clone()),
        name: name.to_string(),
        upstream_url: format!("http://localhost:9999/{}", name),
        transport: McpTransport::Http,
        allowed_tools: Some(tools.iter().map(|t| t.name.clone()).collect()),
        enabled: true,
        created_by: None,
        created_at: now,
        updated_at: now,
        tags: vec![],
        required_credentials: None,
        auth_method: McpAuthMethod::default(),
        template_key: None,
        discovered_tools: Some(tools),
        created_by_user: None,
    };
    store
        .create_mcp_server(&server)
        .await
        .expect("create MCP server");
    store
        .add_mcp_server_workspace(&server.id, workspace_id, None)
        .await
        .expect("bind MCP server to workspace");
    server.id
}

/// Admin user + combined session cookie/csrf on a context that also has an
/// admin workspace.
async fn admin_session(ctx: &TestContext, username: &str) -> (String, String) {
    create_user_in_db(
        &*ctx.store,
        username,
        TEST_PASSWORD,
        UserRole::Admin,
        false,
        true,
    )
    .await;
    let (session, csrf) = login_user(&ctx.app, username, TEST_PASSWORD).await;
    (combined_cookie(&session, &csrf), csrf)
}

fn audit_type_str(t: &AuditEventType) -> String {
    serde_json::to_value(t)
        .ok()
        .and_then(|v| v.as_str().map(String::from))
        .unwrap_or_default()
}

async fn audit_events_of(ctx: &TestContext, event_type: &str) -> Vec<AuditEvent> {
    let filter = AuditFilter {
        limit: 1000,
        ..Default::default()
    };
    ctx.store
        .list_audit_events_filtered(&filter)
        .await
        .expect("list audit")
        .into_iter()
        .filter(|e| audit_type_str(&e.event_type) == event_type)
        .collect()
}

/// `POST /api/v1/workspaces/mcp-authorize` as the admin workspace.
async fn authorize(
    ctx: &TestContext,
    jwt: &str,
    server_name: &str,
    tool_name: &str,
) -> (StatusCode, serde_json::Value) {
    send_json(
        &ctx.app,
        Method::POST,
        "/api/v1/workspaces/mcp-authorize",
        Some(jwt),
        None,
        None,
        Some(json!({ "server_name": server_name, "tool_name": tool_name })),
    )
    .await
}

/// A policy set that permits everything except `whoami` on any MCP server —
/// the shape the Access tab's per-tool Deny writes.
const PER_TOOL_DENY: &str = r#"
permit(
  principal is AgentCordon::Workspace,
  action,
  resource
) when { principal.enabled };

permit(
  principal is AgentCordon::User,
  action,
  resource
);

forbid(
  principal is AgentCordon::Workspace,
  action == AgentCordon::Action::"mcp_tool_call",
  resource is AgentCordon::McpServer
) when { context.tool_name == "whoami" };
"#;

// ===========================================================================
// G-S20-5 — a tool call refused by policy writes an mcp_tool_call_denied row
// ===========================================================================

#[tokio::test]
async fn a_policy_refusal_writes_an_mcp_tool_call_denied_audit_row() {
    let ctx = TestAppBuilder::new()
        .with_policy(PER_TOOL_DENY)
        .with_admin()
        .build()
        .await;
    let ws = ctx.admin_agent.as_ref().unwrap();
    let ws_name = ws.name.clone();
    let ws_id = ws.id.clone();
    create_bound_mcp_server(&*ctx.store, &ws_id, "uat-none").await;
    let jwt = ctx_admin_jwt(&ctx).await;

    let (status, body) = authorize(&ctx, &jwt, "uat-none", "whoami").await;
    assert_eq!(status, StatusCode::OK, "mcp-authorize: {}", body);
    assert_eq!(
        body["data"]["decision"], "forbid",
        "the per-tool deny must refuse: {}",
        body
    );
    let correlation_id = body["data"]["correlation_id"].as_str().unwrap().to_string();

    let denied = audit_events_of(&ctx, "mcp_tool_call_denied").await;
    let row = denied
        .iter()
        .find(|e| e.correlation_id == correlation_id)
        .unwrap_or_else(|| {
            panic!(
                "a policy refusal must write mcp_tool_call_denied; rows: {:?}",
                denied
                    .iter()
                    .map(|e| e.metadata.clone())
                    .collect::<Vec<_>>()
            )
        });

    assert_eq!(
        row.metadata.get("server_name").and_then(|v| v.as_str()),
        Some("uat-none"),
        "the row names the server"
    );
    assert_eq!(
        row.metadata.get("tool_name").and_then(|v| v.as_str()),
        Some("whoami"),
        "the row names the tool"
    );
    assert_eq!(
        row.workspace_name.as_deref(),
        Some(ws_name.as_str()),
        "the row names the workspace that was refused"
    );
    assert_eq!(
        format!("{:?}", row.decision).to_lowercase(),
        "forbid",
        "the row is a forbid"
    );
    let reason = row
        .metadata
        .get("reason")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    assert!(
        !reason.is_empty() && reason != "unknown_server",
        "the row says why the call was refused, not 'unknown_server': {:?}",
        row.metadata
    );
}

#[tokio::test]
async fn a_permitted_tool_call_writes_no_denied_row() {
    let ctx = TestAppBuilder::new()
        .with_policy(PER_TOOL_DENY)
        .with_admin()
        .build()
        .await;
    let ws_id = ctx.admin_agent.as_ref().unwrap().id.clone();
    create_bound_mcp_server(&*ctx.store, &ws_id, "uat-none").await;
    let jwt = ctx_admin_jwt(&ctx).await;

    let (status, body) = authorize(&ctx, &jwt, "uat-none", "echo").await;
    assert_eq!(status, StatusCode::OK, "mcp-authorize: {}", body);
    assert_eq!(body["data"]["decision"], "permit", "{}", body);

    assert!(
        audit_events_of(&ctx, "mcp_tool_call_denied")
            .await
            .is_empty(),
        "a permitted call writes no denial"
    );
    assert_eq!(
        audit_events_of(&ctx, "mcp_tool_called").await.len(),
        1,
        "a permitted call writes the domain event"
    );
}

#[tokio::test]
async fn a_disabled_server_says_so_in_the_denied_row() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let ws_id = ctx.admin_agent.as_ref().unwrap().id.clone();
    let id = create_bound_mcp_server(&*ctx.store, &ws_id, "uat-none").await;
    let (cookie, csrf) = admin_session(&ctx, "s20-disable-admin").await;
    let (status, body) = send_json(
        &ctx.app,
        Method::PUT,
        &format!("/api/v1/mcp-servers/{}", id.0),
        None,
        Some(&cookie),
        Some(&csrf),
        Some(json!({ "enabled": false })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "PUT enabled=false: {}", body);

    let jwt = ctx_admin_jwt(&ctx).await;
    let (status, body) = authorize(&ctx, &jwt, "uat-none", "echo").await;
    assert_eq!(status, StatusCode::OK, "{}", body);
    assert_eq!(body["data"]["decision"], "forbid", "{}", body);

    let denied = audit_events_of(&ctx, "mcp_tool_call_denied").await;
    let row = denied.first().expect("a denial row");
    assert_eq!(
        row.metadata.get("reason").and_then(|v| v.as_str()),
        Some("server_disabled"),
        "a disabled server is not an unknown one: {:?}",
        row.metadata
    );
}

#[tokio::test]
async fn an_unknown_server_still_says_unknown_server() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let jwt = ctx_admin_jwt(&ctx).await;
    let (status, body) = authorize(&ctx, &jwt, "no-such-server", "echo").await;
    assert_eq!(status, StatusCode::OK, "{}", body);
    assert_eq!(body["data"]["decision"], "forbid", "{}", body);

    let denied = audit_events_of(&ctx, "mcp_tool_call_denied").await;
    let row = denied.first().expect("a denial row");
    assert_eq!(
        row.metadata.get("reason").and_then(|v| v.as_str()),
        Some("unknown_server"),
        "{:?}",
        row.metadata
    );
}

// ===========================================================================
// G-S20-2 — the rows generate-policies writes are generated, not authored
// ===========================================================================

/// `POST /api/v1/mcp-servers/{id}/generate-policies` with an empty body, the
/// way the Access tab's button calls it.
async fn generate_policies(
    ctx: &TestContext,
    cookie: &str,
    csrf: &str,
    id: &McpServerId,
) -> (StatusCode, serde_json::Value) {
    send_json(
        &ctx.app,
        Method::POST,
        &format!("/api/v1/mcp-servers/{}/generate-policies", id.0),
        None,
        Some(cookie),
        Some(csrf),
        Some(json!({})),
    )
    .await
}

/// A context whose admin workspace carries a tag, so an empty generate body
/// resolves to that tag and to the server's own tools.
async fn tagged_generator_ctx(username: &str) -> (TestContext, String, String, McpServerId) {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let ws = ctx.admin_agent.as_ref().unwrap().id.clone();
    let mut workspace = ctx
        .store
        .get_workspace(&ws)
        .await
        .expect("load workspace")
        .expect("workspace exists");
    workspace.tags = vec!["uat-s20".to_string()];
    ctx.store
        .update_workspace(&workspace)
        .await
        .expect("tag workspace");

    let id = create_bound_mcp_server(&*ctx.store, &ws, "uat-none").await;
    let (cookie, csrf) = admin_session(&ctx, username).await;
    (ctx, cookie, csrf, id)
}

#[tokio::test]
async fn generated_policies_are_named_with_the_grant_prefix_the_access_tab_uses() {
    let (ctx, cookie, csrf, id) = tagged_generator_ctx("s20-gen-name").await;

    let (status, body) = generate_policies(&ctx, &cookie, &csrf, &id).await;
    assert_eq!(status, StatusCode::OK, "generate-policies: {}", body);
    let created = body["data"]["policies_created"].as_array().unwrap();
    assert!(!created.is_empty(), "policies were created: {}", body);

    for policy in created {
        let name = policy["name"].as_str().unwrap();
        assert!(
            agent_cordon_server::services::policies::is_generated_grant(name),
            "a generated policy must be recognised as generated, not counted as authored: {name}"
        );
        assert!(
            name.starts_with(&format!("grant:mcp:{}:", id.0)),
            "a generated policy is named the way the Access tab names its rows: {name}"
        );
    }
}

#[tokio::test]
async fn generating_policies_does_not_unprotect_the_last_enabled_policy() {
    let (ctx, cookie, csrf, id) = tagged_generator_ctx("s20-gen-guard").await;

    let (status, body) = generate_policies(&ctx, &cookie, &csrf, &id).await;
    assert_eq!(status, StatusCode::OK, "generate-policies: {}", body);
    assert!(
        !body["data"]["policies_created"]
            .as_array()
            .unwrap()
            .is_empty(),
        "policies were created: {}",
        body
    );

    let policies = ctx.store.list_policies().await.expect("list policies");
    let default = policies
        .iter()
        .find(|p| p.name == "default")
        .expect("the seeded default policy");

    let (status, body) = send_json(
        &ctx.app,
        Method::DELETE,
        &format!("/api/v1/policies/{}", default.id.0),
        None,
        Some(&cookie),
        Some(&csrf),
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "the seeded default is still the last authored policy after generating: {}",
        body
    );

    let (status, body) = send_json(
        &ctx.app,
        Method::PUT,
        &format!("/api/v1/policies/{}", default.id.0),
        None,
        Some(&cookie),
        Some(&csrf),
        Some(json!({ "enabled": false })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "and it still refuses to be disabled: {}",
        body
    );
}

#[tokio::test]
async fn a_generated_policy_still_permits_the_tagged_workspace_that_tool() {
    let (ctx, cookie, csrf, id) = tagged_generator_ctx("s20-gen-effect").await;
    let (status, body) = generate_policies(&ctx, &cookie, &csrf, &id).await;
    assert_eq!(status, StatusCode::OK, "{}", body);

    // The rename is a naming change only: the Cedar text still names the
    // server, the tag and the tool.
    let policies = ctx.store.list_policies().await.expect("list policies");
    let generated = policies
        .iter()
        .find(|p| p.name.contains(":mcp_tool_call:echo"))
        .unwrap_or_else(|| {
            panic!(
                "a generated row for echo; got {:?}",
                policies.iter().map(|p| &p.name).collect::<Vec<_>>()
            )
        });
    assert!(
        generated
            .cedar_policy
            .contains("context.tool_name == \"echo\""),
        "{}",
        generated.cedar_policy
    );
    assert!(
        generated
            .cedar_policy
            .contains("principal.tags.contains(\"uat-s20\")"),
        "{}",
        generated.cedar_policy
    );
    assert!(generated.enabled, "a generated grant is enabled");
}

#[tokio::test]
async fn generating_twice_creates_nothing_the_second_time() {
    let (ctx, cookie, csrf, id) = tagged_generator_ctx("s20-gen-twice").await;
    let (status, body) = generate_policies(&ctx, &cookie, &csrf, &id).await;
    assert_eq!(status, StatusCode::OK, "{}", body);
    let first = body["data"]["policies_created"].as_array().unwrap().len();
    assert!(first > 0);

    let (status, body) = generate_policies(&ctx, &cookie, &csrf, &id).await;
    assert_eq!(status, StatusCode::OK, "{}", body);
    assert_eq!(
        body["data"]["policies_created"].as_array().unwrap().len(),
        0,
        "the generator skips names that already exist: {}",
        body
    );
}

/// Installs that already ran `generate-policies` hold `mcp-<id>-<tool>-<tag>`
/// rows, which no name predicate recognises. The startup data migration
/// renames them onto the `grant:` convention so the guard and the Policies
/// list see them the same way as freshly generated ones.
#[tokio::test]
async fn the_startup_migration_renames_legacy_generated_policy_rows() {
    use agent_cordon_core::domain::policy::{PolicyId, StoredPolicy};

    let ctx = TestAppBuilder::new().with_admin().build().await;
    let ws = ctx.admin_agent.as_ref().unwrap().id.clone();
    let id = create_bound_mcp_server(&*ctx.store, &ws, "uat-none").await;

    let now = chrono::Utc::now();
    // A tool and a tag that both carry hyphens: the old name cannot be
    // parsed back, so the migration reads the Cedar text instead.
    let legacy_name = format!("mcp-{}-team-notice-uat-s20", id.0);
    let legacy = StoredPolicy {
        id: PolicyId(Uuid::new_v4()),
        name: legacy_name.clone(),
        description: Some("Auto-generated".to_string()),
        cedar_policy: format!(
            r#"permit(
  principal is AgentCordon::Workspace,
  action == AgentCordon::Action::"mcp_tool_call",
  resource == AgentCordon::McpServer::"{}"
) when {{
  principal.tags.contains("uat-s20") &&
  context.tool_name == "team-notice"
}};"#,
            id.0
        ),
        enabled: true,
        is_system: false,
        created_at: now,
        updated_at: now,
    };
    ctx.store.store_policy(&legacy).await.expect("seed legacy");

    agent_cordon_server::migrations::migrate_generated_mcp_policy_names(&*ctx.store).await;

    let policies = ctx.store.list_policies().await.expect("list policies");
    assert!(
        !policies.iter().any(|p| p.name == legacy_name),
        "the legacy name is gone: {:?}",
        policies.iter().map(|p| &p.name).collect::<Vec<_>>()
    );
    let renamed = policies
        .iter()
        .find(|p| agent_cordon_server::services::policies::is_generated_grant(&p.name))
        .expect("a renamed generated grant");
    assert_eq!(
        renamed.name,
        format!("grant:mcp:{}:tag:uat-s20:mcp_tool_call:team-notice", id.0),
        "the rename recovers tool and tag from the Cedar text"
    );
    assert_eq!(
        renamed.cedar_policy, legacy.cedar_policy,
        "only the name changes"
    );

    // Idempotent: a second pass leaves the renamed row alone.
    agent_cordon_server::migrations::migrate_generated_mcp_policy_names(&*ctx.store).await;
    let after = ctx.store.list_policies().await.expect("list policies");
    assert_eq!(after.len(), policies.len(), "a second pass changes nothing");
}

// ===========================================================================
// G-S20-3 — the policy tester answers a per-tool question
// ===========================================================================

/// `POST /api/v1/policies/test` with a `tool_name` context claim, the way the
/// tester's Tool name field sends it.
async fn test_policy_for_tool(
    ctx: &TestContext,
    cookie: &str,
    csrf: &str,
    workspace_id: &WorkspaceId,
    server_id: &McpServerId,
    tool_name: &str,
) -> (StatusCode, serde_json::Value) {
    send_json(
        &ctx.app,
        Method::POST,
        "/api/v1/policies/test",
        None,
        Some(cookie),
        Some(csrf),
        Some(json!({
            "principal": { "type": "Workspace", "id": workspace_id.0.to_string(), "attributes": {} },
            "action": "mcp_tool_call",
            "resource": { "type": "McpServer", "id": server_id.0.to_string(), "attributes": {} },
            "context": { "tool_name": tool_name },
        })),
    )
    .await
}

#[tokio::test]
async fn the_tester_route_answers_per_tool_under_a_per_tool_deny() {
    let ctx = TestAppBuilder::new()
        .with_policy(PER_TOOL_DENY)
        .with_admin()
        .build()
        .await;
    let ws = ctx.admin_agent.as_ref().unwrap().id.clone();
    let id = create_bound_mcp_server(&*ctx.store, &ws, "uat-none").await;
    let (cookie, csrf) = admin_session(&ctx, "s20-tester").await;

    let (status, body) = test_policy_for_tool(&ctx, &cookie, &csrf, &ws, &id, "echo").await;
    assert_eq!(status, StatusCode::OK, "policies/test: {}", body);
    assert_eq!(
        body["data"]["decision"], "permit",
        "the granted tool is permitted: {}",
        body
    );

    let (status, body) = test_policy_for_tool(&ctx, &cookie, &csrf, &ws, &id, "whoami").await;
    assert_eq!(status, StatusCode::OK, "policies/test: {}", body);
    assert_eq!(
        body["data"]["decision"], "forbid",
        "the denied tool is refused, and the difference is the tool name alone: {}",
        body
    );
}

// ===========================================================================
// G-S20-1 — an MCP server's tool list can be narrowed
// ===========================================================================

async fn put_server(
    ctx: &TestContext,
    cookie: &str,
    csrf: &str,
    id: &McpServerId,
    body: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    send_json(
        &ctx.app,
        Method::PUT,
        &format!("/api/v1/mcp-servers/{}", id.0),
        None,
        Some(cookie),
        Some(csrf),
        Some(body),
    )
    .await
}

#[tokio::test]
async fn allowed_tools_narrows_the_set_an_agent_may_call() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let ws = ctx.admin_agent.as_ref().unwrap().id.clone();
    let id = create_bound_mcp_server(&*ctx.store, &ws, "uat-none").await;
    let (cookie, csrf) = admin_session(&ctx, "s20-narrow").await;

    let (status, body) = put_server(
        &ctx,
        &cookie,
        &csrf,
        &id,
        json!({ "allowed_tools": ["echo"] }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "PUT allowed_tools: {}", body);
    assert_eq!(
        body["data"]["allowed_tools"],
        json!(["echo"]),
        "the response reports the narrowed set: {}",
        body
    );

    // The detail endpoint keeps reporting every discovered tool — the Tools
    // tab has to draw a box per tool, ticked or not — and says which are
    // allowed alongside.
    let (status, body) = send_json(
        &ctx.app,
        Method::GET,
        &format!("/api/v1/mcp-servers/{}", id.0),
        None,
        Some(&cookie),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{}", body);
    let names: Vec<&str> = body["data"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert_eq!(
        names,
        vec!["echo", "whoami", "team_notice"],
        "discovery's list is unchanged: {}",
        body
    );
    assert_eq!(body["data"]["allowed_tools"], json!(["echo"]), "{}", body);
}

#[tokio::test]
async fn allowed_tools_refuses_a_tool_the_server_does_not_have() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let ws = ctx.admin_agent.as_ref().unwrap().id.clone();
    let id = create_bound_mcp_server(&*ctx.store, &ws, "uat-none").await;
    let (cookie, csrf) = admin_session(&ctx, "s20-narrow-bad").await;

    let (status, body) = put_server(
        &ctx,
        &cookie,
        &csrf,
        &id,
        json!({ "allowed_tools": ["echo", "not_a_tool", "also_missing"] }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{}", body);
    let message = body["error"]["message"].as_str().unwrap_or_default();
    assert!(
        message.contains("not_a_tool") && message.contains("also_missing"),
        "the refusal names every unknown tool: {}",
        body
    );

    let server = ctx
        .store
        .get_mcp_server(&id)
        .await
        .expect("load")
        .expect("exists");
    assert_eq!(
        server.allowed_tools,
        Some(vec![
            "echo".to_string(),
            "whoami".to_string(),
            "team_notice".to_string()
        ]),
        "a refused narrowing changes nothing"
    );
}

#[tokio::test]
async fn allowed_tools_accepts_an_empty_list_meaning_none() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let ws = ctx.admin_agent.as_ref().unwrap().id.clone();
    let id = create_bound_mcp_server(&*ctx.store, &ws, "uat-none").await;
    let (cookie, csrf) = admin_session(&ctx, "s20-narrow-none").await;

    let (status, body) =
        put_server(&ctx, &cookie, &csrf, &id, json!({ "allowed_tools": [] })).await;
    assert_eq!(status, StatusCode::OK, "{}", body);
    assert_eq!(body["data"]["allowed_tools"], json!([]), "{}", body);
}

#[tokio::test]
async fn narrowing_the_tool_list_is_audited() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let ws = ctx.admin_agent.as_ref().unwrap().id.clone();
    let id = create_bound_mcp_server(&*ctx.store, &ws, "uat-none").await;
    let (cookie, csrf) = admin_session(&ctx, "s20-narrow-audit").await;

    let (status, body) = put_server(
        &ctx,
        &cookie,
        &csrf,
        &id,
        json!({ "allowed_tools": ["echo"] }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{}", body);

    let updated = audit_events_of(&ctx, "mcp_server_updated").await;
    let row = updated
        .iter()
        .find(|e| e.metadata.get("allowed_tools_changed") == Some(&json!(true)))
        .unwrap_or_else(|| {
            panic!(
                "the narrowing is audited; rows: {:?}",
                updated
                    .iter()
                    .map(|e| e.metadata.clone())
                    .collect::<Vec<_>>()
            )
        });
    assert_eq!(
        row.metadata.get("allowed_tools"),
        Some(&json!(["echo"])),
        "the row names the set it was narrowed to: {:?}",
        row.metadata
    );
}

#[tokio::test]
async fn workspace_sync_carries_only_the_allowed_tools() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let ws = ctx.admin_agent.as_ref().unwrap().id.clone();
    let id = create_bound_mcp_server(&*ctx.store, &ws, "uat-none").await;
    let (cookie, csrf) = admin_session(&ctx, "s20-narrow-sync").await;
    let (status, _) = put_server(
        &ctx,
        &cookie,
        &csrf,
        &id,
        json!({ "allowed_tools": ["echo"] }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let jwt = ctx_admin_jwt(&ctx).await;

    // What `agentcordon mcp-tools` and `agentcordon_mcp_tools` are built from.
    let (status, body) = send_json(
        &ctx.app,
        Method::GET,
        "/api/v1/workspaces/mcp-tools",
        Some(&jwt),
        None,
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{}", body);
    let tools: Vec<&str> = body["data"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|t| t["server"] == "uat-none")
        .map(|t| t["tool"].as_str().unwrap())
        .collect();
    assert_eq!(
        tools,
        vec!["echo"],
        "a narrowed server hands the broker only what it allows: {}",
        body
    );
    // The narrowing must not cost the descriptions discovery captured.
    let echo = body["data"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["tool"] == "echo")
        .unwrap();
    assert_eq!(echo["description"], "the echo tool", "{}", body);

    // And the server sync, which is what the broker caches.
    let (status, body) = send_json(
        &ctx.app,
        Method::GET,
        "/api/v1/workspaces/mcp-servers",
        Some(&jwt),
        None,
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{}", body);
    let entry = body["data"]["servers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["name"] == "uat-none")
        .expect("the bound server");
    assert_eq!(entry["tools"], json!(["echo"]), "{}", body);
    assert_eq!(
        entry["tools_are_authoritative"],
        json!(true),
        "the broker must not re-widen a narrowed list by probing the upstream: {}",
        body
    );
}

#[tokio::test]
async fn a_tool_outside_allowed_tools_is_refused_and_audited() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let ws = ctx.admin_agent.as_ref().unwrap().id.clone();
    let id = create_bound_mcp_server(&*ctx.store, &ws, "uat-none").await;
    let (cookie, csrf) = admin_session(&ctx, "s20-narrow-call").await;
    let (status, _) = put_server(
        &ctx,
        &cookie,
        &csrf,
        &id,
        json!({ "allowed_tools": ["echo"] }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let jwt = ctx_admin_jwt(&ctx).await;

    let (status, body) = authorize(&ctx, &jwt, "uat-none", "echo").await;
    assert_eq!(status, StatusCode::OK, "{}", body);
    assert_eq!(body["data"]["decision"], "permit", "{}", body);

    let (status, body) = authorize(&ctx, &jwt, "uat-none", "whoami").await;
    assert_eq!(status, StatusCode::OK, "{}", body);
    assert_eq!(
        body["data"]["decision"], "forbid",
        "a tool outside the allow-list is refused however permissive the policy is: {}",
        body
    );

    let denied = audit_events_of(&ctx, "mcp_tool_call_denied").await;
    let row = denied
        .iter()
        .find(|e| e.metadata.get("tool_name") == Some(&json!("whoami")))
        .expect("the refusal is audited the same way every other one is");
    assert_eq!(
        row.metadata.get("reason").and_then(|v| v.as_str()),
        Some("tool_not_allowed"),
        "{:?}",
        row.metadata
    );
}

/// A `tools/list` upstream that publishes `tools`.
async fn mock_upstream(tools: &[&str]) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(wm_method("POST"))
        .and(body_string_contains("\"method\":\"initialize\""))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0", "id": 1,
            "result": {
                "protocolVersion": "2025-06-18",
                "capabilities": { "tools": {} },
                "serverInfo": { "name": "mock-mcp", "version": "1.0" },
            }
        })))
        .mount(&server)
        .await;
    Mock::given(wm_method("POST"))
        .and(body_string_contains("notifications/initialized"))
        .respond_with(ResponseTemplate::new(202))
        .mount(&server)
        .await;
    let listed: Vec<serde_json::Value> = tools
        .iter()
        .map(|n| json!({ "name": n, "description": format!("the {n} tool"), "inputSchema": { "type": "object" } }))
        .collect();
    Mock::given(wm_method("POST"))
        .and(body_string_contains("\"method\":\"tools/list\""))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0", "id": 2, "result": { "tools": listed }
        })))
        .mount(&server)
        .await;
    server
}

/// A context whose `uat-none` server points at a live `tools/list` upstream.
async fn rediscoverable_ctx(
    username: &str,
    upstream: &MockServer,
) -> (TestContext, String, String, McpServerId) {
    let ctx = TestAppBuilder::new()
        .with_admin()
        .with_config(|c| c.proxy_allow_loopback = true)
        .build()
        .await;
    let ws = ctx.admin_agent.as_ref().unwrap().id.clone();
    let id = create_bound_mcp_server(&*ctx.store, &ws, "uat-none").await;
    let mut server = ctx
        .store
        .get_mcp_server(&id)
        .await
        .expect("load")
        .expect("exists");
    server.upstream_url = upstream.uri();
    ctx.store
        .update_mcp_server(&server)
        .await
        .expect("point at the upstream");
    let (cookie, csrf) = admin_session(&ctx, username).await;
    (ctx, cookie, csrf, id)
}

async fn rediscover(
    ctx: &TestContext,
    cookie: &str,
    csrf: &str,
    id: &McpServerId,
) -> (StatusCode, serde_json::Value) {
    send_json(
        &ctx.app,
        Method::POST,
        &format!("/api/v1/mcp-servers/{}/discover-tools", id.0),
        None,
        Some(cookie),
        Some(csrf),
        None,
    )
    .await
}

#[tokio::test]
async fn rediscovery_does_not_silently_re_widen_a_narrowed_list() {
    let upstream = mock_upstream(&["echo", "whoami", "team_notice", "brand_new"]).await;
    let (ctx, cookie, csrf, id) = rediscoverable_ctx("s20-rediscover-narrow", &upstream).await;
    let (status, _) = put_server(
        &ctx,
        &cookie,
        &csrf,
        &id,
        json!({ "allowed_tools": ["echo"] }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = rediscover(&ctx, &cookie, &csrf, &id).await;
    assert_eq!(status, StatusCode::OK, "discover-tools: {}", body);

    let after = ctx
        .store
        .get_mcp_server(&id)
        .await
        .expect("load")
        .expect("exists");
    assert_eq!(
        after.allowed_tools,
        Some(vec!["echo".to_string()]),
        "a narrowing survives rediscovery"
    );
    assert_eq!(
        after.discovered_tools.as_ref().map(|t| t.len()),
        Some(4),
        "and the new tool is on the record, ready to be ticked"
    );
}

#[tokio::test]
async fn rediscovery_still_widens_a_server_that_was_never_narrowed() {
    let upstream = mock_upstream(&["echo", "whoami", "team_notice", "brand_new"]).await;
    let (ctx, cookie, csrf, id) = rediscoverable_ctx("s20-rediscover-wide", &upstream).await;

    let (status, body) = rediscover(&ctx, &cookie, &csrf, &id).await;
    assert_eq!(status, StatusCode::OK, "discover-tools: {}", body);

    let after = ctx
        .store
        .get_mcp_server(&id)
        .await
        .expect("load")
        .expect("exists");
    assert_eq!(
        after.allowed_tools.as_ref().map(|t| t.len()),
        Some(4),
        "an unnarrowed server takes everything discovery found"
    );
}

// ===========================================================================
// G-S20-4 — the two prose action references name every schema action
// ===========================================================================

fn repo_root() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
}

/// Every action the Cedar schema defines, sorted.
fn schema_actions() -> Vec<String> {
    let text = std::fs::read_to_string(repo_root().join("policies/schema.cedarschema.json"))
        .expect("read the Cedar schema");
    let schema: serde_json::Value = serde_json::from_str(&text).expect("schema is JSON");
    let namespace = schema
        .get("AgentCordon")
        .expect("the AgentCordon namespace");
    let mut actions: Vec<String> = namespace["actions"]
        .as_object()
        .expect("actions is an object")
        .keys()
        .cloned()
        .collect();
    actions.sort();
    actions
}

/// The `ACTION REFERENCE:` comment block at the head of the shipped default
/// policy — the block itself, not the whole file, so an action that happens to
/// appear in a policy statement below does not count as documented.
fn action_reference_block() -> String {
    let text = std::fs::read_to_string(repo_root().join("policies/default.cedar"))
        .expect("read default.cedar");
    let start = text.find("ACTION REFERENCE").expect("an ACTION REFERENCE block");
    let rest = &text[start..];
    let end = rest
        .find("\n// ====")
        .expect("the block is closed by a rule");
    rest[..end].to_string()
}

/// `policies/default.cedar`'s ACTION REFERENCE and
/// `docs/authorization-and-cedar-policy.md` § Actions are the two lists an
/// operator writes a policy from, and neither is generated from the schema.
/// Both omitted `manage_consents` (uat S20, G-S20-4). This test is the thing
/// that stops them drifting again: a new action in the schema fails it until
/// both references name it.
#[test]
fn both_prose_action_references_name_every_action_the_schema_defines() {
    let actions = schema_actions();
    assert!(
        actions.len() > 10,
        "sanity: the schema defines a real action set, got {actions:?}"
    );

    let doc = std::fs::read_to_string(repo_root().join("docs/authorization-and-cedar-policy.md"))
        .expect("read the authorization doc");
    let reference = action_reference_block();

    let missing_from_doc: Vec<&String> = actions
        .iter()
        .filter(|a| !doc.contains(&format!("`{a}`")))
        .collect();
    let missing_from_cedar: Vec<&String> = actions
        .iter()
        .filter(|a| !reference.contains(a.as_str()))
        .collect();

    assert!(
        missing_from_doc.is_empty(),
        "docs/authorization-and-cedar-policy.md § Actions must name every action the Cedar \
         schema defines — an action nobody documents is one nobody uses and nobody reviews. \
         Missing: {missing_from_doc:?}"
    );
    assert!(
        missing_from_cedar.is_empty(),
        "policies/default.cedar's ACTION REFERENCE must name every action the Cedar schema \
         defines. Missing: {missing_from_cedar:?}"
    );
}
