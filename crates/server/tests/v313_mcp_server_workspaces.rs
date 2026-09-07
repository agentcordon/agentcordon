//! v3.1.3 — MCP ↔ workspace M:N junction routes + security (TA designs §1, §6).
//!
//! Covers the wire shape of:
//!   * `POST /api/v1/mcp-servers/{id}/workspaces`         — share/bind
//!   * `DELETE /api/v1/mcp-servers/{id}/workspaces/{wsid}` — unshare/unbind
//!
//! Every handler test drives the HTTP router so we exercise the full stack
//! (Cedar, extractors, audit). Store-level parity / backfill / cascade tests
//! live in `v313_mcp_sharing_migration.rs`.
//!
//! Traceability: each `case_N_M_*` test maps 1:1 to a row in
//! `docs/internal/plan/test-designs-mcp-share.md` §1 and §6.

use crate::common;

use agent_cordon_core::domain::audit::AuditEvent;
use agent_cordon_core::domain::mcp::{McpAuthMethod, McpServer, McpServerId, McpTransport};
use agent_cordon_core::domain::user::{User, UserRole};
use agent_cordon_core::domain::workspace::{Workspace, WorkspaceId, WorkspaceStatus};
use agent_cordon_core::storage::AuditFilter;
use agent_cordon_server::test_helpers::{TestAppBuilder, TestContext};
use axum::http::{Method, StatusCode};
use serde_json::json;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Builders / helpers
// ---------------------------------------------------------------------------

/// Create an operator-level user whose role is permitted by the default policy
/// to `manage_mcp_servers` on `System`.
async fn make_operator(ctx: &TestContext, username: &str) -> User {
    common::create_test_user(
        &*ctx.store,
        username,
        common::TEST_PASSWORD,
        UserRole::Operator,
    )
    .await
}

/// Create an admin user (broader Cedar permissions).
async fn make_admin(ctx: &TestContext, username: &str) -> User {
    common::create_test_user(
        &*ctx.store,
        username,
        common::TEST_PASSWORD,
        UserRole::Admin,
    )
    .await
}

/// Login a user and return (combined_cookie, csrf).
async fn login(ctx: &TestContext, username: &str) -> (String, String) {
    let (session, csrf) = common::login_user(&ctx.app, username, common::TEST_PASSWORD).await;
    (common::combined_cookie(&session, &csrf), csrf)
}

/// Create a workspace owned by `user`. Skips the builder's `owner_id: None`
/// default so we can exercise owner-based Cedar policies.
async fn make_owned_workspace(ctx: &TestContext, name: &str, user: &User) -> Workspace {
    let now = chrono::Utc::now();
    let ws = Workspace {
        id: WorkspaceId(Uuid::new_v4()),
        name: name.to_string(),
        status: WorkspaceStatus::Active,
        pk_hash: None,
        encryption_public_key: None,
        tags: vec![],
        owner_id: Some(user.id.clone()),
        parent_id: None,
        tool_name: None,
        created_at: now,
        updated_at: now,
    };
    ctx.store.create_workspace(&ws).await.expect("create ws");
    ws
}

/// Create an MCP server owned by `user`, anchored to `original_ws`. Also
/// seeds the junction with the original binding (what provision-via-migration
/// would produce in production).
async fn make_mcp_server(
    ctx: &TestContext,
    name: &str,
    original_ws: &Workspace,
    owner: &User,
    enabled: bool,
) -> McpServer {
    let now = chrono::Utc::now();
    let mcp = McpServer {
        id: McpServerId(Uuid::new_v4()),
        workspace_id: Some(original_ws.id.clone()),
        name: name.to_string(),
        upstream_url: format!("https://example.test/{}", name),
        transport: McpTransport::Http,
        allowed_tools: None,
        enabled,
        created_by: None,
        created_at: now,
        updated_at: now,
        tags: vec![],
        required_credentials: None,
        auth_method: McpAuthMethod::None,
        template_key: None,
        discovered_tools: None,
        created_by_user: Some(owner.id.clone()),
    };
    ctx.store.create_mcp_server(&mcp).await.expect("create mcp");
    // Seed the original junction row — mirrors what migration 010 does for
    // pre-existing rows and what any correct provision path should do.
    ctx.store
        .add_mcp_server_workspace(&mcp.id, &original_ws.id, Some(&owner.id))
        .await
        .expect("seed original binding");
    mcp
}

/// POST /api/v1/mcp-servers/{id}/workspaces with the given body.
async fn post_bindings(
    ctx: &TestContext,
    cookie: &str,
    csrf: &str,
    mcp_id: &McpServerId,
    body: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    let uri = format!("/api/v1/mcp-servers/{}/workspaces", mcp_id.0);
    common::send_json(
        &ctx.app,
        Method::POST,
        &uri,
        None,
        Some(cookie),
        Some(csrf),
        Some(body),
    )
    .await
}

/// DELETE /api/v1/mcp-servers/{id}/workspaces/{workspace_id}.
async fn delete_binding(
    ctx: &TestContext,
    cookie: &str,
    csrf: &str,
    mcp_id: &McpServerId,
    ws_id: &WorkspaceId,
) -> (StatusCode, serde_json::Value) {
    let uri = format!("/api/v1/mcp-servers/{}/workspaces/{}", mcp_id.0, ws_id.0);
    common::send_json(
        &ctx.app,
        Method::DELETE,
        &uri,
        None,
        Some(cookie),
        Some(csrf),
        None,
    )
    .await
}

/// GET /api/v1/mcp-servers/{id} — parse installed_workspaces into a sorted Vec<String>.
async fn get_detail_installed_ws_ids(
    ctx: &TestContext,
    cookie: &str,
    mcp_id: &McpServerId,
) -> Vec<String> {
    let uri = format!("/api/v1/mcp-servers/{}", mcp_id.0);
    let (status, body) =
        common::send_json(&ctx.app, Method::GET, &uri, None, Some(cookie), None, None).await;
    assert_eq!(status, StatusCode::OK, "GET detail: {}", body);
    let arr = body["data"]["installed_workspaces"]
        .as_array()
        .expect("installed_workspaces must be an array");
    let mut ids: Vec<String> = arr
        .iter()
        .filter_map(|v| v["id"].as_str().map(String::from))
        .collect();
    ids.sort();
    ids
}

/// Count audit events matching `event_type` in the whole log.
async fn count_audit_events(ctx: &TestContext, event_type: &str) -> usize {
    let filter = AuditFilter {
        limit: 1000,
        ..Default::default()
    };
    let events = ctx
        .store
        .list_audit_events_filtered(&filter)
        .await
        .expect("list audit");
    events
        .iter()
        .filter(|e| audit_type_str(&e.event_type) == event_type)
        .count()
}

/// Fetch events of a given snake_case type.
async fn audit_events_of(ctx: &TestContext, event_type: &str) -> Vec<AuditEvent> {
    let filter = AuditFilter {
        limit: 1000,
        ..Default::default()
    };
    let events = ctx
        .store
        .list_audit_events_filtered(&filter)
        .await
        .expect("list audit");
    events
        .into_iter()
        .filter(|e| audit_type_str(&e.event_type) == event_type)
        .collect()
}

fn audit_type_str(t: &agent_cordon_core::domain::audit::AuditEventType) -> String {
    serde_json::to_value(t)
        .ok()
        .and_then(|v| v.as_str().map(String::from))
        .unwrap_or_default()
}

/// Fixture: one operator + their "original" workspace + their MCP server.
struct OwnerFixture {
    owner: User,
    owner_cookie: String,
    owner_csrf: String,
    original_ws: Workspace,
    mcp: McpServer,
}

async fn owner_fixture(ctx: &TestContext, suffix: &str) -> OwnerFixture {
    let owner = make_operator(ctx, &format!("owner-{}", suffix)).await;
    let (owner_cookie, owner_csrf) = login(ctx, &format!("owner-{}", suffix)).await;
    let original_ws = make_owned_workspace(ctx, &format!("ws-orig-{}", suffix), &owner).await;
    let mcp = make_mcp_server(ctx, &format!("mcp-{}", suffix), &original_ws, &owner, true).await;
    OwnerFixture {
        owner,
        owner_cookie,
        owner_csrf,
        original_ws,
        mcp,
    }
}

// ===========================================================================
// §1.1 — Owner binds 1 workspace they own
// ===========================================================================

#[tokio::test]
async fn case_1_1_owner_binds_one_workspace_they_own() {
    let ctx = TestAppBuilder::new().build().await;
    let fx = owner_fixture(&ctx, "a").await;

    let ws_b = make_owned_workspace(&ctx, "ws-b-a", &fx.owner).await;

    let audit_before = count_audit_events(&ctx, "mcp_server_shared_with_workspace").await;

    let (status, body) = post_bindings(
        &ctx,
        &fx.owner_cookie,
        &fx.owner_csrf,
        &fx.mcp.id,
        json!({ "workspace_ids": [ws_b.id.0.to_string()] }),
    )
    .await;

    // Per openapi: 201 when at least one new row is created.
    assert_eq!(status, StatusCode::CREATED, "body: {}", body);
    assert_eq!(
        body["data"]["added"].as_array().expect("added array").len(),
        1,
        "one new binding should be returned"
    );
    assert_eq!(body["data"]["added"][0], ws_b.id.0.to_string());
    assert!(
        body["data"]["already_bound"]
            .as_array()
            .expect("already_bound array")
            .is_empty(),
        "already_bound must be empty on first bind"
    );

    // Detail lists BOTH: original + newly-bound.
    let installed = get_detail_installed_ws_ids(&ctx, &fx.owner_cookie, &fx.mcp.id).await;
    assert!(
        installed.contains(&fx.original_ws.id.0.to_string()),
        "detail must include the original workspace (junction anchor): {:?}",
        installed
    );
    assert!(
        installed.contains(&ws_b.id.0.to_string()),
        "detail must include the newly-bound workspace: {:?}",
        installed
    );
    assert_eq!(installed.len(), 2);

    // Audit: exactly one new McpServerSharedWithWorkspace event.
    let audit_after = count_audit_events(&ctx, "mcp_server_shared_with_workspace").await;
    assert_eq!(
        audit_after,
        audit_before + 1,
        "exactly one share event expected"
    );
    let events = audit_events_of(&ctx, "mcp_server_shared_with_workspace").await;
    let last = events.last().expect("event");
    assert_eq!(
        last.metadata["workspace_id"].as_str(),
        Some(ws_b.id.0.to_string().as_str()),
        "event must include target workspace_id in details"
    );
    assert_eq!(last.resource_type, "mcp_server");
    assert_eq!(
        last.resource_id.as_deref(),
        Some(fx.mcp.id.0.to_string().as_str())
    );
}

// ===========================================================================
// §1.1 (bis) — Owner binds N (3) workspaces in one call
// ===========================================================================

#[tokio::test]
async fn case_1_2_owner_binds_many_workspaces_atomic() {
    let ctx = TestAppBuilder::new().build().await;
    let fx = owner_fixture(&ctx, "b").await;

    let ws_b = make_owned_workspace(&ctx, "ws-b-b", &fx.owner).await;
    let ws_c = make_owned_workspace(&ctx, "ws-c-b", &fx.owner).await;
    let ws_d = make_owned_workspace(&ctx, "ws-d-b", &fx.owner).await;

    let (status, body) = post_bindings(
        &ctx,
        &fx.owner_cookie,
        &fx.owner_csrf,
        &fx.mcp.id,
        json!({
            "workspace_ids": [
                ws_b.id.0.to_string(),
                ws_c.id.0.to_string(),
                ws_d.id.0.to_string(),
            ]
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "body: {}", body);

    let added = body["data"]["added"].as_array().expect("added array");
    assert_eq!(added.len(), 3, "three new bindings expected");
    let mut added_ids: Vec<&str> = added.iter().filter_map(|v| v.as_str()).collect();
    added_ids.sort();
    let mut expected = [
        ws_b.id.0.to_string(),
        ws_c.id.0.to_string(),
        ws_d.id.0.to_string(),
    ];
    expected.sort();
    let expected_refs: Vec<&str> = expected.iter().map(|s| s.as_str()).collect();
    assert_eq!(added_ids, expected_refs);

    // Detail must list 4 (original + 3 new).
    let installed = get_detail_installed_ws_ids(&ctx, &fx.owner_cookie, &fx.mcp.id).await;
    assert_eq!(installed.len(), 4);

    // Audit: 3 new share events.
    assert_eq!(
        count_audit_events(&ctx, "mcp_server_shared_with_workspace").await,
        3
    );
}

// ===========================================================================
// §1.3 — Non-owner attempting to share someone else's MCP → 403
// ===========================================================================

#[tokio::test]
async fn case_1_3_non_owner_cannot_share_others_mcp() {
    let ctx = TestAppBuilder::new().build().await;

    // Alice owns the MCP.
    let alice = make_operator(&ctx, "alice-c").await;
    let ws_a = make_owned_workspace(&ctx, "ws-a-c", &alice).await;
    let mcp = make_mcp_server(&ctx, "mcp-alice-c", &ws_a, &alice, true).await;

    // Bob is another operator with his own workspace.
    let _bob = make_operator(&ctx, "bob-c").await;
    let (bob_cookie, bob_csrf) = login(&ctx, "bob-c").await;
    let ws_bob = make_owned_workspace(
        &ctx,
        "ws-bob-c",
        &common::create_test_user(
            &*ctx.store,
            "extra-c",
            common::TEST_PASSWORD,
            UserRole::Operator,
        )
        .await,
    )
    .await;
    let _ = ws_bob; // we just need SOME workspace id to target

    let (status, body) = post_bindings(
        &ctx,
        &bob_cookie,
        &bob_csrf,
        &mcp.id,
        json!({ "workspace_ids": [ws_a.id.0.to_string()] }),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "body: {}", body);
    assert_eq!(body["error"]["code"].as_str(), Some("forbidden"));
}

// ===========================================================================
// §1.4 — Admin may share MCPs they don't own
// ===========================================================================

#[tokio::test]
async fn case_1_4_admin_can_share_others_mcp() {
    let ctx = TestAppBuilder::new().build().await;

    // Alice owns the MCP + ws-a.
    let alice = make_operator(&ctx, "alice-d").await;
    let ws_a = make_owned_workspace(&ctx, "ws-a-d", &alice).await;
    let ws_a2 = make_owned_workspace(&ctx, "ws-a2-d", &alice).await;
    let mcp = make_mcp_server(&ctx, "mcp-alice-d", &ws_a, &alice, true).await;

    // Admin user separate from Alice.
    let _admin = make_admin(&ctx, "admin-d").await;
    let (admin_cookie, admin_csrf) = login(&ctx, "admin-d").await;

    let (status, body) = post_bindings(
        &ctx,
        &admin_cookie,
        &admin_csrf,
        &mcp.id,
        json!({ "workspace_ids": [ws_a2.id.0.to_string()] }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "body: {}", body);
}

// ===========================================================================
// §1.5a — Unknown MCP id → 404 (no partial writes possible)
// ===========================================================================

#[tokio::test]
async fn case_1_5a_unknown_mcp_id_returns_404() {
    let ctx = TestAppBuilder::new().build().await;
    let fx = owner_fixture(&ctx, "e").await;

    let missing = McpServerId(Uuid::new_v4());
    let extra_ws = make_owned_workspace(&ctx, "ws-e", &fx.owner).await;

    let (status, body) = post_bindings(
        &ctx,
        &fx.owner_cookie,
        &fx.owner_csrf,
        &missing,
        json!({ "workspace_ids": [extra_ws.id.0.to_string()] }),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "body: {}", body);
    assert_eq!(body["error"]["code"].as_str(), Some("not_found"));
}

// ===========================================================================
// §1.5b — Unknown workspace_id → 404; no partial writes
// ===========================================================================

#[tokio::test]
async fn case_1_5b_unknown_workspace_id_returns_404_no_partial_writes() {
    let ctx = TestAppBuilder::new().build().await;
    let fx = owner_fixture(&ctx, "f").await;

    // One real (valid) workspace + one phantom.
    let ws_real = make_owned_workspace(&ctx, "ws-real-f", &fx.owner).await;
    let phantom = Uuid::new_v4();

    let (status, body) = post_bindings(
        &ctx,
        &fx.owner_cookie,
        &fx.owner_csrf,
        &fx.mcp.id,
        json!({
            "workspace_ids": [
                ws_real.id.0.to_string(),
                phantom.to_string(),
            ]
        }),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "body: {}", body);

    // Critical: the VALID workspace must NOT have been inserted.
    let bound = ctx
        .store
        .list_workspaces_for_mcp_server(&fx.mcp.id)
        .await
        .expect("list");
    let ids: Vec<String> = bound.iter().map(|(id, _)| id.0.to_string()).collect();
    assert!(
        !ids.contains(&ws_real.id.0.to_string()),
        "partial writes leaked: real ws got bound before phantom was rejected"
    );
    assert_eq!(
        ids.len(),
        1,
        "only the seeded original binding should exist, got: {:?}",
        ids
    );

    // No share audit event should have been emitted.
    assert_eq!(
        count_audit_events(&ctx, "mcp_server_shared_with_workspace").await,
        0
    );
}

// ===========================================================================
// §1.6 — Cross-user bind (owner trying to attach a ws they don't own) → 403
// ===========================================================================

#[tokio::test]
async fn case_1_6_cross_user_bind_forbidden_and_mentions_ws_id() {
    let ctx = TestAppBuilder::new().build().await;

    // Alice owns MCP + original ws.
    let fx = owner_fixture(&ctx, "g").await;

    // Bob owns another workspace. Alice tries to attach it — should fail 403.
    let bob = make_operator(&ctx, "bob-g").await;
    let ws_bob = make_owned_workspace(&ctx, "ws-bob-g", &bob).await;

    let (status, body) = post_bindings(
        &ctx,
        &fx.owner_cookie,
        &fx.owner_csrf,
        &fx.mcp.id,
        json!({ "workspace_ids": [ws_bob.id.0.to_string()] }),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "body: {}", body);
    assert_eq!(body["error"]["code"].as_str(), Some("forbidden"));

    // Error message references the offending ws UUID (for debuggability)
    // but must NOT leak the ws name.
    let msg = body["error"]["message"].as_str().expect("message string");
    assert!(
        msg.contains(&ws_bob.id.0.to_string()),
        "error must reference offending ws id: {}",
        msg
    );
    assert!(
        !msg.contains(&ws_bob.name),
        "error must NOT leak workspace name '{}' (got {})",
        ws_bob.name,
        msg
    );

    // No junction writes.
    let bound = ctx
        .store
        .list_workspaces_for_mcp_server(&fx.mcp.id)
        .await
        .expect("list");
    assert_eq!(bound.len(), 1, "only seeded original binding");
}

// ===========================================================================
// §1.7 — Admin bypasses the cross-user check (admin can bind any-to-any)
// ===========================================================================

#[tokio::test]
async fn case_1_7_admin_bypasses_cross_owner_check() {
    let ctx = TestAppBuilder::new().build().await;

    // Alice owns MCP; Bob owns a workspace. Admin binds Bob's ws to Alice's MCP.
    let alice = make_operator(&ctx, "alice-h").await;
    let ws_alice = make_owned_workspace(&ctx, "ws-alice-h", &alice).await;
    let mcp = make_mcp_server(&ctx, "mcp-alice-h", &ws_alice, &alice, true).await;

    let bob = make_operator(&ctx, "bob-h").await;
    let ws_bob = make_owned_workspace(&ctx, "ws-bob-h", &bob).await;

    let _admin = make_admin(&ctx, "admin-h").await;
    let (admin_cookie, admin_csrf) = login(&ctx, "admin-h").await;

    let (status, body) = post_bindings(
        &ctx,
        &admin_cookie,
        &admin_csrf,
        &mcp.id,
        json!({ "workspace_ids": [ws_bob.id.0.to_string()] }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "admin bypass should create binding: {}",
        body
    );
}

// ===========================================================================
// §1.8 — Idempotent re-add → 200 with already_bound populated, zero new audits
// ===========================================================================

#[tokio::test]
async fn case_1_8_idempotent_readd_emits_no_audit() {
    let ctx = TestAppBuilder::new().build().await;
    let fx = owner_fixture(&ctx, "i").await;
    let ws_b = make_owned_workspace(&ctx, "ws-b-i", &fx.owner).await;

    // First bind — creates.
    let (s1, _) = post_bindings(
        &ctx,
        &fx.owner_cookie,
        &fx.owner_csrf,
        &fx.mcp.id,
        json!({ "workspace_ids": [ws_b.id.0.to_string()] }),
    )
    .await;
    assert_eq!(s1, StatusCode::CREATED);
    let audit_after_first = count_audit_events(&ctx, "mcp_server_shared_with_workspace").await;
    assert_eq!(audit_after_first, 1);

    // Second bind of SAME ws — idempotent no-op.
    let (s2, body2) = post_bindings(
        &ctx,
        &fx.owner_cookie,
        &fx.owner_csrf,
        &fx.mcp.id,
        json!({ "workspace_ids": [ws_b.id.0.to_string()] }),
    )
    .await;
    assert_eq!(s2, StatusCode::OK, "re-add must be 200: {}", body2);
    assert!(
        body2["data"]["added"]
            .as_array()
            .expect("added array")
            .is_empty(),
        "added should be empty on re-add"
    );
    let already: Vec<&str> = body2["data"]["already_bound"]
        .as_array()
        .expect("already_bound array")
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    assert_eq!(already, vec![ws_b.id.0.to_string().as_str()]);

    // Zero NEW audit events.
    let audit_after_second = count_audit_events(&ctx, "mcp_server_shared_with_workspace").await;
    assert_eq!(
        audit_after_second, audit_after_first,
        "idempotent re-add must not emit audit events"
    );
}

// ===========================================================================
// §1.9 — Concurrent duplicate binds: both 2xx, exactly one junction row
// ===========================================================================

#[tokio::test]
async fn case_1_9_concurrent_dup_add_produces_one_row() {
    let ctx = TestAppBuilder::new().build().await;
    let fx = owner_fixture(&ctx, "j").await;
    let ws_b = make_owned_workspace(&ctx, "ws-b-j", &fx.owner).await;

    // Two requests in parallel from the same session.
    let app1 = ctx.app.clone();
    let app2 = ctx.app.clone();
    let cookie1 = fx.owner_cookie.clone();
    let cookie2 = fx.owner_cookie.clone();
    let csrf1 = fx.owner_csrf.clone();
    let csrf2 = fx.owner_csrf.clone();
    let uri = format!("/api/v1/mcp-servers/{}/workspaces", fx.mcp.id.0);
    let body = json!({ "workspace_ids": [ws_b.id.0.to_string()] });

    let t1 = tokio::spawn({
        let body = body.clone();
        let uri = uri.clone();
        async move {
            common::send_json(
                &app1,
                Method::POST,
                &uri,
                None,
                Some(&cookie1),
                Some(&csrf1),
                Some(body),
            )
            .await
        }
    });
    let t2 = tokio::spawn({
        let body = body.clone();
        let uri = uri.clone();
        async move {
            common::send_json(
                &app2,
                Method::POST,
                &uri,
                None,
                Some(&cookie2),
                Some(&csrf2),
                Some(body),
            )
            .await
        }
    });

    let (r1, r2) = tokio::join!(t1, t2);
    let (s1, b1) = r1.expect("task1");
    let (s2, b2) = r2.expect("task2");
    assert!(s1.is_success(), "req1 should 2xx: {} {}", s1, b1);
    assert!(s2.is_success(), "req2 should 2xx: {} {}", s2, b2);

    // Junction has exactly 2 rows for this MCP (original + ws_b), NOT 3.
    let bound = ctx
        .store
        .list_workspaces_for_mcp_server(&fx.mcp.id)
        .await
        .expect("list");
    assert_eq!(
        bound.len(),
        2,
        "PK should collapse concurrent duplicates into one row"
    );

    // Exactly one share audit event — the other concurrent call observed
    // the row already present and emitted nothing.
    let share_events = count_audit_events(&ctx, "mcp_server_shared_with_workspace").await;
    assert_eq!(share_events, 1);
}

// ===========================================================================
// §1.10 — MCP disabled — bind still succeeds
// ===========================================================================

#[tokio::test]
async fn case_1_10_disabled_mcp_can_still_be_bound() {
    let ctx = TestAppBuilder::new().build().await;

    let owner = make_operator(&ctx, "owner-k").await;
    let (cookie, csrf) = login(&ctx, "owner-k").await;
    let ws_orig = make_owned_workspace(&ctx, "ws-orig-k", &owner).await;
    let mcp = make_mcp_server(&ctx, "mcp-k", &ws_orig, &owner, /*enabled*/ false).await;
    let ws_extra = make_owned_workspace(&ctx, "ws-extra-k", &owner).await;

    let (status, body) = post_bindings(
        &ctx,
        &cookie,
        &csrf,
        &mcp.id,
        json!({ "workspace_ids": [ws_extra.id.0.to_string()] }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "disabled MCP should still accept new bindings: {}",
        body
    );
}

// ===========================================================================
// §1.11a — Empty array → 422
// ===========================================================================

#[tokio::test]
async fn case_1_11a_empty_array_returns_422() {
    let ctx = TestAppBuilder::new().build().await;
    let fx = owner_fixture(&ctx, "l").await;

    let (status, body) = post_bindings(
        &ctx,
        &fx.owner_cookie,
        &fx.owner_csrf,
        &fx.mcp.id,
        json!({ "workspace_ids": [] }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "empty array rejected: {}",
        body
    );
}

// ===========================================================================
// §1.11b — Malformed UUID in body → 4xx (client error)
// ===========================================================================

#[tokio::test]
async fn case_1_11b_malformed_uuid_returns_4xx() {
    let ctx = TestAppBuilder::new().build().await;
    let fx = owner_fixture(&ctx, "m").await;

    let (status, _) = post_bindings(
        &ctx,
        &fx.owner_cookie,
        &fx.owner_csrf,
        &fx.mcp.id,
        json!({ "workspace_ids": ["not-a-uuid"] }),
    )
    .await;
    // Axum's JSON rejection surfaces as 400 Bad Request for serde Uuid parse
    // failures; some stacks route this through 422. Accept either.
    assert!(
        status == StatusCode::BAD_REQUEST || status == StatusCode::UNPROCESSABLE_ENTITY,
        "malformed UUID should be 400 or 422, got {}",
        status
    );
    assert!(
        status.is_client_error(),
        "must be a client error: {}",
        status
    );
}

// ===========================================================================
// §2.1 — Owner unshares a non-original binding → 204
// ===========================================================================

#[tokio::test]
async fn case_2_1_owner_unshares_non_original_binding() {
    let ctx = TestAppBuilder::new().build().await;
    let fx = owner_fixture(&ctx, "n").await;
    let ws_b = make_owned_workspace(&ctx, "ws-b-n", &fx.owner).await;

    // Add a second binding (ws_b), then unshare ws_b — original remains.
    let (s1, _) = post_bindings(
        &ctx,
        &fx.owner_cookie,
        &fx.owner_csrf,
        &fx.mcp.id,
        json!({ "workspace_ids": [ws_b.id.0.to_string()] }),
    )
    .await;
    assert_eq!(s1, StatusCode::CREATED);

    let audit_before = count_audit_events(&ctx, "mcp_server_unshared_from_workspace").await;

    let (status, body) =
        delete_binding(&ctx, &fx.owner_cookie, &fx.owner_csrf, &fx.mcp.id, &ws_b.id).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "body: {}", body);

    // Detail now excludes ws_b but still includes the original.
    let installed = get_detail_installed_ws_ids(&ctx, &fx.owner_cookie, &fx.mcp.id).await;
    assert_eq!(installed, vec![fx.original_ws.id.0.to_string()]);

    // Audit event was emitted with the target workspace_id.
    let audit_after = count_audit_events(&ctx, "mcp_server_unshared_from_workspace").await;
    assert_eq!(audit_after, audit_before + 1);
    let evts = audit_events_of(&ctx, "mcp_server_unshared_from_workspace").await;
    assert_eq!(
        evts.last().unwrap().metadata["workspace_id"].as_str(),
        Some(ws_b.id.0.to_string().as_str())
    );
}

// ===========================================================================
// §2.2 — Owner unshares the ORIGINAL while others remain
// ===========================================================================
// `mcp_servers.workspace_id` must NOT change — it's an immutable audit anchor.

#[tokio::test]
async fn case_2_2_owner_unshares_original_preserves_audit_anchor() {
    let ctx = TestAppBuilder::new().build().await;
    let fx = owner_fixture(&ctx, "o").await;
    let ws_b = make_owned_workspace(&ctx, "ws-b-o", &fx.owner).await;

    let (s1, _) = post_bindings(
        &ctx,
        &fx.owner_cookie,
        &fx.owner_csrf,
        &fx.mcp.id,
        json!({ "workspace_ids": [ws_b.id.0.to_string()] }),
    )
    .await;
    assert_eq!(s1, StatusCode::CREATED);

    // Snapshot the stored `workspace_id` (audit anchor) BEFORE unshare.
    let before = ctx
        .store
        .get_mcp_server(&fx.mcp.id)
        .await
        .expect("get")
        .expect("exists");
    let anchor_before = before.workspace_id.clone();

    let (status, _) = delete_binding(
        &ctx,
        &fx.owner_cookie,
        &fx.owner_csrf,
        &fx.mcp.id,
        &fx.original_ws.id,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // Junction no longer has the original.
    let installed = get_detail_installed_ws_ids(&ctx, &fx.owner_cookie, &fx.mcp.id).await;
    assert_eq!(installed, vec![ws_b.id.0.to_string()]);

    // But `mcp_servers.workspace_id` is UNCHANGED.
    let after = ctx
        .store
        .get_mcp_server(&fx.mcp.id)
        .await
        .expect("get")
        .expect("exists");
    assert_eq!(
        after.workspace_id, anchor_before,
        "mcp_servers.workspace_id is an immutable audit anchor; unshare must not mutate it"
    );
}

// ===========================================================================
// §2.3 — Owner unshares the LAST binding → 409 with exact message
// ===========================================================================

#[tokio::test]
async fn case_2_3_owner_unshares_last_returns_409() {
    let ctx = TestAppBuilder::new().build().await;
    let fx = owner_fixture(&ctx, "p").await;

    // Only the seeded original binding exists.
    let (status, body) = delete_binding(
        &ctx,
        &fx.owner_cookie,
        &fx.owner_csrf,
        &fx.mcp.id,
        &fx.original_ws.id,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "body: {}", body);
    assert_eq!(body["error"]["code"].as_str(), Some("conflict"));
    assert_eq!(
        body["error"]["message"].as_str(),
        Some("cannot remove last workspace binding — delete the MCP server instead"),
        "exact wording from spec",
    );

    // Junction still has the single row.
    let bound = ctx
        .store
        .list_workspaces_for_mcp_server(&fx.mcp.id)
        .await
        .expect("list");
    assert_eq!(bound.len(), 1);

    // No unshare audit event.
    assert_eq!(
        count_audit_events(&ctx, "mcp_server_unshared_from_workspace").await,
        0
    );
}

// ===========================================================================
// §2.4a — Non-owner DELETE → 403
// ===========================================================================

#[tokio::test]
async fn case_2_4a_non_owner_delete_forbidden() {
    let ctx = TestAppBuilder::new().build().await;
    let fx = owner_fixture(&ctx, "q").await;

    let _bob = make_operator(&ctx, "bob-q").await;
    let (bob_cookie, bob_csrf) = login(&ctx, "bob-q").await;

    let (status, body) =
        delete_binding(&ctx, &bob_cookie, &bob_csrf, &fx.mcp.id, &fx.original_ws.id).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "body: {}", body);
}

// ===========================================================================
// §2.4b — Unknown MCP id on DELETE → 404
// ===========================================================================

#[tokio::test]
async fn case_2_4b_unknown_mcp_returns_404() {
    let ctx = TestAppBuilder::new().build().await;
    let fx = owner_fixture(&ctx, "r").await;

    let phantom = McpServerId(Uuid::new_v4());
    let (status, body) = delete_binding(
        &ctx,
        &fx.owner_cookie,
        &fx.owner_csrf,
        &phantom,
        &fx.original_ws.id,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "body: {}", body);
}

// ===========================================================================
// §2.4c — Binding doesn't exist on DELETE → 404
// ===========================================================================

#[tokio::test]
async fn case_2_4c_nonexistent_binding_returns_404() {
    let ctx = TestAppBuilder::new().build().await;
    let fx = owner_fixture(&ctx, "s").await;
    let ws_b = make_owned_workspace(&ctx, "ws-b-s", &fx.owner).await;
    // ws_b was NEVER bound to the MCP. DELETE on it should 404 (after the
    // last-binding guard passes — ensure we have >1 bindings first).
    let ws_c = make_owned_workspace(&ctx, "ws-c-s", &fx.owner).await;
    let (s_bind, _) = post_bindings(
        &ctx,
        &fx.owner_cookie,
        &fx.owner_csrf,
        &fx.mcp.id,
        json!({ "workspace_ids": [ws_c.id.0.to_string()] }),
    )
    .await;
    assert_eq!(s_bind, StatusCode::CREATED);

    let (status, body) =
        delete_binding(&ctx, &fx.owner_cookie, &fx.owner_csrf, &fx.mcp.id, &ws_b.id).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "no binding for this ws: {}",
        body
    );
}

// ===========================================================================
// §2.5 — Admin unshares a non-last binding → 204
// ===========================================================================

#[tokio::test]
async fn case_2_5_admin_unshares_non_last() {
    let ctx = TestAppBuilder::new().build().await;
    let fx = owner_fixture(&ctx, "t").await;
    let ws_b = make_owned_workspace(&ctx, "ws-b-t", &fx.owner).await;

    // Owner adds a second binding.
    let (s1, _) = post_bindings(
        &ctx,
        &fx.owner_cookie,
        &fx.owner_csrf,
        &fx.mcp.id,
        json!({ "workspace_ids": [ws_b.id.0.to_string()] }),
    )
    .await;
    assert_eq!(s1, StatusCode::CREATED);

    // Admin removes ws_b.
    let _admin = make_admin(&ctx, "admin-t").await;
    let (admin_cookie, admin_csrf) = login(&ctx, "admin-t").await;
    let (status, _) = delete_binding(&ctx, &admin_cookie, &admin_csrf, &fx.mcp.id, &ws_b.id).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
}

// ===========================================================================
// §2.6 — Admin unshares the LAST binding → 409 (state invariant, not authz)
// ===========================================================================

#[tokio::test]
async fn case_2_6_admin_unshares_last_still_409() {
    let ctx = TestAppBuilder::new().build().await;
    let fx = owner_fixture(&ctx, "u").await;

    let _admin = make_admin(&ctx, "admin-u").await;
    let (admin_cookie, admin_csrf) = login(&ctx, "admin-u").await;

    let (status, body) = delete_binding(
        &ctx,
        &admin_cookie,
        &admin_csrf,
        &fx.mcp.id,
        &fx.original_ws.id,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "body: {}", body);
    assert_eq!(
        body["error"]["message"].as_str(),
        Some("cannot remove last workspace binding — delete the MCP server instead")
    );
}

// ===========================================================================
// §2.7 — MCP disabled — unbind still succeeds (204)
// ===========================================================================

#[tokio::test]
async fn case_2_7_disabled_mcp_unbind_succeeds() {
    let ctx = TestAppBuilder::new().build().await;

    let owner = make_operator(&ctx, "owner-v").await;
    let (cookie, csrf) = login(&ctx, "owner-v").await;
    let ws_orig = make_owned_workspace(&ctx, "ws-orig-v", &owner).await;
    let mcp = make_mcp_server(&ctx, "mcp-v", &ws_orig, &owner, /*enabled*/ false).await;
    let ws_extra = make_owned_workspace(&ctx, "ws-extra-v", &owner).await;

    let (s1, _) = post_bindings(
        &ctx,
        &cookie,
        &csrf,
        &mcp.id,
        json!({ "workspace_ids": [ws_extra.id.0.to_string()] }),
    )
    .await;
    assert_eq!(s1, StatusCode::CREATED);

    let (status, _) = delete_binding(&ctx, &cookie, &csrf, &mcp.id, &ws_extra.id).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
}

// ===========================================================================
// §6.1 — Non-admin's GET /api/v1/workspaces only sees their own
// ===========================================================================

#[tokio::test]
async fn case_6_1_workspace_list_is_tenant_scoped() {
    let ctx = TestAppBuilder::new().build().await;

    let alice = make_operator(&ctx, "alice-w").await;
    let bob = make_operator(&ctx, "bob-w").await;

    let ws_alice = make_owned_workspace(&ctx, "ws-alice-w", &alice).await;
    let ws_bob = make_owned_workspace(&ctx, "ws-bob-w", &bob).await;

    // Alice logs in.
    let (alice_cookie, _) = login(&ctx, "alice-w").await;
    let (status, body) = common::send_json(
        &ctx.app,
        Method::GET,
        "/api/v1/workspaces",
        None,
        Some(&alice_cookie),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {}", body);
    let ids: Vec<&str> = body["data"]
        .as_array()
        .expect("data array")
        .iter()
        .filter_map(|w| w["id"].as_str())
        .collect();
    assert!(
        ids.contains(&ws_alice.id.0.to_string().as_str()),
        "alice should see her workspace"
    );
    assert!(
        !ids.contains(&ws_bob.id.0.to_string().as_str()),
        "alice MUST NOT see bob's workspace"
    );
}

// ===========================================================================
// §6.2 — Admin's GET /api/v1/workspaces sees everyone's
// ===========================================================================

#[tokio::test]
async fn case_6_2_workspace_list_admin_sees_all() {
    let ctx = TestAppBuilder::new().build().await;

    let alice = make_operator(&ctx, "alice-x").await;
    let bob = make_operator(&ctx, "bob-x").await;
    let ws_alice = make_owned_workspace(&ctx, "ws-alice-x", &alice).await;
    let ws_bob = make_owned_workspace(&ctx, "ws-bob-x", &bob).await;

    let _admin = make_admin(&ctx, "admin-x").await;
    let (admin_cookie, _) = login(&ctx, "admin-x").await;

    let (status, body) = common::send_json(
        &ctx.app,
        Method::GET,
        "/api/v1/workspaces",
        None,
        Some(&admin_cookie),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let ids: Vec<&str> = body["data"]
        .as_array()
        .expect("data array")
        .iter()
        .filter_map(|w| w["id"].as_str())
        .collect();
    assert!(
        ids.contains(&ws_alice.id.0.to_string().as_str())
            && ids.contains(&ws_bob.id.0.to_string().as_str()),
        "admin should see both: got {:?}",
        ids
    );
}
