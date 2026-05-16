//! v3.1.3 — MCP ↔ workspace junction: migration idempotency, store DAO parity,
//! and cascade coverage (TA designs §1-store, §2).
//!
//! These tests drive the storage trait directly (no HTTP) because:
//!
//!   * The raw backfill SQL shape is already covered by the unit test
//!     `crates/core/src/storage/sqlite/mcp_server_workspaces.rs::
//!      migration_backfills_junction_from_existing_mcp_servers`, which can
//!     reach the private `conn()` for arbitrary SQL. We do NOT re-prove the
//!     SELECT … INSERT wording here — that would duplicate a unit test.
//!   * What the integration layer needs to verify is that the `Store` trait
//!     surface (`add_`, `remove_`, `list_`, `count_`) behaves identically to
//!     the SQL it wraps, AND that the foreign-key cascades defined by
//!     migration 010 actually fire through the trait `delete_*` methods that
//!     product code uses.
//!   * The postgres DAO is compiled behind the `postgres` feature and not
//!     exercised by this binary; it is validated separately in the core
//!     crate's postgres-only tests (see `crates/core/src/storage/postgres/
//!     mcp_server_workspaces.rs`). Documenting the gap here rather than
//!     duplicating the test grid.

use agent_cordon_core::domain::mcp::{McpAuthMethod, McpServer, McpServerId, McpTransport};
use agent_cordon_core::domain::workspace::{Workspace, WorkspaceId, WorkspaceStatus};
use agent_cordon_core::storage::sqlite::SqliteStore;
use agent_cordon_core::storage::{McpServerWorkspaceStore, McpStore, Store, WorkspaceStore};
use chrono::Utc;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Builders
// ---------------------------------------------------------------------------

async fn open_store() -> SqliteStore {
    let store = SqliteStore::new_in_memory().await.expect("open sqlite");
    store.run_migrations().await.expect("run migrations");
    store
}

fn mk_workspace(name: &str) -> Workspace {
    let now = Utc::now();
    Workspace {
        id: WorkspaceId(Uuid::new_v4()),
        name: name.to_string(),
        enabled: true,
        status: WorkspaceStatus::Active,
        pk_hash: None,
        encryption_public_key: None,
        tags: vec![],
        owner_id: None,
        parent_id: None,
        tool_name: None,
        created_at: now,
        updated_at: now,
    }
}

fn mk_mcp(workspace_id: &WorkspaceId, name: &str, enabled: bool) -> McpServer {
    let now = Utc::now();
    McpServer {
        id: McpServerId(Uuid::new_v4()),
        workspace_id: Some(workspace_id.clone()),
        name: name.to_string(),
        upstream_url: "https://example.test".to_string(),
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
        created_by_user: None,
    }
}

// ===========================================================================
// Migration 010 is idempotent — run_migrations() twice is safe.
// ===========================================================================
//
// Verifies the schema_migrations version tracker + `ON CONFLICT DO NOTHING`
// backfill don't explode on a re-run (e.g. in-place upgrade restart).

#[tokio::test]
async fn migration_run_migrations_is_idempotent() {
    let store = SqliteStore::new_in_memory().await.expect("open sqlite");
    store.run_migrations().await.expect("first migrate");
    store
        .run_migrations()
        .await
        .expect("second migrate must be a no-op");
    store
        .run_migrations()
        .await
        .expect("third migrate still safe");

    // Add a binding and confirm the junction table survives the replays.
    let ws = mk_workspace("ws");
    store.create_workspace(&ws).await.expect("ws");
    let mcp = mk_mcp(&ws.id, "m", true);
    store.create_mcp_server(&mcp).await.expect("mcp");
    assert!(store
        .add_mcp_server_workspace(&mcp.id, &ws.id, None)
        .await
        .expect("add"));
    assert_eq!(
        store
            .count_workspaces_for_mcp_server(&mcp.id)
            .await
            .expect("count"),
        1
    );
}

// ===========================================================================
// Store DAO — `add` is idempotent via composite PK
// ===========================================================================

#[tokio::test]
async fn store_add_is_idempotent_returns_false_on_duplicate() {
    let store = open_store().await;
    let ws = mk_workspace("ws");
    store.create_workspace(&ws).await.expect("ws");
    let mcp = mk_mcp(&ws.id, "mcp", true);
    store.create_mcp_server(&mcp).await.expect("mcp");

    let first = store
        .add_mcp_server_workspace(&mcp.id, &ws.id, None)
        .await
        .expect("add 1");
    assert!(first, "first insert reports true (new row)");

    let second = store
        .add_mcp_server_workspace(&mcp.id, &ws.id, None)
        .await
        .expect("add 2");
    assert!(
        !second,
        "duplicate insert reports false (row already existed)"
    );

    assert_eq!(
        store
            .count_workspaces_for_mcp_server(&mcp.id)
            .await
            .expect("count"),
        1,
        "junction has exactly one row"
    );
}

// ===========================================================================
// Store DAO — `remove` reports rows-affected
// ===========================================================================

#[tokio::test]
async fn store_remove_returns_rows_affected() {
    let store = open_store().await;
    let ws = mk_workspace("ws");
    store.create_workspace(&ws).await.expect("ws");
    let mcp = mk_mcp(&ws.id, "mcp", true);
    store.create_mcp_server(&mcp).await.expect("mcp");
    store
        .add_mcp_server_workspace(&mcp.id, &ws.id, None)
        .await
        .expect("add");

    let first = store
        .remove_mcp_server_workspace(&mcp.id, &ws.id)
        .await
        .expect("remove 1");
    assert!(first, "remove of existing row reports true");

    let second = store
        .remove_mcp_server_workspace(&mcp.id, &ws.id)
        .await
        .expect("remove 2");
    assert!(!second, "remove of missing row reports false");
}

// ===========================================================================
// Store DAO — list_mcp_servers_for_workspace filters disabled MCPs
// ===========================================================================
//
// This is the function the broker's `mcp_sync` tick calls. Disabled MCPs must
// not leak into broker caches, even if their junction row is present.

#[tokio::test]
async fn store_list_for_workspace_filters_disabled() {
    let store = open_store().await;
    let ws = mk_workspace("ws");
    store.create_workspace(&ws).await.expect("ws");
    let enabled = mk_mcp(&ws.id, "m-enabled", true);
    let disabled = mk_mcp(&ws.id, "m-disabled", false);
    store.create_mcp_server(&enabled).await.expect("mcp-e");
    store.create_mcp_server(&disabled).await.expect("mcp-d");

    store
        .add_mcp_server_workspace(&enabled.id, &ws.id, None)
        .await
        .expect("add e");
    store
        .add_mcp_server_workspace(&disabled.id, &ws.id, None)
        .await
        .expect("add d");

    let for_ws = store
        .list_mcp_servers_for_workspace(&ws.id)
        .await
        .expect("list");
    let names: Vec<String> = for_ws.iter().map(|s| s.name.clone()).collect();
    assert_eq!(
        names,
        vec!["m-enabled".to_string()],
        "broker sync must not see disabled MCPs: got {:?}",
        names
    );
}

// ===========================================================================
// Store DAO — list_workspaces_for_mcp_server ignores enabled=false filter
// ===========================================================================
//
// The reverse-direction view (what workspaces is this MCP bound to?) is used
// by the MCP detail handler. It must return ALL bindings regardless of the
// MCP's enable flag, so admins can see disabled MCPs' live footprint.

#[tokio::test]
async fn store_list_workspaces_for_mcp_ignores_enabled_flag() {
    let store = open_store().await;
    let ws_a = mk_workspace("A");
    let ws_b = mk_workspace("B");
    store.create_workspace(&ws_a).await.expect("ws A");
    store.create_workspace(&ws_b).await.expect("ws B");

    // Disabled MCP bound to two workspaces.
    let disabled = mk_mcp(&ws_a.id, "m-disabled", false);
    store.create_mcp_server(&disabled).await.expect("mcp");
    store
        .add_mcp_server_workspace(&disabled.id, &ws_a.id, None)
        .await
        .expect("add A");
    store
        .add_mcp_server_workspace(&disabled.id, &ws_b.id, None)
        .await
        .expect("add B");

    let bound = store
        .list_workspaces_for_mcp_server(&disabled.id)
        .await
        .expect("list");
    assert_eq!(bound.len(), 2, "list must include both bindings");
}

// ===========================================================================
// Cascade — deleting a workspace drops only its junction rows
// ===========================================================================

#[tokio::test]
async fn cascade_workspace_delete_drops_only_that_rows() {
    let store = open_store().await;
    let ws_a = mk_workspace("ws-A");
    let ws_b = mk_workspace("ws-B");
    store.create_workspace(&ws_a).await.expect("ws A");
    store.create_workspace(&ws_b).await.expect("ws B");

    let mcp = mk_mcp(&ws_a.id, "mcp", true);
    store.create_mcp_server(&mcp).await.expect("mcp");

    store
        .add_mcp_server_workspace(&mcp.id, &ws_a.id, None)
        .await
        .expect("bind A");
    store
        .add_mcp_server_workspace(&mcp.id, &ws_b.id, None)
        .await
        .expect("bind B");
    assert_eq!(
        store
            .count_workspaces_for_mcp_server(&mcp.id)
            .await
            .expect("count"),
        2
    );

    // Delete workspace B — ON DELETE CASCADE clears (mcp, ws_b) only.
    let deleted = store.delete_workspace(&ws_b.id).await.expect("delete ws B");
    assert!(deleted);

    let bound = store
        .list_workspaces_for_mcp_server(&mcp.id)
        .await
        .expect("list after cascade");
    assert_eq!(bound.len(), 1, "only (mcp, ws_a) remains");
    assert_eq!(bound[0].0, ws_a.id, "ws_a binding preserved");
}

// ===========================================================================
// Cascade — deleting an MCP drops all its junction rows
// ===========================================================================

#[tokio::test]
async fn cascade_mcp_delete_drops_all_its_rows() {
    let store = open_store().await;
    let ws_a = mk_workspace("ws-A");
    let ws_b = mk_workspace("ws-B");
    store.create_workspace(&ws_a).await.expect("ws A");
    store.create_workspace(&ws_b).await.expect("ws B");

    let mcp_x = mk_mcp(&ws_a.id, "mcp-X", true);
    let mcp_y = mk_mcp(&ws_a.id, "mcp-Y", true);
    store.create_mcp_server(&mcp_x).await.expect("mcp X");
    store.create_mcp_server(&mcp_y).await.expect("mcp Y");

    store
        .add_mcp_server_workspace(&mcp_x.id, &ws_a.id, None)
        .await
        .expect("bind X→A");
    store
        .add_mcp_server_workspace(&mcp_x.id, &ws_b.id, None)
        .await
        .expect("bind X→B");
    store
        .add_mcp_server_workspace(&mcp_y.id, &ws_a.id, None)
        .await
        .expect("bind Y→A");

    // Delete MCP X — ON DELETE CASCADE removes its two junction rows.
    store.delete_mcp_server(&mcp_x.id).await.expect("delete X");

    assert_eq!(
        store
            .count_workspaces_for_mcp_server(&mcp_x.id)
            .await
            .expect("count X"),
        0,
        "cascade must drop all junction rows for deleted MCP"
    );

    // Y's row survived intact.
    let y_bound = store
        .list_workspaces_for_mcp_server(&mcp_y.id)
        .await
        .expect("list Y");
    assert_eq!(y_bound.len(), 1);
    assert_eq!(y_bound[0].0, ws_a.id);
}
