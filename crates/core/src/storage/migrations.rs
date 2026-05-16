use crate::error::StoreError;

pub const MIGRATION_001: &str = include_str!("../../../../migrations/001_init.sql");
pub const MIGRATION_002: &str = include_str!("../../../../migrations/002_mcp_oauth_states.sql");
pub const MIGRATION_003: &str = include_str!("../../../../migrations/003_mcp_oauth_apps.sql");
pub const MIGRATION_004: &str = include_str!("../../../../migrations/004_mcp_user_ownership.sql");
pub const MIGRATION_005: &str =
    include_str!("../../../../migrations/005_oauth_provider_clients.sql");
pub const MIGRATION_006: &str = include_str!("../../../../migrations/006_device_codes.sql");
pub const MIGRATION_007: &str =
    include_str!("../../../../migrations/007_credential_name_unique.sql");
pub const MIGRATION_008: &str =
    include_str!("../../../../migrations/008_bootstrap_client_mcp_discover_scope.sql");
pub const MIGRATION_009: &str = include_str!("../../../../migrations/009_device_code_pk_hash.sql");
pub const MIGRATION_010: &str =
    include_str!("../../../../migrations/010_mcp_server_workspaces.sql");
pub const MIGRATION_011: &str =
    include_str!("../../../../migrations/011_drop_credential_name_unique.sql");
pub const MIGRATION_012: &str =
    include_str!("../../../../migrations/012_relax_mcp_servers_workspace_id.sql");

/// All migrations in order. Each entry is (version, SQL content).
const MIGRATIONS: [(i64, &str); 12] = [
    (1, MIGRATION_001),
    (2, MIGRATION_002),
    (3, MIGRATION_003),
    (4, MIGRATION_004),
    (5, MIGRATION_005),
    (6, MIGRATION_006),
    (7, MIGRATION_007),
    (8, MIGRATION_008),
    (9, MIGRATION_009),
    (10, MIGRATION_010),
    (11, MIGRATION_011),
    (12, MIGRATION_012),
];

/// Run all pending migrations, tracking applied versions in a `schema_migrations` table.
///
/// This function is idempotent: running it multiple times against the same database
/// will only execute migrations that have not yet been recorded.
pub fn run_migrations(conn: &rusqlite::Connection) -> Result<(), StoreError> {
    // 1. Ensure the schema_migrations tracking table exists.
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS schema_migrations (
            version INTEGER PRIMARY KEY,
            applied_at TEXT NOT NULL
        );",
    )
    .map_err(|e| StoreError::Database(format!("create schema_migrations: {}", e)))?;

    // 2. Query which migrations have already been applied.
    let applied: std::collections::HashSet<i64> = {
        let mut stmt = conn
            .prepare("SELECT version FROM schema_migrations")
            .map_err(|e| StoreError::Database(format!("query schema_migrations: {}", e)))?;
        let rows = stmt
            .query_map([], |row| row.get::<_, i64>(0))
            .map_err(|e| StoreError::Database(format!("read schema_migrations: {}", e)))?;
        let mut set = std::collections::HashSet::new();
        for row in rows {
            let v =
                row.map_err(|e| StoreError::Database(format!("read migration version: {}", e)))?;
            set.insert(v);
        }
        set
    };

    // 3. Run each unapplied migration in order, recording it on success.
    let now = chrono::Utc::now().to_rfc3339();
    for (version, sql) in &MIGRATIONS {
        if applied.contains(version) {
            continue;
        }

        // Use a savepoint so a single migration failure doesn't corrupt state.
        let sp_name = format!("migration_{:03}", version);
        conn.execute_batch(&format!("SAVEPOINT {}", sp_name))
            .map_err(|e| {
                StoreError::Database(format!("savepoint migration {:03}: {}", version, e))
            })?;

        let result = conn
            .execute_batch(sql)
            .map_err(|e| StoreError::Database(format!("migration {:03}: {}", version, e)));

        match result {
            Ok(()) => {
                // Record the migration as applied.
                conn.execute(
                    "INSERT INTO schema_migrations (version, applied_at) VALUES (?1, ?2)",
                    rusqlite::params![version, now],
                )
                .map_err(|e| {
                    StoreError::Database(format!("record migration {:03}: {}", version, e))
                })?;

                conn.execute_batch(&format!("RELEASE {}", sp_name))
                    .map_err(|e| {
                        StoreError::Database(format!("release migration {:03}: {}", version, e))
                    })?;
            }
            Err(e) => {
                // Roll back the failed migration's savepoint.
                let _ = conn.execute_batch(&format!("ROLLBACK TO {}", sp_name));
                let _ = conn.execute_batch(&format!("RELEASE {}", sp_name));
                return Err(e);
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open_memory_db() -> rusqlite::Connection {
        let conn = rusqlite::Connection::open_in_memory().expect("open in-memory db");
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")
            .expect("set pragmas");
        conn
    }

    #[test]
    fn test_migrations_idempotent_fresh_db() {
        let conn = open_memory_db();

        // First run — migration should apply.
        run_migrations(&conn).expect("first run_migrations");

        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM schema_migrations", [], |row| {
                row.get(0)
            })
            .expect("count");
        assert_eq!(
            count,
            MIGRATIONS.len() as i64,
            "all migrations should be recorded"
        );

        // Second run — must not panic or error (idempotent).
        run_migrations(&conn).expect("second run_migrations should be idempotent");

        let count2: i64 = conn
            .query_row("SELECT COUNT(*) FROM schema_migrations", [], |row| {
                row.get(0)
            })
            .expect("count after second run");
        assert_eq!(
            count2,
            MIGRATIONS.len() as i64,
            "same count after second run"
        );
    }

    #[test]
    fn test_schema_has_all_tables() {
        let conn = open_memory_db();
        run_migrations(&conn).expect("run migrations");

        let tables: Vec<String> = {
            let mut stmt = conn
                .prepare(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name",
                )
                .expect("prepare");
            stmt.query_map([], |row| row.get(0))
                .expect("query")
                .map(|r| r.expect("row"))
                .collect()
        };

        let expected = vec![
            "audit_events",
            "credential_secret_history",
            "credentials",
            "crypto_state",
            "device_codes",
            "mcp_oauth_states",
            "mcp_server_workspaces",
            "mcp_servers",
            "oauth_access_tokens",
            "oauth_auth_codes",
            "oauth_clients",
            "oauth_consents",
            "oauth_provider_clients",
            "oauth_refresh_tokens",
            "oidc_auth_states",
            "oidc_providers",
            "policies",
            "provisioning_tokens",
            "schema_migrations",
            "sessions",
            "users",
            "vault_shares",
            "workspace_registrations",
            "workspace_used_jtis",
            "workspaces",
        ];

        assert_eq!(tables, expected);
    }

    #[test]
    fn test_workspace_table_columns() {
        let conn = open_memory_db();
        run_migrations(&conn).expect("run migrations");

        conn.execute(
            "INSERT INTO workspaces (id, name, enabled, status, pk_hash, encryption_public_key,
             tags, owner_id, tool_name, enrollment_token_hash, last_authenticated_at,
             parent_id, created_at, updated_at)
             VALUES ('ws1', 'test', 1, 'active', 'hash1', '{\"kty\":\"EC\"}',
             '[\"tag1\"]', NULL, 'claude-code', 'tok_hash', '2026-01-01',
             NULL, '2026-01-01', '2026-01-01')",
            [],
        )
        .expect("insert workspace with all columns");

        // Verify parent_id self-reference works
        conn.execute(
            "INSERT INTO workspaces (id, name, enabled, status, tags, parent_id, created_at, updated_at)
             VALUES ('ws2', 'child', 1, 'active', '[]', 'ws1', '2026-01-01', '2026-01-01')",
            [],
        )
        .expect("insert child workspace");
    }

    #[test]
    fn test_credential_names_not_unique() {
        // Per the v3.1.1 design (see v311_credential_name_scoping.rs), credential
        // names are NOT unique. Vend-by-name uses Cedar-filtered matching: list
        // candidates, evaluate authorization, return the authorized one (or 300
        // Multiple Choices if ambiguous). Migration 011 drops the global UNIQUE
        // index that migration 007 added — that index was a regression that
        // leaked the existence of other tenants' credentials via 409 Conflict.
        let conn = open_memory_db();
        run_migrations(&conn).expect("run migrations");

        conn.execute(
            "INSERT INTO workspaces (id, name, status, tags, created_at, updated_at) VALUES ('ws1', 'a', 'active', '[]', '2026-01-01', '2026-01-01')",
            [],
        ).expect("insert ws1");
        conn.execute(
            "INSERT INTO workspaces (id, name, status, tags, created_at, updated_at) VALUES ('ws2', 'b', 'active', '[]', '2026-01-01', '2026-01-01')",
            [],
        ).expect("insert ws2");

        conn.execute(
            "INSERT INTO credentials (id, name, service, encrypted_value, nonce, created_by, created_at, updated_at)
             VALUES ('c1', 'api-key', 'github', X'00', X'00', 'ws1', '2026-01-01', '2026-01-01')",
            [],
        ).expect("insert cred for ws1");

        // Same name under a different workspace — must succeed.
        conn.execute(
            "INSERT INTO credentials (id, name, service, encrypted_value, nonce, created_by, created_at, updated_at)
             VALUES ('c2', 'api-key', 'github', X'00', X'00', 'ws2', '2026-01-01', '2026-01-01')",
            [],
        ).expect("duplicate name across workspaces must be allowed");

        // Same name under the same workspace — also must succeed.
        conn.execute(
            "INSERT INTO credentials (id, name, service, encrypted_value, nonce, created_by, created_at, updated_at)
             VALUES ('c3', 'api-key', 'github', X'00', X'00', 'ws1', '2026-01-01', '2026-01-01')",
            [],
        ).expect("duplicate name in same workspace must be allowed");
    }

    #[test]
    fn test_bootstrap_client_has_mcp_discover_scope() {
        let conn = open_memory_db();
        run_migrations(&conn).expect("run migrations");

        let scopes: String = conn
            .query_row(
                "SELECT allowed_scopes FROM oauth_clients WHERE client_id = 'agentcordon-broker'",
                [],
                |row| row.get(0),
            )
            .expect("bootstrap client row");

        for required in [
            "credentials:discover",
            "credentials:vend",
            "mcp:discover",
            "mcp:invoke",
        ] {
            assert!(
                scopes.split(',').any(|s| s.trim() == required),
                "bootstrap client must allow scope {required:?}, got: {scopes:?}"
            );
        }
    }

    #[test]
    fn test_mcp_servers_workspace_id_is_nullable_after_migrations() {
        // Issue #37: `mcp_server_workspaces` is the single source of truth for
        // workspace↔MCP routing. Migration 012 relaxes the legacy
        // `mcp_servers.workspace_id NOT NULL` constraint so new rows can be
        // written without a denormalized owner column.
        let conn = open_memory_db();
        run_migrations(&conn).expect("run migrations");

        conn.execute(
            "INSERT INTO workspaces (id, name, status, tags, created_at, updated_at) \
             VALUES ('ws_anchor', 'anchor', 'active', '[]', '2026-01-01', '2026-01-01')",
            [],
        )
        .expect("seed anchor workspace");

        // INSERT with workspace_id = NULL must succeed.
        conn.execute(
            "INSERT INTO mcp_servers \
             (id, workspace_id, name, upstream_url, transport, credential_bindings, \
              allowed_tools, enabled, created_at, updated_at) \
             VALUES ('mcp_no_owner', NULL, 'orphan-mcp', 'http://x', 'http', '[]', \
                     NULL, 1, '2026-01-01', '2026-01-01')",
            [],
        )
        .expect("INSERT with workspace_id=NULL must succeed after migration 012");

        let stored_workspace_id: Option<String> = conn
            .query_row(
                "SELECT workspace_id FROM mcp_servers WHERE id = 'mcp_no_owner'",
                [],
                |row| row.get(0),
            )
            .expect("row exists");
        assert!(
            stored_workspace_id.is_none(),
            "row should keep workspace_id = NULL, got {:?}",
            stored_workspace_id
        );
    }

    #[test]
    fn test_crypto_state_table() {
        let conn = open_memory_db();
        run_migrations(&conn).expect("run migrations");

        conn.execute(
            "INSERT INTO crypto_state (key_id, encryption_count, last_updated) VALUES ('test', 0, '2026-01-01')",
            [],
        ).expect("insert into crypto_state");

        let count: i64 = conn
            .query_row(
                "SELECT encryption_count FROM crypto_state WHERE key_id = 'test'",
                [],
                |row| row.get(0),
            )
            .expect("query crypto_state");
        assert_eq!(count, 0);
    }
}
