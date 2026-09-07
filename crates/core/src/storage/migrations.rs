use crate::domain::time::format_timestamp;
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
pub const MIGRATION_013: &str =
    include_str!("../../../../migrations/013_restore_mcp_server_workspace_bindings.sql");
pub const MIGRATION_014: &str = include_str!("../../../../migrations/014_user_oidc_identities.sql");
pub const MIGRATION_015: &str =
    include_str!("../../../../migrations/015_refresh_token_families.sql");
pub const MIGRATION_016: &str = include_str!("../../../../migrations/016_oauth_workspace_id.sql");
pub const MIGRATION_017: &str =
    include_str!("../../../../migrations/017_workspace_status_disabled.sql");
pub const MIGRATION_018: &str =
    include_str!("../../../../migrations/018_credential_name_index.sql");
pub const MIGRATION_019: &str =
    include_str!("../../../../migrations/019_secret_history_key_version.sql");
pub const MIGRATION_020: &str = include_str!("../../../../migrations/020_drop_dead_tables.sql");
pub const MIGRATION_021: &str = include_str!("../../../../migrations/021_vaults_table.sql");

/// All migrations in order. Each entry is (version, SQL content).
const MIGRATIONS: [(i64, &str); 21] = [
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
    (13, MIGRATION_013),
    (14, MIGRATION_014),
    (15, MIGRATION_015),
    (16, MIGRATION_016),
    (17, MIGRATION_017),
    (18, MIGRATION_018),
    (19, MIGRATION_019),
    (20, MIGRATION_020),
    (21, MIGRATION_021),
];

/// Run all pending migrations, tracking applied versions in a `schema_migrations` table.
///
/// This function is idempotent: running it multiple times against the same database
/// will only execute migrations that have not yet been recorded.
pub fn run_migrations(conn: &rusqlite::Connection) -> Result<(), StoreError> {
    run_migrations_up_to(conn, i64::MAX)
}

/// Run pending migrations whose version is `<= max_version`.
///
/// Exists so upgrade tests can stop at a known schema version, seed rows the
/// way a real deployment would have them, and then apply the next migration
/// against data. Production callers use [`run_migrations`].
pub fn run_migrations_up_to(
    conn: &rusqlite::Connection,
    max_version: i64,
) -> Result<(), StoreError> {
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
    let now = format_timestamp(&chrono::Utc::now());
    for (version, sql) in &MIGRATIONS {
        if *version > max_version || applied.contains(version) {
            continue;
        }

        if rebuilds_a_table(sql) {
            apply_with_foreign_keys_off(conn, *version, sql, &now)?;
        } else {
            apply_in_savepoint(conn, *version, sql, &now)?;
        }
    }

    Ok(())
}

/// Marker a migration puts on its first line when it recreates a table.
///
/// SQLite cannot alter a column constraint in place, so such migrations
/// `DROP TABLE` and rename a replacement. Every production connection has
/// `PRAGMA foreign_keys=ON`, under which the drop cascades into every child
/// table (that is how 012 emptied `mcp_server_workspaces`). SQLite's
/// documented procedure is to turn enforcement off for the rebuild, run it
/// in a transaction, verify with `foreign_key_check`, then turn enforcement
/// back on. The pragma is a no-op inside a transaction, so the runner has to
/// do this outside its usual savepoint.
pub const TABLE_REBUILD_MARKER: &str = "-- migration-mode: foreign_keys_off";

fn rebuilds_a_table(sql: &str) -> bool {
    sql.trim_start().starts_with(TABLE_REBUILD_MARKER)
}

/// Default path: run the migration inside a savepoint so a failure leaves
/// the schema as it was.
fn apply_in_savepoint(
    conn: &rusqlite::Connection,
    version: i64,
    sql: &str,
    now: &str,
) -> Result<(), StoreError> {
    let sp_name = format!("migration_{:03}", version);
    conn.execute_batch(&format!("SAVEPOINT {}", sp_name))
        .map_err(|e| StoreError::Database(format!("savepoint migration {:03}: {}", version, e)))?;

    let result = conn
        .execute_batch(sql)
        .map_err(|e| StoreError::Database(format!("migration {:03}: {}", version, e)))
        .and_then(|()| record_applied(conn, version, now));

    match result {
        Ok(()) => conn
            .execute_batch(&format!("RELEASE {}", sp_name))
            .map_err(|e| StoreError::Database(format!("release migration {:03}: {}", version, e))),
        Err(e) => {
            let _ = conn.execute_batch(&format!("ROLLBACK TO {}", sp_name));
            let _ = conn.execute_batch(&format!("RELEASE {}", sp_name));
            Err(e)
        }
    }
}

/// Table-rebuild path: foreign-key enforcement off, one transaction, an
/// explicit integrity check before commit, enforcement restored no matter
/// what happened.
fn apply_with_foreign_keys_off(
    conn: &rusqlite::Connection,
    version: i64,
    sql: &str,
    now: &str,
) -> Result<(), StoreError> {
    conn.execute_batch("PRAGMA foreign_keys=OFF;")
        .map_err(|e| StoreError::Database(format!("migration {:03}: fk off: {}", version, e)))?;

    let result = conn
        .execute_batch("BEGIN;")
        .map_err(|e| StoreError::Database(format!("migration {:03}: begin: {}", version, e)))
        .and_then(|()| {
            conn.execute_batch(sql)
                .map_err(|e| StoreError::Database(format!("migration {:03}: {}", version, e)))
        })
        .and_then(|()| {
            let violations: i64 = conn
                .query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |r| {
                    r.get(0)
                })
                .map_err(|e| {
                    StoreError::Database(format!("migration {:03}: fk check: {}", version, e))
                })?;
            if violations > 0 {
                return Err(StoreError::Database(format!(
                    "migration {:03}: {} foreign key violation(s) after table rebuild",
                    version, violations
                )));
            }
            Ok(())
        })
        .and_then(|()| record_applied(conn, version, now))
        .and_then(|()| {
            conn.execute_batch("COMMIT;").map_err(|e| {
                StoreError::Database(format!("migration {:03}: commit: {}", version, e))
            })
        });

    if result.is_err() {
        let _ = conn.execute_batch("ROLLBACK;");
    }
    // Restore enforcement for the rest of this connection's life regardless.
    let restore = conn
        .execute_batch("PRAGMA foreign_keys=ON;")
        .map_err(|e| StoreError::Database(format!("migration {:03}: fk on: {}", version, e)));

    result.and(restore)
}

fn record_applied(conn: &rusqlite::Connection, version: i64, now: &str) -> Result<(), StoreError> {
    conn.execute(
        "INSERT INTO schema_migrations (version, applied_at) VALUES (?1, ?2)",
        rusqlite::params![version, now],
    )
    .map(|_| ())
    .map_err(|e| StoreError::Database(format!("record migration {:03}: {}", version, e)))
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
            "schema_migrations",
            "sessions",
            "user_oidc_identities",
            "users",
            "vault_shares",
            "vaults",
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

    /// Upgrade path: 020 drops the four tables nothing reads any more. An
    /// install at version 19 still holds rows in them (a JTI, a pending
    /// registration, a provisioning token, the nonce counter); the drop must
    /// succeed over those rows, leave every live table and its rows alone,
    /// and leave no dangling foreign keys.
    #[test]
    fn migration_020_drops_dead_tables_over_existing_rows() {
        let conn = open_memory_db();
        run_migrations_up_to(&conn, 19).expect("migrate to 019");

        conn.execute_batch(
            "INSERT INTO workspaces (id, name, pk_hash, enabled, status, created_at, updated_at) \
               VALUES ('w1', 'ws1', 'h1', 1, 'active', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z');
             INSERT INTO workspace_used_jtis (jti, device_id, expires_at) \
               VALUES ('jti-1', 'w1', '2027-01-01T00:00:00Z');
             INSERT INTO workspace_registrations (pk_hash, code_challenge, code_hash, expires_at, created_at) \
               VALUES ('h-pending', 'c', 'ch', '2027-01-01T00:00:00Z', '2026-01-01T00:00:00Z');
             INSERT INTO provisioning_tokens (token_hash, name, expires_at, created_at) \
               VALUES ('t1', 'ci', '2027-01-01T00:00:00Z', '2026-01-01T00:00:00Z');
             INSERT INTO crypto_state (key_id, encryption_count, last_updated) \
               VALUES ('master', 4200, '2026-01-01T00:00:00Z');",
        )
        .expect("seed an install at version 19");

        run_migrations(&conn).expect("apply 020 onward");

        let table_exists = |name: &str| -> bool {
            conn.query_row(
                "SELECT COUNT(*) > 0 FROM sqlite_master WHERE type = 'table' AND name = ?1",
                [name],
                |r| r.get(0),
            )
            .expect("sqlite_master query")
        };
        for dropped in [
            "workspace_used_jtis",
            "workspace_registrations",
            "provisioning_tokens",
            "crypto_state",
        ] {
            assert!(!table_exists(dropped), "{dropped} must be gone after 020");
        }
        assert!(table_exists("workspaces"), "live tables stay");
        let workspaces: i64 = conn
            .query_row("SELECT COUNT(*) FROM workspaces", [], |r| r.get(0))
            .expect("count workspaces");
        assert_eq!(workspaces, 1, "rows in live tables are untouched");

        let fk_violations: i64 = conn
            .query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |r| {
                r.get(0)
            })
            .expect("fk check");
        assert_eq!(fk_violations, 0);
    }

    /// Upgrade path: a workspace binding that exists at schema version 11
    /// must still exist after migration 012.
    ///
    /// 012 rebuilds `mcp_servers` with DROP TABLE. Every production
    /// connection runs with `PRAGMA foreign_keys=ON`, and the junction
    /// declares `ON DELETE CASCADE` to `mcp_servers`, so the drop cascades.
    #[test]
    fn mcp_server_workspace_bindings_survive_migration_012() {
        let conn = open_memory_db();
        run_migrations_up_to(&conn, 11).expect("migrate to 011");

        conn.execute_batch(
            "INSERT INTO workspaces (id, name, pk_hash, enabled, status, created_at, updated_at) \
               VALUES ('w1', 'ws', 'h1', 1, 'active', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z');
             INSERT INTO mcp_servers (id, workspace_id, name, upstream_url, created_at, updated_at) \
               VALUES ('m1', 'w1', 'gh', 'https://x', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z');
             INSERT INTO mcp_server_workspaces (mcp_server_id, workspace_id) VALUES ('m1', 'w1');",
        )
        .expect("seed a bound MCP server at version 11");

        run_migrations(&conn).expect("apply 012 onward");

        let bindings: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM mcp_server_workspaces \
                 WHERE mcp_server_id = 'm1' AND workspace_id = 'w1'",
                [],
                |row| row.get(0),
            )
            .expect("count bindings");
        assert_eq!(
            bindings, 1,
            "the m1<->w1 binding must survive the 012 table rebuild"
        );

        let fk_violations: i64 = conn
            .query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |row| {
                row.get(0)
            })
            .expect("foreign_key_check");
        assert_eq!(fk_violations, 0, "no dangling foreign keys after upgrade");
    }

    /// Repair path: an install that already ran the cascading 012 has MCP
    /// servers whose legacy `workspace_id` is set but whose junction row is
    /// gone. The next migration must restore the binding from the legacy
    /// column, and must not disturb bindings that are still present.
    #[test]
    fn migration_013_restores_bindings_lost_to_cascade() {
        let conn = open_memory_db();
        run_migrations_up_to(&conn, 12).expect("migrate to 012");

        conn.execute_batch(
            "INSERT INTO workspaces (id, name, pk_hash, enabled, status, created_at, updated_at) \
               VALUES ('w1', 'ws1', 'h1', 1, 'active', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z'), \
                      ('w2', 'ws2', 'h2', 1, 'active', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z');
             -- lost: legacy anchor present, junction row missing
             INSERT INTO mcp_servers (id, workspace_id, name, upstream_url, created_at, updated_at) \
               VALUES ('m_lost', 'w1', 'gh', 'https://x', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z');
             -- intact: junction row still there
             INSERT INTO mcp_servers (id, workspace_id, name, upstream_url, created_at, updated_at) \
               VALUES ('m_ok', 'w2', 'jira', 'https://y', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z');
             INSERT INTO mcp_server_workspaces (mcp_server_id, workspace_id) VALUES ('m_ok', 'w2');
             -- post-012 row with no legacy anchor: nothing to restore
             INSERT INTO mcp_servers (id, workspace_id, name, upstream_url, created_at, updated_at) \
               VALUES ('m_new', NULL, 'slack', 'https://z', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z');",
        )
        .expect("seed a damaged install at version 12");

        run_migrations(&conn).expect("apply 013 onward");

        let rows: Vec<(String, String)> = {
            let mut stmt = conn
                .prepare(
                    "SELECT mcp_server_id, workspace_id FROM mcp_server_workspaces \
                     ORDER BY mcp_server_id",
                )
                .expect("prepare");
            stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
                .expect("query")
                .map(|r| r.expect("row"))
                .collect()
        };
        assert_eq!(
            rows,
            vec![
                ("m_lost".to_string(), "w1".to_string()),
                ("m_ok".to_string(), "w2".to_string()),
            ],
            "lost binding restored, intact binding kept, anchorless row untouched"
        );
    }

    /// Upgrade path: OAuth rows issued before 016 are bound to their
    /// workspace through the key hash they were issued against. A client
    /// whose hash matches no workspace stays unbound.
    #[test]
    fn migration_016_backfills_workspace_id_from_the_key_hash() {
        let conn = open_memory_db();
        run_migrations_up_to(&conn, 15).expect("migrate to 015");

        conn.execute_batch(
            "INSERT INTO workspaces (id, name, pk_hash, enabled, status, created_at, updated_at) \
               VALUES ('w1', 'ws1', 'h1', 1, 'active', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z');
             INSERT INTO oauth_clients (id, client_id, workspace_name, public_key_hash, redirect_uris, allowed_scopes, created_by_user, created_at) \
               VALUES ('c1', 'client-1', 'ws1', 'h1', '[]', '', 'u1', '2026-01-01T00:00:00Z'), \
                      ('c2', 'client-2', 'orphan', 'h-none', '[]', '', 'u1', '2026-01-01T00:00:00Z');
             INSERT INTO oauth_access_tokens (token_hash, client_id, user_id, scopes, created_at, expires_at) \
               VALUES ('at1', 'client-1', 'u1', '', '2026-01-01T00:00:00Z', '2027-01-01T00:00:00Z');
             INSERT INTO oauth_refresh_tokens (token_hash, client_id, user_id, scopes, access_token_hash, family_id, created_at, expires_at) \
               VALUES ('rt1', 'client-1', 'u1', '', 'at1', 'rt1', '2026-01-01T00:00:00Z', '2027-01-01T00:00:00Z');",
        )
        .expect("seed an install at version 15");

        run_migrations(&conn).expect("apply 016 onward");

        let bound = |sql: &str| -> Option<String> {
            conn.query_row(sql, [], |r| r.get::<_, Option<String>>(0))
                .expect("query")
        };
        assert_eq!(
            bound("SELECT workspace_id FROM oauth_clients WHERE client_id = 'client-1'"),
            Some("w1".to_string())
        );
        assert_eq!(
            bound("SELECT workspace_id FROM oauth_clients WHERE client_id = 'client-2'"),
            None,
            "a client whose hash matches no workspace stays unbound"
        );
        assert_eq!(
            bound("SELECT workspace_id FROM oauth_access_tokens WHERE token_hash = 'at1'"),
            Some("w1".to_string())
        );
        assert_eq!(
            bound("SELECT workspace_id FROM oauth_refresh_tokens WHERE token_hash = 'rt1'"),
            Some("w1".to_string())
        );
        let fk_violations: i64 = conn
            .query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |r| {
                r.get(0)
            })
            .expect("fk check");
        assert_eq!(fk_violations, 0);
    }

    /// Upgrade path: the two lifecycle flags collapse into `status`. A row
    /// that was switched off becomes `disabled`; revoked stays revoked; the
    /// `enabled` column is left in step with the status for older readers.
    #[test]
    fn migration_017_folds_enabled_into_status() {
        let conn = open_memory_db();
        run_migrations_up_to(&conn, 16).expect("migrate to 016");

        conn.execute_batch(
            "INSERT INTO workspaces (id, name, enabled, status, created_at, updated_at) VALUES \
               ('on',      'on',      1, 'active',  '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z'), \
               ('off',     'off',     0, 'active',  '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z'), \
               ('revoked', 'revoked', 1, 'revoked', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z'), \
               ('pending', 'pending', 0, 'pending', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z');",
        )
        .expect("seed an install at version 16");

        run_migrations(&conn).expect("apply 017 onward");

        let rows: Vec<(String, String, bool)> = {
            let mut stmt = conn
                .prepare("SELECT id, status, enabled FROM workspaces ORDER BY id")
                .expect("prepare");
            stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
                .expect("query")
                .map(|r| r.expect("row"))
                .collect()
        };
        assert_eq!(
            rows,
            vec![
                ("off".to_string(), "disabled".to_string(), false),
                ("on".to_string(), "active".to_string(), true),
                ("pending".to_string(), "pending".to_string(), false),
                ("revoked".to_string(), "revoked".to_string(), false),
            ]
        );
    }

    /// Upgrade path: 018 adds the name index over existing rows, including
    /// duplicate names, and the lookup it serves still finds both rows.
    #[test]
    fn migration_018_indexes_credential_names_without_touching_rows() {
        let conn = open_memory_db();
        run_migrations_up_to(&conn, 17).expect("migrate to 017");
        conn.execute_batch(
            "INSERT INTO credentials (id, name, service, encrypted_value, nonce, created_at, updated_at) \
               VALUES ('c1', 'api-key', 'github', X'00', X'00', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z'), \
                      ('c2', 'api-key', 'gitlab', X'00', X'00', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z');",
        )
        .expect("seed two credentials sharing a name at version 17");

        run_migrations(&conn).expect("apply 018 onward");

        let has_index: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM sqlite_master WHERE type = 'index' AND name = 'idx_credentials_name'",
                [],
                |r| r.get(0),
            )
            .expect("index query");
        assert!(has_index, "idx_credentials_name must exist after 018");
        let by_name: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM credentials WHERE name = 'api-key'",
                [],
                |r| r.get(0),
            )
            .expect("count");
        assert_eq!(by_name, 2);
    }

    /// Upgrade path: 019 rebuilds the history table so every row carries
    /// `key_version`, backfilled to 1, with the parent credential and the
    /// index intact and no foreign-key damage from the rebuild.
    #[test]
    fn migration_019_history_rows_carry_key_version_one() {
        let conn = open_memory_db();
        run_migrations_up_to(&conn, 18).expect("migrate to 018");
        conn.execute_batch(
            "INSERT INTO credentials (id, name, service, encrypted_value, nonce, created_at, updated_at) \
               VALUES ('c1', 'api-key', 'github', X'00', X'00', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z'); \
             INSERT INTO credential_secret_history \
               (id, credential_id, encrypted_value, nonce, changed_at, changed_by_user, changed_by_agent) \
               VALUES ('h1', 'c1', X'AB', X'CD', '2026-01-02T00:00:00Z', 'u1', NULL);",
        )
        .expect("seed a credential with one history row at version 18");

        run_migrations(&conn).expect("apply 019 onward");

        // (credential_id, encrypted_value, nonce, changed_at, changed_by_user,
        //  changed_by_agent, key_version)
        type HistoryRow = (
            String,
            Vec<u8>,
            Vec<u8>,
            String,
            Option<String>,
            Option<String>,
            i64,
        );
        let row: HistoryRow = conn
            .query_row(
                "SELECT credential_id, encrypted_value, nonce, changed_at, changed_by_user, \
                        changed_by_agent, key_version \
                 FROM credential_secret_history WHERE id = 'h1'",
                [],
                |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        r.get(3)?,
                        r.get(4)?,
                        r.get(5)?,
                        r.get(6)?,
                    ))
                },
            )
            .expect("history row survives the rebuild");
        assert_eq!(
            row,
            (
                "c1".to_string(),
                vec![0xAB],
                vec![0xCD],
                "2026-01-02T00:00:00Z".to_string(),
                Some("u1".to_string()),
                None,
                1
            )
        );

        let has_index: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM sqlite_master WHERE type = 'index' \
                 AND name = 'idx_secret_history_credential'",
                [],
                |r| r.get(0),
            )
            .expect("index query");
        assert!(has_index, "history index must exist after 019");

        let fk_violations: i64 = conn
            .query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |r| {
                r.get(0)
            })
            .expect("fk check");
        assert_eq!(fk_violations, 0);
        let fk_on: i64 = conn
            .query_row("PRAGMA foreign_keys", [], |r| r.get(0))
            .expect("pragma");
        assert_eq!(fk_on, 1, "foreign keys are back on after the rebuild");

        // The column is written from here on: a versioned insert round-trips.
        conn.execute_batch(
            "INSERT INTO credential_secret_history \
               (id, credential_id, encrypted_value, nonce, changed_at, key_version) \
               VALUES ('h2', 'c1', X'01', X'02', '2026-01-03T00:00:00Z', 2);",
        )
        .expect("insert with key_version");
        let v2: i64 = conn
            .query_row(
                "SELECT key_version FROM credential_secret_history WHERE id = 'h2'",
                [],
                |r| r.get(0),
            )
            .expect("read");
        assert_eq!(v2, 2);
    }

    /// Upgrade path: credential names are not unique by design (011 says
    /// so, and the by-name vend path returns 300 on ambiguity). An install
    /// at version 6 holding two credentials with the same name must upgrade
    /// cleanly and keep both rows.
    #[test]
    fn duplicate_credential_names_at_version_6_survive_upgrade() {
        let conn = open_memory_db();
        run_migrations_up_to(&conn, 6).expect("migrate to 006");

        conn.execute_batch(
            "INSERT INTO credentials (id, name, service, encrypted_value, nonce, created_at, updated_at) \
               VALUES ('c1', 'api-key', 'github', X'00', X'00', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z'), \
                      ('c2', 'api-key', 'github', X'00', X'00', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z');",
        )
        .expect("seed two credentials sharing a name at version 6");

        run_migrations(&conn).expect("upgrade must not fail on duplicate credential names");

        let names: Vec<String> = {
            let mut stmt = conn
                .prepare("SELECT name FROM credentials ORDER BY id")
                .expect("prepare");
            stmt.query_map([], |r| r.get(0))
                .expect("query")
                .map(|r| r.expect("row"))
                .collect()
        };
        assert_eq!(names, vec!["api-key", "api-key"], "both rows survive");
    }

    fn fk_violations(conn: &rusqlite::Connection) -> i64 {
        conn.query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |r| {
            r.get(0)
        })
        .expect("foreign_key_check")
    }

    /// Upgrade path: 010 creates the MCP<->workspace junction and backfills
    /// one row per existing server from its legacy `workspace_id`.
    #[test]
    fn migration_010_backfills_the_junction_from_legacy_workspace_ids() {
        let conn = open_memory_db();
        run_migrations_up_to(&conn, 9).expect("migrate to 009");

        conn.execute_batch(
            "INSERT INTO workspaces (id, name, pk_hash, enabled, status, created_at, updated_at) \
               VALUES ('w1', 'ws1', 'h1', 1, 'active', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z'), \
                      ('w2', 'ws2', 'h2', 1, 'active', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z');
             INSERT INTO mcp_servers (id, workspace_id, name, upstream_url, created_at, updated_at) \
               VALUES ('m1', 'w1', 'gh', 'https://x', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z'), \
                      ('m2', 'w2', 'gl', 'https://y', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z');",
        )
        .expect("seed two bound MCP servers at version 9");

        run_migrations_up_to(&conn, 10).expect("apply 010");

        let bindings: Vec<(String, String)> = {
            let mut stmt = conn
                .prepare(
                    "SELECT mcp_server_id, workspace_id FROM mcp_server_workspaces \
                     ORDER BY mcp_server_id",
                )
                .expect("prepare");
            stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
                .expect("query")
                .map(|r| r.expect("row"))
                .collect()
        };
        assert_eq!(
            bindings,
            vec![
                ("m1".to_string(), "w1".to_string()),
                ("m2".to_string(), "w2".to_string()),
            ],
            "every server gets exactly one junction row for its legacy workspace"
        );
        assert_eq!(fk_violations(&conn), 0);
    }

    /// Upgrade path: 011 drops the global unique index on credential names
    /// that the original 007 created (007 is a no-op today, so the test
    /// creates the index the way that install would have it), so a second
    /// credential with an existing name can be created after it and the
    /// existing row is untouched.
    #[test]
    fn migration_011_lets_credential_names_repeat() {
        let conn = open_memory_db();
        run_migrations_up_to(&conn, 10).expect("migrate to 010");
        conn.execute_batch(
            "CREATE UNIQUE INDEX idx_credentials_name_unique ON credentials(name);
             INSERT INTO credentials (id, name, service, encrypted_value, nonce, created_at, updated_at) \
               VALUES ('c1', 'api-key', 'github', X'00', X'00', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z');",
        )
        .expect("seed an install that ran the original 007, at version 10");
        let before = conn.execute(
            "INSERT INTO credentials (id, name, service, encrypted_value, nonce, created_at, updated_at) \
               VALUES ('c2', 'api-key', 'gitlab', X'00', X'00', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')",
            [],
        );
        assert!(before.is_err(), "at version 10 the name is still unique");

        run_migrations_up_to(&conn, 11).expect("apply 011");

        conn.execute(
            "INSERT INTO credentials (id, name, service, encrypted_value, nonce, created_at, updated_at) \
               VALUES ('c2', 'api-key', 'gitlab', X'00', X'00', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')",
            [],
        )
        .expect("a duplicate name is accepted after 011");
        let has_unique_index: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM sqlite_master WHERE type = 'index' AND name = 'idx_credentials_name_unique'",
                [],
                |r| r.get(0),
            )
            .expect("index query");
        assert!(!has_unique_index);
        let by_name: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM credentials WHERE name = 'api-key'",
                [],
                |r| r.get(0),
            )
            .expect("count");
        assert_eq!(by_name, 2);
    }

    /// Upgrade path: 014 adds the OIDC identity table over an install with
    /// users and a provider; an identity can then be linked, and goes away
    /// with its user.
    #[test]
    fn migration_014_adds_oidc_identities_that_follow_their_user() {
        let conn = open_memory_db();
        run_migrations_up_to(&conn, 13).expect("migrate to 013");
        conn.execute_batch(
            "INSERT INTO users (id, username, password_hash, role, is_root, enabled, created_at, updated_at) \
               VALUES ('u1', 'alice', 'h', 'admin', 0, 1, '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z');
             INSERT INTO oidc_providers (id, name, issuer_url, client_id, encrypted_client_secret, nonce, created_at, updated_at) \
               VALUES ('p1', 'corp', 'https://idp.example', 'cid', X'00', X'00', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z');",
        )
        .expect("seed a user and a provider at version 13");

        run_migrations_up_to(&conn, 14).expect("apply 014");

        conn.execute(
            "INSERT INTO user_oidc_identities (provider_id, subject, user_id, created_at) \
             VALUES ('p1', 'sub-1', 'u1', '2026-01-02T00:00:00Z')",
            [],
        )
        .expect("link an identity after 014");
        let duplicate = conn.execute(
            "INSERT INTO user_oidc_identities (provider_id, subject, user_id, created_at) \
             VALUES ('p1', 'sub-1', 'u1', '2026-01-02T00:00:00Z')",
            [],
        );
        assert!(duplicate.is_err(), "(provider, subject) is the primary key");
        assert_eq!(fk_violations(&conn), 0);

        conn.execute("DELETE FROM users WHERE id = 'u1'", [])
            .expect("delete user");
        let remaining: i64 = conn
            .query_row("SELECT COUNT(*) FROM user_oidc_identities", [], |r| {
                r.get(0)
            })
            .expect("count");
        assert_eq!(remaining, 0, "identities cascade with their user");
    }

    /// Upgrade path: 015 gives every existing refresh token its own family
    /// (rooted at itself) and indexes the column.
    #[test]
    fn migration_015_roots_existing_refresh_tokens_in_their_own_family() {
        let conn = open_memory_db();
        run_migrations_up_to(&conn, 14).expect("migrate to 014");
        conn.execute_batch(
            "INSERT INTO oauth_clients (id, client_id, workspace_name, public_key_hash, redirect_uris, allowed_scopes, created_by_user, created_at) \
               VALUES ('c1', 'client-1', 'ws1', 'h1', '[]', '', 'u1', '2026-01-01T00:00:00Z');
             INSERT INTO oauth_refresh_tokens (token_hash, client_id, user_id, scopes, access_token_hash, created_at, expires_at) \
               VALUES ('rt1', 'client-1', 'u1', '', 'at1', '2026-01-01T00:00:00Z', '2027-01-01T00:00:00Z'), \
                      ('rt2', 'client-1', 'u1', '', 'at2', '2026-01-01T00:00:00Z', '2027-01-01T00:00:00Z');",
        )
        .expect("seed two refresh tokens at version 14");

        run_migrations_up_to(&conn, 15).expect("apply 015");

        let families: Vec<(String, Option<String>)> = {
            let mut stmt = conn
                .prepare(
                    "SELECT token_hash, family_id FROM oauth_refresh_tokens ORDER BY token_hash",
                )
                .expect("prepare");
            stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
                .expect("query")
                .map(|r| r.expect("row"))
                .collect()
        };
        assert_eq!(
            families,
            vec![
                ("rt1".to_string(), Some("rt1".to_string())),
                ("rt2".to_string(), Some("rt2".to_string())),
            ],
            "each pre-existing token is the root of its own family"
        );
        let has_index: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM sqlite_master WHERE type = 'index' AND name = 'idx_oauth_refresh_tokens_family'",
                [],
                |r| r.get(0),
            )
            .expect("index query");
        assert!(has_index);
        assert_eq!(fk_violations(&conn), 0);
    }

    /// Upgrade path: 021 turns the `vault` name column into rows in a real
    /// `vaults` table.
    ///
    /// The rule is one vault per distinct (name, owning user) pair among the
    /// existing credentials: two users who each called a vault `team` had two
    /// vaults all along, and the old string column could not say so. A
    /// credential with no creating user was made by a workspace, so it lands
    /// in the vault of that name owned by the workspace's owner, falling back
    /// to root when the workspace has none. Everything named `default` lands
    /// in the one system vault, which has a fixed id and no owner. A share
    /// row names its vault by (name, sharer), so it follows the vault its
    /// sharer owns.
    #[test]
    fn migration_021_gives_every_credential_a_vault_row() {
        use crate::domain::vault::DEFAULT_VAULT_ID;
        let conn = open_memory_db();
        run_migrations_up_to(&conn, 20).expect("migrate to 020");

        conn.execute_batch(
            "INSERT INTO users (id, username, password_hash, role, is_root, created_at, updated_at) VALUES \
               ('u-root', 'root', 'h', 'admin', 1, '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z'), \
               ('u-alice', 'alice', 'h', 'admin', 0, '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z'), \
               ('u-bob', 'bob', 'h', 'admin', 0, '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z');
             INSERT INTO workspaces (id, name, owner_id, status, tags, created_at, updated_at) VALUES \
               ('w1', 'bobs-ws', 'u-bob', 'active', '[]', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z'), \
               ('w2', 'ownerless-ws', NULL, 'active', '[]', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z');
             INSERT INTO credentials (id, name, service, encrypted_value, nonce, vault, created_by, created_by_user, created_at, updated_at) VALUES \
               ('c1', 'in-default', 's', X'00', X'00', 'default', NULL, 'u-alice', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z'), \
               ('c2', 'alice-team-1', 's', X'00', X'00', 'team',    NULL, 'u-alice', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z'), \
               ('c3', 'bob-team',     's', X'00', X'00', 'team',    NULL, 'u-bob',   '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z'), \
               ('c4', 'alice-team-2', 's', X'00', X'00', 'team',    NULL, 'u-alice', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z'), \
               ('c5', 'from-ws',      's', X'00', X'00', 'ws',      'w1', NULL,      '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z'), \
               ('c6', 'from-orphan',  's', X'00', X'00', 'orphan',  'w2', NULL,      '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z');
             INSERT INTO vault_shares (id, vault_name, shared_with_user_id, permission_level, shared_by_user_id, created_at) VALUES \
               ('s1', 'team', 'u-bob', 'read', 'u-alice', '2026-01-01T00:00:00Z');",
        )
        .expect("seed an install at version 20");

        run_migrations(&conn).expect("apply 021 onward");

        // The credentials table names its vault by id, not by string.
        let has_vault_name_column: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM pragma_table_info('credentials') WHERE name = 'vault'",
                [],
                |r| r.get(0),
            )
            .expect("table_info");
        assert!(
            !has_vault_name_column,
            "the `vault` name column is replaced by `vault_id`"
        );

        // (vault name, owner) for a credential.
        let placement = |cred: &str| -> (String, String, Option<String>) {
            conn.query_row(
                "SELECT v.id, v.name, v.owner_user_id FROM credentials c \
                 JOIN vaults v ON v.id = c.vault_id WHERE c.id = ?1",
                [cred],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap_or_else(|e| panic!("placement of {cred}: {e}"))
        };

        let (default_id, default_name, default_owner) = placement("c1");
        assert_eq!(
            default_id, DEFAULT_VAULT_ID,
            "`default` is the system vault"
        );
        assert_eq!(default_name, "default");
        assert_eq!(default_owner, None, "the system vault has no owner");

        let (alice_team, name, owner) = placement("c2");
        assert_eq!((name.as_str(), owner.as_deref()), ("team", Some("u-alice")));
        assert_eq!(
            placement("c4").0,
            alice_team,
            "both of Alice's `team` credentials land in the same vault"
        );

        let (bob_team, name, owner) = placement("c3");
        assert_eq!((name.as_str(), owner.as_deref()), ("team", Some("u-bob")));
        assert_ne!(
            bob_team, alice_team,
            "two users who each named a vault `team` had two vaults all along"
        );

        let (_, name, owner) = placement("c5");
        assert_eq!(
            (name.as_str(), owner.as_deref()),
            ("ws", Some("u-bob")),
            "a workspace's credential lands in its owner's vault"
        );

        let (_, name, owner) = placement("c6");
        assert_eq!(
            (name.as_str(), owner.as_deref()),
            ("orphan", Some("u-root")),
            "with no workspace owner, root takes the vault"
        );

        let vault_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM vaults", [], |r| r.get(0))
            .expect("count vaults");
        assert_eq!(
            vault_count, 5,
            "the system vault plus team/alice, team/bob, ws/bob and orphan/root"
        );

        let shared_vault: String = conn
            .query_row(
                "SELECT vault_id FROM vault_shares WHERE id = 's1'",
                [],
                |r| r.get(0),
            )
            .expect("the share survives");
        assert_eq!(
            shared_vault, alice_team,
            "the share follows the vault its sharer owns"
        );

        assert_eq!(fk_violations(&conn), 0);
    }
}
