use crate::error::StoreError;

pub const MIGRATION_001: &str = include_str!("../../../../migrations/001_init.sql");
pub const MIGRATION_003: &str =
    include_str!("../../../../migrations/003_remove_oauth_authz_server.sql");
pub const MIGRATION_004: &str =
    include_str!("../../../../migrations/20260321000000_workspace_unification.sql");
pub const MIGRATION_005: &str =
    include_str!("../../../../migrations/20260321220000_registration_approval_code.sql");
pub const MIGRATION_006: &str =
    include_str!("../../../../migrations/20260322000000_registration_approved_by.sql");
pub const MIGRATION_007: &str =
    include_str!("../../../../migrations/20260321220100_provisioning_tokens.sql");
pub const MIGRATION_008: &str =
    include_str!("../../../../migrations/20260324000000_credential_name_scoped_uniqueness.sql");

/// All migrations in order. Each entry is (version, SQL content).
const MIGRATIONS: [(i64, &str); 7] = [
    (1, MIGRATION_001),
    (3, MIGRATION_003),
    (4, MIGRATION_004),
    (5, MIGRATION_005),
    (6, MIGRATION_006),
    (7, MIGRATION_007),
    (8, MIGRATION_008),
];

/// Run all pending migrations, tracking applied versions in a `schema_migrations` table.
///
/// This function is idempotent: running it multiple times against the same database
/// will only execute migrations that have not yet been recorded.
///
/// For existing dev databases that had the old incremental migrations (versions 1–42),
/// we detect them and mark the new collapsed v1 migration as already applied.
pub fn run_migrations(conn: &rusqlite::Connection) -> Result<(), StoreError> {
    // 1. Ensure the schema_migrations tracking table exists.
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS schema_migrations (
            version INTEGER PRIMARY KEY,
            applied_at TEXT NOT NULL
        );",
    )
    .map_err(|e| StoreError::Database(format!("create schema_migrations: {}", e)))?;

    // 2. Handle existing dev databases: if old incremental migrations (v29–v42)
    //    are recorded but the new collapsed v1 is not, mark v1 as applied.
    //    New migrations (v3 etc.) are NOT considered "old" — they are post-consolidation.
    let has_old_migrations: bool = {
        let mut stmt = conn
            .prepare("SELECT COUNT(*) FROM schema_migrations WHERE version >= 29")
            .map_err(|e| StoreError::Database(format!("query schema_migrations: {}", e)))?;
        let count: i64 = stmt
            .query_row([], |row| row.get(0))
            .map_err(|e| StoreError::Database(format!("read schema_migrations: {}", e)))?;
        count > 0
    };

    if has_old_migrations {
        // Old incremental migrations exist — the schema is already at the v1 baseline.
        // Clear old entries and record the collapsed v1 as applied.
        let now = chrono::Utc::now().to_rfc3339();
        conn.execute_batch("DELETE FROM schema_migrations")
            .map_err(|e| StoreError::Database(format!("clear old migrations: {}", e)))?;
        conn.execute(
            "INSERT OR IGNORE INTO schema_migrations (version, applied_at) VALUES (1, ?1)",
            rusqlite::params![now],
        )
        .map_err(|e| StoreError::Database(format!("record collapsed migration: {}", e)))?;

        // Ensure crypto_state table exists (new in v1.15.0, not in old migrations).
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS crypto_state (
                key_id TEXT PRIMARY KEY,
                encryption_count INTEGER NOT NULL DEFAULT 0,
                last_updated TEXT NOT NULL
            );",
        )
        .map_err(|e| StoreError::Database(format!("create crypto_state for existing db: {}", e)))?;

        return Ok(());
    }

    // 3. Query which migrations have already been applied.
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

    // 4. Run each unapplied migration in order, recording it on success.
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
    fn test_schema_migrations_table_has_correct_versions() {
        let conn = open_memory_db();
        run_migrations(&conn).expect("run migrations");

        let mut stmt = conn
            .prepare("SELECT version FROM schema_migrations ORDER BY version")
            .expect("prepare");
        let versions: Vec<i64> = stmt
            .query_map([], |row| row.get(0))
            .expect("query")
            .map(|r| r.expect("row"))
            .collect();

        let expected_versions: Vec<i64> = MIGRATIONS.iter().map(|(v, _)| *v).collect();
        assert_eq!(versions, expected_versions);
    }

    #[test]
    fn test_existing_dev_db_migration_collapse() {
        let conn = open_memory_db();

        // Simulate an existing dev database with old migrations applied.
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS schema_migrations (
                version INTEGER PRIMARY KEY,
                applied_at TEXT NOT NULL
            );",
        )
        .expect("create schema_migrations");

        // Insert some old migration versions
        for v in &[1i64, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42] {
            conn.execute(
                "INSERT INTO schema_migrations (version, applied_at) VALUES (?1, '2026-01-01')",
                rusqlite::params![v],
            )
            .expect("insert old migration");
        }

        // Manually create the old schema tables so the DB is in a valid state.
        // We just need the schema_migrations logic to work — the actual tables
        // don't matter for this test.

        // Run the new migration runner — should detect old migrations and skip.
        run_migrations(&conn).expect("run_migrations on existing dev db");

        // Should have exactly one migration recorded now.
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM schema_migrations", [], |row| {
                row.get(0)
            })
            .expect("count");
        assert_eq!(count, 1, "should have collapsed to 1 migration record");

        let version: i64 = conn
            .query_row("SELECT version FROM schema_migrations", [], |row| {
                row.get(0)
            })
            .expect("version");
        assert_eq!(version, 1, "should be version 1");

        // crypto_state table should exist
        let table_exists: bool = conn
            .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='crypto_state'")
            .expect("prepare")
            .exists([])
            .expect("exists");
        assert!(table_exists, "crypto_state table should exist");
    }

    #[test]
    fn test_crypto_state_table_created() {
        let conn = open_memory_db();
        run_migrations(&conn).expect("run migrations");

        // Verify crypto_state table exists and is usable.
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

    #[test]
    fn test_workspace_unification_migration() {
        let conn = open_memory_db();
        run_migrations(&conn).expect("run all migrations");

        // Verify workspaces table exists with correct columns
        conn.execute(
            "INSERT INTO workspaces (id, name, enabled, status, tags, created_at, updated_at)
             VALUES ('ws1', 'test-workspace', 1, 'active', '[]', '2026-01-01', '2026-01-01')",
            [],
        )
        .expect("insert into workspaces");

        let name: String = conn
            .query_row("SELECT name FROM workspaces WHERE id = 'ws1'", [], |row| {
                row.get(0)
            })
            .expect("query workspaces");
        assert_eq!(name, "test-workspace");

        // Verify parent_id self-reference works
        conn.execute(
            "INSERT INTO workspaces (id, name, enabled, status, tags, parent_id, created_at, updated_at)
             VALUES ('ws2', 'child-workspace', 1, 'active', '[]', 'ws1', '2026-01-01', '2026-01-01')",
            [],
        ).expect("insert child workspace");

        // Verify workspace_used_jtis table exists (renamed from device_used_jtis)
        conn.execute(
            "INSERT INTO workspace_used_jtis (jti, device_id, expires_at) VALUES ('jti1', 'ws1', '2026-12-31')",
            [],
        ).expect("insert into workspace_used_jtis");

        // Verify old tables are renamed to *_legacy
        let legacy_exists: bool = conn
            .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='agents_legacy'")
            .expect("prepare")
            .exists([])
            .expect("exists");
        assert!(legacy_exists, "agents_legacy table should exist");

        let devices_legacy_exists: bool = conn
            .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='devices_legacy'")
            .expect("prepare")
            .exists([])
            .expect("exists");
        assert!(devices_legacy_exists, "devices_legacy table should exist");

        // Verify workspaces table has all expected columns
        conn.execute(
            "INSERT INTO workspaces (id, name, enabled, status, pk_hash, encryption_public_key,
             tags, owner_id, tool_name, enrollment_token_hash, last_authenticated_at,
             created_at, updated_at)
             VALUES ('ws3', 'full-workspace', 1, 'active', 'hash123', '{\"kty\":\"EC\"}',
             '[\"tag1\"]', NULL, 'claude-code', 'token_hash', '2026-01-01',
             '2026-01-01', '2026-01-01')",
            [],
        )
        .expect("insert workspace with all columns");
    }

    #[test]
    fn test_workspace_migration_data_flow() {
        let conn = open_memory_db();

        // Run only migrations 1 and 3 first to set up base schema
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS schema_migrations (
                version INTEGER PRIMARY KEY,
                applied_at TEXT NOT NULL
            );",
        )
        .expect("create schema_migrations");

        conn.execute_batch(MIGRATION_001)
            .expect("run migration 001");
        conn.execute(
            "INSERT INTO schema_migrations (version, applied_at) VALUES (1, '2026-01-01')",
            [],
        )
        .expect("record migration 1");
        conn.execute_batch(MIGRATION_003)
            .expect("run migration 003");
        conn.execute(
            "INSERT INTO schema_migrations (version, applied_at) VALUES (3, '2026-01-01')",
            [],
        )
        .expect("record migration 3");

        // Insert test data into agents/devices/workspace_identities
        conn.execute(
            "INSERT INTO devices (id, name, status, public_key_jwk, tags, created_at, updated_at)
             VALUES ('dev1', 'my-device', 'active', '{\"kty\":\"EC\"}', '[]', '2026-01-01', '2026-01-01')",
            [],
        ).expect("insert device");

        conn.execute(
            "INSERT INTO agents (id, name, tags, enabled, device_id, created_at, updated_at)
             VALUES ('agent1', 'my-agent', '[\"test\"]', 1, 'dev1', '2026-01-01', '2026-01-01')",
            [],
        )
        .expect("insert agent");

        conn.execute(
            "INSERT INTO workspace_identities (id, pk_hash, status, created_at, updated_at)
             VALUES ('agent1', 'pkhash123', 'active', '2026-01-01', '2026-01-01')",
            [],
        )
        .expect("insert workspace_identity");

        // Insert an orphaned device (no agent binding)
        conn.execute(
            "INSERT INTO devices (id, name, status, tags, created_at, updated_at)
             VALUES ('dev2', 'orphan-device', 'pending', '[]', '2026-01-01', '2026-01-01')",
            [],
        )
        .expect("insert orphaned device");

        // Insert MCP server bound to dev1
        conn.execute(
            "INSERT INTO mcp_servers (id, device_id, name, upstream_url, created_at, updated_at)
             VALUES ('mcp1', 'dev1', 'test-mcp', 'http://localhost', '2026-01-01', '2026-01-01')",
            [],
        )
        .expect("insert mcp_server");

        // Now run migration 4 (workspace unification)
        conn.execute_batch(MIGRATION_004)
            .expect("run workspace unification migration");
        conn.execute(
            "INSERT INTO schema_migrations (version, applied_at) VALUES (4, '2026-01-01')",
            [],
        )
        .expect("record migration 4");

        // Verify agent was migrated to workspaces with device and identity data
        let (ws_name, ws_pk_hash, ws_enc_key): (String, Option<String>, Option<String>) = conn
            .query_row(
                "SELECT name, pk_hash, encryption_public_key FROM workspaces WHERE id = 'agent1'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .expect("query migrated agent workspace");
        assert_eq!(ws_name, "my-agent");
        assert_eq!(ws_pk_hash, Some("pkhash123".to_string()));
        assert_eq!(ws_enc_key, Some("{\"kty\":\"EC\"}".to_string()));

        // Verify orphaned device was migrated
        let orphan_status: String = conn
            .query_row(
                "SELECT status FROM workspaces WHERE id = 'dev2'",
                [],
                |row| row.get(0),
            )
            .expect("query orphaned device workspace");
        assert_eq!(orphan_status, "pending");

        // Verify MCP server was mapped to workspace
        let mcp_workspace: Option<String> = conn
            .query_row(
                "SELECT workspace_id FROM mcp_servers WHERE id = 'mcp1'",
                [],
                |row| row.get(0),
            )
            .expect("query mcp_server workspace_id");
        assert_eq!(mcp_workspace, Some("agent1".to_string()));

        // Verify total workspace count (1 agent + 1 orphaned device = 2)
        let ws_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM workspaces", [], |row| row.get(0))
            .expect("count workspaces");
        assert_eq!(ws_count, 2);
    }
}
