mod audit;
mod credentials;
mod mcp;
mod oauth;
mod oidc;
mod policies;
mod rows;
mod sessions;
mod users;
mod vaults;
mod workspace;
pub(crate) use rows::*;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use crate::domain::credential::{CredentialId, CredentialSummary, StoredCredential};
use crate::domain::mcp::{McpServer, McpServerId};
use crate::domain::oidc::{OidcAuthState, OidcProvider, OidcProviderId, OidcProviderSummary};
use crate::domain::policy::{PolicyId, StoredPolicy};
use crate::domain::session::Session;
use crate::domain::user::{User, UserId, UserRole};
use crate::domain::vault::VaultShare;
use crate::domain::workspace::{Workspace, WorkspaceId, WorkspaceStatus};
use crate::error::StoreError;

use super::Store;

// Re-export shared serialization helpers
use crate::storage::shared::{
    deserialize_decision, deserialize_event_type,
    deserialize_user_role, serialize_decision, serialize_event_type,
    serialize_user_role,
};

// ---------------------------------------------------------------------------
// PostgresStore
// ---------------------------------------------------------------------------

/// PostgreSQL-backed implementation of the Store trait.
pub struct PostgresStore {
    pool: PgPool,
}

impl PostgresStore {
    /// Connect to a PostgreSQL database at the given URL and run migrations.
    pub async fn new(database_url: &str) -> Result<Self, StoreError> {
        let pool = PgPool::connect(database_url)
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;
        Ok(Self { pool })
    }

    /// Create from an existing connection pool.
    pub async fn new_with_pool(pool: PgPool) -> Self {
        Self { pool }
    }
}

// ---------------------------------------------------------------------------
// PostgreSQL-specific helpers
// ---------------------------------------------------------------------------

/// Check if a sqlx error is a unique-constraint violation (PostgreSQL error code 23505).
fn is_unique_violation(e: &sqlx::Error) -> bool {
    if let sqlx::Error::Database(ref db_err) = e {
        db_err.code().map_or(false, |c| c == "23505")
    } else {
        false
    }
}

fn db_err(e: sqlx::Error) -> StoreError {
    StoreError::Database(e.to_string())
}

// ---------------------------------------------------------------------------
// Store trait implementation — only lifecycle; domain methods are on sub-traits
// ---------------------------------------------------------------------------

#[async_trait]
impl Store for PostgresStore {
    async fn run_migrations(&self) -> Result<(), StoreError> {
        let migrations: &[(i64, &str)] = &[
            (
                1,
                include_str!("../../../../../migrations/postgres/001_init.sql"),
            ),
            (
                2,
                include_str!("../../../../../migrations/postgres/002_mcp_catalog_fields.sql"),
            ),
            (
                3,
                include_str!(
                    "../../../../../migrations/postgres/003_remove_oauth_authz_server.sql"
                ),
            ),
        ];

        let has_table: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'schema_migrations')",
        )
        .fetch_one(&self.pool)
        .await
        .map_err(db_err)?;

        let applied: std::collections::HashSet<i64> = if has_table {
            let rows: Vec<(i64,)> = sqlx::query_as("SELECT version FROM schema_migrations")
                .fetch_all(&self.pool)
                .await
                .map_err(db_err)?;
            rows.into_iter().map(|(v,)| v).collect()
        } else {
            std::collections::HashSet::new()
        };

        for (version, sql) in migrations {
            if applied.contains(version) {
                continue;
            }

            sqlx::raw_sql(sql)
                .execute(&self.pool)
                .await
                .map_err(|e| StoreError::Database(format!("migration {:03}: {}", version, e)))?;

            sqlx::query("INSERT INTO schema_migrations (version, applied_at) VALUES ($1, $2) ON CONFLICT DO NOTHING")
                .bind(*version)
                .bind(Utc::now())
                .execute(&self.pool)
                .await
                .map_err(|e| StoreError::Database(format!("record migration {:03}: {}", version, e)))?;
        }

        Ok(())
    }
}
