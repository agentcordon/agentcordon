mod audit;
mod credentials;
mod enrollment;
pub(crate) mod helpers;
mod mcp;
mod oidc;
mod policies;
mod sessions;
mod users;
mod vaults;
mod workspace;

use std::sync::atomic::{AtomicUsize, Ordering};

use async_trait::async_trait;
use tokio_rusqlite::Connection;

use crate::error::StoreError;

use super::Store;

/// Default connection pool size for file-backed databases.
const DEFAULT_FILE_POOL_SIZE: usize = 4;

/// SQLite-backed implementation of the Store trait.
///
/// Uses a pool of connections with round-robin selection to allow concurrent
/// read operations. SQLite with WAL mode supports concurrent readers, so
/// distributing reads across multiple connections reduces contention.
pub struct SqliteStore {
    pool: Vec<Connection>,
    next: AtomicUsize,
}

impl SqliteStore {
    /// Open (or create) a SQLite database at the given path with WAL mode enabled
    /// and a default pool of 4 connections.
    pub async fn new(path: &str) -> Result<Self, StoreError> {
        Self::new_with_pool_size(path, DEFAULT_FILE_POOL_SIZE).await
    }

    /// Open a SQLite database with a specific connection pool size.
    pub async fn new_with_pool_size(path: &str, pool_size: usize) -> Result<Self, StoreError> {
        let pool_size = pool_size.max(1);
        let mut pool = Vec::with_capacity(pool_size);

        for _ in 0..pool_size {
            let conn = Connection::open(path)
                .await
                .map_err(|e| StoreError::Database(e.to_string()))?;

            conn.call(|c| {
                c.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")
                    .map_err(tokio_rusqlite::Error::Rusqlite)
            })
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;

            pool.push(conn);
        }

        Ok(Self {
            pool,
            next: AtomicUsize::new(0),
        })
    }

    /// Create an in-memory SQLite database (useful for testing).
    ///
    /// In-memory databases are isolated per connection, so a single connection
    /// is used regardless. For concurrent read testing, use a file-backed store.
    pub async fn new_in_memory() -> Result<Self, StoreError> {
        let conn = Connection::open_in_memory()
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;

        conn.call(|c| {
            c.execute_batch("PRAGMA foreign_keys=ON;")
                .map_err(tokio_rusqlite::Error::Rusqlite)
        })
        .await
        .map_err(|e| StoreError::Database(e.to_string()))?;

        Ok(Self {
            pool: vec![conn],
            next: AtomicUsize::new(0),
        })
    }

    /// Get a connection from the pool using round-robin selection.
    pub(crate) fn conn(&self) -> &Connection {
        let idx = self.next.fetch_add(1, Ordering::Relaxed) % self.pool.len();
        &self.pool[idx]
    }
}

// ---------------------------------------------------------------------------
// Store trait implementation — only lifecycle; domain methods are on sub-traits
// ---------------------------------------------------------------------------

#[async_trait]
impl Store for SqliteStore {
    async fn run_migrations(&self) -> Result<(), StoreError> {
        self.conn()
            .call(|conn| {
                super::migrations::run_migrations(conn).map_err(helpers::store_err_to_tokio)
            })
            .await
            .map_err(|e| StoreError::Database(e.to_string()))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests;
