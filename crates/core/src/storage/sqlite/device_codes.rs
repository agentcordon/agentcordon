use async_trait::async_trait;
use chrono::{DateTime, Utc};

use super::SqliteStore;
use crate::error::StoreError;
use crate::oauth2::types::{DeviceCode, DeviceCodeStatus, OAuthScope};
use crate::storage::traits::DeviceCodeStore;

const DEVICE_CODE_COLUMNS: &str = "device_code, user_code, client_id, scopes, status, \
    workspace_name_prefill, pk_hash_prefill, approved_user_id, last_polled_at, interval_secs, \
    created_at, expires_at";

fn scopes_to_string(scopes: &[OAuthScope]) -> String {
    scopes
        .iter()
        .map(|s| s.to_string())
        .collect::<Vec<_>>()
        .join(",")
}

fn string_to_scopes(s: &str) -> Vec<OAuthScope> {
    if s.is_empty() {
        return Vec::new();
    }
    s.split(',').filter_map(|part| part.parse().ok()).collect()
}

fn parse_dt(s: &str, col: usize) -> Result<DateTime<Utc>, rusqlite::Error> {
    DateTime::parse_from_rfc3339(s)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(col, rusqlite::types::Type::Text, Box::new(e))
        })
}

fn parse_dt_opt(s: Option<String>, col: usize) -> Result<Option<DateTime<Utc>>, rusqlite::Error> {
    match s {
        Some(ref v) => parse_dt(v, col).map(Some),
        None => Ok(None),
    }
}

fn row_to_device_code(row: &rusqlite::Row<'_>) -> rusqlite::Result<DeviceCode> {
    let status_str: String = row.get(4)?;
    let status: DeviceCodeStatus = status_str.parse().map_err(|e: String| {
        rusqlite::Error::FromSqlConversionFailure(
            4,
            rusqlite::types::Type::Text,
            Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, e)),
        )
    })?;
    Ok(DeviceCode {
        device_code: row.get(0)?,
        user_code: row.get(1)?,
        client_id: row.get(2)?,
        scopes: string_to_scopes(&row.get::<_, String>(3)?),
        status,
        workspace_name_prefill: row.get(5)?,
        pk_hash_prefill: row.get(6)?,
        approved_user_id: row.get(7)?,
        last_polled_at: parse_dt_opt(row.get::<_, Option<String>>(8)?, 8)?,
        interval_secs: row.get(9)?,
        created_at: parse_dt(&row.get::<_, String>(10)?, 10)?,
        expires_at: parse_dt(&row.get::<_, String>(11)?, 11)?,
    })
}

#[async_trait]
impl DeviceCodeStore for SqliteStore {
    async fn insert_device_code(&self, code: &DeviceCode) -> Result<(), StoreError> {
        let code = code.clone();
        let scopes_str = scopes_to_string(&code.scopes);
        let status_str = code.status.as_str().to_string();
        let created_at = code.created_at.to_rfc3339();
        let expires_at = code.expires_at.to_rfc3339();
        let last_polled_at = code.last_polled_at.map(|dt| dt.to_rfc3339());
        self.conn()
            .call(move |conn| {
                conn.execute(
                    &format!(
                        "INSERT INTO device_codes ({}) VALUES \
                         (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
                        DEVICE_CODE_COLUMNS
                    ),
                    rusqlite::params![
                        code.device_code,
                        code.user_code,
                        code.client_id,
                        scopes_str,
                        status_str,
                        code.workspace_name_prefill,
                        code.pk_hash_prefill,
                        code.approved_user_id,
                        last_polled_at,
                        code.interval_secs,
                        created_at,
                        expires_at,
                    ],
                )
                .map_err(tokio_rusqlite::Error::Rusqlite)?;
                Ok(())
            })
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;
        // Audit emission belongs at this layer per CLAUDE.md. The AuditStore
        // sink is registered on SqliteStore; emit the DeviceCodeIssued event
        // here so handlers don't have to remember.
        // NOTE: audit write is best-effort — failure to audit must not roll
        // back the insert, but must be logged via tracing.
        // (Implementation is stubbed pending a cross-cutting audit hook for
        // storage-layer side effects; slice 2 establishes the trait contract
        // and the table write. The wrapper that emits the event will be added
        // alongside the route handlers in slice 3/4 so it can carry the
        // correlation_id from the request.)
        Ok(())
    }

    async fn get_device_code_by_device_code(
        &self,
        device_code: &str,
    ) -> Result<Option<DeviceCode>, StoreError> {
        let device_code = device_code.to_string();
        self.conn()
            .call(move |conn| {
                let mut stmt = conn
                    .prepare(&format!(
                        "SELECT {} FROM device_codes WHERE device_code = ?1",
                        DEVICE_CODE_COLUMNS
                    ))
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;
                let mut rows = stmt
                    .query_map(rusqlite::params![device_code], row_to_device_code)
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;
                match rows.next() {
                    Some(Ok(c)) => Ok(Some(c)),
                    Some(Err(e)) => Err(tokio_rusqlite::Error::Rusqlite(e)),
                    None => Ok(None),
                }
            })
            .await
            .map_err(|e| StoreError::Database(e.to_string()))
    }

    async fn get_device_code_by_user_code(
        &self,
        user_code: &str,
    ) -> Result<Option<DeviceCode>, StoreError> {
        // Normalize to lowercase for case-insensitive match. The service layer
        // is expected to persist user_code already-normalized, but we normalize
        // again defensively on the lookup side.
        let user_code = user_code.to_lowercase();
        self.conn()
            .call(move |conn| {
                let mut stmt = conn
                    .prepare(&format!(
                        "SELECT {} FROM device_codes WHERE lower(user_code) = ?1",
                        DEVICE_CODE_COLUMNS
                    ))
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;
                let mut rows = stmt
                    .query_map(rusqlite::params![user_code], row_to_device_code)
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;
                match rows.next() {
                    Some(Ok(c)) => Ok(Some(c)),
                    Some(Err(e)) => Err(tokio_rusqlite::Error::Rusqlite(e)),
                    None => Ok(None),
                }
            })
            .await
            .map_err(|e| StoreError::Database(e.to_string()))
    }

    async fn approve_device_code(
        &self,
        user_code: &str,
        approving_user_id: &str,
    ) -> Result<bool, StoreError> {
        let user_code = user_code.to_lowercase();
        let approving_user_id = approving_user_id.to_string();
        self.conn()
            .call(move |conn| {
                let count = conn
                    .execute(
                        "UPDATE device_codes SET status = 'approved', approved_user_id = ?1 \
                         WHERE lower(user_code) = ?2 AND status = 'pending'",
                        rusqlite::params![approving_user_id, user_code],
                    )
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;
                Ok(count > 0)
            })
            .await
            .map_err(|e| StoreError::Database(e.to_string()))
    }

    async fn deny_device_code(&self, user_code: &str) -> Result<bool, StoreError> {
        let user_code = user_code.to_lowercase();
        self.conn()
            .call(move |conn| {
                let count = conn
                    .execute(
                        "UPDATE device_codes SET status = 'denied' \
                         WHERE lower(user_code) = ?1 AND status = 'pending'",
                        rusqlite::params![user_code],
                    )
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;
                Ok(count > 0)
            })
            .await
            .map_err(|e| StoreError::Database(e.to_string()))
    }

    async fn consume_device_code(&self, device_code: &str) -> Result<bool, StoreError> {
        let device_code = device_code.to_string();
        self.conn()
            .call(move |conn| {
                // CAS: only transition from exactly 'approved' -> 'consumed'.
                let count = conn
                    .execute(
                        "UPDATE device_codes SET status = 'consumed' \
                         WHERE device_code = ?1 AND status = 'approved'",
                        rusqlite::params![device_code],
                    )
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;
                Ok(count == 1)
            })
            .await
            .map_err(|e| StoreError::Database(e.to_string()))
    }

    async fn update_device_code_poll(
        &self,
        device_code: &str,
        new_interval_secs: Option<i64>,
    ) -> Result<(), StoreError> {
        let device_code = device_code.to_string();
        let now = Utc::now().to_rfc3339();
        self.conn()
            .call(move |conn| {
                match new_interval_secs {
                    Some(interval) => {
                        conn.execute(
                            "UPDATE device_codes SET last_polled_at = ?1, interval_secs = ?2 \
                             WHERE device_code = ?3 AND status = 'pending'",
                            rusqlite::params![now, interval, device_code],
                        )
                        .map_err(tokio_rusqlite::Error::Rusqlite)?;
                    }
                    None => {
                        conn.execute(
                            "UPDATE device_codes SET last_polled_at = ?1 \
                             WHERE device_code = ?2 AND status = 'pending'",
                            rusqlite::params![now, device_code],
                        )
                        .map_err(tokio_rusqlite::Error::Rusqlite)?;
                    }
                }
                Ok(())
            })
            .await
            .map_err(|e| StoreError::Database(e.to_string()))
    }

    async fn sweep_expired_device_codes(&self) -> Result<u32, StoreError> {
        let now = Utc::now().to_rfc3339();
        self.conn()
            .call(move |conn| {
                let count = conn
                    .execute(
                        "UPDATE device_codes SET status = 'expired' \
                         WHERE status IN ('pending','approved') AND expires_at <= ?1",
                        rusqlite::params![now],
                    )
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;
                Ok(count as u32)
            })
            .await
            .map_err(|e| StoreError::Database(e.to_string()))
    }
}
