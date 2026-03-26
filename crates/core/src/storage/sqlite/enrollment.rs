use async_trait::async_trait;

use super::helpers::*;
use super::SqliteStore;

use crate::domain::enrollment::EnrollmentSession;
use crate::error::StoreError;
use crate::storage::EnrollmentStore;
use chrono::Utc;

impl SqliteStore {
    pub(crate) async fn create_enrollment_session(
        &self,
        session: &EnrollmentSession,
    ) -> Result<(), StoreError> {
        let id = session.id.hyphenated().to_string();
        let session_token_hash = session.session_token_hash.clone();
        let approval_ref = session.approval_ref.clone();
        let approval_code = session.approval_code.clone();
        let agent_name = session.agent_name.clone();
        let agent_description = session.agent_description.clone();
        let agent_tags = serialize_tags(&session.agent_tags)?;
        let status = serialize_enrollment_session_status(&session.status);
        let created_at = session.created_at.to_rfc3339();
        let expires_at = session.expires_at.to_rfc3339();
        let client_ip = session.client_ip.clone();
        let workspace_id_str = session
            .workspace_id
            .as_ref()
            .map(|w| w.0.hyphenated().to_string());

        self.conn()
            .call(move |conn| {
                conn.execute(
                    "INSERT INTO enrollment_sessions (id, session_token_hash, approval_ref, approval_code, agent_name, agent_description, agent_tags, status, created_at, expires_at, client_ip, workspace_id) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
                    rusqlite::params![id, session_token_hash, approval_ref, approval_code, agent_name, agent_description, agent_tags, status, created_at, expires_at, client_ip, workspace_id_str],
                )
                .map_err(tokio_rusqlite::Error::Rusqlite)?;
                Ok(())
            })
            .await
            .map_err(|e| StoreError::Database(e.to_string()))
    }

    pub(crate) async fn get_enrollment_session_by_token_hash(
        &self,
        token_hash: &str,
    ) -> Result<Option<EnrollmentSession>, StoreError> {
        let token_hash = token_hash.to_string();

        self.conn()
            .call(move |conn| {
                let mut stmt = conn
                    .prepare(
                        "SELECT id, session_token_hash, approval_ref, approval_code, agent_name, agent_description, agent_tags, status, created_at, expires_at, approved_by, approved_at, claimed_at, client_ip, claim_attempts, workspace_id \
                         FROM enrollment_sessions WHERE session_token_hash = ?1",
                    )
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;

                let mut rows = stmt
                    .query_map(rusqlite::params![token_hash], row_to_enrollment_session)
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;

                match rows.next() {
                    Some(Ok(session)) => Ok(Some(session)),
                    Some(Err(e)) => Err(tokio_rusqlite::Error::Rusqlite(e)),
                    None => Ok(None),
                }
            })
            .await
            .map_err(|e| StoreError::Database(e.to_string()))
    }

    pub(crate) async fn get_enrollment_session_by_ref(
        &self,
        approval_ref: &str,
    ) -> Result<Option<EnrollmentSession>, StoreError> {
        let approval_ref = approval_ref.to_string();

        self.conn()
            .call(move |conn| {
                let mut stmt = conn
                    .prepare(
                        "SELECT id, session_token_hash, approval_ref, approval_code, agent_name, agent_description, agent_tags, status, created_at, expires_at, approved_by, approved_at, claimed_at, client_ip, claim_attempts, workspace_id \
                         FROM enrollment_sessions WHERE approval_ref = ?1",
                    )
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;

                let mut rows = stmt
                    .query_map(rusqlite::params![approval_ref], row_to_enrollment_session)
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;

                match rows.next() {
                    Some(Ok(session)) => Ok(Some(session)),
                    Some(Err(e)) => Err(tokio_rusqlite::Error::Rusqlite(e)),
                    None => Ok(None),
                }
            })
            .await
            .map_err(|e| StoreError::Database(e.to_string()))
    }

    pub(crate) async fn list_pending_enrollment_sessions(
        &self,
    ) -> Result<Vec<EnrollmentSession>, StoreError> {
        self.conn()
            .call(move |conn| {
                let mut stmt = conn
                    .prepare(
                        "SELECT id, session_token_hash, approval_ref, approval_code, agent_name, agent_description, agent_tags, status, created_at, expires_at, approved_by, approved_at, claimed_at, client_ip, claim_attempts, workspace_id \
                         FROM enrollment_sessions WHERE status = 'pending' ORDER BY created_at DESC",
                    )
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;

                let rows = stmt
                    .query_map([], row_to_enrollment_session)
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;

                let mut sessions = Vec::new();
                for row in rows {
                    sessions.push(row.map_err(tokio_rusqlite::Error::Rusqlite)?);
                }
                Ok(sessions)
            })
            .await
            .map_err(|e| StoreError::Database(e.to_string()))
    }

    pub(crate) async fn count_pending_enrollment_sessions(&self) -> Result<u32, StoreError> {
        self.conn()
            .call(move |conn| {
                let count: u32 = conn
                    .query_row(
                        "SELECT COUNT(*) FROM enrollment_sessions WHERE status = 'pending'",
                        [],
                        |row| row.get(0),
                    )
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;
                Ok(count)
            })
            .await
            .map_err(|e| StoreError::Database(e.to_string()))
    }

    pub(crate) async fn count_recent_enrollment_sessions_by_ip(
        &self,
        client_ip: &str,
        window_seconds: u64,
    ) -> Result<u32, StoreError> {
        let client_ip = client_ip.to_string();
        let cutoff = (Utc::now() - chrono::Duration::seconds(window_seconds as i64)).to_rfc3339();

        self.conn()
            .call(move |conn| {
                let count: u32 = conn
                    .query_row(
                        "SELECT COUNT(*) FROM enrollment_sessions WHERE client_ip = ?1 AND created_at > ?2",
                        rusqlite::params![client_ip, cutoff],
                        |row| row.get(0),
                    )
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;
                Ok(count)
            })
            .await
            .map_err(|e| StoreError::Database(e.to_string()))
    }

    pub(crate) async fn approve_enrollment_session(
        &self,
        id: &str,
        approved_by: &str,
    ) -> Result<bool, StoreError> {
        let id = id.to_string();
        let approved_by = approved_by.to_string();
        let now = Utc::now().to_rfc3339();

        self.conn()
            .call(move |conn| {
                let rows = conn
                    .execute(
                        "UPDATE enrollment_sessions SET status = 'approved', approved_by = ?1, approved_at = ?2 WHERE id = ?3 AND status = 'pending'",
                        rusqlite::params![approved_by, now, id],
                    )
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;
                Ok(rows > 0)
            })
            .await
            .map_err(|e| StoreError::Database(e.to_string()))
    }

    pub(crate) async fn deny_enrollment_session(&self, id: &str) -> Result<bool, StoreError> {
        let id = id.to_string();

        self.conn()
            .call(move |conn| {
                let rows = conn
                    .execute(
                        "UPDATE enrollment_sessions SET status = 'denied' WHERE id = ?1 AND status = 'pending'",
                        rusqlite::params![id],
                    )
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;
                Ok(rows > 0)
            })
            .await
            .map_err(|e| StoreError::Database(e.to_string()))
    }

    pub(crate) async fn claim_enrollment_session(
        &self,
        id: &str,
    ) -> Result<Option<String>, StoreError> {
        let id = id.to_string();
        let now = Utc::now().to_rfc3339();

        self.conn()
            .call(move |conn| {
                // Check if session is approved
                let exists: bool = conn
                    .query_row(
                        "SELECT 1 FROM enrollment_sessions WHERE id = ?1 AND status = 'approved'",
                        rusqlite::params![id],
                        |_row| Ok(true),
                    )
                    .unwrap_or(false);

                if exists {
                    // Mark as claimed
                    conn.execute(
                        "UPDATE enrollment_sessions SET status = 'claimed', claimed_at = ?1 WHERE id = ?2 AND status = 'approved'",
                        rusqlite::params![now, id],
                    )
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;
                    Ok(Some("claimed".to_string()))
                } else {
                    // Increment claim_attempts even on failure
                    conn.execute(
                        "UPDATE enrollment_sessions SET claim_attempts = claim_attempts + 1 WHERE id = ?1",
                        rusqlite::params![id],
                    )
                    .ok();
                    Ok(None)
                }
            })
            .await
            .map_err(|e| StoreError::Database(e.to_string()))
    }

    pub(crate) async fn expire_enrollment_sessions(&self) -> Result<u32, StoreError> {
        let now = Utc::now().to_rfc3339();

        self.conn()
            .call(move |conn| {
                let rows = conn
                    .execute(
                        "UPDATE enrollment_sessions SET status = 'expired' WHERE status = 'pending' AND expires_at < ?1",
                        rusqlite::params![now],
                    )
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;
                Ok(rows as u32)
            })
            .await
            .map_err(|e| StoreError::Database(e.to_string()))
    }
}

#[async_trait]
impl EnrollmentStore for SqliteStore {
    async fn create_enrollment_session(
        &self,
        session: &EnrollmentSession,
    ) -> Result<(), StoreError> {
        self.create_enrollment_session(session).await
    }
    async fn get_enrollment_session_by_token_hash(
        &self,
        token_hash: &str,
    ) -> Result<Option<EnrollmentSession>, StoreError> {
        self.get_enrollment_session_by_token_hash(token_hash).await
    }
    async fn get_enrollment_session_by_ref(
        &self,
        approval_ref: &str,
    ) -> Result<Option<EnrollmentSession>, StoreError> {
        self.get_enrollment_session_by_ref(approval_ref).await
    }
    async fn list_pending_enrollment_sessions(&self) -> Result<Vec<EnrollmentSession>, StoreError> {
        self.list_pending_enrollment_sessions().await
    }
    async fn count_pending_enrollment_sessions(&self) -> Result<u32, StoreError> {
        self.count_pending_enrollment_sessions().await
    }
    async fn count_recent_enrollment_sessions_by_ip(
        &self,
        client_ip: &str,
        window_seconds: u64,
    ) -> Result<u32, StoreError> {
        self.count_recent_enrollment_sessions_by_ip(client_ip, window_seconds)
            .await
    }
    async fn approve_enrollment_session(
        &self,
        id: &str,
        approved_by: &str,
    ) -> Result<bool, StoreError> {
        self.approve_enrollment_session(id, approved_by).await
    }
    async fn deny_enrollment_session(&self, id: &str) -> Result<bool, StoreError> {
        self.deny_enrollment_session(id).await
    }
    async fn claim_enrollment_session(&self, id: &str) -> Result<Option<String>, StoreError> {
        self.claim_enrollment_session(id).await
    }
    async fn expire_enrollment_sessions(&self) -> Result<u32, StoreError> {
        self.expire_enrollment_sessions().await
    }
}
