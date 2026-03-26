use async_trait::async_trait;
use chrono::Utc;
use uuid::Uuid;

use super::{db_err, serialize_enrollment_status, EnrollmentRow, PostgresStore};
use crate::domain::enrollment::EnrollmentSession;
use crate::error::StoreError;
use crate::storage::EnrollmentStore;

#[async_trait]
impl EnrollmentStore for PostgresStore {
    async fn create_enrollment_session(
        &self,
        session: &EnrollmentSession,
    ) -> Result<(), StoreError> {
        let agent_tags = serde_json::to_value(&session.agent_tags).unwrap_or_default();
        let status = serialize_enrollment_status(&session.status);
        let workspace_id = session.workspace_id.as_ref().map(|w| w.0);

        sqlx::query(
            "INSERT INTO enrollment_sessions (id, session_token_hash, approval_ref, approval_code, \
             agent_name, agent_description, agent_tags, status, created_at, expires_at, client_ip, workspace_id) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
        )
        .bind(session.id)
        .bind(&session.session_token_hash)
        .bind(&session.approval_ref)
        .bind(&session.approval_code)
        .bind(&session.agent_name)
        .bind(&session.agent_description)
        .bind(&agent_tags)
        .bind(status)
        .bind(session.created_at)
        .bind(session.expires_at)
        .bind(&session.client_ip)
        .bind(workspace_id)
        .execute(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(())
    }

    async fn get_enrollment_session_by_token_hash(
        &self,
        token_hash: &str,
    ) -> Result<Option<EnrollmentSession>, StoreError> {
        let row = sqlx::query_as::<_, EnrollmentRow>(
            "SELECT id, session_token_hash, approval_ref, approval_code, agent_name, agent_description, \
             agent_tags, status, created_at, expires_at, approved_by, approved_at, claimed_at, client_ip, \
             claim_attempts, workspace_id \
             FROM enrollment_sessions WHERE session_token_hash = $1",
        )
        .bind(token_hash)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_err)?;
        row.map(|r| r.into_session()).transpose()
    }

    async fn get_enrollment_session_by_ref(
        &self,
        approval_ref: &str,
    ) -> Result<Option<EnrollmentSession>, StoreError> {
        let row = sqlx::query_as::<_, EnrollmentRow>(
            "SELECT id, session_token_hash, approval_ref, approval_code, agent_name, agent_description, \
             agent_tags, status, created_at, expires_at, approved_by, approved_at, claimed_at, client_ip, \
             claim_attempts, workspace_id \
             FROM enrollment_sessions WHERE approval_ref = $1",
        )
        .bind(approval_ref)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_err)?;
        row.map(|r| r.into_session()).transpose()
    }

    async fn list_pending_enrollment_sessions(&self) -> Result<Vec<EnrollmentSession>, StoreError> {
        let rows = sqlx::query_as::<_, EnrollmentRow>(
            "SELECT id, session_token_hash, approval_ref, approval_code, agent_name, agent_description, \
             agent_tags, status, created_at, expires_at, approved_by, approved_at, claimed_at, client_ip, \
             claim_attempts, workspace_id \
             FROM enrollment_sessions WHERE status = 'pending' ORDER BY created_at DESC",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(db_err)?;
        rows.into_iter().map(|r| r.into_session()).collect()
    }

    async fn count_pending_enrollment_sessions(&self) -> Result<u32, StoreError> {
        let row: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM enrollment_sessions WHERE status = 'pending'")
                .fetch_one(&self.pool)
                .await
                .map_err(db_err)?;
        Ok(row.0 as u32)
    }

    async fn count_recent_enrollment_sessions_by_ip(
        &self,
        client_ip: &str,
        window_seconds: u64,
    ) -> Result<u32, StoreError> {
        let cutoff = Utc::now() - chrono::Duration::seconds(window_seconds as i64);
        let row: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM enrollment_sessions WHERE client_ip = $1 AND created_at > $2",
        )
        .bind(client_ip)
        .bind(cutoff)
        .fetch_one(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(row.0 as u32)
    }

    async fn approve_enrollment_session(
        &self,
        id: &str,
        approved_by: &str,
    ) -> Result<bool, StoreError> {
        let now = Utc::now();
        let session_id = Uuid::parse_str(id)
            .map_err(|e| StoreError::Database(format!("invalid session id: {}", e)))?;
        let result = sqlx::query(
            "UPDATE enrollment_sessions SET status = 'approved', approved_by = $1, approved_at = $2 \
             WHERE id = $3 AND status = 'pending'",
        )
        .bind(approved_by)
        .bind(now)
        .bind(session_id)
        .execute(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(result.rows_affected() > 0)
    }

    async fn deny_enrollment_session(&self, id: &str) -> Result<bool, StoreError> {
        let session_id = Uuid::parse_str(id)
            .map_err(|e| StoreError::Database(format!("invalid session id: {}", e)))?;
        let result = sqlx::query(
            "UPDATE enrollment_sessions SET status = 'denied' WHERE id = $1 AND status = 'pending'",
        )
        .bind(session_id)
        .execute(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(result.rows_affected() > 0)
    }

    async fn claim_enrollment_session(&self, id: &str) -> Result<Option<String>, StoreError> {
        let session_id = Uuid::parse_str(id)
            .map_err(|e| StoreError::Database(format!("invalid session id: {}", e)))?;
        let now = Utc::now();

        let mut tx = self.pool.begin().await.map_err(db_err)?;

        let row: Option<(Uuid,)> = sqlx::query_as(
            "SELECT id FROM enrollment_sessions \
             WHERE id = $1 AND status = 'approved' \
             FOR UPDATE",
        )
        .bind(session_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db_err)?;

        if row.is_some() {
            sqlx::query(
                "UPDATE enrollment_sessions SET status = 'claimed', claimed_at = $1 WHERE id = $2",
            )
            .bind(now)
            .bind(session_id)
            .execute(&mut *tx)
            .await
            .map_err(db_err)?;
            tx.commit().await.map_err(db_err)?;
            Ok(Some("claimed".to_string()))
        } else {
            let _ = tx.rollback().await;
            let _ = sqlx::query(
                "UPDATE enrollment_sessions SET claim_attempts = claim_attempts + 1 WHERE id = $1",
            )
            .bind(session_id)
            .execute(&self.pool)
            .await;
            Ok(None)
        }
    }

    async fn expire_enrollment_sessions(&self) -> Result<u32, StoreError> {
        let now = Utc::now();
        let result = sqlx::query(
            "UPDATE enrollment_sessions SET status = 'expired' WHERE status = 'pending' AND expires_at < $1",
        )
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(result.rows_affected() as u32)
    }
}
