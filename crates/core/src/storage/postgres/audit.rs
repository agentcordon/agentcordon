use async_trait::async_trait;
use uuid::Uuid;

use super::{db_err, serialize_decision, serialize_event_type, AuditRow, PostgresStore};
use crate::domain::audit::AuditEvent;
use crate::error::StoreError;
use crate::storage::shared::{
    build_audit_filter_sql, log_audit_event, PlaceholderStyle, AUDIT_COLUMNS,
};
use crate::storage::traits::audit_store::AuditFilter;
use crate::storage::AuditStore;

#[async_trait]
impl AuditStore for PostgresStore {
    async fn append_audit_event(&self, event: &AuditEvent) -> Result<(), StoreError> {
        log_audit_event(event);

        let event_type = serialize_event_type(&event.event_type)?;
        let decision = serialize_decision(&event.decision)?;
        let workspace_id = event.workspace_id.as_ref().map(|w| w.0);

        let sql = format!(
            "INSERT INTO audit_events ({}) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)",
            AUDIT_COLUMNS
        );

        sqlx::query(&sql)
            .bind(event.id)
            .bind(event.timestamp)
            .bind(&event.correlation_id)
            .bind(&event_type)
            .bind(workspace_id)
            .bind(&event.workspace_name)
            .bind(&event.action)
            .bind(&event.resource_type)
            .bind(&event.resource_id)
            .bind(&decision)
            .bind(&event.decision_reason)
            .bind(&event.metadata)
            .bind(&event.user_id)
            .bind(&event.user_name)
            .execute(&self.pool)
            .await
            .map_err(db_err)?;
        Ok(())
    }

    async fn get_audit_event(&self, id: &Uuid) -> Result<Option<AuditEvent>, StoreError> {
        let sql = format!("SELECT {} FROM audit_events WHERE id = $1", AUDIT_COLUMNS);
        let row = sqlx::query_as::<_, AuditRow>(&sql)
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(db_err)?;
        row.map(|r| r.into_event()).transpose()
    }

    async fn list_audit_events(
        &self,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<AuditEvent>, StoreError> {
        let sql = format!(
            "SELECT {} FROM audit_events ORDER BY timestamp DESC LIMIT $1 OFFSET $2",
            AUDIT_COLUMNS
        );
        let rows = sqlx::query_as::<_, AuditRow>(&sql)
            .bind(limit as i64)
            .bind(offset as i64)
            .fetch_all(&self.pool)
            .await
            .map_err(db_err)?;
        rows.into_iter().map(|r| r.into_event()).collect()
    }

    async fn list_audit_events_filtered(
        &self,
        filter: &AuditFilter,
    ) -> Result<Vec<AuditEvent>, StoreError> {
        let fq = build_audit_filter_sql(filter, PlaceholderStyle::DollarSign);

        let mut query = sqlx::query_as::<_, AuditRow>(&fq.sql);
        for v in &fq.param_values {
            query = query.bind(v.clone());
        }
        query = query.bind(fq.limit as i64).bind(fq.offset as i64);

        let rows = query.fetch_all(&self.pool).await.map_err(db_err)?;
        rows.into_iter().map(|r| r.into_event()).collect()
    }
}
