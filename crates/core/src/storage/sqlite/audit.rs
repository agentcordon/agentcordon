use async_trait::async_trait;

use super::helpers::*;
use super::SqliteStore;

use crate::domain::audit::AuditEvent;
use crate::error::StoreError;
use crate::storage::shared::{
    build_audit_filter_sql, log_audit_event, PlaceholderStyle, AUDIT_COLUMNS,
};
use crate::storage::{AuditFilter, AuditStore};
use uuid::Uuid;

impl SqliteStore {
    pub(crate) async fn append_audit_event(&self, event: &AuditEvent) -> Result<(), StoreError> {
        log_audit_event(event);

        let event_id = event.id.hyphenated().to_string();
        let timestamp = event.timestamp.to_rfc3339();
        let correlation_id = event.correlation_id.clone();
        let event_type = serialize_event_type(&event.event_type)?;
        let workspace_id = event
            .workspace_id
            .as_ref()
            .map(|w| w.0.hyphenated().to_string());
        let workspace_name = event.workspace_name.clone();
        let action = event.action.clone();
        let resource_type = event.resource_type.clone();
        let resource_id = event.resource_id.clone();
        let decision = serialize_decision(&event.decision)?;
        let decision_reason = event.decision_reason.clone();
        let metadata_json = serialize_metadata(&event.metadata)?;
        let user_id = event.user_id.clone();
        let user_name = event.user_name.clone();

        self.conn()
            .call(move |conn| {
                let sql = format!(
                    "INSERT INTO audit_events ({}) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
                    AUDIT_COLUMNS
                );
                conn.execute(
                    &sql,
                    rusqlite::params![
                        event_id,
                        timestamp,
                        correlation_id,
                        event_type,
                        workspace_id,
                        workspace_name,
                        action,
                        resource_type,
                        resource_id,
                        decision,
                        decision_reason,
                        metadata_json,
                        user_id,
                        user_name,
                    ],
                )
                .map_err(tokio_rusqlite::Error::Rusqlite)?;
                Ok(())
            })
            .await
            .map_err(|e| StoreError::Database(e.to_string()))
    }

    pub(crate) async fn get_audit_event(
        &self,
        id: &Uuid,
    ) -> Result<Option<AuditEvent>, StoreError> {
        let id_str = id.hyphenated().to_string();
        self.conn()
            .call(move |conn| {
                let sql = format!("SELECT {} FROM audit_events WHERE id = ?1", AUDIT_COLUMNS);
                let mut stmt = conn
                    .prepare(&sql)
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;

                let mut rows = stmt
                    .query_map(rusqlite::params![id_str], row_to_audit_event)
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;

                match rows.next() {
                    Some(row) => Ok(Some(row.map_err(tokio_rusqlite::Error::Rusqlite)?)),
                    None => Ok(None),
                }
            })
            .await
            .map_err(|e| StoreError::Database(e.to_string()))
    }

    pub(crate) async fn list_audit_events(
        &self,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<AuditEvent>, StoreError> {
        self.conn()
            .call(move |conn| {
                let sql = format!(
                    "SELECT {} FROM audit_events ORDER BY timestamp DESC LIMIT ?1 OFFSET ?2",
                    AUDIT_COLUMNS
                );
                let mut stmt = conn
                    .prepare(&sql)
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;

                let rows = stmt
                    .query_map(rusqlite::params![limit, offset], row_to_audit_event)
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;

                let mut events = Vec::new();
                for row in rows {
                    events.push(row.map_err(tokio_rusqlite::Error::Rusqlite)?);
                }
                Ok(events)
            })
            .await
            .map_err(|e| StoreError::Database(e.to_string()))
    }

    pub(crate) async fn list_audit_events_filtered(
        &self,
        filter: &AuditFilter,
    ) -> Result<Vec<AuditEvent>, StoreError> {
        let filter = filter.clone();

        self.conn()
            .call(move |conn| {
                let fq = build_audit_filter_sql(&filter, PlaceholderStyle::QuestionMark);

                let mut params: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();
                for v in &fq.param_values {
                    params.push(Box::new(v.clone()));
                }
                params.push(Box::new(fq.limit));
                params.push(Box::new(fq.offset));

                let mut stmt = conn
                    .prepare(&fq.sql)
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;
                let param_refs: Vec<&dyn rusqlite::types::ToSql> =
                    params.iter().map(|p| p.as_ref()).collect();
                let rows = stmt
                    .query_map(param_refs.as_slice(), row_to_audit_event)
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;

                let mut events = Vec::new();
                for row in rows {
                    events.push(row.map_err(tokio_rusqlite::Error::Rusqlite)?);
                }
                Ok(events)
            })
            .await
            .map_err(|e| StoreError::Database(e.to_string()))
    }
}

#[async_trait]
impl AuditStore for SqliteStore {
    async fn append_audit_event(&self, event: &AuditEvent) -> Result<(), StoreError> {
        self.append_audit_event(event).await
    }
    async fn list_audit_events(
        &self,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<AuditEvent>, StoreError> {
        self.list_audit_events(limit, offset).await
    }
    async fn get_audit_event(&self, id: &uuid::Uuid) -> Result<Option<AuditEvent>, StoreError> {
        self.get_audit_event(id).await
    }
    async fn list_audit_events_filtered(
        &self,
        filter: &AuditFilter,
    ) -> Result<Vec<AuditEvent>, StoreError> {
        self.list_audit_events_filtered(filter).await
    }
}
