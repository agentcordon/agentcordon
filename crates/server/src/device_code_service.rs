//! Device code service — the audit-emitting wrapper around `DeviceCodeStore`.
//!
//! This service is the canonical layer at which device-flow state changes
//! happen: every call site in the server crate MUST go through it rather than
//! touching `DeviceCodeStore` directly. Audit emission lives here (not in
//! HTTP handlers) because:
//!
//! 1. It matches the CLAUDE.md rule "side effects at the layer where the
//!    state change happens" — if every state change routes through this
//!    service, the service IS that layer.
//! 2. Audit events need the request `correlation_id`, which lives on the
//!    HTTP boundary — threading it through the raw `Store` trait would
//!    pollute the storage layer with HTTP concerns.
//! 3. Parallels the existing `auditing_policy_engine` pattern.
//!
//! Audit writes are best-effort: failures are logged via `tracing::error!`
//! but never fail the underlying state change (we don't want to refuse a
//! legitimate approval because the audit sink is down).

use std::sync::Arc;

use chrono::{DateTime, Duration, Utc};
use tracing::error;

use agent_cordon_core::domain::audit::{AuditDecision, AuditEvent, AuditEventType};
use agent_cordon_core::error::StoreError;
use agent_cordon_core::oauth2::types::{DeviceCode, DeviceCodeStatus, OAuthScope};
use agent_cordon_core::storage::Store;

use crate::state::SharedStore;

/// Policy-checked, audit-emitting wrapper around `DeviceCodeStore`.
#[derive(Clone)]
pub struct DeviceCodeService {
    store: SharedStore,
}

impl DeviceCodeService {
    pub fn new(store: SharedStore) -> Self {
        Self { store }
    }

    /// Issue a new device code row. Emits `DeviceCodeIssued` on success.
    #[allow(clippy::too_many_arguments)]
    pub async fn issue(
        &self,
        device_code: String,
        user_code: String,
        client_id: String,
        scopes: Vec<OAuthScope>,
        workspace_name_prefill: Option<String>,
        pk_hash_prefill: Option<String>,
        ttl_secs: i64,
        interval_secs: i64,
        correlation_id: &str,
    ) -> Result<DeviceCode, StoreError> {
        let now = Utc::now();
        let row = DeviceCode {
            device_code: device_code.clone(),
            user_code: user_code.clone(),
            client_id: client_id.clone(),
            scopes: scopes.clone(),
            status: DeviceCodeStatus::Pending,
            workspace_name_prefill: workspace_name_prefill.clone(),
            pk_hash_prefill: pk_hash_prefill.clone(),
            approved_user_id: None,
            last_polled_at: None,
            interval_secs,
            created_at: now,
            expires_at: now + Duration::seconds(ttl_secs),
        };
        self.store.insert_device_code(&row).await?;

        self.emit(
            AuditEventType::DeviceCodeIssued,
            "issue_device_code",
            AuditDecision::Permit,
            &client_id,
            correlation_id,
            serde_json::json!({
                "client_id": client_id,
                "scopes": scopes.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
                "ttl_secs": ttl_secs,
                "interval_secs": interval_secs,
                "workspace_name_prefill": workspace_name_prefill,
                "pk_hash_bound_at_issue": pk_hash_prefill.is_some(),
                // Deliberately NOT logged: device_code, user_code, pk_hash itself.
            }),
        )
        .await;

        Ok(row)
    }

    /// Approve by user_code. Emits `DeviceCodeApproved` on transition.
    pub async fn approve(
        &self,
        user_code: &str,
        approving_user_id: &str,
        correlation_id: &str,
    ) -> Result<bool, StoreError> {
        let ok = self
            .store
            .approve_device_code(user_code, approving_user_id)
            .await?;
        if ok {
            self.emit(
                AuditEventType::DeviceCodeApproved,
                "approve_device_code",
                AuditDecision::Permit,
                approving_user_id,
                correlation_id,
                serde_json::json!({ "approving_user_id": approving_user_id }),
            )
            .await;
        }
        Ok(ok)
    }

    /// Deny by user_code. Emits `DeviceCodeDenied` on transition.
    pub async fn deny(
        &self,
        user_code: &str,
        denying_user_id: &str,
        correlation_id: &str,
    ) -> Result<bool, StoreError> {
        let ok = self.store.deny_device_code(user_code).await?;
        if ok {
            self.emit(
                AuditEventType::DeviceCodeDenied,
                "deny_device_code",
                AuditDecision::Forbid,
                denying_user_id,
                correlation_id,
                serde_json::json!({ "denying_user_id": denying_user_id }),
            )
            .await;
        }
        Ok(ok)
    }

    /// Look up by device_code (passthrough).
    pub async fn get_by_device_code(
        &self,
        device_code: &str,
    ) -> Result<Option<DeviceCode>, StoreError> {
        self.store.get_device_code_by_device_code(device_code).await
    }

    /// Look up by user_code (passthrough).
    pub async fn get_by_user_code(
        &self,
        user_code: &str,
    ) -> Result<Option<DeviceCode>, StoreError> {
        self.store.get_device_code_by_user_code(user_code).await
    }

    /// CAS consume an approved row. Strict: returns true only on affected==1.
    pub async fn consume(&self, device_code: &str) -> Result<bool, StoreError> {
        self.store.consume_device_code(device_code).await
    }

    /// Update poll bookkeeping for a pending row.
    pub async fn update_poll(
        &self,
        device_code: &str,
        new_interval_secs: Option<i64>,
    ) -> Result<(), StoreError> {
        self.store
            .update_device_code_poll(device_code, new_interval_secs)
            .await
    }

    /// Sweep expired rows. Emits a single aggregate `DeviceCodeExpired`
    /// event with the count. (Per-row emission would flood the audit log.)
    pub async fn sweep_expired(&self, correlation_id: &str) -> Result<u32, StoreError> {
        let count = self.store.sweep_expired_device_codes().await?;
        if count > 0 {
            self.emit(
                AuditEventType::DeviceCodeExpired,
                "sweep_expired_device_codes",
                AuditDecision::NotApplicable,
                "system",
                correlation_id,
                serde_json::json!({ "expired_count": count }),
            )
            .await;
        }
        Ok(count)
    }

    async fn emit(
        &self,
        event_type: AuditEventType,
        action: &str,
        decision: AuditDecision,
        resource_id: &str,
        correlation_id: &str,
        metadata: serde_json::Value,
    ) {
        let event = AuditEvent::builder(event_type)
            .action(action)
            .resource("device_code", resource_id)
            .decision(decision, None)
            .details(metadata)
            .correlation_id(correlation_id)
            .build();
        if let Err(e) = self.store.append_audit_event(&event).await {
            error!(error = %e, "failed to append device-code audit event");
        }
    }
}

// Unused-import silencers for the narrow surface actually touched here.
#[allow(dead_code)]
fn _assert_types(_: DateTime<Utc>, _: Arc<dyn Store + Send + Sync>) {}
