use async_trait::async_trait;

use crate::error::StoreError;
use crate::oauth2::types::DeviceCode;

/// Storage trait for RFC 8628 Device Authorization Grant records.
///
/// Audit emission for `DeviceCodeIssued`, `DeviceCodeApproved`, `DeviceCodeDenied`,
/// and `DeviceCodeExpired` is the responsibility of implementations of this trait,
/// per the CLAUDE.md rule that side effects live at the layer where the state
/// change happens — not in HTTP handlers.
#[async_trait]
pub trait DeviceCodeStore: Send + Sync {
    /// Persist a new device code row with status=`pending`.
    async fn insert_device_code(&self, code: &DeviceCode) -> Result<(), StoreError>;

    /// Look up a device code by its `device_code` (lookup string — the service
    /// layer decides whether that is a plaintext token or a hash).
    async fn get_device_code_by_device_code(
        &self,
        device_code: &str,
    ) -> Result<Option<DeviceCode>, StoreError>;

    /// Look up a device code by its `user_code` (case-insensitive match expected
    /// at the service layer; implementations MAY normalize).
    async fn get_device_code_by_user_code(
        &self,
        user_code: &str,
    ) -> Result<Option<DeviceCode>, StoreError>;

    /// Mark a pending device code as approved. Returns true if a row was
    /// transitioned. Also persists the approving `user_id` as owner.
    async fn approve_device_code(
        &self,
        user_code: &str,
        approving_user_id: &str,
    ) -> Result<bool, StoreError>;

    /// Mark a pending device code as denied. Returns true if a row was transitioned.
    async fn deny_device_code(&self, user_code: &str) -> Result<bool, StoreError>;

    /// Atomically transition an approved row to `consumed` (single-use).
    /// Returns true only if the CAS update affected exactly one row.
    async fn consume_device_code(&self, device_code: &str) -> Result<bool, StoreError>;

    /// Update the poll bookkeeping for a pending row: set `last_polled_at = now`
    /// and optionally increase `interval_secs` (used when returning `slow_down`).
    async fn update_device_code_poll(
        &self,
        device_code: &str,
        new_interval_secs: Option<i64>,
    ) -> Result<(), StoreError>;

    /// Sweep: mark any non-terminal rows whose `expires_at` has passed as `expired`.
    /// Returns the number of rows transitioned. Implementations MUST emit a
    /// `DeviceCodeExpired` audit event per transitioned row.
    async fn sweep_expired_device_codes(&self) -> Result<u32, StoreError>;
}
