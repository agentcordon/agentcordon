use async_trait::async_trait;

use super::PostgresStore;
use crate::error::StoreError;
use crate::oauth2::types::DeviceCode;
use crate::storage::traits::DeviceCodeStore;

/// Postgres DeviceCodeStore — stubbed to satisfy the composite `Store` trait
/// bound. Parity with the other Postgres OAuth impls in this crate: returns
/// `StoreError::Database("not implemented")` until the Postgres migration lands.
#[async_trait]
impl DeviceCodeStore for PostgresStore {
    async fn insert_device_code(&self, _code: &DeviceCode) -> Result<(), StoreError> {
        Err(StoreError::Database(
            "device_codes: postgres not yet implemented".into(),
        ))
    }

    async fn get_device_code_by_device_code(
        &self,
        _device_code: &str,
    ) -> Result<Option<DeviceCode>, StoreError> {
        Err(StoreError::Database(
            "device_codes: postgres not yet implemented".into(),
        ))
    }

    async fn get_device_code_by_user_code(
        &self,
        _user_code: &str,
    ) -> Result<Option<DeviceCode>, StoreError> {
        Err(StoreError::Database(
            "device_codes: postgres not yet implemented".into(),
        ))
    }

    async fn approve_device_code(
        &self,
        _user_code: &str,
        _approving_user_id: &str,
    ) -> Result<bool, StoreError> {
        Err(StoreError::Database(
            "device_codes: postgres not yet implemented".into(),
        ))
    }

    async fn deny_device_code(&self, _user_code: &str) -> Result<bool, StoreError> {
        Err(StoreError::Database(
            "device_codes: postgres not yet implemented".into(),
        ))
    }

    async fn consume_device_code(&self, _device_code: &str) -> Result<bool, StoreError> {
        Err(StoreError::Database(
            "device_codes: postgres not yet implemented".into(),
        ))
    }

    async fn update_device_code_poll(
        &self,
        _device_code: &str,
        _new_interval_secs: Option<i64>,
    ) -> Result<(), StoreError> {
        Err(StoreError::Database(
            "device_codes: postgres not yet implemented".into(),
        ))
    }

    async fn sweep_expired_device_codes(&self) -> Result<u32, StoreError> {
        Err(StoreError::Database(
            "device_codes: postgres not yet implemented".into(),
        ))
    }
}
