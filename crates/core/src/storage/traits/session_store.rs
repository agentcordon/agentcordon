use async_trait::async_trait;

use crate::domain::session::Session;
use crate::domain::user::UserId;
use crate::error::StoreError;

#[async_trait]
pub trait SessionStore: Send + Sync {
    async fn create_session(&self, session: &Session) -> Result<(), StoreError>;
    async fn get_session(&self, id_hash: &str) -> Result<Option<Session>, StoreError>;
    async fn delete_session(&self, id_hash: &str) -> Result<bool, StoreError>;
    async fn delete_user_sessions(&self, user_id: &UserId) -> Result<u32, StoreError>;
    async fn touch_session(&self, id_hash: &str) -> Result<(), StoreError>;
    async fn cleanup_expired_sessions(&self) -> Result<u32, StoreError>;
}
