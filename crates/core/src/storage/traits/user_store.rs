use async_trait::async_trait;

use crate::domain::user::{User, UserId};
use crate::error::StoreError;

#[async_trait]
pub trait UserStore: Send + Sync {
    async fn create_user(&self, user: &User) -> Result<(), StoreError>;
    async fn get_user(&self, id: &UserId) -> Result<Option<User>, StoreError>;
    async fn get_user_by_username(&self, username: &str) -> Result<Option<User>, StoreError>;
    async fn list_users(&self) -> Result<Vec<User>, StoreError>;
    async fn update_user(&self, user: &User) -> Result<(), StoreError>;
    async fn delete_user(&self, id: &UserId) -> Result<bool, StoreError>;
    async fn get_root_user(&self) -> Result<Option<User>, StoreError>;
}
