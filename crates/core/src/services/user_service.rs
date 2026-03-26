use std::sync::Arc;

use crate::domain::user::{User, UserId};
use crate::error::ServiceError;
use crate::storage::traits::{AuditStore, UserStore};

/// Service layer for user operations.
///
/// Handles user CRUD. Password hashing and session management
/// remain in route handlers.
pub struct UserService<S: UserStore + AuditStore> {
    store: Arc<S>,
}

impl<S: UserStore + AuditStore> UserService<S> {
    pub fn new(store: Arc<S>) -> Self {
        Self { store }
    }

    pub async fn create(&self, user: &User) -> Result<(), ServiceError> {
        if user.username.trim().is_empty() {
            return Err(ServiceError::Validation {
                field: "username".into(),
                message: "username must not be empty".into(),
            });
        }
        // Check for username uniqueness
        if let Some(_existing) = self.store.get_user_by_username(&user.username).await? {
            return Err(ServiceError::Conflict {
                message: format!("user with username '{}' already exists", user.username),
            });
        }
        self.store.create_user(user).await?;
        Ok(())
    }

    pub async fn get(&self, id: &UserId) -> Result<User, ServiceError> {
        self.store
            .get_user(id)
            .await?
            .ok_or_else(|| ServiceError::NotFound {
                resource: "user".into(),
                id: id.0.to_string(),
            })
    }

    pub async fn get_by_username(&self, username: &str) -> Result<User, ServiceError> {
        self.store
            .get_user_by_username(username)
            .await?
            .ok_or_else(|| ServiceError::NotFound {
                resource: "user".into(),
                id: username.to_string(),
            })
    }

    pub async fn list(&self) -> Result<Vec<User>, ServiceError> {
        Ok(self.store.list_users().await?)
    }

    pub async fn update(&self, user: &User) -> Result<(), ServiceError> {
        if user.username.trim().is_empty() {
            return Err(ServiceError::Validation {
                field: "username".into(),
                message: "username must not be empty".into(),
            });
        }
        // Ensure the user exists
        self.store
            .get_user(&user.id)
            .await?
            .ok_or_else(|| ServiceError::NotFound {
                resource: "user".into(),
                id: user.id.0.to_string(),
            })?;
        self.store.update_user(user).await?;
        Ok(())
    }

    pub async fn delete(&self, id: &UserId) -> Result<(), ServiceError> {
        // Prevent deletion of root user
        if let Some(user) = self.store.get_user(id).await? {
            if user.is_root {
                return Err(ServiceError::Forbidden {
                    reason: "cannot delete the root user".into(),
                });
            }
        }
        let deleted = self.store.delete_user(id).await?;
        if !deleted {
            return Err(ServiceError::NotFound {
                resource: "user".into(),
                id: id.0.to_string(),
            });
        }
        Ok(())
    }
}
