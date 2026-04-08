use std::sync::{Arc, OnceLock};

use crate::crypto::password::{hash_password, verify_password_async};
use crate::domain::user::User;
use crate::error::{AuthError, LoginFailureReason};
use crate::storage::Store;

/// A dummy hash generated with the real Argon2 parameters at startup.
/// Using a hash with matching params ensures timing-safe user enumeration
/// protection — the verify step takes the same time whether the user exists
/// or not. A hardcoded hash with different params would create a measurable
/// timing side-channel.
fn dummy_hash() -> &'static str {
    static HASH: OnceLock<String> = OnceLock::new();
    HASH.get_or_init(|| {
        hash_password("__dummy_timing_equalization__").expect("dummy hash generation must succeed")
    })
}

/// Authenticates a user by username + password.
///
/// Timing-safe: always performs a password verification even when the user is
/// not found, to prevent user-enumeration via timing side-channels.
pub struct PasswordAuthenticator<S: Store + ?Sized> {
    store: Arc<S>,
}

impl<S: Store + ?Sized> PasswordAuthenticator<S> {
    pub fn new(store: Arc<S>) -> Self {
        Self { store }
    }

    /// Authenticate a user by username and password.
    ///
    /// Returns the `User` on success or `AuthError::Unauthorized` on failure.
    /// The error message is intentionally vague to avoid leaking whether the
    /// username exists.
    pub async fn authenticate(&self, username: &str, password: &str) -> Result<User, AuthError> {
        let user_opt = self
            .store
            .get_user_by_username(username)
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;

        match user_opt {
            Some(user) => {
                let matches = verify_password_async(password, &user.password_hash)
                    .await
                    .map_err(|e| AuthError::Internal(e.to_string()))?;

                if !matches {
                    return Err(AuthError::LoginFailed(LoginFailureReason::InvalidPassword));
                }

                if !user.enabled {
                    // Intentionally vague to the caller: do NOT reveal that the
                    // account exists but is disabled — that would be an
                    // enumeration vector. The `LoginFailureReason` is only used
                    // for internal audit logging.
                    return Err(AuthError::LoginFailed(LoginFailureReason::UserDisabled));
                }

                Ok(user)
            }
            None => {
                // Timing-safe: verify against a dummy hash generated with the
                // real Argon2 production params. This ensures the user-not-found
                // path takes the same time as the wrong-password path, preventing
                // timing-based user enumeration.
                let _ = verify_password_async(password, dummy_hash()).await;

                Err(AuthError::LoginFailed(LoginFailureReason::UserNotFound))
            }
        }
    }
}

#[cfg(all(test, feature = "sqlite"))]
mod tests {
    use super::*;
    use crate::crypto::password::hash_password;
    use crate::domain::user::{User, UserId, UserRole};
    use crate::error::LoginFailureReason;
    use crate::storage::sqlite::SqliteStore;
    use chrono::Utc;
    use std::sync::Arc;
    use uuid::Uuid;

    async fn setup() -> (Arc<SqliteStore>, User) {
        let store = SqliteStore::new_in_memory()
            .await
            .expect("create in-memory store");
        store.run_migrations().await.expect("run migrations");
        let store = Arc::new(store);

        let password = "test-password-123";
        let password_hash = hash_password(password).expect("hash password");
        let now = Utc::now();
        let user = User {
            id: UserId(Uuid::new_v4()),
            username: "testuser".to_string(),
            display_name: Some("Test User".to_string()),
            password_hash,
            role: UserRole::Admin,
            is_root: false,
            enabled: true,
            created_at: now,
            updated_at: now,
        };

        store.create_user(&user).await.expect("create user");

        (store, user)
    }

    #[tokio::test]
    async fn authenticate_with_valid_credentials() {
        let (store, user) = setup().await;
        let auth = PasswordAuthenticator::new(store);

        let result = auth.authenticate("testuser", "test-password-123").await;
        assert!(result.is_ok());
        let authenticated_user = result.unwrap();
        assert_eq!(authenticated_user.id, user.id);
        assert_eq!(authenticated_user.username, "testuser");
    }

    #[tokio::test]
    async fn authenticate_with_wrong_password() {
        let (store, _user) = setup().await;
        let auth = PasswordAuthenticator::new(store);

        let result = auth.authenticate("testuser", "wrong-password").await;
        assert!(result.is_err());
        match result.unwrap_err() {
            AuthError::LoginFailed(reason) => {
                assert_eq!(reason, LoginFailureReason::InvalidPassword);
            }
            other => panic!("expected LoginFailed(InvalidPassword), got {:?}", other),
        }
    }

    #[tokio::test]
    async fn authenticate_nonexistent_user() {
        let (store, _user) = setup().await;
        let auth = PasswordAuthenticator::new(store);

        let result = auth.authenticate("nouser", "any-password").await;
        assert!(result.is_err());
        match result.unwrap_err() {
            AuthError::LoginFailed(reason) => {
                assert_eq!(reason, LoginFailureReason::UserNotFound);
            }
            other => panic!("expected LoginFailed(UserNotFound), got {:?}", other),
        }
    }

    #[tokio::test]
    async fn authenticate_disabled_user_rejected() {
        let store = SqliteStore::new_in_memory()
            .await
            .expect("create in-memory store");
        store.run_migrations().await.expect("run migrations");
        let store = Arc::new(store);

        let password = "test-password-123";
        let password_hash = hash_password(password).expect("hash password");
        let now = Utc::now();
        let user = User {
            id: UserId(Uuid::new_v4()),
            username: "disabled-user".to_string(),
            display_name: None,
            password_hash,
            role: UserRole::Viewer,
            is_root: false,
            enabled: false,
            created_at: now,
            updated_at: now,
        };
        store.create_user(&user).await.expect("create user");

        let auth = PasswordAuthenticator::new(store);
        let result = auth
            .authenticate("disabled-user", "test-password-123")
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            AuthError::LoginFailed(reason) => {
                // Internally we know it's UserDisabled, but the Display message
                // shown to the client is still generic ("invalid username or
                // password") to prevent enumeration.
                assert_eq!(reason, LoginFailureReason::UserDisabled);
            }
            other => panic!("expected LoginFailed(UserDisabled), got {:?}", other),
        }
    }
}
