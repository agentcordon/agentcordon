use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::agent::AgentId;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct UserId(pub Uuid);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: UserId,
    pub username: String,
    pub display_name: Option<String>,
    #[serde(skip_serializing)]
    pub password_hash: String,
    pub role: UserRole,
    pub is_root: bool,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl User {
    /// Administrative privilege: the admin role, or the root flag, which
    /// grants it regardless of role. The one definition every "is this an
    /// admin" question in the server goes through.
    pub fn is_admin(&self) -> bool {
        self.is_root || self.role == UserRole::Admin
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UserRole {
    Admin,
    Operator,
    Viewer,
}

#[cfg(test)]
mod is_admin_tests {
    use super::*;

    fn user(role: UserRole, is_root: bool) -> User {
        User {
            id: UserId(Uuid::new_v4()),
            username: "u".to_string(),
            display_name: None,
            password_hash: String::new(),
            role,
            is_root,
            enabled: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn admin_role_or_root_flag_is_admin() {
        assert!(user(UserRole::Admin, false).is_admin());
        assert!(
            user(UserRole::Viewer, true).is_admin(),
            "root outranks role"
        );
        assert!(!user(UserRole::Operator, false).is_admin());
        assert!(!user(UserRole::Viewer, false).is_admin());
    }
}

/// Represents an actor that can be either a User or an Agent.
/// Used in contexts where either identity type may act (audit, ownership).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "id")]
pub enum ActorId {
    User(UserId),
    Agent(AgentId),
}
