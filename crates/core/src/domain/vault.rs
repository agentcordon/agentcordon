use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::user::UserId;

/// Represents a vault share — granting another user access to a vault.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultShare {
    pub id: String,
    pub vault_name: String,
    pub shared_with_user_id: UserId,
    pub permission_level: String, // "read", "write", "admin"
    pub shared_by_user_id: UserId,
    pub created_at: DateTime<Utc>,
}
