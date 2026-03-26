use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::user::UserId;

/// A user session. The `id` field stores a hash of the session token,
/// not the raw token itself. The raw token is given to the client as
/// a cookie. This way, a database compromise does not immediately
/// yield valid sessions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    /// SHA-256 hash of the session token (hex-encoded).
    pub id: String,
    pub user_id: UserId,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub last_seen_at: DateTime<Utc>,
}
