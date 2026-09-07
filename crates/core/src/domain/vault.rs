//! Vaults: named groups of credentials, owned by a user.
//!
//! A vault is a row, not a string. Two users may each call a vault `team`
//! without sharing anything: the id is the identity, the name is a label,
//! and neither is unique on its own. One vault is special — the system
//! default, which has a fixed id, no owner, and takes any credential whose
//! creator named no vault. It cannot be renamed, shared or deleted.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::user::UserId;

/// The id of the one system default vault. Fixed so that every install
/// names the same row, and reserved so nothing else can claim it.
pub const DEFAULT_VAULT_ID: &str = "00000000-0000-0000-0000-000000000001";

/// The display name the system default vault is created with.
pub const DEFAULT_VAULT_NAME: &str = "default";

/// A vault: an id, a display name, and the user who owns it.
///
/// `name` carries no uniqueness constraint. A user with two vaults called
/// `team` is their own business; the id tells them apart.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vault {
    pub id: String,
    pub name: String,
    /// The owner, or `None` for the system default vault.
    pub owner_user_id: Option<UserId>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Vault {
    /// `true` for the one vault every user may put a credential in and no
    /// user may rename, share or delete.
    pub fn is_default(&self) -> bool {
        self.id == DEFAULT_VAULT_ID
    }

    /// `true` when `user` owns this vault outright.
    pub fn is_owned_by(&self, user: &UserId) -> bool {
        self.owner_user_id.as_ref() == Some(user)
    }
}

/// Represents a vault share — granting another user access to a vault.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultShare {
    pub id: String,
    pub vault_id: String,
    pub shared_with_user_id: UserId,
    pub permission_level: String, // "read" (the only level until the authorization rework)
    pub shared_by_user_id: UserId,
    pub created_at: DateTime<Utc>,
}
