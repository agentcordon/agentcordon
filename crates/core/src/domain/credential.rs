use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::agent::AgentId;
use super::user::UserId;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CredentialId(pub Uuid);

/// A credential stored in the vault. The encrypted_value is never exposed directly.
#[derive(Debug, Clone)]
pub struct StoredCredential {
    pub id: CredentialId,
    pub name: String,
    pub service: String,
    pub encrypted_value: Vec<u8>,
    pub nonce: Vec<u8>,
    pub scopes: Vec<String>,
    pub metadata: serde_json::Value,
    /// The agent that created this credential (legacy / agent-created).
    /// NULL when a user created the credential.
    pub created_by: Option<AgentId>,
    /// The user that created this credential.
    /// NULL for agent-created (legacy) credentials.
    pub created_by_user: Option<UserId>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    /// Optional glob pattern restricting which URLs this credential may be used with.
    /// `None` means the credential can be used with any URL (backward-compatible default).
    pub allowed_url_pattern: Option<String>,
    /// Optional expiry date. `None` means the credential never expires (backward-compatible).
    pub expires_at: Option<DateTime<Utc>>,
    /// Optional Rhai script for transforming the decrypted secret before injection.
    pub transform_script: Option<String>,
    /// Optional named built-in transform (e.g., "identity", "basic-auth", "bearer").
    pub transform_name: Option<String>,
    /// Vault grouping. Defaults to "default".
    pub vault: String,
    /// Credential type: "generic" (default), "aws", etc.
    pub credential_type: String,
    /// User-defined tags for categorization and policy matching.
    pub tags: Vec<String>,
    /// Encryption key version. Incremented on each key rotation.
    pub key_version: i64,
}

impl StoredCredential {
    /// Returns `true` if this credential has an expiry date that is in the past.
    pub fn is_expired(&self) -> bool {
        self.expires_at
            .map(|exp| chrono::Utc::now() > exp)
            .unwrap_or(false)
    }
}

/// Public view of a credential -- no secret material.
#[derive(Debug, Clone, Serialize)]
pub struct CredentialSummary {
    pub id: CredentialId,
    pub name: String,
    pub service: String,
    pub scopes: Vec<String>,
    pub metadata: serde_json::Value,
    /// The agent that created this credential (legacy / agent-created).
    pub created_by: Option<AgentId>,
    /// The user that created this credential.
    pub created_by_user: Option<UserId>,
    pub created_at: DateTime<Utc>,
    /// Optional glob pattern restricting which URLs this credential may be used with.
    pub allowed_url_pattern: Option<String>,
    /// Optional expiry date. `None` means the credential never expires.
    pub expires_at: Option<DateTime<Utc>>,
    /// `true` if this credential has expired.
    pub expired: bool,
    /// Optional Rhai script for transforming the decrypted secret before injection.
    pub transform_script: Option<String>,
    /// Optional named built-in transform (e.g., "identity", "basic-auth", "bearer").
    pub transform_name: Option<String>,
    /// Vault grouping. Defaults to "default".
    pub vault: String,
    /// Credential type: "generic" (default), "aws", "oauth2_client_credentials", etc.
    pub credential_type: String,
    /// User-defined tags for categorization and policy matching.
    pub tags: Vec<String>,
    /// Resolved owner username (populated at response time, not stored).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner_username: Option<String>,
}

impl From<StoredCredential> for CredentialSummary {
    fn from(cred: StoredCredential) -> Self {
        let expired = cred.is_expired();
        CredentialSummary {
            id: cred.id,
            name: cred.name,
            service: cred.service,
            scopes: cred.scopes,
            metadata: cred.metadata,
            created_by: cred.created_by,
            created_by_user: cred.created_by_user,
            created_at: cred.created_at,
            allowed_url_pattern: cred.allowed_url_pattern,
            expires_at: cred.expires_at,
            expired,
            transform_script: cred.transform_script,
            transform_name: cred.transform_name,
            vault: cred.vault,
            credential_type: cred.credential_type,
            tags: cred.tags,
            owner_username: None,
        }
    }
}

/// Partial update struct for credentials. Only non-None fields are applied.
#[derive(Debug, Clone, Deserialize)]
pub struct CredentialUpdate {
    pub name: Option<String>,
    pub service: Option<String>,
    pub scopes: Option<Vec<String>>,
    pub metadata: Option<serde_json::Value>,
    pub allowed_url_pattern: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub transform_script: Option<String>,
    pub transform_name: Option<String>,
    pub vault: Option<String>,
    /// Optional tags update. When provided, replaces the existing tags entirely.
    pub tags: Option<Vec<String>>,
    /// New encrypted secret value (set by the route handler after encrypting).
    #[serde(skip)]
    pub encrypted_value: Option<Vec<u8>>,
    /// New nonce for the encrypted secret value.
    #[serde(skip)]
    pub nonce: Option<Vec<u8>>,
    /// New key version (set during encryption key rotation).
    #[serde(skip)]
    pub key_version: Option<i64>,
}

/// A record of a historical secret value (without the actual encrypted value).
#[derive(Debug, Clone, Serialize)]
pub struct SecretHistoryEntry {
    pub id: Uuid,
    pub credential_id: Uuid,
    pub changed_at: DateTime<Utc>,
    pub changed_by_user: Option<String>,
    pub changed_by_agent: Option<String>,
}

/// A per-credential permission grant for a specific agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialPermission {
    pub credential_id: CredentialId,
    pub agent_id: AgentId,
    pub permission: String, // "read" | "write" | "delete" | "delegated_use"
    /// The agent that granted this permission (None when a user granted it).
    pub granted_by: Option<AgentId>,
    /// The user that granted this permission (None when an agent granted it).
    pub granted_by_user: Option<UserId>,
    pub granted_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;
    use serde_json::json;

    /// Helper: build a StoredCredential with the given expires_at.
    fn make_stored(expires_at: Option<DateTime<Utc>>) -> StoredCredential {
        StoredCredential {
            id: CredentialId(Uuid::new_v4()),
            name: "test-cred".to_string(),
            service: "test-svc".to_string(),
            encrypted_value: vec![1, 2, 3],
            nonce: vec![4, 5, 6],
            scopes: vec!["read".to_string()],
            metadata: json!({}),
            created_by: None,
            created_by_user: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            allowed_url_pattern: None,
            expires_at,
            transform_script: None,
            transform_name: None,
            vault: "default".to_string(),
            credential_type: "generic".to_string(),
            tags: vec!["test".to_string()],
            key_version: 1,
        }
    }

    #[test]
    fn test_from_stored_not_expired() {
        let future = Utc::now() + Duration::hours(24);
        let stored = make_stored(Some(future));
        let summary = CredentialSummary::from(stored.clone());

        assert!(
            !summary.expired,
            "credential with future expiry should not be expired"
        );
        assert_eq!(summary.id, stored.id);
        assert_eq!(summary.name, "test-cred");
        assert_eq!(summary.service, "test-svc");
    }

    #[test]
    fn test_from_stored_expired() {
        let past = Utc::now() - Duration::hours(24);
        let stored = make_stored(Some(past));
        let summary = CredentialSummary::from(stored);

        assert!(
            summary.expired,
            "credential with past expiry should be expired"
        );
    }

    #[test]
    fn test_from_stored_no_expiry() {
        let stored = make_stored(None);
        let summary = CredentialSummary::from(stored);

        assert!(
            !summary.expired,
            "credential with no expiry should not be expired"
        );
        assert_eq!(summary.expires_at, None);
    }

    #[test]
    fn test_from_stored_owner_is_none() {
        let stored = make_stored(None);
        let summary = CredentialSummary::from(stored);

        assert_eq!(
            summary.owner_username, None,
            "From impl should set owner_username to None (populated later by enrich_owner_usernames)"
        );
    }
}
