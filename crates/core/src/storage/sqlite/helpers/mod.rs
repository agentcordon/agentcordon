mod extended;
pub(crate) use extended::*;

use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::domain::credential::{CredentialId, CredentialSummary, StoredCredential};
use crate::domain::enrollment::{EnrollmentSession, EnrollmentSessionStatus};
use crate::domain::policy::{PolicyId, StoredPolicy};
use crate::domain::session::Session;
use crate::domain::user::{User, UserId};
use crate::domain::vault::VaultShare;
use crate::domain::workspace::WorkspaceId;
use crate::error::StoreError;

// ---------------------------------------------------------------------------
// Re-export shared serialization helpers (used by both SQLite and Postgres)
// ---------------------------------------------------------------------------

pub(crate) use crate::storage::shared::{
    deserialize_decision, deserialize_enrollment_status as deserialize_enrollment_session_status,
    deserialize_event_type, deserialize_user_role, serialize_decision,
    serialize_enrollment_status as serialize_enrollment_session_status_shared,
    serialize_event_type, serialize_metadata, serialize_scopes, serialize_tags,
    serialize_user_role,
};

/// Wrapper for enrollment status serialization that returns String (backwards compat with callers).
pub(crate) fn serialize_enrollment_session_status(s: &EnrollmentSessionStatus) -> String {
    serialize_enrollment_session_status_shared(s).to_string()
}

// ---------------------------------------------------------------------------
// SQLite-specific row mapping functions (below)
// These cannot be shared because SQLite uses rusqlite::Row with string-encoded
// UUIDs/dates, while Postgres uses sqlx::FromRow with native types.
// ---------------------------------------------------------------------------

pub(crate) fn row_to_enrollment_session(
    row: &rusqlite::Row<'_>,
) -> Result<EnrollmentSession, rusqlite::Error> {
    let id_str: String = row.get(0)?;
    let session_token_hash: String = row.get(1)?;
    let approval_ref: String = row.get(2)?;
    let approval_code: String = row.get(3)?;
    let agent_name: String = row.get(4)?;
    let agent_description: Option<String> = row.get(5)?;
    let agent_tags_json: String = row.get(6)?;
    let status_str: String = row.get(7)?;
    let created_at_str: String = row.get(8)?;
    let expires_at_str: String = row.get(9)?;
    let approved_by: Option<String> = row.get(10)?;
    let approved_at_str: Option<String> = row.get(11)?;
    let claimed_at_str: Option<String> = row.get(12)?;
    let client_ip: Option<String> = row.get(13)?;
    let claim_attempts: u32 = row.get(14)?;
    let workspace_id_str: Option<String> = row.get(15)?;

    let id = Uuid::parse_str(&id_str).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e))
    })?;
    let agent_tags: Vec<String> = serde_json::from_str(&agent_tags_json).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(6, rusqlite::types::Type::Text, Box::new(e))
    })?;
    let status = deserialize_enrollment_session_status(&status_str).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(
            7,
            rusqlite::types::Type::Text,
            Box::new(StoreErrorWrapper(e)),
        )
    })?;
    let created_at = DateTime::parse_from_rfc3339(&created_at_str)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(8, rusqlite::types::Type::Text, Box::new(e))
        })?;
    let expires_at = DateTime::parse_from_rfc3339(&expires_at_str)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(9, rusqlite::types::Type::Text, Box::new(e))
        })?;
    let approved_at = approved_at_str
        .and_then(|s| DateTime::parse_from_rfc3339(&s).ok())
        .map(|dt| dt.with_timezone(&Utc));
    let claimed_at = claimed_at_str
        .and_then(|s| DateTime::parse_from_rfc3339(&s).ok())
        .map(|dt| dt.with_timezone(&Utc));
    let workspace_id = workspace_id_str
        .map(|s| Uuid::parse_str(&s).map(WorkspaceId))
        .transpose()
        .map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(15, rusqlite::types::Type::Text, Box::new(e))
        })?;

    Ok(EnrollmentSession {
        id,
        session_token_hash,
        approval_ref,
        approval_code,
        agent_name,
        agent_description,
        agent_tags,
        status,
        created_at,
        expires_at,
        approved_by,
        approved_at,
        claimed_at,
        client_ip,
        claim_attempts,
        workspace_id,
    })
}

/// Wrapper to make StoreError implement std::error::Error for rusqlite conversion.
#[derive(Debug)]
pub(crate) struct StoreErrorWrapper(pub(crate) StoreError);

impl std::fmt::Display for StoreErrorWrapper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

impl std::error::Error for StoreErrorWrapper {}

pub(crate) fn row_to_stored_credential(
    row: &rusqlite::Row<'_>,
) -> Result<StoredCredential, rusqlite::Error> {
    let id_str: String = row.get(0)?;
    let name: String = row.get(1)?;
    let service: String = row.get(2)?;
    let encrypted_value: Vec<u8> = row.get(3)?;
    let nonce: Vec<u8> = row.get(4)?;
    let scopes_json: String = row.get(5)?;
    let metadata_json: String = row.get(6)?;
    let created_by_str: Option<String> = row.get(7)?;
    let created_at_str: String = row.get(8)?;
    let updated_at_str: String = row.get(9)?;
    let allowed_url_pattern: Option<String> = row.get(10)?;
    let created_by_user_str: Option<String> = row.get(11)?;
    let expires_at_str: Option<String> = row.get(12)?;
    let transform_script: Option<String> = row.get(13)?;
    let transform_name: Option<String> = row.get(14)?;
    let vault: String = row.get(15)?;
    let credential_type: String = row.get(16)?;
    let tags_json: String = row.get(17)?;
    let key_version: i64 = row.get(18)?;

    let id = Uuid::parse_str(&id_str).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e))
    })?;
    let scopes: Vec<String> = serde_json::from_str(&scopes_json).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(5, rusqlite::types::Type::Text, Box::new(e))
    })?;
    let metadata: serde_json::Value = serde_json::from_str(&metadata_json).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(6, rusqlite::types::Type::Text, Box::new(e))
    })?;
    let tags: Vec<String> = serde_json::from_str(&tags_json).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(17, rusqlite::types::Type::Text, Box::new(e))
    })?;
    let created_by = created_by_str
        .map(|s| Uuid::parse_str(&s).map(WorkspaceId))
        .transpose()
        .map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(7, rusqlite::types::Type::Text, Box::new(e))
        })?;
    let created_by_user = created_by_user_str
        .map(|s| Uuid::parse_str(&s).map(UserId))
        .transpose()
        .map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(11, rusqlite::types::Type::Text, Box::new(e))
        })?;
    let created_at = DateTime::parse_from_rfc3339(&created_at_str)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(8, rusqlite::types::Type::Text, Box::new(e))
        })?;
    let updated_at = DateTime::parse_from_rfc3339(&updated_at_str)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(9, rusqlite::types::Type::Text, Box::new(e))
        })?;
    let expires_at = expires_at_str
        .map(|s| DateTime::parse_from_rfc3339(&s).map(|dt| dt.with_timezone(&Utc)))
        .transpose()
        .map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(12, rusqlite::types::Type::Text, Box::new(e))
        })?;

    Ok(StoredCredential {
        id: CredentialId(id),
        name,
        service,
        encrypted_value,
        nonce,
        scopes,
        metadata,
        created_by,
        created_by_user,
        created_at,
        updated_at,
        allowed_url_pattern,
        expires_at,
        transform_script,
        transform_name,
        vault,
        credential_type,
        tags,
        key_version,
    })
}

pub(crate) fn row_to_credential_summary(
    row: &rusqlite::Row<'_>,
) -> Result<CredentialSummary, rusqlite::Error> {
    let id_str: String = row.get(0)?;
    let name: String = row.get(1)?;
    let service: String = row.get(2)?;
    let scopes_json: String = row.get(3)?;
    let metadata_json: String = row.get(4)?;
    let created_by_str: Option<String> = row.get(5)?;
    let created_at_str: String = row.get(6)?;
    let allowed_url_pattern: Option<String> = row.get(7)?;
    let created_by_user_str: Option<String> = row.get(8)?;
    let expires_at_str: Option<String> = row.get(9)?;
    let transform_script: Option<String> = row.get(10)?;
    let transform_name: Option<String> = row.get(11)?;
    let vault: String = row.get(12)?;
    let credential_type: String = row.get(13)?;
    let tags_json: String = row.get(14)?;

    let id = Uuid::parse_str(&id_str).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e))
    })?;
    let scopes: Vec<String> = serde_json::from_str(&scopes_json).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(3, rusqlite::types::Type::Text, Box::new(e))
    })?;
    let metadata: serde_json::Value = serde_json::from_str(&metadata_json).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(4, rusqlite::types::Type::Text, Box::new(e))
    })?;
    let tags: Vec<String> = serde_json::from_str(&tags_json).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(14, rusqlite::types::Type::Text, Box::new(e))
    })?;
    let created_by = created_by_str
        .map(|s| Uuid::parse_str(&s).map(WorkspaceId))
        .transpose()
        .map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(5, rusqlite::types::Type::Text, Box::new(e))
        })?;
    let created_by_user = created_by_user_str
        .map(|s| Uuid::parse_str(&s).map(UserId))
        .transpose()
        .map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(8, rusqlite::types::Type::Text, Box::new(e))
        })?;
    let created_at = DateTime::parse_from_rfc3339(&created_at_str)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(6, rusqlite::types::Type::Text, Box::new(e))
        })?;
    let expires_at = expires_at_str
        .map(|s| DateTime::parse_from_rfc3339(&s).map(|dt| dt.with_timezone(&Utc)))
        .transpose()
        .map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(9, rusqlite::types::Type::Text, Box::new(e))
        })?;
    let expired = expires_at
        .map(|exp| chrono::Utc::now() > exp)
        .unwrap_or(false);

    Ok(CredentialSummary {
        id: CredentialId(id),
        name,
        service,
        scopes,
        metadata,
        created_by,
        created_by_user,
        created_at,
        allowed_url_pattern,
        expires_at,
        expired,
        transform_script,
        transform_name,
        vault,
        credential_type,
        tags,
        owner_username: None, // Populated at the route layer
    })
}

pub(crate) fn row_to_vault_share(row: &rusqlite::Row<'_>) -> Result<VaultShare, rusqlite::Error> {
    let id: String = row.get(0)?;
    let vault_name: String = row.get(1)?;
    let shared_with_str: String = row.get(2)?;
    let permission_level: String = row.get(3)?;
    let shared_by_str: String = row.get(4)?;
    let created_at_str: String = row.get(5)?;

    let shared_with_user_id = Uuid::parse_str(&shared_with_str).map(UserId).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(2, rusqlite::types::Type::Text, Box::new(e))
    })?;
    let shared_by_user_id = Uuid::parse_str(&shared_by_str).map(UserId).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(4, rusqlite::types::Type::Text, Box::new(e))
    })?;
    let created_at = DateTime::parse_from_rfc3339(&created_at_str)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(5, rusqlite::types::Type::Text, Box::new(e))
        })?;

    Ok(VaultShare {
        id,
        vault_name,
        shared_with_user_id,
        permission_level,
        shared_by_user_id,
        created_at,
    })
}

pub(crate) fn row_to_stored_policy(
    row: &rusqlite::Row<'_>,
) -> Result<StoredPolicy, rusqlite::Error> {
    let id_str: String = row.get(0)?;
    let name: String = row.get(1)?;
    let description: Option<String> = row.get(2)?;
    let cedar_policy: String = row.get(3)?;
    let enabled: bool = row.get(4)?;
    let created_at_str: String = row.get(5)?;
    let updated_at_str: String = row.get(6)?;
    let is_system: bool = row.get(7).unwrap_or(false);

    let id = Uuid::parse_str(&id_str).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e))
    })?;
    let created_at = DateTime::parse_from_rfc3339(&created_at_str)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(5, rusqlite::types::Type::Text, Box::new(e))
        })?;
    let updated_at = DateTime::parse_from_rfc3339(&updated_at_str)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(6, rusqlite::types::Type::Text, Box::new(e))
        })?;

    Ok(StoredPolicy {
        id: PolicyId(id),
        name,
        description,
        cedar_policy,
        enabled,
        is_system,
        created_at,
        updated_at,
    })
}

pub(crate) fn row_to_user(row: &rusqlite::Row<'_>) -> Result<User, rusqlite::Error> {
    let id_str: String = row.get(0)?;
    let username: String = row.get(1)?;
    let display_name: Option<String> = row.get(2)?;
    let password_hash: String = row.get(3)?;
    let role_str: String = row.get(4)?;
    let is_root: bool = row.get(5)?;
    let enabled: bool = row.get(6)?;
    let created_at_str: String = row.get(7)?;
    let updated_at_str: String = row.get(8)?;
    let show_advanced: bool = row.get(9).unwrap_or(false);

    let id = Uuid::parse_str(&id_str).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e))
    })?;
    let role = deserialize_user_role(&role_str).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(4, rusqlite::types::Type::Text, Box::new(e))
    })?;
    let created_at = DateTime::parse_from_rfc3339(&created_at_str)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(7, rusqlite::types::Type::Text, Box::new(e))
        })?;
    let updated_at = DateTime::parse_from_rfc3339(&updated_at_str)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(8, rusqlite::types::Type::Text, Box::new(e))
        })?;

    Ok(User {
        id: UserId(id),
        username,
        display_name,
        password_hash,
        role,
        is_root,
        enabled,
        show_advanced,
        created_at,
        updated_at,
    })
}

pub(crate) fn row_to_session(row: &rusqlite::Row<'_>) -> Result<Session, rusqlite::Error> {
    let id: String = row.get(0)?;
    let user_id_str: String = row.get(1)?;
    let created_at_str: String = row.get(2)?;
    let expires_at_str: String = row.get(3)?;
    let last_seen_at_str: String = row.get(4)?;

    let user_id = Uuid::parse_str(&user_id_str).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(1, rusqlite::types::Type::Text, Box::new(e))
    })?;
    let created_at = DateTime::parse_from_rfc3339(&created_at_str)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(2, rusqlite::types::Type::Text, Box::new(e))
        })?;
    let expires_at = DateTime::parse_from_rfc3339(&expires_at_str)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(3, rusqlite::types::Type::Text, Box::new(e))
        })?;
    let last_seen_at = DateTime::parse_from_rfc3339(&last_seen_at_str)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(4, rusqlite::types::Type::Text, Box::new(e))
        })?;

    Ok(Session {
        id,
        user_id: UserId(user_id),
        created_at,
        expires_at,
        last_seen_at,
    })
}
