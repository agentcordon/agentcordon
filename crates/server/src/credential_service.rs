//! Shared credential creation logic.
//!
//! Provides reusable building blocks for credential creation that are shared
//! between `create.rs` (admin/user-initiated) and `agent_store.rs`
//! (workspace-initiated). Handlers resolve their own input-specific validation
//! (AWS fields, OAuth2, conflict handling) then call into this module for the
//! common operations: type validation, encryption, StoredCredential
//! construction, and UI event emission.

use chrono::{DateTime, Utc};
use uuid::Uuid;

use agent_cordon_core::crypto::SecretEncryptor;
use agent_cordon_core::domain::credential::{CredentialId, StoredCredential};
use agent_cordon_core::domain::user::UserId;
use agent_cordon_core::domain::workspace::WorkspaceId;

use crate::events::UiEvent;
use crate::response::ApiError;
use crate::routes::admin_api::credentials::KNOWN_CREDENTIAL_TYPES;
use crate::state::AppState;

/// Validate a credential type string against known types.
pub fn validate_credential_type(credential_type: &str) -> Result<(), ApiError> {
    if !KNOWN_CREDENTIAL_TYPES.contains(&credential_type) {
        return Err(ApiError::BadRequest(format!(
            "unknown credential_type '{}': valid types are {}",
            credential_type,
            KNOWN_CREDENTIAL_TYPES.join(", ")
        )));
    }
    Ok(())
}

/// Encrypt a secret value using the credential ID as additional authenticated data.
pub fn encrypt_secret(
    encryptor: &dyn SecretEncryptor,
    secret: &str,
    cred_id: &CredentialId,
) -> Result<(Vec<u8>, Vec<u8>), ApiError> {
    Ok(encryptor.encrypt(secret.as_bytes(), cred_id.0.to_string().as_bytes())?)
}

/// Parameters for building a new `StoredCredential`.
pub struct NewCredentialParams {
    pub name: String,
    pub service: String,
    pub secret_value: String,
    pub credential_type: String,
    pub scopes: Vec<String>,
    pub metadata: serde_json::Value,
    pub tags: Vec<String>,
    pub vault: String,
    pub created_by: Option<WorkspaceId>,
    pub created_by_user: Option<UserId>,
    pub allowed_url_pattern: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub transform_script: Option<String>,
    pub transform_name: Option<String>,
}

/// Strip common auth scheme prefixes (`Bearer `, `token `, `Basic `) from a
/// secret value. Users frequently paste the full header value; the transform
/// layer adds the prefix back, so storing it causes double-wrapping
/// (e.g. `"Bearer Bearer ghp_..."` → 401).
///
/// Only applies to credential types where a transform adds the prefix
/// automatically (i.e. not `aws` or `oauth2_client_credentials`).
pub fn strip_auth_prefix(value: &str) -> String {
    let trimmed = value.trim();
    for prefix in &["Bearer ", "bearer ", "token ", "Token ", "Basic ", "basic "] {
        if let Some(rest) = trimmed.strip_prefix(prefix) {
            let rest = rest.trim();
            if !rest.is_empty() {
                return rest.to_string();
            }
        }
    }
    trimmed.to_string()
}

/// Build a `StoredCredential` from parameters.
///
/// Generates a new credential ID, encrypts the secret value using the ID as
/// AAD, and returns the fully constructed `StoredCredential` ready for storage.
///
/// For non-AWS/non-OAuth2 credential types, automatically strips common auth
/// prefixes from the secret value to prevent double-wrapping.
pub fn build_credential(
    encryptor: &dyn SecretEncryptor,
    params: NewCredentialParams,
) -> Result<StoredCredential, ApiError> {
    let cred_id = CredentialId(Uuid::new_v4());

    // Strip auth prefixes for types where the transform adds them back.
    let secret_value = match params.credential_type.as_str() {
        "aws" | "oauth2_client_credentials" => params.secret_value.clone(),
        _ => strip_auth_prefix(&params.secret_value),
    };

    let (encrypted_value, nonce) = encrypt_secret(encryptor, &secret_value, &cred_id)?;
    let now = Utc::now();

    Ok(StoredCredential {
        id: cred_id,
        name: params.name,
        service: params.service,
        encrypted_value,
        nonce,
        scopes: params.scopes,
        metadata: params.metadata,
        created_by: params.created_by,
        created_by_user: params.created_by_user,
        created_at: now,
        updated_at: now,
        allowed_url_pattern: params.allowed_url_pattern,
        expires_at: params.expires_at,
        transform_script: params.transform_script,
        transform_name: params.transform_name,
        vault: params.vault,
        credential_type: params.credential_type,
        tags: params.tags,
        key_version: 1,
    })
}

/// Emit a `CredentialCreated` UI event for browser auto-refresh.
pub fn emit_credential_created(state: &AppState, cred_id: Uuid, cred_name: String) {
    state.ui_event_bus.emit(UiEvent::CredentialCreated {
        credential_id: cred_id,
        credential_name: cred_name,
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_bearer_prefix() {
        assert_eq!(strip_auth_prefix("Bearer ghp_abc123"), "ghp_abc123");
    }

    #[test]
    fn strip_bearer_lowercase() {
        assert_eq!(strip_auth_prefix("bearer ghp_abc123"), "ghp_abc123");
    }

    #[test]
    fn strip_token_prefix() {
        assert_eq!(strip_auth_prefix("token ghp_abc123"), "ghp_abc123");
    }

    #[test]
    fn strip_basic_prefix() {
        assert_eq!(strip_auth_prefix("Basic dXNlcjpwYXNz"), "dXNlcjpwYXNz");
    }

    #[test]
    fn no_prefix_unchanged() {
        assert_eq!(strip_auth_prefix("ghp_abc123"), "ghp_abc123");
    }

    #[test]
    fn whitespace_trimmed() {
        assert_eq!(strip_auth_prefix("  Bearer ghp_abc123  "), "ghp_abc123");
    }

    #[test]
    fn bearer_only_returns_unchanged() {
        // "Bearer " with nothing after it should return "Bearer" trimmed
        assert_eq!(strip_auth_prefix("Bearer "), "Bearer");
    }
}
