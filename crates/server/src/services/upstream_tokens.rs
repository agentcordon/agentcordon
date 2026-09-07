//! Upstream OAuth2 access tokens for OAuth-backed credentials.
//!
//! An `oauth2_user_authorization` credential stores a provider refresh
//! token; an `oauth2_client_credentials` credential stores a client secret.
//! Neither leaves the server. When a broker needs to call the provider
//! (MCP sync, vend), the credential service runs the exchange here with the
//! shared [`OAuth2TokenManager`](agent_cordon_core::oauth2::OAuth2TokenManager)
//! and hands back a short-lived access token with its expiry, which is what
//! gets sealed into the ECIES envelope.
//!
//! A rotated refresh token (RFC 6749 §6) is persisted on the credential
//! right here, with the secret-history row and audit event that every
//! secret rotation gets.

use chrono::{DateTime, Utc};

use agent_cordon_core::crypto::SecretEncryptor;
use agent_cordon_core::domain::audit::{AuditDecision, AuditEvent, AuditEventType};
use agent_cordon_core::domain::credential::{CredentialUpdate, StoredCredential};
use agent_cordon_core::domain::workspace::WorkspaceId;
use agent_cordon_core::oauth2::{OAuth2Error, OAuth2Grant, OAuth2TokenRequest};

use crate::response::ApiError;

use super::credentials::{self, CredentialService};
use super::write_audit;

/// Credential types whose stored secret is exchanged for an access token
/// rather than sent as-is.
pub fn is_upstream_oauth(credential_type: &str) -> bool {
    matches!(
        credential_type,
        "oauth2_user_authorization" | "oauth2_client_credentials"
    )
}

/// A short-lived upstream access token.
pub struct UpstreamAccessToken {
    pub access_token: String,
    pub expires_at: DateTime<Utc>,
}

impl UpstreamAccessToken {
    /// The envelope plaintext for this token: what a broker receives.
    pub fn material(&self) -> serde_json::Value {
        serde_json::json!({
            "value": self.access_token,
            "expires_at": self.expires_at.to_rfc3339(),
        })
    }
}

/// Why no access token could be produced. `Display` never includes a
/// secret or a provider response body.
#[derive(Debug, thiserror::Error)]
pub enum UpstreamTokenError {
    #[error("credential '{name}' is of type '{credential_type}', not an upstream OAuth2 type")]
    NotOAuth {
        name: String,
        credential_type: String,
    },
    #[error("credential '{name}' has no {field}")]
    MissingMetadata { name: String, field: &'static str },
    #[error("credential '{name}': stored secret could not be opened")]
    Decrypt { name: String },
    #[error("credential '{name}': upstream token exchange failed: {source}")]
    Exchange {
        name: String,
        #[source]
        source: OAuth2Error,
    },
    #[error("credential '{name}': rotated refresh token could not be persisted")]
    Persist { name: String },
}

impl From<UpstreamTokenError> for ApiError {
    fn from(e: UpstreamTokenError) -> Self {
        match e {
            UpstreamTokenError::Exchange { .. } => ApiError::BadGateway(e.to_string()),
            other => ApiError::Internal(other.to_string()),
        }
    }
}

/// Who asked, for the audit row a refresh-token rotation writes.
pub struct TokenActor<'a> {
    pub workspace_id: &'a WorkspaceId,
    pub workspace_name: &'a str,
}

/// Obtain an access token for an OAuth-backed credential, exchanging on a
/// cache miss and persisting any rotated refresh token.
pub async fn access_token_for(
    svc: &CredentialService,
    cred: &StoredCredential,
    actor: TokenActor<'_>,
) -> Result<UpstreamAccessToken, UpstreamTokenError> {
    match cred.credential_type.as_str() {
        "oauth2_client_credentials" => client_credentials_token(svc, cred).await,
        "oauth2_user_authorization" => refresh_grant_token(svc, cred, actor).await,
        _ => Err(UpstreamTokenError::NotOAuth {
            name: cred.name.clone(),
            credential_type: cred.credential_type.clone(),
        }),
    }
}

fn metadata_str<'a>(
    cred: &'a StoredCredential,
    field: &'static str,
) -> Result<&'a str, UpstreamTokenError> {
    cred.metadata
        .get(field)
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| UpstreamTokenError::MissingMetadata {
            name: cred.name.clone(),
            field,
        })
}

fn stored_secret(
    svc: &CredentialService,
    cred: &StoredCredential,
) -> Result<String, UpstreamTokenError> {
    credentials::decrypt_secret(&svc.key_ring, cred)
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .ok_or_else(|| UpstreamTokenError::Decrypt {
            name: cred.name.clone(),
        })
}

async fn client_credentials_token(
    svc: &CredentialService,
    cred: &StoredCredential,
) -> Result<UpstreamAccessToken, UpstreamTokenError> {
    let client_secret = stored_secret(svc, cred)?;
    let token = svc
        .oauth2_token_manager
        .get_token(cred, &client_secret)
        .await
        .map_err(|source| UpstreamTokenError::Exchange {
            name: cred.name.clone(),
            source,
        })?;
    Ok(UpstreamAccessToken {
        access_token: token.access_token,
        expires_at: token.expires_at,
    })
}

async fn refresh_grant_token(
    svc: &CredentialService,
    cred: &StoredCredential,
    actor: TokenActor<'_>,
) -> Result<UpstreamAccessToken, UpstreamTokenError> {
    let token_url = metadata_str(cred, "oauth2_token_url")?;
    let client_id = metadata_str(cred, "oauth2_client_id")?;
    let client_secret = provider_client_secret(svc, cred).await;
    let refresh_token = stored_secret(svc, cred)?;

    let token = svc
        .oauth2_token_manager
        .get_token_with(
            &cred.id,
            OAuth2TokenRequest {
                token_endpoint: token_url,
                client_id,
                client_secret: client_secret.as_deref(),
                grant: OAuth2Grant::RefreshToken {
                    refresh_token: &refresh_token,
                },
            },
        )
        .await
        .map_err(|source| UpstreamTokenError::Exchange {
            name: cred.name.clone(),
            source,
        })?;

    if let Some(rotated) = token.rotated_refresh_token.as_deref() {
        if let Err(e) = persist_rotated_refresh_token(svc, cred, rotated, &actor).await {
            // The provider may already have retired the old refresh token;
            // do not hand out an access token whose successor is lost.
            tracing::error!(
                error = ?e,
                credential_id = %cred.id.0,
                "failed to persist rotated OAuth2 refresh token"
            );
            svc.oauth2_token_manager.evict(&cred.id).await;
            return Err(UpstreamTokenError::Persist {
                name: cred.name.clone(),
            });
        }
    }

    Ok(UpstreamAccessToken {
        access_token: token.access_token,
        expires_at: token.expires_at,
    })
}

/// The client secret of the OAuth provider client that owns this
/// credential, looked up by the `authorization_server_url` captured at
/// provisioning. `None` for public clients and when the row is missing or
/// unreadable, in which case the exchange runs without one.
async fn provider_client_secret(
    svc: &CredentialService,
    cred: &StoredCredential,
) -> Option<String> {
    let as_url = cred
        .metadata
        .get("authorization_server_url")
        .and_then(|v| v.as_str())?;
    let app = match svc
        .store
        .get_oauth_provider_client_by_authorization_server_url(as_url)
        .await
    {
        Ok(Some(app)) if app.enabled => app,
        Ok(_) => {
            tracing::debug!(
                authorization_server_url = %as_url,
                "no enabled OAuth provider client for credential"
            );
            return None;
        }
        Err(e) => {
            tracing::warn!(
                error = %e,
                authorization_server_url = %as_url,
                "failed to look up OAuth provider client"
            );
            return None;
        }
    };
    let (enc, nonce) = (app.encrypted_client_secret.as_ref()?, app.nonce.as_ref()?);
    match svc
        .key_ring
        .decrypt(enc, nonce, app.id.0.to_string().as_bytes())
    {
        Ok(bytes) => String::from_utf8(bytes).ok(),
        Err(e) => {
            tracing::warn!(
                error = %e,
                authorization_server_url = %as_url,
                "failed to decrypt OAuth provider client secret"
            );
            None
        }
    }
}

/// Replace the credential's stored refresh token, archiving the previous
/// one, and record the rotation. The token value is never logged or put in
/// the audit details.
async fn persist_rotated_refresh_token(
    svc: &CredentialService,
    cred: &StoredCredential,
    new_refresh_token: &str,
    actor: &TokenActor<'_>,
) -> Result<(), ApiError> {
    let (encrypted, nonce, key_version) =
        credentials::encrypt_secret(&svc.key_ring, new_refresh_token, &cred.id)?;

    // Only the sealed secret changes; every other field stays as it is.
    let updates = CredentialUpdate {
        name: None,
        service: None,
        scopes: None,
        metadata: None,
        allowed_url_pattern: None,
        expires_at: None,
        transform_script: None,
        transform_name: None,
        vault_id: None,
        tags: None,
        description: None,
        target_identity: None,
        encrypted_value: Some(encrypted),
        nonce: Some(nonce),
        key_version: Some(key_version),
    };
    // The previous token is archived in the same transaction that writes
    // the new one.
    if !svc
        .store
        .rotate_credential_secret(
            &cred.id,
            &updates,
            None,
            Some(&actor.workspace_id.0.to_string()),
        )
        .await?
    {
        return Err(ApiError::Internal(
            "credential disappeared during refresh token rotation".to_string(),
        ));
    }

    let event = AuditEvent::builder(AuditEventType::CredentialSecretRotated)
        .action("oauth2_refresh_token_rotated")
        .workspace_actor(actor.workspace_id, actor.workspace_name)
        .resource("credential", &cred.id.0.to_string())
        .decision(AuditDecision::Permit, Some("oauth2_refresh_rotation"))
        .details(serde_json::json!({
            "credential_name": cred.name,
            "credential_type": cred.credential_type,
            "rotation_source": "oauth2_provider",
        }))
        .build();
    write_audit(&*svc.store, &event).await;

    tracing::info!(
        credential_id = %cred.id.0,
        "persisted rotated OAuth2 refresh token"
    );
    Ok(())
}
