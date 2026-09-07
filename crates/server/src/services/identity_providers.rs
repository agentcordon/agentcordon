//! Identity-provider service: the two server-wide identity configurations an
//! administrator edits — OIDC login providers and the OAuth provider clients
//! (`client_id`/`client_secret`) that MCP provisioning uses against an
//! upstream authorization server.
//!
//! Both are System-scoped admin configuration holding an encrypted secret, so
//! they share one service: it owns the encryption, the store writes, and the
//! audit event for each of them. Handlers parse and shape; reads stay in the
//! handler.

use std::sync::Arc;

use uuid::Uuid;

use agent_cordon_core::crypto::key_ring::KeyRing;
use agent_cordon_core::crypto::session::generate_session_token;
use agent_cordon_core::crypto::SecretEncryptor;
use agent_cordon_core::domain::audit::{AuditDecision, AuditEvent, AuditEventType};
use agent_cordon_core::domain::credential::StoredCredential;
use agent_cordon_core::domain::mcp::McpAuthMethod;
use agent_cordon_core::domain::oauth_provider_client::{
    OAuthProviderClient, OAuthProviderClientId, RegistrationSource,
};
use agent_cordon_core::domain::oidc::{OidcAuthState, OidcProvider, OidcProviderId};
use agent_cordon_core::domain::policy::PolicyDecision;
use agent_cordon_core::policy::{actions, PolicyResource};

use crate::authz::Authz;
use crate::config::AppConfig;
use crate::extractors::AuthenticatedUser;
use crate::response::ApiError;
use crate::state::SharedStore;

use super::write_audit;

/// Input for [`IdentityProviderService::create_oidc_provider`].
pub struct NewOidcProvider {
    pub name: String,
    pub issuer_url: String,
    pub client_id: String,
    pub client_secret: String,
    pub scopes: Option<Vec<String>>,
    pub role_mapping: Option<serde_json::Value>,
    pub auto_provision: Option<bool>,
    pub enabled: Option<bool>,
    pub username_claim: Option<String>,
}

/// Input for [`IdentityProviderService::update_oidc_provider`]; `None` leaves
/// a field unchanged.
pub struct OidcProviderChanges {
    pub name: Option<String>,
    pub issuer_url: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub scopes: Option<Vec<String>>,
    pub role_mapping: Option<serde_json::Value>,
    pub auto_provision: Option<bool>,
    pub enabled: Option<bool>,
    pub username_claim: Option<String>,
}

/// Input for [`IdentityProviderService::create_oauth_client`].
pub struct NewOAuthProviderClient {
    pub label: String,
    pub authorization_server_url: String,
    pub authorize_endpoint: String,
    pub token_endpoint: String,
    pub client_id: String,
    pub client_secret: Option<String>,
    pub requested_scopes: Option<String>,
    pub enabled: Option<bool>,
}

/// Input for [`IdentityProviderService::update_oauth_client`]; `None` leaves a
/// field unchanged.
pub struct OAuthProviderClientChanges {
    pub label: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub authorize_endpoint: Option<String>,
    pub token_endpoint: Option<String>,
    pub requested_scopes: Option<String>,
    pub enabled: Option<bool>,
}

/// What stands behind a provider client: the `oauth2_user_authorization`
/// credentials issued against its authorization server, and the OAuth2 MCP
/// servers that authenticate with them.
///
/// Deleting the row would leave every one of those unable to refresh — the
/// `client_id`/`client_secret` the token exchange needs lives only here — so
/// a delete is refused while either count is non-zero. An update is not:
/// rotating a provider secret is exactly how these rows are kept working.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ProviderClientDependents {
    pub credentials: usize,
    pub mcp_servers: usize,
}

impl ProviderClientDependents {
    pub fn any(self) -> bool {
        self.credentials > 0 || self.mcp_servers > 0
    }
}

/// What [`IdentityProviderService::consume_login_state`] found.
pub enum LoginState {
    Valid(OidcAuthState),
    /// Never issued, already consumed, or expired — a caller cannot tell
    /// these apart and should not be told which it was.
    Unusable,
    /// The store could not be read at all.
    Unavailable,
}

#[derive(Clone)]
pub struct IdentityProviderService {
    store: SharedStore,
    authz: Arc<Authz>,
    key_ring: Arc<KeyRing>,
    config: AppConfig,
}

impl IdentityProviderService {
    pub fn new(
        store: SharedStore,
        authz: Arc<Authz>,
        key_ring: Arc<KeyRing>,
        config: AppConfig,
    ) -> Self {
        Self {
            store,
            authz,
            key_ring,
            config,
        }
    }

    // ------------------------------------------------------------------
    // OIDC login providers
    // ------------------------------------------------------------------

    /// Check Cedar policy for `manage_oidc_providers` on `System` resource.
    pub async fn check_manage_oidc_providers(
        &self,
        auth: &AuthenticatedUser,
    ) -> Result<PolicyDecision, ApiError> {
        self.authz
            .authorize(
                auth,
                actions::MANAGE_OIDC_PROVIDERS,
                &PolicyResource::System,
            )
            .await
    }

    /// The provider, or 404.
    pub async fn load_oidc_provider(&self, id: &OidcProviderId) -> Result<OidcProvider, ApiError> {
        self.store
            .get_oidc_provider(id)
            .await?
            .ok_or_else(|| ApiError::NotFound("OIDC provider not found".to_string()))
    }

    pub async fn create_oidc_provider(
        &self,
        auth: &AuthenticatedUser,
        corr: &str,
        new: NewOidcProvider,
    ) -> Result<OidcProvider, ApiError> {
        let policy_decision = self.check_manage_oidc_providers(auth).await?;

        // Validate input
        if new.name.trim().is_empty() {
            return Err(ApiError::BadRequest("name is required".to_string()));
        }
        if new.client_id.trim().is_empty() {
            return Err(ApiError::BadRequest("client_id is required".to_string()));
        }
        if new.client_secret.is_empty() {
            return Err(ApiError::BadRequest(
                "client_secret is required".to_string(),
            ));
        }
        validate_issuer_url(&new.issuer_url)?;

        // Generate provider ID early so we can use it as AAD
        let provider_id = OidcProviderId(Uuid::new_v4());

        // Encrypt the client secret with provider ID as AAD
        let (encrypted_secret, nonce) = self.key_ring.encrypt(
            new.client_secret.as_bytes(),
            provider_id.0.to_string().as_bytes(),
        )?;

        let now = chrono::Utc::now();
        let provider = OidcProvider {
            id: provider_id,
            name: new.name.trim().to_string(),
            issuer_url: new.issuer_url.trim().trim_end_matches('/').to_string(),
            client_id: new.client_id.trim().to_string(),
            encrypted_client_secret: encrypted_secret,
            nonce,
            scopes: new.scopes.unwrap_or_else(|| {
                vec![
                    "openid".to_string(),
                    "profile".to_string(),
                    "email".to_string(),
                ]
            }),
            role_mapping: new.role_mapping.unwrap_or(serde_json::json!({})),
            auto_provision: new.auto_provision.unwrap_or(true),
            enabled: new.enabled.unwrap_or(true),
            username_claim: new
                .username_claim
                .unwrap_or_else(|| "preferred_username".to_string()),
            created_at: now,
            updated_at: now,
        };

        self.store.create_oidc_provider(&provider).await?;

        let event = AuditEvent::builder(AuditEventType::OidcProviderCreated)
            .action("create")
            .user_actor(&auth.user)
            .resource("oidc_provider", &provider.id.0.to_string())
            .correlation_id(corr)
            .decision(
                AuditDecision::Permit,
                Some(&policy_decision.reasons.join(", ")),
            )
            .details(serde_json::json!({
                "provider_name": provider.name,
                "issuer_url": provider.issuer_url,
            }))
            .build();
        write_audit(&*self.store, &event).await;

        Ok(provider)
    }

    pub async fn update_oidc_provider(
        &self,
        auth: &AuthenticatedUser,
        corr: &str,
        id: &OidcProviderId,
        changes: OidcProviderChanges,
    ) -> Result<OidcProvider, ApiError> {
        let policy_decision = self.check_manage_oidc_providers(auth).await?;

        let mut provider = self.load_oidc_provider(id).await?;

        if let Some(name) = changes.name {
            let trimmed = name.trim().to_string();
            if trimmed.is_empty() {
                return Err(ApiError::BadRequest("name cannot be empty".to_string()));
            }
            provider.name = trimmed;
        }
        if let Some(issuer_url) = changes.issuer_url {
            validate_issuer_url(&issuer_url)?;
            provider.issuer_url = issuer_url.trim().trim_end_matches('/').to_string();
        }
        if let Some(client_id) = changes.client_id {
            let trimmed = client_id.trim().to_string();
            if trimmed.is_empty() {
                return Err(ApiError::BadRequest(
                    "client_id cannot be empty".to_string(),
                ));
            }
            provider.client_id = trimmed;
        }
        if let Some(client_secret) = changes.client_secret {
            if client_secret.is_empty() {
                return Err(ApiError::BadRequest(
                    "client_secret cannot be empty".to_string(),
                ));
            }
            // Re-encrypt the new client secret with provider ID as AAD
            let (encrypted, nonce) = self
                .key_ring
                .encrypt(client_secret.as_bytes(), id.0.to_string().as_bytes())?;
            provider.encrypted_client_secret = encrypted;
            provider.nonce = nonce;
        }
        if let Some(scopes) = changes.scopes {
            provider.scopes = scopes;
        }
        if let Some(role_mapping) = changes.role_mapping {
            provider.role_mapping = role_mapping;
        }
        if let Some(auto_provision) = changes.auto_provision {
            provider.auto_provision = auto_provision;
        }
        if let Some(enabled) = changes.enabled {
            provider.enabled = enabled;
        }
        if let Some(username_claim) = changes.username_claim {
            provider.username_claim = username_claim;
        }
        provider.updated_at = chrono::Utc::now();

        self.store.update_oidc_provider(&provider).await?;

        let event = AuditEvent::builder(AuditEventType::OidcProviderUpdated)
            .action("update")
            .user_actor(&auth.user)
            .resource("oidc_provider", &provider.id.0.to_string())
            .correlation_id(corr)
            .decision(
                AuditDecision::Permit,
                Some(&policy_decision.reasons.join(", ")),
            )
            .details(serde_json::json!({
                "provider_name": provider.name,
            }))
            .build();
        write_audit(&*self.store, &event).await;

        Ok(provider)
    }

    pub async fn delete_oidc_provider(
        &self,
        auth: &AuthenticatedUser,
        corr: &str,
        id: &OidcProviderId,
    ) -> Result<(), ApiError> {
        let policy_decision = self.check_manage_oidc_providers(auth).await?;

        let provider = self.load_oidc_provider(id).await?;

        self.store.delete_oidc_provider(id).await?;

        let event = AuditEvent::builder(AuditEventType::OidcProviderDeleted)
            .action("delete")
            .user_actor(&auth.user)
            .resource("oidc_provider", &provider.id.0.to_string())
            .correlation_id(corr)
            .decision(
                AuditDecision::Permit,
                Some(&policy_decision.reasons.join(", ")),
            )
            .details(serde_json::json!({
                "provider_name": provider.name,
            }))
            .build();
        write_audit(&*self.store, &event).await;

        Ok(())
    }

    /// Open an OIDC provider's client secret. `None` when no key in the ring
    /// opens the row, or what it opens is not UTF-8: the login flow answers
    /// all of those the same generic way rather than saying which.
    pub fn open_oidc_client_secret(&self, provider: &OidcProvider) -> Option<String> {
        let bytes = match self.key_ring.decrypt(
            &provider.encrypted_client_secret,
            &provider.nonce,
            provider.id.0.to_string().as_bytes(),
        ) {
            Ok(b) => b,
            Err(_) => {
                tracing::error!(
                    "Failed to decrypt OIDC client secret for provider {}",
                    provider.id.0
                );
                return None;
            }
        };
        match String::from_utf8(bytes) {
            Ok(s) => Some(s),
            Err(_) => {
                tracing::error!(
                    "OIDC client secret is not valid UTF-8 for provider {}",
                    provider.id.0
                );
                None
            }
        }
    }

    /// Open an OAuth provider client's secret. `Ok(None)` means the client is
    /// public and has none; an unopenable or non-UTF-8 row is an error.
    pub fn open_oauth_client_secret(
        &self,
        client: &OAuthProviderClient,
    ) -> Result<Option<String>, ApiError> {
        let (Some(enc), Some(nonce)) = (
            client.encrypted_client_secret.as_ref(),
            client.nonce.as_ref(),
        ) else {
            return Ok(None);
        };
        let bytes = self
            .key_ring
            .decrypt(enc, nonce, client.id.0.to_string().as_bytes())?;
        let secret = String::from_utf8(bytes).map_err(|_| {
            ApiError::Internal("oauth provider client_secret is not valid UTF-8".to_string())
        })?;
        Ok(Some(secret))
    }

    /// Mint and store the single-use state/nonce pair for one OIDC login
    /// attempt. The callback consumes it by deleting the row.
    pub async fn create_login_state(
        &self,
        provider_id: &OidcProviderId,
        redirect_uri: &str,
    ) -> Result<OidcAuthState, ApiError> {
        let now = chrono::Utc::now();
        let ttl = chrono::Duration::seconds(self.config.oidc_state_ttl_seconds as i64);
        let auth_state = OidcAuthState {
            state: generate_session_token(),
            nonce: generate_session_token(),
            provider_id: provider_id.clone(),
            redirect_uri: redirect_uri.to_string(),
            created_at: now,
            expires_at: now + ttl,
        };
        self.store.create_oidc_auth_state(&auth_state).await?;
        Ok(auth_state)
    }

    /// Consume the login state named by the callback's `state` parameter:
    /// read it, delete it, and check its expiry, so a replayed callback
    /// finds nothing left to use.
    pub async fn consume_login_state(&self, state_param: &str) -> Result<LoginState, ApiError> {
        let auth_state = match self.store.get_oidc_auth_state(state_param).await {
            Ok(Some(s)) => s,
            Ok(None) => return Ok(LoginState::Unusable),
            Err(_) => return Ok(LoginState::Unavailable),
        };

        let deleted = self
            .store
            .delete_oidc_auth_state(state_param)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "failed to delete OIDC auth state");
                ApiError::Internal("authentication failed".to_string())
            })?;

        if !deleted {
            tracing::warn!("OIDC auth state already consumed (possible replay)");
            return Ok(LoginState::Unusable);
        }

        if auth_state.expires_at < chrono::Utc::now() {
            return Ok(LoginState::Unusable);
        }

        Ok(LoginState::Valid(auth_state))
    }

    // ------------------------------------------------------------------
    // OAuth provider clients
    // ------------------------------------------------------------------

    /// Reading a provider client is part of managing MCP servers — an
    /// operator needs to see which client an origin uses — so the read side
    /// stays on `manage_mcp_servers` over `System`. The response never
    /// carries the client secret.
    pub async fn check_read_oauth_clients(
        &self,
        auth: &AuthenticatedUser,
    ) -> Result<PolicyDecision, ApiError> {
        self.authz
            .authorize(auth, actions::MANAGE_MCP_SERVERS, &PolicyResource::System)
            .await
    }

    /// Creating, updating, deleting or re-registering a provider client
    /// rewrites the registration every MCP server at that origin
    /// authenticates with, across every tenant. That needs
    /// `manage_oauth_provider_clients`, which the default policy grants to
    /// enabled admins only.
    ///
    /// The check is `System`-scoped: a provider client carries no owner, and
    /// giving it one is the next phase's authorization-model work.
    pub async fn check_manage_oauth_clients(
        &self,
        auth: &AuthenticatedUser,
    ) -> Result<PolicyDecision, ApiError> {
        self.authz
            .authorize(
                auth,
                actions::MANAGE_OAUTH_PROVIDER_CLIENTS,
                &PolicyResource::System,
            )
            .await
    }

    /// Count what depends on a provider client.
    ///
    /// A credential names its authorization server in metadata
    /// (`authorization_server_url`, written at provisioning); rows written
    /// before that fall back to the origin of the token endpoint they use.
    /// An MCP server is at the origin when it is an OAuth2 server whose
    /// required credentials include one of those.
    pub async fn provider_client_dependents(
        &self,
        client: &OAuthProviderClient,
    ) -> Result<ProviderClientDependents, ApiError> {
        let as_origin = origin_of(&client.authorization_server_url);
        let token_origin = origin_of(&client.token_endpoint);

        let credentials: Vec<StoredCredential> = self
            .store
            .list_all_stored_credentials()
            .await?
            .into_iter()
            .filter(|c| c.credential_type == "oauth2_user_authorization")
            .filter(|c| credential_at_origin(c, as_origin.as_deref(), token_origin.as_deref()))
            .collect();

        let credential_ids: std::collections::HashSet<uuid::Uuid> =
            credentials.iter().map(|c| c.id.0).collect();

        let mcp_servers = self
            .store
            .list_mcp_servers()
            .await?
            .into_iter()
            .filter(|s| s.auth_method == McpAuthMethod::OAuth2)
            .filter(|s| {
                s.required_credentials
                    .as_ref()
                    .is_some_and(|reqs| reqs.iter().any(|id| credential_ids.contains(&id.0)))
            })
            .count();

        Ok(ProviderClientDependents {
            credentials: credentials.len(),
            mcp_servers,
        })
    }

    /// The client, or 404.
    pub async fn load_oauth_client(
        &self,
        id: &OAuthProviderClientId,
    ) -> Result<OAuthProviderClient, ApiError> {
        self.store
            .get_oauth_provider_client(id)
            .await?
            .ok_or_else(|| ApiError::NotFound("OAuth provider client not found".to_string()))
    }

    pub async fn create_oauth_client(
        &self,
        auth: &AuthenticatedUser,
        corr: &str,
        new: NewOAuthProviderClient,
    ) -> Result<OAuthProviderClient, ApiError> {
        let policy_decision = self.check_manage_oauth_clients(auth).await?;

        if new.label.trim().is_empty() {
            return Err(ApiError::BadRequest("label is required".to_string()));
        }
        if new.client_id.trim().is_empty() {
            return Err(ApiError::BadRequest("client_id is required".to_string()));
        }
        validate_url(&new.authorization_server_url, "authorization_server_url")?;
        validate_url(&new.authorize_endpoint, "authorize_endpoint")?;
        validate_url(&new.token_endpoint, "token_endpoint")?;

        let as_url = new.authorization_server_url.trim().to_string();

        if self
            .store
            .get_oauth_provider_client_by_authorization_server_url(&as_url)
            .await?
            .is_some()
        {
            return Err(ApiError::Conflict(format!(
                "An OAuth provider client for '{as_url}' already exists"
            )));
        }

        let client_id_val = OAuthProviderClientId(Uuid::new_v4());

        let (encrypted_secret, nonce) = if let Some(secret) = new.client_secret.as_ref() {
            if secret.is_empty() {
                (None, None)
            } else {
                let (enc, n) = self
                    .key_ring
                    .encrypt(secret.as_bytes(), client_id_val.0.to_string().as_bytes())?;
                (Some(enc), Some(n))
            }
        } else {
            (None, None)
        };

        let now = chrono::Utc::now();
        let client = OAuthProviderClient {
            id: client_id_val,
            authorization_server_url: as_url,
            issuer: None,
            authorize_endpoint: new.authorize_endpoint.trim().to_string(),
            token_endpoint: new.token_endpoint.trim().to_string(),
            registration_endpoint: None,
            code_challenge_methods_supported: vec![],
            token_endpoint_auth_methods_supported: vec![],
            scopes_supported: vec![],
            client_id: new.client_id.trim().to_string(),
            encrypted_client_secret: encrypted_secret,
            nonce,
            requested_scopes: new.requested_scopes.unwrap_or_default(),
            registration_source: RegistrationSource::Manual,
            client_id_issued_at: None,
            client_secret_expires_at: None,
            registration_access_token_encrypted: None,
            registration_access_token_nonce: None,
            registration_client_uri: None,
            label: new.label.trim().to_string(),
            enabled: new.enabled.unwrap_or(true),
            created_at: now,
            updated_at: now,
        };

        self.store.create_oauth_provider_client(&client).await?;

        let event = AuditEvent::builder(AuditEventType::OAuthProviderClientCreated)
            .action("create")
            .user_actor(&auth.user)
            .resource("oauth_provider_client", &client.id.0.to_string())
            .correlation_id(corr)
            .decision(
                AuditDecision::Permit,
                Some(&policy_decision.reasons.join(", ")),
            )
            .details(serde_json::json!({
                "authorization_server_url": client.authorization_server_url,
                "label": client.label,
            }))
            .build();
        write_audit(&*self.store, &event).await;

        Ok(client)
    }

    pub async fn update_oauth_client(
        &self,
        auth: &AuthenticatedUser,
        corr: &str,
        id: &OAuthProviderClientId,
        changes: OAuthProviderClientChanges,
    ) -> Result<OAuthProviderClient, ApiError> {
        let policy_decision = self.check_manage_oauth_clients(auth).await?;

        let mut client = self.load_oauth_client(id).await?;

        // Reject edits on DCR-sourced rows.
        if client.registration_source == RegistrationSource::Dcr {
            return Err(ApiError::Conflict(
                "cannot edit DCR-registered clients — delete and re-register instead".to_string(),
            ));
        }

        // What is standing behind the row as it changes. Update is allowed
        // with dependents — a rotated provider secret has to get in somehow —
        // so the audit row carries the blast radius instead of a refusal.
        let dependents = self.provider_client_dependents(&client).await?;
        let mut changed: Vec<&'static str> = Vec::new();

        if let Some(label) = changes.label {
            let trimmed = label.trim().to_string();
            if trimmed.is_empty() {
                return Err(ApiError::BadRequest("label cannot be empty".to_string()));
            }
            if trimmed != client.label {
                changed.push("label");
            }
            client.label = trimmed;
        }
        if let Some(cid) = changes.client_id {
            let trimmed = cid.trim().to_string();
            if trimmed.is_empty() {
                return Err(ApiError::BadRequest(
                    "client_id cannot be empty".to_string(),
                ));
            }
            if trimmed != client.client_id {
                changed.push("client_id");
            }
            client.client_id = trimmed;
        }
        if let Some(secret) = changes.client_secret {
            if secret.is_empty() {
                return Err(ApiError::BadRequest(
                    "client_secret cannot be empty".to_string(),
                ));
            }
            let (enc, n) = self
                .key_ring
                .encrypt(secret.as_bytes(), id.0.to_string().as_bytes())?;
            client.encrypted_client_secret = Some(enc);
            client.nonce = Some(n);
            // Named, never valued: the audit row says the secret was
            // replaced and nothing more.
            changed.push("client_secret");
        }
        if let Some(authorize_endpoint) = changes.authorize_endpoint {
            validate_url(&authorize_endpoint, "authorize_endpoint")?;
            let trimmed = authorize_endpoint.trim().to_string();
            if trimmed != client.authorize_endpoint {
                changed.push("authorize_endpoint");
            }
            client.authorize_endpoint = trimmed;
        }
        if let Some(token_endpoint) = changes.token_endpoint {
            validate_url(&token_endpoint, "token_endpoint")?;
            let trimmed = token_endpoint.trim().to_string();
            if trimmed != client.token_endpoint {
                changed.push("token_endpoint");
            }
            client.token_endpoint = trimmed;
        }
        if let Some(scopes) = changes.requested_scopes {
            if scopes != client.requested_scopes {
                changed.push("requested_scopes");
            }
            client.requested_scopes = scopes;
        }
        if let Some(enabled) = changes.enabled {
            if enabled != client.enabled {
                changed.push("enabled");
            }
            client.enabled = enabled;
        }
        client.updated_at = chrono::Utc::now();

        self.store.update_oauth_provider_client(&client).await?;

        let event = AuditEvent::builder(AuditEventType::OAuthProviderClientUpdated)
            .action("update")
            .user_actor(&auth.user)
            .resource("oauth_provider_client", &client.id.0.to_string())
            .correlation_id(corr)
            .decision(
                AuditDecision::Permit,
                Some(&policy_decision.reasons.join(", ")),
            )
            .details(serde_json::json!({
                "authorization_server_url": client.authorization_server_url,
                "label": client.label,
                "changed_fields": changed,
                "dependent_credentials": dependents.credentials,
                "dependent_mcp_servers": dependents.mcp_servers,
            }))
            .build();
        write_audit(&*self.store, &event).await;

        Ok(client)
    }

    pub async fn delete_oauth_client(
        &self,
        auth: &AuthenticatedUser,
        corr: &str,
        id: &OAuthProviderClientId,
    ) -> Result<(), ApiError> {
        let policy_decision = self.check_manage_oauth_clients(auth).await?;

        let client = self.load_oauth_client(id).await?;

        // The `client_id`/`client_secret` the token exchange needs lives only
        // on this row. Deleting it while anything still authenticates at the
        // origin breaks those silently, at the next refresh.
        let dependents = self.provider_client_dependents(&client).await?;
        if dependents.any() {
            return Err(ApiError::Conflict(format!(
                "OAuth provider client '{}' is still in use: {} OAuth2 credential(s) and \
                 {} MCP server(s) authenticate at {}. Remove those first; to rotate the \
                 registration, update this client instead of deleting it.",
                client.label,
                dependents.credentials,
                dependents.mcp_servers,
                client.authorization_server_url,
            )));
        }

        self.store.delete_oauth_provider_client(id).await?;

        let event = AuditEvent::builder(AuditEventType::OAuthProviderClientDeleted)
            .action("delete")
            .user_actor(&auth.user)
            .resource("oauth_provider_client", &client.id.0.to_string())
            .correlation_id(corr)
            .decision(
                AuditDecision::Permit,
                Some(&policy_decision.reasons.join(", ")),
            )
            .details(serde_json::json!({
                "authorization_server_url": client.authorization_server_url,
                "label": client.label,
            }))
            .build();
        write_audit(&*self.store, &event).await;

        Ok(())
    }

    /// Re-register a DCR-sourced client at its authorization server: re-run
    /// discovery and the DCR POST, then update the existing row in place so
    /// the `id` stays stable. Manual rows are rejected — those are edited
    /// directly.
    pub async fn reregister_oauth_client(
        &self,
        auth: &AuthenticatedUser,
        corr: &str,
        id: &OAuthProviderClientId,
    ) -> Result<OAuthProviderClient, ApiError> {
        let policy_decision = self.check_manage_oauth_clients(auth).await?;

        let existing = self.load_oauth_client(id).await?;

        if existing.registration_source != RegistrationSource::Dcr {
            return Err(ApiError::BadRequest(
                "only DCR-registered clients can be re-registered; edit manual clients directly"
                    .to_string(),
            ));
        }

        // Re-fetch AS metadata to pick up any endpoint changes.
        let as_meta = crate::oauth_discovery::fetch_authorization_server_metadata(
            &existing.authorization_server_url,
        )
        .await
        .map_err(|e| ApiError::BadRequest(format!("failed to re-fetch AS metadata: {e}")))?;

        // Build redirect URI from configured base_url.
        let base_url = self.config.base_url.as_deref().ok_or_else(|| {
            ApiError::BadRequest("AGTCRDN_BASE_URL must be configured for DCR".to_string())
        })?;
        let redirect_uri = format!(
            "{}/api/v1/mcp-servers/oauth/callback",
            base_url.trim_end_matches('/')
        );

        let client_name = self
            .config
            .instance_label
            .clone()
            .unwrap_or_else(|| "AgentCordon".to_string());

        let scopes = if existing.requested_scopes.is_empty() {
            None
        } else {
            Some(existing.requested_scopes.as_str())
        };

        let dcr_resp =
            crate::oauth_discovery::register_client(&as_meta, &redirect_uri, &client_name, scopes)
                .await
                .map_err(|e| ApiError::BadRequest(format!("DCR re-registration failed: {e}")))?;

        // Build the updated row, keeping the same id.
        let id_bytes = existing.id.0.to_string();
        let (encrypted_client_secret, secret_nonce) =
            if let Some(secret) = dcr_resp.client_secret.as_deref() {
                let (enc, nonce) = self
                    .key_ring
                    .encrypt(secret.as_bytes(), id_bytes.as_bytes())
                    .map_err(|e| ApiError::Internal(format!("encryption: {e}")))?;
                (Some(enc), Some(nonce))
            } else {
                (None, None)
            };
        let (rat_enc, rat_nonce) = if let Some(rat) = dcr_resp.registration_access_token.as_deref()
        {
            let (enc, nonce) = self
                .key_ring
                .encrypt(rat.as_bytes(), id_bytes.as_bytes())
                .map_err(|e| ApiError::Internal(format!("encryption: {e}")))?;
            (Some(enc), Some(nonce))
        } else {
            (None, None)
        };

        let updated = OAuthProviderClient {
            id: existing.id.clone(),
            authorization_server_url: existing.authorization_server_url.clone(),
            issuer: Some(as_meta.issuer.clone()),
            authorize_endpoint: as_meta.authorization_endpoint.clone(),
            token_endpoint: as_meta.token_endpoint.clone(),
            registration_endpoint: as_meta.registration_endpoint.clone(),
            code_challenge_methods_supported: as_meta.code_challenge_methods_supported.clone(),
            token_endpoint_auth_methods_supported: as_meta
                .token_endpoint_auth_methods_supported
                .clone(),
            scopes_supported: as_meta.scopes_supported.clone(),
            client_id: dcr_resp.client_id.clone(),
            encrypted_client_secret,
            nonce: secret_nonce,
            requested_scopes: existing.requested_scopes.clone(),
            registration_source: RegistrationSource::Dcr,
            client_id_issued_at: dcr_resp
                .client_id_issued_at
                .and_then(|ts| chrono::DateTime::from_timestamp(ts, 0)),
            client_secret_expires_at: dcr_resp
                .client_secret_expires_at
                .filter(|ts| *ts != 0)
                .and_then(|ts| chrono::DateTime::from_timestamp(ts, 0)),
            registration_access_token_encrypted: rat_enc,
            registration_access_token_nonce: rat_nonce,
            registration_client_uri: dcr_resp.registration_client_uri.clone(),
            label: existing.label.clone(),
            enabled: existing.enabled,
            created_at: existing.created_at,
            updated_at: chrono::Utc::now(),
        };

        self.store.update_oauth_provider_client(&updated).await?;

        let event = AuditEvent::builder(AuditEventType::OAuthProviderClientUpdated)
            .action("reregister")
            .user_actor(&auth.user)
            .resource("oauth_provider_client", &updated.id.0.to_string())
            .correlation_id(corr)
            .decision(
                AuditDecision::Permit,
                Some(&policy_decision.reasons.join(", ")),
            )
            .details(serde_json::json!({
                "authorization_server_url": updated.authorization_server_url,
                "source": "dcr",
            }))
            .build();
        write_audit(&*self.store, &event).await;

        Ok(updated)
    }
}

/// The origin (`scheme://host[:port]`) of a URL, lowercased. `None` when the
/// string is not a URL with a host — a row that cannot be placed at an origin
/// is never counted as a dependent of one.
fn origin_of(url: &str) -> Option<String> {
    crate::oauth_discovery::normalize_as_url(url.trim()).ok()
}

/// Whether an `oauth2_user_authorization` credential was issued against this
/// authorization server. Provisioning records the server on the credential
/// (`authorization_server_url`); rows written before that fall back to the
/// origin of the token endpoint they use.
fn credential_at_origin(
    cred: &StoredCredential,
    as_origin: Option<&str>,
    token_origin: Option<&str>,
) -> bool {
    if let Some(recorded) = cred
        .metadata
        .get("authorization_server_url")
        .and_then(serde_json::Value::as_str)
    {
        return as_origin.is_some() && origin_of(recorded).as_deref() == as_origin;
    }
    match cred
        .metadata
        .get("oauth2_token_url")
        .and_then(serde_json::Value::as_str)
    {
        Some(token_url) => {
            token_origin.is_some() && origin_of(token_url).as_deref() == token_origin
        }
        None => false,
    }
}

/// Validate an issuer URL: must be HTTPS except for localhost (dev).
fn validate_issuer_url(url: &str) -> Result<(), ApiError> {
    let parsed = reqwest::Url::parse(url.trim())
        .map_err(|_| ApiError::BadRequest("issuer_url is not a valid URL".to_string()))?;

    let scheme = parsed.scheme();
    let host = parsed.host_str().unwrap_or("");

    if scheme != "https" && host != "localhost" && host != "127.0.0.1" {
        return Err(ApiError::BadRequest(
            "issuer_url must use HTTPS (except localhost for development)".to_string(),
        ));
    }

    Ok(())
}

/// Validate an endpoint URL: must be HTTPS except for localhost (dev).
fn validate_url(url: &str, field_name: &str) -> Result<(), ApiError> {
    let parsed = reqwest::Url::parse(url.trim())
        .map_err(|_| ApiError::BadRequest(format!("{field_name} is not a valid URL")))?;

    let scheme = parsed.scheme();
    let host = parsed.host_str().unwrap_or("");

    if scheme != "https" && host != "localhost" && host != "127.0.0.1" {
        return Err(ApiError::BadRequest(format!(
            "{field_name} must use HTTPS (except localhost for development)"
        )));
    }

    Ok(())
}
