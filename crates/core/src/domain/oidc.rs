use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct OidcProviderId(pub Uuid);

/// Full OIDC provider configuration including encrypted client secret.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcProvider {
    pub id: OidcProviderId,
    pub name: String,
    pub issuer_url: String,
    pub client_id: String,
    /// AES-256-GCM encrypted client secret.
    #[serde(skip_serializing)]
    pub encrypted_client_secret: Vec<u8>,
    /// AES-256-GCM nonce for client secret decryption.
    #[serde(skip_serializing)]
    pub nonce: Vec<u8>,
    pub scopes: Vec<String>,
    /// Maps IdP claims/roles to local user roles. JSON object.
    pub role_mapping: serde_json::Value,
    /// Whether to auto-create users on first OIDC login.
    pub auto_provision: bool,
    pub enabled: bool,
    /// Which ID token claim to use as the username (e.g. "preferred_username", "email", "upn").
    /// Defaults to "preferred_username" if not set.
    pub username_claim: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Summary of an OIDC provider without sensitive fields (client secret).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcProviderSummary {
    pub id: OidcProviderId,
    pub name: String,
    pub issuer_url: String,
    pub client_id: String,
    pub scopes: Vec<String>,
    pub role_mapping: serde_json::Value,
    pub auto_provision: bool,
    pub enabled: bool,
    /// Which ID token claim to use as the username.
    pub username_claim: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<&OidcProvider> for OidcProviderSummary {
    fn from(p: &OidcProvider) -> Self {
        Self {
            id: p.id.clone(),
            name: p.name.clone(),
            issuer_url: p.issuer_url.clone(),
            client_id: p.client_id.clone(),
            scopes: p.scopes.clone(),
            role_mapping: p.role_mapping.clone(),
            auto_provision: p.auto_provision,
            enabled: p.enabled,
            username_claim: p.username_claim.clone(),
            created_at: p.created_at,
            updated_at: p.updated_at,
        }
    }
}

/// OIDC auth state stored in DB during authorization code flow.
/// Tracks state (CSRF) and nonce for validation on callback.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcAuthState {
    /// Cryptographically random state parameter (CSRF protection).
    pub state: String,
    /// Cryptographically random nonce for ID token validation.
    pub nonce: String,
    /// Which OIDC provider this auth flow is for.
    pub provider_id: OidcProviderId,
    /// The redirect_uri used in the authorization request.
    pub redirect_uri: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}
