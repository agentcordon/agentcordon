use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Unique identifier for an OAuth provider client configuration.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct OAuthProviderClientId(pub Uuid);

/// How this provider client was registered with the upstream authorization server.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RegistrationSource {
    /// Created via RFC 7591 Dynamic Client Registration.
    Dcr,
    /// Manually configured by an admin.
    Manual,
}

impl RegistrationSource {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Dcr => "dcr",
            Self::Manual => "manual",
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "dcr" => Some(Self::Dcr),
            "manual" => Some(Self::Manual),
            _ => None,
        }
    }
}

/// Full OAuth provider client configuration including encrypted client secret.
///
/// One row per (authorization_server_url) — multiple MCP servers/templates
/// pointing at the same authorization server share a single client registration.
#[derive(Debug, Clone)]
pub struct OAuthProviderClient {
    pub id: OAuthProviderClientId,

    /// Primary business key — origin of the upstream authorization server.
    pub authorization_server_url: String,
    /// Optional issuer (from AS metadata).
    pub issuer: Option<String>,

    /// Discovered/configured endpoints.
    pub authorize_endpoint: String,
    pub token_endpoint: String,
    pub registration_endpoint: Option<String>,

    /// AS metadata (JSON-encoded string arrays in storage).
    pub code_challenge_methods_supported: Vec<String>,
    pub token_endpoint_auth_methods_supported: Vec<String>,
    pub scopes_supported: Vec<String>,

    /// Client credentials.
    pub client_id: String,
    pub encrypted_client_secret: Option<Vec<u8>>,
    pub nonce: Option<Vec<u8>>,

    /// Space-separated scopes we will request.
    pub requested_scopes: String,

    /// Provenance of this row.
    pub registration_source: RegistrationSource,
    pub client_id_issued_at: Option<DateTime<Utc>>,
    pub client_secret_expires_at: Option<DateTime<Utc>>,

    /// RFC 7592 management credentials (only present for DCR rows).
    pub registration_access_token_encrypted: Option<Vec<u8>>,
    pub registration_access_token_nonce: Option<Vec<u8>>,
    pub registration_client_uri: Option<String>,

    /// Human-readable label.
    pub label: String,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Summary of an OAuth provider client without sensitive fields (client secret).
#[derive(Debug, Clone, Serialize)]
pub struct OAuthProviderClientSummary {
    pub id: OAuthProviderClientId,
    pub authorization_server_url: String,
    pub issuer: Option<String>,
    pub authorize_endpoint: String,
    pub token_endpoint: String,
    pub registration_endpoint: Option<String>,
    pub code_challenge_methods_supported: Vec<String>,
    pub token_endpoint_auth_methods_supported: Vec<String>,
    pub scopes_supported: Vec<String>,
    pub client_id: String,
    pub requested_scopes: String,
    pub registration_source: RegistrationSource,
    pub client_id_issued_at: Option<DateTime<Utc>>,
    pub client_secret_expires_at: Option<DateTime<Utc>>,
    pub registration_client_uri: Option<String>,
    pub label: String,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<&OAuthProviderClient> for OAuthProviderClientSummary {
    fn from(c: &OAuthProviderClient) -> Self {
        Self {
            id: c.id.clone(),
            authorization_server_url: c.authorization_server_url.clone(),
            issuer: c.issuer.clone(),
            authorize_endpoint: c.authorize_endpoint.clone(),
            token_endpoint: c.token_endpoint.clone(),
            registration_endpoint: c.registration_endpoint.clone(),
            code_challenge_methods_supported: c.code_challenge_methods_supported.clone(),
            token_endpoint_auth_methods_supported: c.token_endpoint_auth_methods_supported.clone(),
            scopes_supported: c.scopes_supported.clone(),
            client_id: c.client_id.clone(),
            requested_scopes: c.requested_scopes.clone(),
            registration_source: c.registration_source,
            client_id_issued_at: c.client_id_issued_at,
            client_secret_expires_at: c.client_secret_expires_at,
            registration_client_uri: c.registration_client_uri.clone(),
            label: c.label.clone(),
            enabled: c.enabled,
            created_at: c.created_at,
            updated_at: c.updated_at,
        }
    }
}
