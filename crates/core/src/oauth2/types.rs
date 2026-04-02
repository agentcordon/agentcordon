//! OAuth 2.0 Authorization Server domain types.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::domain::user::UserId;

/// OAuth 2.0 scopes supported by the AgentCordon AS.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum OAuthScope {
    /// Discover available credentials.
    #[serde(rename = "credentials:discover")]
    CredentialsDiscover,
    /// Vend (retrieve) credential values via the proxy.
    #[serde(rename = "credentials:vend")]
    CredentialsVend,
    /// Discover available MCP servers and tools.
    #[serde(rename = "mcp:discover")]
    McpDiscover,
    /// Invoke MCP tools.
    #[serde(rename = "mcp:invoke")]
    McpInvoke,
}

impl std::fmt::Display for OAuthScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OAuthScope::CredentialsDiscover => f.write_str("credentials:discover"),
            OAuthScope::CredentialsVend => f.write_str("credentials:vend"),
            OAuthScope::McpDiscover => f.write_str("mcp:discover"),
            OAuthScope::McpInvoke => f.write_str("mcp:invoke"),
        }
    }
}

impl std::str::FromStr for OAuthScope {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "credentials:discover" => Ok(OAuthScope::CredentialsDiscover),
            "credentials:vend" => Ok(OAuthScope::CredentialsVend),
            "mcp:discover" => Ok(OAuthScope::McpDiscover),
            "mcp:invoke" => Ok(OAuthScope::McpInvoke),
            other => Err(format!("unknown OAuth scope: {}", other)),
        }
    }
}

impl OAuthScope {
    /// Parse a space-separated scope string into a list of scopes.
    pub fn parse_scope_string(s: &str) -> Result<Vec<OAuthScope>, String> {
        if s.is_empty() {
            return Ok(Vec::new());
        }
        s.split_whitespace().map(|part| part.parse()).collect()
    }

    /// Serialize a list of scopes to a space-separated string.
    pub fn to_scope_string(scopes: &[OAuthScope]) -> String {
        scopes
            .iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>()
            .join(" ")
    }
}

/// An OAuth 2.0 client registration (one per workspace).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthClient {
    pub id: Uuid,
    /// Client identifier in `ac_cli_{random}` format.
    pub client_id: String,
    /// SHA-256 hash of the client secret, or `None` for public clients.
    pub client_secret_hash: Option<String>,
    pub workspace_name: String,
    /// SHA-256 of the workspace Ed25519 public key.
    pub public_key_hash: String,
    /// Allowed redirect URIs (must be localhost).
    pub redirect_uris: Vec<String>,
    pub allowed_scopes: Vec<OAuthScope>,
    pub created_by_user: UserId,
    pub created_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

/// An OAuth 2.0 authorization code (single-use, short-lived).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthAuthCode {
    /// SHA-256 hash of the authorization code.
    pub code_hash: String,
    pub client_id: String,
    pub user_id: UserId,
    pub redirect_uri: String,
    pub scopes: Vec<OAuthScope>,
    /// PKCE S256 code challenge.
    pub code_challenge: Option<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub consumed_at: Option<DateTime<Utc>>,
}

/// An OAuth 2.0 access token (opaque, stored as hash).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthAccessToken {
    /// SHA-256 hash of the access token.
    pub token_hash: String,
    pub client_id: String,
    pub user_id: UserId,
    pub scopes: Vec<OAuthScope>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

/// An OAuth 2.0 refresh token (opaque, stored as hash).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthRefreshToken {
    /// SHA-256 hash of the refresh token.
    pub token_hash: String,
    pub client_id: String,
    pub user_id: UserId,
    pub scopes: Vec<OAuthScope>,
    /// Hash of the associated access token.
    pub access_token_hash: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

/// A consent record (user approved scopes for a client).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthConsent {
    pub client_id: String,
    pub user_id: UserId,
    pub scopes: Vec<OAuthScope>,
    pub granted_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scope_display_roundtrip() {
        let scopes = vec![
            OAuthScope::CredentialsDiscover,
            OAuthScope::CredentialsVend,
            OAuthScope::McpInvoke,
        ];
        for scope in &scopes {
            let s = scope.to_string();
            let parsed: OAuthScope = s.parse().unwrap();
            assert_eq!(&parsed, scope);
        }
    }

    #[test]
    fn test_scope_from_str_unknown() {
        let result = "unknown:scope".parse::<OAuthScope>();
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_scope_string() {
        let scopes = OAuthScope::parse_scope_string("credentials:discover mcp:invoke").unwrap();
        assert_eq!(scopes.len(), 2);
        assert_eq!(scopes[0], OAuthScope::CredentialsDiscover);
        assert_eq!(scopes[1], OAuthScope::McpInvoke);
    }

    #[test]
    fn test_parse_scope_string_empty() {
        let scopes = OAuthScope::parse_scope_string("").unwrap();
        assert!(scopes.is_empty());
    }

    #[test]
    fn test_to_scope_string() {
        let scopes = vec![OAuthScope::CredentialsVend, OAuthScope::McpInvoke];
        let s = OAuthScope::to_scope_string(&scopes);
        assert_eq!(s, "credentials:vend mcp:invoke");
    }

    #[test]
    fn test_scope_serde_roundtrip() {
        let scope = OAuthScope::CredentialsDiscover;
        let json = serde_json::to_string(&scope).unwrap();
        assert_eq!(json, "\"credentials:discover\"");
        let parsed: OAuthScope = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, scope);
    }
}
