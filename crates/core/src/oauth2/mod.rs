//! OAuth 2.0 modules for AgentCordon.
//!
//! - `client_credentials`: Token manager for upstream OAuth2 client_credentials grants.
//! - `types`: Domain types for the AgentCordon OAuth 2.0 Authorization Server.
//! - `tokens`: Token generation and PKCE validation utilities.
//! - `storage`: Re-exports the `OAuthStore` trait.

#[cfg(feature = "http-client")]
pub mod client_credentials;

pub mod storage;
pub mod tokens;
pub mod types;

// Re-exports for convenience.
#[cfg(feature = "http-client")]
pub use client_credentials::{OAuth2Error, OAuth2TokenManager, TokenResult};

pub use storage::OAuthStore;
pub use tokens::{
    generate_access_token, generate_auth_code, generate_client_id, generate_client_secret,
    generate_refresh_token, hash_token, validate_pkce,
};
pub use types::{
    OAuthAccessToken, OAuthAuthCode, OAuthClient, OAuthConsent, OAuthRefreshToken, OAuthScope,
};
