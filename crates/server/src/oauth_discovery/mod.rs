//! OAuth 2.0 authorization server discovery and Dynamic Client Registration
//! (RFC 7591 / RFC 7592 / RFC 8414 / RFC 9728).

pub mod cache;
pub mod client;
pub mod error;
pub mod metadata;
pub mod registration;

pub use cache::DiscoveryCache;
pub use client::ensure_provider_client;
pub use error::DiscoveryError;
pub use metadata::{
    discovery_http_client, fetch_authorization_server_metadata, fetch_protected_resource,
    normalize_as_url, validate_endpoint_origin, AuthorizationServerMetadata,
    ProtectedResourceMetadata,
};
pub use registration::{register_client, rotate_registration, DcrRequest, DcrResponse};
