//! Re-export of the OAuth 2.0 storage trait.
//!
//! The canonical `OAuthStore` trait lives in `crate::storage::traits::oauth_store`.
//! This module re-exports it for convenience when importing from `crate::oauth2`.

pub use crate::storage::traits::OAuthStore;
