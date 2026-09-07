//! The server↔broker wire contract.
//!
//! Every request body, response body, form and query string that crosses
//! between the control-plane server and a broker is defined here exactly
//! once. The server route serialises (or deserialises) the type; the
//! broker's `ServerClient` deserialises (or serialises) the same type. A
//! renamed field is therefore a compile error in both crates rather than a
//! silent production break that leaves both test suites green.
//!
//! Rules for anything added here:
//!
//! - Field names are the wire format. Renaming one is a protocol change and
//!   needs a migration story, not a refactor.
//! - Types carry both `Serialize` and `Deserialize`: each side needs the
//!   opposite half, and the contract tests round-trip them.
//! - Optional fields the server always populates stay `Option` only where a
//!   broker must tolerate an older server omitting them; each such field
//!   says so in its doc comment.
//! - No behaviour lives here. Validation, defaulting and normalisation stay
//!   in the route (server) or the client (broker) that owns the decision.

use serde::{Deserialize, Serialize};

pub mod credentials;
pub mod mcp;
pub mod oauth;

/// The `{"data": ...}` envelope every non-OAuth control-plane response is
/// wrapped in. The server builds it (as `ApiResponse`); the broker reads it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiEnvelope<T> {
    pub data: T,
}

impl<T> ApiEnvelope<T> {
    pub fn ok(data: T) -> Self {
        Self { data }
    }
}

/// An ECIES envelope as it crosses the wire: the binary fields of
/// [`crate::crypto::ecies::EncryptedEnvelope`] base64-encoded.
///
/// Used by both the credential vend response and the MCP sync response;
/// the two must not drift apart, because the broker decrypts both through
/// the same code path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedEnvelopeWire {
    pub version: u8,
    pub ephemeral_public_key: String,
    pub ciphertext: String,
    pub nonce: String,
    pub aad: String,
}

/// `skip_serializing_if` helper for `bool` fields that default to false, so
/// a query string omits them entirely rather than sending `=false`.
pub(crate) fn is_false(b: &bool) -> bool {
    !*b
}
