//! Credential vend wire types.
//!
//! `POST /api/v1/credentials/{id}/vend` and
//! `POST /api/v1/credentials/vend-device/{name}`.

use serde::{Deserialize, Serialize};

use super::EncryptedEnvelopeWire;

/// Request body for the vend endpoints.
///
/// Every field is optional on the wire: an admin-initiated vend may send no
/// body at all. The server decides what a missing `target_url` means (see
/// the route), and the broker always sends all three.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VendRequest {
    /// Base64url-encoded uncompressed P-256 public key (65 bytes decoded).
    /// When present, the server encrypts the credential envelope to this key
    /// instead of the workspace's `encryption_public_key`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub broker_public_key: Option<String>,
    /// HTTP method of the request the credential will be injected into.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    /// Full URL of that request. Checked against the credential's allowed
    /// URL pattern; required when the credential has one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_url: Option<String>,
}

/// Response body for the vend endpoints (inside an
/// [`ApiEnvelope`](super::ApiEnvelope)).
///
/// The credential material is ONLY in `encrypted_envelope`; everything else
/// is metadata the broker needs to inject it correctly.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VendResponse {
    /// Drives which injection transform the broker applies. NOT carried in
    /// the envelope plaintext — the broker must read it from here.
    pub credential_type: String,
    /// Named built-in or Rhai transform to apply before injection.
    #[serde(default)]
    pub transform_name: Option<String>,
    /// The pattern the server checked the target against. The broker checks
    /// again right before injecting; absent means the credential is unbound.
    #[serde(default)]
    pub allowed_url_pattern: Option<String>,
    pub encrypted_envelope: EncryptedEnvelopeWire,
    /// Correlates this vend with its audit event.
    pub vend_id: String,
}
