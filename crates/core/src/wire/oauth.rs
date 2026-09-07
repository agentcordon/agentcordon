//! OAuth wire types shared by the server's authorization-server routes and
//! the broker's enrollment / token-refresh client.
//!
//! `POST /api/v1/oauth/device/code` (RFC 8628 §3.1–3.2) and
//! `POST /api/v1/oauth/token` (RFC 6749 §4.1.3, §6; RFC 8628 §3.4).
//!
//! Both endpoints take `application/x-www-form-urlencoded` bodies, so the
//! request types are serialised as forms, not JSON. `skip_serializing_if`
//! on every optional field keeps an unset field out of the form entirely
//! rather than sending an empty value.

use serde::{Deserialize, Serialize};

/// `POST /oauth/device/code` form body.
///
/// Extends RFC 8628 §3.1 with AgentCordon's `workspace_name` and
/// `public_key_hash` so the server can bind the pending device code to a
/// specific workspace identity.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DeviceAuthorizationRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    /// Space-separated scopes. Empty means "the client's registered scopes".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// The workspace name this device code is for. Stored on the
    /// device_code row so the approver's UI can show the workspace being
    /// authorized and so approve can create the workspace record.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace_name: Option<String>,
    /// SHA-256 hash of the workspace's public key, hex-encoded (the
    /// `sha256:` prefix is accepted). Bound to the device_code row at issue
    /// time; approve verifies the caller re-presents the same hash.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key_hash: Option<String>,
}

/// RFC 8628 §3.2 Device Authorization Response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceAuthorizationResponse {
    /// SECURITY: a secret. Never log it.
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    /// `Option` for tolerance only — this server always sends it.
    #[serde(default)]
    pub verification_uri_complete: Option<String>,
    pub expires_in: i64,
    /// Minimum seconds between polls. `Option` for tolerance only — this
    /// server always sends it; RFC 8628 §3.2 defaults it to 5.
    #[serde(default)]
    pub interval: Option<i64>,
}

/// RFC 8628 §3.2 default poll interval, used when a server omits `interval`.
pub const DEFAULT_DEVICE_POLL_INTERVAL_SECS: i64 = 5;

/// `POST /oauth/token` form body (RFC 6749 §4.1.3, §6, §4.4.2; RFC 8628 §3.4).
///
/// One struct covers every grant; which fields matter is decided by
/// `grant_type` in the server's token service.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TokenRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_type: Option<String>,
    // authorization_code fields
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redirect_uri: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code_verifier: Option<String>,
    // refresh_token fields
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    // device_code grant fields (RFC 8628)
    /// SECURITY: a secret. Never log it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_code: Option<String>,
    // common
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}

/// Grant type values this server implements.
pub mod grant_types {
    pub const AUTHORIZATION_CODE: &str = "authorization_code";
    pub const REFRESH_TOKEN: &str = "refresh_token";
    pub const CLIENT_CREDENTIALS: &str = "client_credentials";
    pub const DEVICE_CODE: &str = "urn:ietf:params:oauth:grant-type:device_code";
}

/// RFC 6749 §5.1 Access Token Response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    /// Space-separated granted scopes. `Option` for tolerance only — this
    /// server always sends it.
    #[serde(default)]
    pub scope: Option<String>,
    /// Per-workspace `client_id` the issued tokens are bound to. The broker
    /// MUST persist this and echo it on subsequent refresh calls — using the
    /// bootstrap client_id instead causes server-side `invalid_grant:
    /// client_id mismatch`. `Option` for back-compat with pre-fix servers;
    /// absent means fall back to the bootstrap id and log, so the
    /// misconfiguration is visible.
    #[serde(default)]
    pub client_id: Option<String>,
}

/// RFC 6749 §5.2 error response body, which RFC 8628 §3.5 reuses for the
/// device-code poll (`authorization_pending`, `slow_down`, `expired_token`,
/// `access_denied`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthErrorBody {
    pub error: String,
    #[serde(default)]
    pub error_description: Option<String>,
}

/// The RFC 8628 §3.5 poll error codes the broker's state machine branches on.
pub mod device_poll_errors {
    pub const AUTHORIZATION_PENDING: &str = "authorization_pending";
    pub const SLOW_DOWN: &str = "slow_down";
    pub const EXPIRED_TOKEN: &str = "expired_token";
    pub const ACCESS_DENIED: &str = "access_denied";
}
