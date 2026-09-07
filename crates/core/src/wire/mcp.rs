//! MCP sync and authorization wire types.
//!
//! `GET /api/v1/workspaces/mcp-servers`, `GET /api/v1/workspaces/mcp-tools`
//! and `POST /api/v1/workspaces/mcp-authorize`.

use serde::{Deserialize, Serialize};

use super::{is_false, EncryptedEnvelopeWire};

/// Query string for `GET /api/v1/workspaces/mcp-servers`.
///
/// The broker serialises this; the server deserialises it. `false` /
/// `None` serialise to nothing, so a plain listing sends no query string.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct McpSyncQuery {
    /// When true, include ECIES-encrypted credential envelopes in the
    /// response. Requires `broker_public_key`.
    #[serde(default, skip_serializing_if = "is_false")]
    pub include_credentials: bool,
    /// Base64url-encoded uncompressed P-256 public key (65 bytes).
    /// Required when `include_credentials` is true.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub broker_public_key: Option<String>,
}

/// One MCP server in the sync response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpServerSyncEntry {
    pub id: String,
    pub name: String,
    /// What this server is for, in one line — the description of the catalog
    /// template it was provisioned from. `None` for a hand-registered server,
    /// which has no description anywhere to give. Added after the rest of the
    /// entry, so it is omitted when absent and an older reader sees the
    /// bytes it always saw.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub transport: String,
    pub url: Option<String>,
    #[serde(default)]
    pub tools: Vec<String>,
    /// True when `tools` is the server's `allowed_tools` allow-list rather
    /// than "nothing is known yet". The broker probes an upstream's
    /// `tools/list` for servers it has no tools for; without this flag a
    /// server narrowed to a subset — or to none — would have its full tool
    /// list handed straight back to the agent by that probe. Added after the
    /// rest of the entry, so an older reader sees the bytes it always saw.
    #[serde(default)]
    pub tools_are_authoritative: bool,
    pub enabled: bool,
    /// Credential IDs this server needs. Informational for the broker: the
    /// material it may actually hold arrives in `credential_envelopes`.
    /// Serialised even when null: the field has always been on the wire.
    #[serde(default)]
    pub required_credentials: Option<Vec<String>>,
    pub auth_method: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_envelopes: Option<Vec<McpCredentialEnvelope>>,
    /// Why one or more required credentials have no envelope: the server
    /// could not obtain an upstream access token for them. Never carries a
    /// secret. The rest of the sync is unaffected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_error: Option<String>,
}

/// An ECIES-encrypted credential envelope for a single credential.
///
/// For `oauth2_user_authorization` and `oauth2_client_credentials`
/// credentials the plaintext is a short-lived upstream access token with
/// its `expires_at`; the refresh token or client secret that produced it
/// stays on the server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpCredentialEnvelope {
    pub credential_name: String,
    pub credential_type: String,
    #[serde(default)]
    pub transform_name: Option<String>,
    pub encrypted_envelope: EncryptedEnvelopeWire,
}

/// Response body for `GET /api/v1/workspaces/mcp-servers` (inside an
/// [`ApiEnvelope`](super::ApiEnvelope)).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpServerSyncResponse {
    pub servers: Vec<McpServerSyncEntry>,
}

/// One tool in the `GET /api/v1/workspaces/mcp-tools` response, which is a
/// bare list inside an [`ApiEnvelope`](super::ApiEnvelope).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpToolSyncEntry {
    pub server: String,
    pub tool: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub input_schema: Option<serde_json::Value>,
}

/// Request body for `POST /api/v1/workspaces/mcp-authorize`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpAuthorizeRequest {
    pub server_name: String,
    pub tool_name: String,
}

/// Response body for `POST /api/v1/workspaces/mcp-authorize` (inside an
/// [`ApiEnvelope`](super::ApiEnvelope)).
///
/// Reasons (`policy_id`, `policy_name`, `statement_index`) are
/// intentionally absent: this is an untrusted-caller-facing endpoint and
/// the reasons would let workspaces enumerate the policy graph. The full
/// reasons are recorded in the `PolicyEvaluated` audit event, retrievable
/// by admins via `correlation_id`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpAuthorizeResponse {
    /// `"permit"` or `"forbid"` — see [`McpAuthorizeResponse::PERMIT`].
    pub decision: String,
    pub correlation_id: String,
}

impl McpAuthorizeResponse {
    /// The only `decision` value that lets a tool call proceed.
    pub const PERMIT: &'static str = "permit";
    /// Every other outcome.
    pub const FORBID: &'static str = "forbid";

    /// True when the tool call is allowed to proceed.
    pub fn is_permit(&self) -> bool {
        self.decision == Self::PERMIT
    }
}
