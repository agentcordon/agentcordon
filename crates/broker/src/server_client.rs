//! HTTP client for calling the AgentCordon server.

use serde::{Deserialize, Serialize};

/// HTTP client for server communication (OAuth, credential vend, MCP).
#[derive(Clone)]
pub struct ServerClient {
    http: reqwest::Client,
    base_url: String,
}

// ---------------------------------------------------------------------------
// Server response types
// ---------------------------------------------------------------------------

/// Generic API envelope from the server.
#[derive(Debug, Deserialize)]
pub struct ApiEnvelope<T> {
    pub data: T,
}

/// Response from `POST /api/v1/oauth/device/code` (RFC 8628 §3.2).
#[derive(Debug, Clone, Deserialize)]
pub struct DeviceCodeResponse {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    #[serde(default)]
    pub verification_uri_complete: Option<String>,
    pub expires_in: u64,
    #[serde(default = "default_device_interval")]
    pub interval: u64,
}

fn default_device_interval() -> u64 {
    5
}

/// Outcome of a single device-code token poll. The four RFC 8628 §3.5
/// error values are first-class variants so the broker's poll loop can
/// implement its `slow_down`/`expired_token`/`access_denied` state machine
/// without reparsing strings.
#[derive(Debug)]
pub enum DeviceTokenPollResult {
    Pending,
    SlowDown,
    Expired,
    Denied,
    Success(TokenResponse),
    /// Any other RFC-defined error (e.g. `invalid_grant`).
    Other(String),
    /// Transport / deserialization error — treat like `Pending` in the
    /// caller (retry) but log.
    Transport(String),
}

#[derive(Debug, Deserialize)]
struct DeviceTokenErrorBody {
    error: String,
}

/// Response from `POST /api/v1/oauth/token`.
#[derive(Debug, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    #[allow(dead_code)]
    pub token_type: String,
    pub expires_in: u64,
    pub refresh_token: Option<String>,
    pub scope: Option<String>,
}

/// Credential vend response from the server.
#[derive(Debug, Deserialize)]
pub struct VendResponse {
    #[allow(dead_code)]
    pub credential_id: Option<String>,
    #[allow(dead_code)]
    pub credential_name: Option<String>,
    #[allow(dead_code)]
    pub credential_type: String,
    pub transform_name: Option<String>,
    pub encrypted_envelope: VendEnvelope,
    #[allow(dead_code)]
    pub vend_id: String,
}

/// ECIES envelope from vend response.
#[derive(Debug, Deserialize)]
pub struct VendEnvelope {
    pub version: u8,
    pub ephemeral_public_key: String,
    pub ciphertext: String,
    pub nonce: String,
    pub aad: String,
}

/// Summary of a credential (from list endpoint).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialSummary {
    pub id: String,
    pub name: String,
    pub service: Option<String>,
    pub credential_type: String,
    #[serde(default)]
    pub scopes: Vec<String>,
    pub allowed_url_pattern: Option<String>,
    pub expires_at: Option<String>,
    #[serde(default)]
    pub expired: bool,
    pub vault: Option<String>,
}

/// MCP server summary from the server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpServerSummary {
    pub name: String,
    pub description: Option<String>,
    #[serde(default)]
    pub tools: Vec<String>,
    pub transport: Option<String>,
    pub url: Option<String>,
}

/// MCP tool summary from the server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpToolSummary {
    pub server: String,
    pub tool: String,
    pub description: Option<String>,
    pub input_schema: Option<serde_json::Value>,
}

/// MCP server sync entry (from credential-enhanced sync endpoint).
#[derive(Debug, Clone, Deserialize)]
pub struct McpServerSyncEntry {
    pub id: String,
    pub name: String,
    pub transport: String,
    pub url: Option<String>,
    #[serde(default)]
    pub tools: Vec<String>,
    pub enabled: bool,
    pub auth_method: String,
    pub credential_envelopes: Option<Vec<McpCredentialEnvelope>>,
}

/// ECIES-encrypted credential envelope for an MCP server's credential.
#[derive(Debug, Clone, Deserialize)]
pub struct McpCredentialEnvelope {
    pub credential_name: String,
    pub credential_type: String,
    pub transform_name: Option<String>,
    pub encrypted_envelope: EncryptedEnvelopeResponse,
}

/// Wire format for an ECIES encrypted envelope (deserialization side).
#[derive(Debug, Clone, Deserialize)]
pub struct EncryptedEnvelopeResponse {
    pub version: u8,
    pub ephemeral_public_key: String,
    pub ciphertext: String,
    pub nonce: String,
    pub aad: String,
}

/// MCP authorization response.
#[derive(Debug, Deserialize)]
pub struct McpAuthorizeResponse {
    pub decision: String,
    pub correlation_id: String,
}

/// Client error type.
#[derive(Debug, thiserror::Error)]
pub enum ServerClientError {
    #[error("request failed: {0}")]
    RequestFailed(String),
    #[error("server returned {status}: {body}")]
    ServerError { status: u16, body: String },
    #[error("invalid response: {0}")]
    InvalidResponse(String),
}

impl ServerClient {
    pub fn new(http: reqwest::Client, base_url: String) -> Self {
        Self {
            http,
            base_url: base_url.trim_end_matches('/').to_string(),
        }
    }

    /// Request a device authorization code (RFC 8628 §3.1).
    ///
    /// Extends RFC 8628 with AgentCordon-specific `workspace_name` and
    /// `public_key_hash` form fields so the server can bind the pending
    /// device code to a specific workspace identity. On approval the server
    /// creates (or replaces, per the v0.3.0 locked-decision behaviour) the
    /// workspace owned by the approving user.
    pub async fn request_device_code(
        &self,
        client_id: &str,
        scopes: &[String],
        workspace_name: &str,
        public_key_hash: &str,
    ) -> Result<DeviceCodeResponse, ServerClientError> {
        let url = format!("{}/api/v1/oauth/device/code", self.base_url);

        let scope = scopes.join(" ");
        let params = [
            ("client_id", client_id),
            ("scope", &scope),
            ("workspace_name", workspace_name),
            ("public_key_hash", public_key_hash),
        ];

        let resp = self
            .http
            .post(&url)
            .form(&params)
            .send()
            .await
            .map_err(|e| ServerClientError::RequestFailed(e.to_string()))?;

        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(ServerClientError::ServerError {
                status: status.as_u16(),
                body: text,
            });
        }

        let device_resp: DeviceCodeResponse = resp
            .json()
            .await
            .map_err(|e| ServerClientError::InvalidResponse(e.to_string()))?;
        Ok(device_resp)
    }

    /// Poll the server's token endpoint once with the device_code grant
    /// (RFC 8628 §3.4). Returns a [`DeviceTokenPollResult`] rather than an
    /// error for the four RFC-defined pending/failure cases, because the
    /// caller drives its own state machine around them.
    ///
    /// SECURITY: `device_code` is a secret — callers must not log it.
    pub async fn poll_device_token(
        &self,
        device_code: &str,
        client_id: &str,
    ) -> DeviceTokenPollResult {
        let url = format!("{}/api/v1/oauth/token", self.base_url);

        let params = [
            ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
            ("device_code", device_code),
            ("client_id", client_id),
        ];

        let resp = match self.http.post(&url).form(&params).send().await {
            Ok(r) => r,
            Err(e) => return DeviceTokenPollResult::Transport(e.to_string()),
        };

        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();

        if status.is_success() {
            match serde_json::from_str::<TokenResponse>(&text) {
                Ok(t) => DeviceTokenPollResult::Success(t),
                Err(e) => DeviceTokenPollResult::Transport(format!("invalid token JSON: {e}")),
            }
        } else {
            // RFC 8628 §3.5 defines error codes in a JSON body on 4xx.
            let err: DeviceTokenErrorBody =
                serde_json::from_str(&text).unwrap_or(DeviceTokenErrorBody {
                    error: "invalid_request".to_string(),
                });
            match err.error.as_str() {
                "authorization_pending" => DeviceTokenPollResult::Pending,
                "slow_down" => DeviceTokenPollResult::SlowDown,
                "expired_token" => DeviceTokenPollResult::Expired,
                "access_denied" => DeviceTokenPollResult::Denied,
                other => DeviceTokenPollResult::Other(other.to_string()),
            }
        }
    }

    /// Refresh an OAuth token.
    pub async fn refresh_token(
        &self,
        refresh_token: &str,
        client_id: &str,
    ) -> Result<TokenResponse, ServerClientError> {
        let url = format!("{}/api/v1/oauth/token", self.base_url);

        let params = [
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
            ("client_id", client_id),
        ];

        let resp = self
            .http
            .post(&url)
            .form(&params)
            .send()
            .await
            .map_err(|e| ServerClientError::RequestFailed(e.to_string()))?;

        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(ServerClientError::ServerError {
                status: status.as_u16(),
                body: text,
            });
        }

        let token_resp: TokenResponse = resp
            .json()
            .await
            .map_err(|e| ServerClientError::InvalidResponse(e.to_string()))?;

        Ok(token_resp)
    }

    /// Vend a credential from the server (ECIES-encrypted).
    pub async fn vend_credential(
        &self,
        credential_name: &str,
        access_token: &str,
        broker_pub_key_b64: &str,
    ) -> Result<VendResponse, ServerClientError> {
        let url = format!(
            "{}/api/v1/credentials/vend-device/{}",
            self.base_url,
            urlencoding::encode(credential_name)
        );

        let body = serde_json::json!({
            "broker_public_key": broker_pub_key_b64,
        });

        let resp = self
            .http
            .post(&url)
            .bearer_auth(access_token)
            .json(&body)
            .send()
            .await
            .map_err(|e| ServerClientError::RequestFailed(e.to_string()))?;

        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(ServerClientError::ServerError {
                status: status.as_u16(),
                body: text,
            });
        }

        let envelope: ApiEnvelope<VendResponse> = resp
            .json()
            .await
            .map_err(|e| ServerClientError::InvalidResponse(e.to_string()))?;

        Ok(envelope.data)
    }

    /// List credentials available to a workspace.
    pub async fn list_credentials(
        &self,
        access_token: &str,
    ) -> Result<Vec<CredentialSummary>, ServerClientError> {
        let url = format!("{}/api/v1/credentials", self.base_url);

        let resp = self
            .http
            .get(&url)
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(|e| ServerClientError::RequestFailed(e.to_string()))?;

        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(ServerClientError::ServerError {
                status: status.as_u16(),
                body: text,
            });
        }

        let envelope: ApiEnvelope<Vec<CredentialSummary>> = resp
            .json()
            .await
            .map_err(|e| ServerClientError::InvalidResponse(e.to_string()))?;

        Ok(envelope.data)
    }

    /// List MCP servers available to a workspace.
    pub async fn list_mcp_servers(
        &self,
        access_token: &str,
    ) -> Result<Vec<McpServerSummary>, ServerClientError> {
        let url = format!("{}/api/v1/workspaces/mcp-servers", self.base_url);

        let resp = self
            .http
            .get(&url)
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(|e| ServerClientError::RequestFailed(e.to_string()))?;

        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(ServerClientError::ServerError {
                status: status.as_u16(),
                body: text,
            });
        }

        // Server returns { data: { servers: [...] } }
        #[derive(Deserialize)]
        struct ServersWrapper {
            servers: Vec<McpServerSummary>,
        }

        let envelope: ApiEnvelope<ServersWrapper> = resp
            .json()
            .await
            .map_err(|e| ServerClientError::InvalidResponse(e.to_string()))?;

        Ok(envelope.data.servers)
    }

    /// List MCP tools available to a workspace.
    pub async fn list_mcp_tools(
        &self,
        access_token: &str,
    ) -> Result<Vec<McpToolSummary>, ServerClientError> {
        let url = format!("{}/api/v1/workspaces/mcp-tools", self.base_url);

        let resp = self
            .http
            .get(&url)
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(|e| ServerClientError::RequestFailed(e.to_string()))?;

        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(ServerClientError::ServerError {
                status: status.as_u16(),
                body: text,
            });
        }

        let envelope: ApiEnvelope<Vec<McpToolSummary>> = resp
            .json()
            .await
            .map_err(|e| ServerClientError::InvalidResponse(e.to_string()))?;

        Ok(envelope.data)
    }

    /// Authorize an MCP tool call via Cedar policy on the server.
    pub async fn mcp_authorize(
        &self,
        server_name: &str,
        tool_name: &str,
        access_token: &str,
    ) -> Result<McpAuthorizeResponse, ServerClientError> {
        let url = format!("{}/api/v1/workspaces/mcp-authorize", self.base_url);

        let body = serde_json::json!({
            "server_name": server_name,
            "tool_name": tool_name,
        });

        let resp = self
            .http
            .post(&url)
            .bearer_auth(access_token)
            .json(&body)
            .send()
            .await
            .map_err(|e| ServerClientError::RequestFailed(e.to_string()))?;

        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(ServerClientError::ServerError {
                status: status.as_u16(),
                body: text,
            });
        }

        let envelope: ApiEnvelope<McpAuthorizeResponse> = resp
            .json()
            .await
            .map_err(|e| ServerClientError::InvalidResponse(e.to_string()))?;

        Ok(envelope.data)
    }

    /// List MCP servers with ECIES-encrypted credential envelopes.
    pub async fn list_mcp_servers_with_credentials(
        &self,
        token: &str,
        broker_public_key: &str,
    ) -> Result<Vec<McpServerSyncEntry>, ServerClientError> {
        let url = format!(
            "{}/api/v1/workspaces/mcp-servers?include_credentials=true&broker_public_key={}",
            self.base_url,
            urlencoding::encode(broker_public_key),
        );

        let resp = self
            .http
            .get(&url)
            .bearer_auth(token)
            .send()
            .await
            .map_err(|e| ServerClientError::RequestFailed(e.to_string()))?;

        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(ServerClientError::ServerError {
                status: status.as_u16(),
                body: text,
            });
        }

        #[derive(Deserialize)]
        struct ServersWrapper {
            servers: Vec<McpServerSyncEntry>,
        }

        let envelope: ApiEnvelope<ServersWrapper> = resp
            .json()
            .await
            .map_err(|e| ServerClientError::InvalidResponse(e.to_string()))?;

        Ok(envelope.data.servers)
    }

    /// Create a credential via the workspace-initiated `agent-store` endpoint.
    ///
    /// `body` is the raw JSON object the server's `agent-store` route accepts
    /// (`name`, `service`, `secret_value`, optional `metadata`, `tags`, etc.).
    /// Returns the deserialized `CredentialSummary` from the server's envelope.
    pub async fn agent_store_credential(
        &self,
        access_token: &str,
        body: &serde_json::Value,
    ) -> Result<CredentialSummary, ServerClientError> {
        let url = format!("{}/api/v1/credentials/agent-store", self.base_url);

        let resp = self
            .http
            .post(&url)
            .bearer_auth(access_token)
            .json(body)
            .send()
            .await
            .map_err(|e| ServerClientError::RequestFailed(e.to_string()))?;

        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(ServerClientError::ServerError {
                status: status.as_u16(),
                body: text,
            });
        }

        let envelope: ApiEnvelope<CredentialSummary> = resp
            .json()
            .await
            .map_err(|e| ServerClientError::InvalidResponse(e.to_string()))?;

        Ok(envelope.data)
    }

    /// Persist a rotated OAuth2 refresh token for an MCP credential.
    ///
    /// Calls the server's workspace-scoped rotation endpoint. The server
    /// enforces that the credential belongs to the calling workspace and
    /// emits an audit event. On success returns `Ok(())`; any non-2xx or
    /// transport error is propagated so the broker can abort the refresh
    /// and avoid caching a stale access token.
    ///
    /// SECURITY: the new refresh token value is sent in the JSON body and
    /// MUST NOT be logged at any level.
    pub async fn update_mcp_credential_refresh_token(
        &self,
        workspace_token: &str,
        credential_name: &str,
        new_refresh_token: &str,
    ) -> Result<(), ServerClientError> {
        let url = format!(
            "{}/api/v1/workspaces/mcp/rotate-refresh-token",
            self.base_url
        );

        let body = serde_json::json!({
            "credential_name": credential_name,
            "new_refresh_token": new_refresh_token,
        });

        let resp = self
            .http
            .post(&url)
            .bearer_auth(workspace_token)
            .json(&body)
            .send()
            .await
            .map_err(|e| ServerClientError::RequestFailed(e.to_string()))?;

        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(ServerClientError::ServerError {
                status: status.as_u16(),
                body: text,
            });
        }
        Ok(())
    }

    /// Check if the server is reachable.
    pub async fn health_check(&self) -> bool {
        let url = format!("{}/health", self.base_url);
        matches!(
            self.http.get(&url).timeout(std::time::Duration::from_secs(5)).send().await,
            Ok(resp) if resp.status().is_success()
        )
    }
}
