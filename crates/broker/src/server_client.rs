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

    /// Exchange an authorization code for tokens.
    pub async fn exchange_auth_code(
        &self,
        code: &str,
        code_verifier: &str,
        redirect_uri: &str,
        client_id: &str,
    ) -> Result<TokenResponse, ServerClientError> {
        let url = format!("{}/api/v1/oauth/token", self.base_url);

        let params = [
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", redirect_uri),
            ("client_id", client_id),
            ("code_verifier", code_verifier),
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

    /// Check if the server is reachable.
    pub async fn health_check(&self) -> bool {
        let url = format!("{}/health", self.base_url);
        matches!(
            self.http.get(&url).timeout(std::time::Duration::from_secs(5)).send().await,
            Ok(resp) if resp.status().is_success()
        )
    }
}
