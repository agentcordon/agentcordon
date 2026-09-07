//! HTTP client for calling the AgentCordon server.
//!
//! Every request body, form, query string and response body here is one of
//! the shared wire types in [`agent_cordon_core::wire`] — the same types the
//! server's routes use. Nothing on this path builds a body with
//! `serde_json::json!` or reads a response through `serde_json::Value`
//! lookups: a field renamed on the server is a compile error here.

use agent_cordon_core::wire::credentials::{VendRequest, VendResponse};
use agent_cordon_core::wire::mcp::{
    McpAuthorizeRequest, McpAuthorizeResponse, McpServerSyncEntry, McpServerSyncResponse,
    McpSyncQuery, McpToolSyncEntry,
};
use agent_cordon_core::wire::oauth::{
    device_poll_errors, grant_types, DeviceAuthorizationRequest, OAuthErrorBody, TokenRequest,
};
pub use agent_cordon_core::wire::oauth::{DeviceAuthorizationResponse, TokenResponse};
use agent_cordon_core::wire::ApiEnvelope;

use agent_cordon_core::domain::credential::CredentialSummary;

// Re-exported so the rest of the broker names these types through the
// client it talks to the server with.
pub use agent_cordon_core::wire::mcp::McpCredentialEnvelope;
pub use agent_cordon_core::wire::EncryptedEnvelopeWire;

/// HTTP client for server communication (OAuth, credential vend, MCP).
#[derive(Clone)]
pub struct ServerClient {
    http: reqwest::Client,
    base_url: String,
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
    ) -> Result<DeviceAuthorizationResponse, ServerClientError> {
        let url = format!("{}/api/v1/oauth/device/code", self.base_url);

        let form = DeviceAuthorizationRequest {
            client_id: Some(client_id.to_string()),
            scope: Some(scopes.join(" ")),
            workspace_name: Some(workspace_name.to_string()),
            public_key_hash: Some(public_key_hash.to_string()),
        };

        let resp = self
            .http
            .post(&url)
            .form(&form)
            .send()
            .await
            .map_err(|e| ServerClientError::RequestFailed(e.to_string()))?;

        let resp = check_status(resp).await?;

        resp.json()
            .await
            .map_err(|e| ServerClientError::InvalidResponse(e.to_string()))
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

        let form = TokenRequest {
            grant_type: Some(grant_types::DEVICE_CODE.to_string()),
            device_code: Some(device_code.to_string()),
            client_id: Some(client_id.to_string()),
            ..TokenRequest::default()
        };

        let resp = match self.http.post(&url).form(&form).send().await {
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
            let err: OAuthErrorBody =
                serde_json::from_str(&text).unwrap_or_else(|_| OAuthErrorBody {
                    error: "invalid_request".to_string(),
                    error_description: None,
                });
            match err.error.as_str() {
                device_poll_errors::AUTHORIZATION_PENDING => DeviceTokenPollResult::Pending,
                device_poll_errors::SLOW_DOWN => DeviceTokenPollResult::SlowDown,
                device_poll_errors::EXPIRED_TOKEN => DeviceTokenPollResult::Expired,
                device_poll_errors::ACCESS_DENIED => DeviceTokenPollResult::Denied,
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

        let form = TokenRequest {
            grant_type: Some(grant_types::REFRESH_TOKEN.to_string()),
            refresh_token: Some(refresh_token.to_string()),
            client_id: Some(client_id.to_string()),
            ..TokenRequest::default()
        };

        let resp = self
            .http
            .post(&url)
            .form(&form)
            .send()
            .await
            .map_err(|e| ServerClientError::RequestFailed(e.to_string()))?;

        let resp = check_status(resp).await?;

        resp.json()
            .await
            .map_err(|e| ServerClientError::InvalidResponse(e.to_string()))
    }

    /// Vend a credential from the server (ECIES-encrypted) for one request:
    /// `method` and `target_url` name where the credential is about to be
    /// sent so the server can refuse a target outside the credential's
    /// allowed URL pattern.
    pub async fn vend_credential(
        &self,
        credential_name: &str,
        access_token: &str,
        broker_pub_key_b64: &str,
        method: &str,
        target_url: &str,
    ) -> Result<VendResponse, ServerClientError> {
        let url = format!(
            "{}/api/v1/credentials/vend-device/{}",
            self.base_url,
            urlencoding::encode(credential_name)
        );

        let body = VendRequest {
            broker_public_key: Some(broker_pub_key_b64.to_string()),
            method: Some(method.to_string()),
            target_url: Some(target_url.to_string()),
        };

        let resp = self
            .http
            .post(&url)
            .bearer_auth(access_token)
            .json(&body)
            .send()
            .await
            .map_err(|e| ServerClientError::RequestFailed(e.to_string()))?;

        envelope::<VendResponse>(check_status(resp).await?).await
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

        envelope::<Vec<CredentialSummary>>(check_status(resp).await?).await
    }

    /// List MCP servers available to a workspace, without credentials.
    pub async fn list_mcp_servers(
        &self,
        access_token: &str,
    ) -> Result<Vec<McpServerSyncEntry>, ServerClientError> {
        self.sync_mcp_servers(access_token, McpSyncQuery::default())
            .await
    }

    /// List MCP servers with ECIES-encrypted credential envelopes.
    pub async fn list_mcp_servers_with_credentials(
        &self,
        access_token: &str,
        broker_public_key: &str,
    ) -> Result<Vec<McpServerSyncEntry>, ServerClientError> {
        self.sync_mcp_servers(
            access_token,
            McpSyncQuery {
                include_credentials: true,
                broker_public_key: Some(broker_public_key.to_string()),
            },
        )
        .await
    }

    /// `GET /api/v1/workspaces/mcp-servers` — the one sync call, with and
    /// without credential envelopes.
    async fn sync_mcp_servers(
        &self,
        access_token: &str,
        query: McpSyncQuery,
    ) -> Result<Vec<McpServerSyncEntry>, ServerClientError> {
        let url = format!("{}/api/v1/workspaces/mcp-servers", self.base_url);

        let resp = self
            .http
            .get(&url)
            .query(&query)
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(|e| ServerClientError::RequestFailed(e.to_string()))?;

        let body = envelope::<McpServerSyncResponse>(check_status(resp).await?).await?;
        Ok(body.servers)
    }

    /// List MCP tools available to a workspace.
    pub async fn list_mcp_tools(
        &self,
        access_token: &str,
    ) -> Result<Vec<McpToolSyncEntry>, ServerClientError> {
        let url = format!("{}/api/v1/workspaces/mcp-tools", self.base_url);

        let resp = self
            .http
            .get(&url)
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(|e| ServerClientError::RequestFailed(e.to_string()))?;

        envelope::<Vec<McpToolSyncEntry>>(check_status(resp).await?).await
    }

    /// Authorize an MCP tool call via Cedar policy on the server.
    pub async fn mcp_authorize(
        &self,
        server_name: &str,
        tool_name: &str,
        access_token: &str,
    ) -> Result<McpAuthorizeResponse, ServerClientError> {
        let url = format!("{}/api/v1/workspaces/mcp-authorize", self.base_url);

        let body = McpAuthorizeRequest {
            server_name: server_name.to_string(),
            tool_name: tool_name.to_string(),
        };

        let resp = self
            .http
            .post(&url)
            .bearer_auth(access_token)
            .json(&body)
            .send()
            .await
            .map_err(|e| ServerClientError::RequestFailed(e.to_string()))?;

        envelope::<McpAuthorizeResponse>(check_status(resp).await?).await
    }

    /// Create a credential via the workspace-initiated `agent-store` endpoint.
    ///
    /// `body` is the raw JSON object the CLI sent (`name`, `service`,
    /// `secret_value`, optional `metadata`, `tags`, ...). It is forwarded
    /// unread: the broker deliberately takes no view of the fields the
    /// server's `agent-store` route validates.
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

        envelope::<CredentialSummary>(check_status(resp).await?).await
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

/// Turn a non-2xx answer into a [`ServerClientError::ServerError`] carrying
/// the body, so callers can branch on the status (401 drives token refresh).
async fn check_status(resp: reqwest::Response) -> Result<reqwest::Response, ServerClientError> {
    let status = resp.status();
    if status.is_success() {
        return Ok(resp);
    }
    Err(ServerClientError::ServerError {
        status: status.as_u16(),
        body: resp.text().await.unwrap_or_default(),
    })
}

/// Read a `{"data": ...}` body into `T`.
async fn envelope<T: serde::de::DeserializeOwned>(
    resp: reqwest::Response,
) -> Result<T, ServerClientError> {
    let body: ApiEnvelope<T> = resp
        .json()
        .await
        .map_err(|e| ServerClientError::InvalidResponse(e.to_string()))?;
    Ok(body.data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_response_deserializes_client_id_when_present() {
        let json = r#"{
            "access_token": "at",
            "token_type": "Bearer",
            "expires_in": 900,
            "refresh_token": "rt",
            "scope": "credentials:discover",
            "client_id": "ws-client-abc"
        }"#;
        let resp: TokenResponse = serde_json::from_str(json).expect("parse");
        assert_eq!(resp.client_id.as_deref(), Some("ws-client-abc"));
    }

    #[test]
    fn token_response_deserializes_to_none_when_client_id_absent() {
        // Back-compat: pre-fix server omits the field; broker must parse OK
        // and surface `None` so the install path can decide what to do.
        let json = r#"{
            "access_token": "at",
            "token_type": "Bearer",
            "expires_in": 900,
            "refresh_token": "rt",
            "scope": "credentials:discover"
        }"#;
        let resp: TokenResponse = serde_json::from_str(json).expect("parse");
        assert_eq!(resp.client_id, None);
    }
}
