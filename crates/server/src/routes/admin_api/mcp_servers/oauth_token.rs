//! OAuth2 token exchange and PKCE helpers for MCP server provisioning.

use serde::Deserialize;

use crate::response::ApiError;

/// Generate a 32-byte cryptographic random state token (base64url-encoded).
pub(super) fn generate_state_token() -> String {
    use base64::Engine;
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Generate PKCE S256 code_verifier and code_challenge.
pub(super) fn generate_pkce() -> (String, String) {
    use base64::Engine;
    use rand::RngCore;
    use sha2::{Digest, Sha256};
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    let verifier = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(Sha256::digest(verifier.as_bytes()));
    (verifier, challenge)
}

#[derive(Deserialize)]
pub(super) struct TokenResponse {
    pub access_token: String,
    pub refresh_token: Option<String>,
    #[allow(dead_code)]
    pub token_type: Option<String>,
    #[allow(dead_code)]
    pub expires_in: Option<u64>,
}

/// Exchange an authorization code for tokens at the provider's token endpoint.
pub(super) async fn exchange_code_for_tokens(
    client: &reqwest::Client,
    token_url: &str,
    code: &str,
    redirect_uri: &str,
    client_id: &str,
    client_secret: Option<&str>,
    code_verifier: Option<&str>,
) -> Result<TokenResponse, ApiError> {
    let mut params = vec![
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", redirect_uri),
        ("client_id", client_id),
    ];
    if let Some(secret) = client_secret {
        params.push(("client_secret", secret));
    }
    if let Some(verifier) = code_verifier {
        params.push(("code_verifier", verifier));
    }

    let response = client
        .post(token_url)
        .form(&params)
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
        .map_err(|e| {
            tracing::warn!(error = %e, "OAuth2 token exchange request failed");
            ApiError::Internal("failed to exchange OAuth2 authorization code".to_string())
        })?;

    let status = response.status();
    if !status.is_success() {
        let _body = response.text().await.unwrap_or_default();
        tracing::warn!(status = %status, "OAuth2 token exchange returned non-success status");
        return Err(ApiError::Internal(format!(
            "OAuth2 token exchange failed with status {status}"
        )));
    }

    response.json::<TokenResponse>().await.map_err(|e| {
        tracing::warn!(error = %e, "failed to parse OAuth2 token response");
        ApiError::Internal("failed to parse OAuth2 token response".to_string())
    })
}
