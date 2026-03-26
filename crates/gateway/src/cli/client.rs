use reqwest::header;
use serde::de::DeserializeOwned;

/// Wrapper around reqwest for AgentCordon API calls.
pub struct ApiClient {
    client: reqwest::Client,
    base_url: String,
}

/// Standard API response wrapper: `{ "data": T }`
#[derive(serde::Deserialize)]
pub struct ApiResponse<T> {
    pub data: T,
}

/// API error response: `{ "error": { "message": "..." } }`
#[derive(serde::Deserialize)]
struct ApiErrorResponse {
    error: Option<ApiErrorDetail>,
}

#[derive(serde::Deserialize)]
struct ApiErrorDetail {
    message: Option<String>,
}

impl ApiClient {
    pub fn new(base_url: &str) -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .user_agent("agentcordon-cli/1.3.0")
            .build()
            .expect("failed to build HTTP client");

        Self {
            client,
            base_url: base_url.trim_end_matches('/').to_string(),
        }
    }

    /// Make an unauthenticated POST request.
    pub async fn post_unauth<B: serde::Serialize, R: DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<R, String> {
        let url = format!("{}{}", self.base_url, path);
        let resp = self
            .client
            .post(&url)
            .json(body)
            .send()
            .await
            .map_err(|e| format!("request failed: {}", e))?;

        handle_response(resp).await
    }

    /// Make an unauthenticated GET request.
    #[allow(dead_code)]
    pub async fn get_unauth<R: DeserializeOwned>(&self, path: &str) -> Result<R, String> {
        let url = format!("{}{}", self.base_url, path);
        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| format!("request failed: {}", e))?;

        handle_response(resp).await
    }

    /// Make an authenticated POST request (Bearer token).
    #[allow(dead_code)]
    pub async fn post_auth<B: serde::Serialize, R: DeserializeOwned>(
        &self,
        path: &str,
        token: &str,
        body: &B,
    ) -> Result<R, String> {
        let url = format!("{}{}", self.base_url, path);
        let resp = self
            .client
            .post(&url)
            .header(header::AUTHORIZATION, format!("Bearer {}", token))
            .json(body)
            .send()
            .await
            .map_err(|e| format!("request failed: {}", e))?;

        handle_response(resp).await
    }

    /// Make an authenticated GET request (Bearer token).
    pub async fn get_auth<R: DeserializeOwned>(
        &self,
        path: &str,
        token: &str,
    ) -> Result<R, String> {
        let url = format!("{}{}", self.base_url, path);
        let resp = self
            .client
            .get(&url)
            .header(header::AUTHORIZATION, format!("Bearer {}", token))
            .send()
            .await
            .map_err(|e| format!("request failed: {}", e))?;

        handle_response(resp).await
    }

    /// Make an authenticated POST and return raw response text (for non-standard responses).
    pub async fn post_auth_raw<B: serde::Serialize>(
        &self,
        path: &str,
        token: &str,
        body: &B,
    ) -> Result<(u16, String), String> {
        let url = format!("{}{}", self.base_url, path);
        let resp = self
            .client
            .post(&url)
            .header(header::AUTHORIZATION, format!("Bearer {}", token))
            .json(body)
            .send()
            .await
            .map_err(|e| format!("request failed: {}", e))?;

        let status = resp.status().as_u16();
        let body = resp
            .text()
            .await
            .map_err(|e| format!("failed to read response: {}", e))?;
        Ok((status, body))
    }

    /// Make an unauthenticated GET and return raw response (status + body).
    pub async fn get_raw(&self, path: &str) -> Result<(u16, String), String> {
        let url = format!("{}{}", self.base_url, path);
        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| format!("request failed: {}", e))?;

        let status = resp.status().as_u16();
        let body = resp
            .text()
            .await
            .map_err(|e| format!("failed to read response: {}", e))?;
        Ok((status, body))
    }
}

async fn handle_response<R: DeserializeOwned>(resp: reqwest::Response) -> Result<R, String> {
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        if let Ok(err) = serde_json::from_str::<ApiErrorResponse>(&body) {
            if let Some(detail) = err.error {
                if let Some(msg) = detail.message {
                    return Err(format!("{} - {}", status.as_u16(), msg));
                }
            }
        }
        return Err(format!("{} - {}", status.as_u16(), body));
    }

    let body = resp
        .text()
        .await
        .map_err(|e| format!("failed to read response: {}", e))?;
    serde_json::from_str(&body)
        .map_err(|e| format!("failed to parse response: {} (body: {})", e, body))
}
