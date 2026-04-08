use serde::Deserialize;

use super::error::DiscoveryError;

#[derive(Debug, Clone, Deserialize)]
pub struct ProtectedResourceMetadata {
    pub resource: String,
    pub authorization_servers: Vec<String>,
    #[serde(default)]
    pub bearer_methods_supported: Vec<String>,
    #[serde(default)]
    pub resource_documentation: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AuthorizationServerMetadata {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    #[serde(default)]
    pub registration_endpoint: Option<String>,
    #[serde(default)]
    pub response_types_supported: Vec<String>,
    #[serde(default)]
    pub grant_types_supported: Vec<String>,
    #[serde(default)]
    pub token_endpoint_auth_methods_supported: Vec<String>,
    #[serde(default)]
    pub code_challenge_methods_supported: Vec<String>,
    #[serde(default)]
    pub scopes_supported: Vec<String>,
    #[serde(default)]
    pub revocation_endpoint: Option<String>,
}

/// Build a hardened HTTP client for discovery calls.
/// - 5s timeout
/// - HTTPS only (allow http://127.0.0.1 and http://localhost for dev)
/// - No redirects
/// - Small user-agent
pub fn discovery_http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none())
        .user_agent(concat!(
            "AgentCordon/",
            env!("CARGO_PKG_VERSION"),
            " (oauth-discovery)"
        ))
        .build()
        .expect("failed to build discovery HTTP client")
}

const MAX_METADATA_BYTES: usize = 64 * 1024;

/// Fetch /.well-known/oauth-protected-resource from the given resource URL.
pub async fn fetch_protected_resource(
    resource_url: &str,
) -> Result<ProtectedResourceMetadata, DiscoveryError> {
    let normalized = resource_url.trim_end_matches('/');
    let url = format!("{}/.well-known/oauth-protected-resource", normalized);
    verify_scheme(&url)?;
    let client = discovery_http_client();
    let resp = client.get(&url).send().await.map_err(|e| {
        if e.is_timeout() {
            DiscoveryError::Timeout
        } else {
            DiscoveryError::RequestFailed(e.to_string())
        }
    })?;
    let bytes = read_capped_body(resp).await?;
    serde_json::from_slice(&bytes).map_err(|e| DiscoveryError::InvalidMetadata(e.to_string()))
}

/// Fetch /.well-known/oauth-authorization-server from the given AS URL.
pub async fn fetch_authorization_server_metadata(
    as_url: &str,
) -> Result<AuthorizationServerMetadata, DiscoveryError> {
    let normalized = as_url.trim_end_matches('/');
    let url = format!("{}/.well-known/oauth-authorization-server", normalized);
    verify_scheme(&url)?;
    let client = discovery_http_client();
    let resp = client.get(&url).send().await.map_err(|e| {
        if e.is_timeout() {
            DiscoveryError::Timeout
        } else {
            DiscoveryError::RequestFailed(e.to_string())
        }
    })?;
    let bytes = read_capped_body(resp).await?;
    serde_json::from_slice(&bytes).map_err(|e| DiscoveryError::InvalidMetadata(e.to_string()))
}

async fn read_capped_body(resp: reqwest::Response) -> Result<Vec<u8>, DiscoveryError> {
    if let Some(len) = resp.content_length() {
        if len as usize > MAX_METADATA_BYTES {
            return Err(DiscoveryError::ResponseTooLarge);
        }
    }
    let bytes = resp
        .bytes()
        .await
        .map_err(|e| DiscoveryError::RequestFailed(e.to_string()))?;
    if bytes.len() > MAX_METADATA_BYTES {
        return Err(DiscoveryError::ResponseTooLarge);
    }
    Ok(bytes.to_vec())
}

fn verify_scheme(url: &str) -> Result<(), DiscoveryError> {
    let parsed = url::Url::parse(url).map_err(|e| DiscoveryError::InvalidUrl(e.to_string()))?;
    match parsed.scheme() {
        "https" => Ok(()),
        "http" => {
            let host = parsed.host_str().unwrap_or("");
            if host == "localhost" || host == "127.0.0.1" {
                Ok(())
            } else {
                Err(DiscoveryError::InvalidUrl(format!(
                    "http scheme only allowed for localhost: {}",
                    url
                )))
            }
        }
        other => Err(DiscoveryError::InvalidUrl(format!(
            "unsupported scheme: {}",
            other
        ))),
    }
}

/// Normalize a URL to its origin (scheme + host + port, lowercased, no trailing slash, no path).
pub fn normalize_as_url(url: &str) -> Result<String, DiscoveryError> {
    let parsed = url::Url::parse(url).map_err(|e| DiscoveryError::InvalidUrl(e.to_string()))?;
    let scheme = parsed.scheme().to_lowercase();
    let host = parsed
        .host_str()
        .ok_or_else(|| DiscoveryError::InvalidUrl("no host".to_string()))?
        .to_lowercase();
    match parsed.port() {
        Some(port) => Ok(format!("{}://{}:{}", scheme, host, port)),
        None => Ok(format!("{}://{}", scheme, host)),
    }
}

/// Verify that an endpoint URL has the same origin as the resource URL.
pub fn validate_endpoint_origin(
    resource_url: &str,
    endpoint_url: &str,
) -> Result<(), DiscoveryError> {
    let resource_origin = normalize_as_url(resource_url)?;
    let endpoint_origin = normalize_as_url(endpoint_url)?;
    if resource_origin != endpoint_origin {
        return Err(DiscoveryError::CrossOriginEndpoint {
            expected: resource_origin,
            actual: endpoint_origin,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_as_url_variants() {
        assert_eq!(
            normalize_as_url("https://Example.COM/").unwrap(),
            "https://example.com"
        );
        assert_eq!(
            normalize_as_url("https://example.com:8443/path").unwrap(),
            "https://example.com:8443"
        );
        assert_eq!(
            normalize_as_url("http://localhost:3140").unwrap(),
            "http://localhost:3140"
        );
    }

    #[test]
    fn test_verify_scheme_https() {
        verify_scheme("https://example.com/.well-known/oauth-authorization-server").unwrap();
    }

    #[test]
    fn test_verify_scheme_localhost_http() {
        verify_scheme("http://localhost:3140/x").unwrap();
        verify_scheme("http://127.0.0.1:3140/x").unwrap();
    }

    #[test]
    fn test_verify_scheme_external_http_rejected() {
        assert!(verify_scheme("http://example.com/x").is_err());
        assert!(verify_scheme("ftp://example.com/x").is_err());
    }

    #[test]
    fn test_validate_endpoint_origin_match() {
        validate_endpoint_origin("https://example.com/resource", "https://example.com/token")
            .unwrap();
    }

    #[test]
    fn test_validate_endpoint_origin_mismatch() {
        let err =
            validate_endpoint_origin("https://example.com/resource", "https://evil.com/token")
                .unwrap_err();
        assert!(matches!(err, DiscoveryError::CrossOriginEndpoint { .. }));
    }
}
