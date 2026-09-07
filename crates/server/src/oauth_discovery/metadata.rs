use agent_cordon_core::proxy::url_safety::validate_proxy_target_resolved;
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
        .user_agent(agent_cordon_core::user_agent_for("oauth-discovery"))
        .build()
        .expect("failed to build discovery HTTP client")
}

const MAX_METADATA_BYTES: usize = 64 * 1024;

/// The RFC 9728 metadata URL for a resource identifier.
pub fn protected_resource_metadata_url(resource_url: &str) -> String {
    format!(
        "{}/.well-known/oauth-protected-resource",
        resource_url.trim_end_matches('/')
    )
}

/// Fetch /.well-known/oauth-protected-resource from the given resource URL.
pub async fn fetch_protected_resource(
    resource_url: &str,
) -> Result<ProtectedResourceMetadata, DiscoveryError> {
    fetch_protected_resource_metadata_url(&protected_resource_metadata_url(resource_url)).await
}

/// Fetch RFC 9728 protected-resource metadata from an absolute metadata URL.
///
/// Used directly when the URL came from the `resource_metadata` parameter of a
/// `WWW-Authenticate` challenge, where the resource server — not the client —
/// chooses where its metadata lives.
pub async fn fetch_protected_resource_metadata_url(
    metadata_url: &str,
) -> Result<ProtectedResourceMetadata, DiscoveryError> {
    verify_scheme(metadata_url)?;
    let client = discovery_http_client();
    let resp = client.get(metadata_url).send().await.map_err(|e| {
        if e.is_timeout() {
            DiscoveryError::Timeout
        } else {
            DiscoveryError::RequestFailed(e.to_string())
        }
    })?;
    let status = resp.status();
    if !status.is_success() {
        return Err(DiscoveryError::RequestFailed(format!(
            "protected-resource metadata: HTTP {}",
            status.as_u16()
        )));
    }
    let bytes = read_capped_body(resp).await?;
    serde_json::from_slice(&bytes).map_err(|e| DiscoveryError::InvalidMetadata(e.to_string()))
}

/// Ask an MCP endpoint where its protected-resource metadata lives (RFC 9728).
///
/// An unauthenticated request draws a `401` whose `WWW-Authenticate: Bearer`
/// challenge carries `resource_metadata="<url>"`. Returns `None` when the
/// server answers without that hint; transport failures are `None` too, since
/// the probe is only ever a fallback for a template with no configured
/// resource URL.
pub async fn probe_resource_metadata_url(mcp_url: &str) -> Option<String> {
    verify_scheme(mcp_url).ok()?;
    let client = discovery_http_client();

    if let Ok(resp) = client.get(mcp_url).send().await {
        if let Some(hint) = resource_metadata_hint(&resp) {
            return Some(hint);
        }
    }

    // Streamable-HTTP MCP servers often answer `GET` with 405; the challenge
    // then only appears on a JSON-RPC POST.
    let init = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": { "name": "agentcordon", "version": env!("CARGO_PKG_VERSION") }
        }
    });
    let resp = client.post(mcp_url).json(&init).send().await.ok()?;
    resource_metadata_hint(&resp)
}

fn resource_metadata_hint(resp: &reqwest::Response) -> Option<String> {
    let header = resp.headers().get(reqwest::header::WWW_AUTHENTICATE)?;
    parse_resource_metadata_challenge(header.to_str().ok()?)
}

/// Pull `resource_metadata` out of a `WWW-Authenticate: Bearer …` challenge.
///
/// The parameter is defined by RFC 9728 and is the discovery hint an MCP
/// server returns with its `401`. Values may be quoted or bare, and the
/// challenge may carry other parameters (`realm`, `error`, …) in any order.
pub fn parse_resource_metadata_challenge(header: &str) -> Option<String> {
    const KEY: &str = "resource_metadata";
    // `to_ascii_lowercase` is byte-length preserving, so indices are shared.
    let lower = header.to_ascii_lowercase();
    if !lower.contains("bearer") {
        return None;
    }

    let mut from = 0usize;
    while let Some(offset) = lower[from..].find(KEY) {
        let start = from + offset;
        from = start + KEY.len();

        // Must be a whole parameter name, not the tail of a longer one.
        let preceded_ok = start == 0
            || !matches!(lower.as_bytes()[start - 1], b'_' | b'-' | b'0'..=b'9' | b'a'..=b'z');
        let rest = header[from..].trim_start();
        let Some(rest) = rest.strip_prefix('=') else {
            continue;
        };
        if !preceded_ok {
            continue;
        }
        let rest = rest.trim_start();
        let value = match rest.strip_prefix('"') {
            Some(quoted) => quoted.split('"').next().unwrap_or_default(),
            None => rest
                .split(|c: char| c == ',' || c.is_whitespace())
                .next()
                .unwrap_or_default(),
        };
        if !value.is_empty() {
            return Some(value.to_string());
        }
    }
    None
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
    let status = resp.status();
    if !status.is_success() {
        return Err(DiscoveryError::RequestFailed(format!(
            "authorization-server metadata: HTTP {}",
            status.as_u16()
        )));
    }
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

/// Verify that an endpoint URL has the same origin as `base_url`.
///
/// Discovery applies this between an authorization server's `issuer` and every
/// endpoint that server advertises, so a compromised or hostile metadata
/// document cannot send the token exchange to a third origin.
pub fn validate_endpoint_origin(base_url: &str, endpoint_url: &str) -> Result<(), DiscoveryError> {
    let base_origin = normalize_as_url(base_url)?;
    let endpoint_origin = normalize_as_url(endpoint_url)?;
    if base_origin != endpoint_origin {
        return Err(DiscoveryError::CrossOriginEndpoint {
            expected: base_origin,
            actual: endpoint_origin,
        });
    }
    Ok(())
}

/// RFC 8414: the `issuer` in authorization-server metadata must identify the
/// URL the metadata was fetched from. Without this an attacker-controlled
/// metadata document could claim any issuer identity it liked.
pub fn validate_issuer(as_url: &str, issuer: &str) -> Result<(), DiscoveryError> {
    let expected = normalize_as_url(as_url)?;
    let actual = normalize_as_url(issuer)?;
    if expected != actual {
        return Err(DiscoveryError::IssuerMismatch { expected, actual });
    }
    Ok(())
}

/// Gate every URL discovery is about to fetch.
///
/// Checks the scheme (HTTPS, or HTTP for a loopback host) and then, unless the
/// deployment allows loopback targets, resolves the host and refuses any answer
/// in a private or reserved range — the same SSRF guard the broker and MCP tool
/// discovery apply. Discovery follows URLs chosen by a remote resource server,
/// so this is what keeps it off the internal network.
pub async fn guard_fetch_target(url: &str, allow_loopback: bool) -> Result<(), DiscoveryError> {
    verify_scheme(url)?;
    if allow_loopback {
        return Ok(());
    }
    validate_proxy_target_resolved(url)
        .await
        .map_err(|reason| DiscoveryError::BlockedTarget(format!("{url}: {reason}")))
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
    fn test_validate_issuer_matches_metadata_url() {
        validate_issuer("https://as.example.com", "https://as.example.com").unwrap();
        validate_issuer("https://as.example.com", "https://AS.example.com/").unwrap();
    }

    #[test]
    fn test_validate_issuer_rejects_other_origin() {
        let err = validate_issuer("https://as.example.com", "https://evil.example").unwrap_err();
        assert!(matches!(err, DiscoveryError::IssuerMismatch { .. }));
    }

    #[test]
    fn test_parse_resource_metadata_challenge() {
        assert_eq!(
            parse_resource_metadata_challenge(
                r#"Bearer realm="mcp", resource_metadata="https://rs.example/.well-known/oauth-protected-resource""#
            )
            .as_deref(),
            Some("https://rs.example/.well-known/oauth-protected-resource")
        );
        // Bare value, parameter first, extra parameters after.
        assert_eq!(
            parse_resource_metadata_challenge(
                "Bearer resource_metadata=https://rs.example/prm, error=\"invalid_token\""
            )
            .as_deref(),
            Some("https://rs.example/prm")
        );
    }

    #[test]
    fn test_parse_resource_metadata_challenge_absent() {
        assert!(parse_resource_metadata_challenge(r#"Bearer realm="mcp""#).is_none());
        // Not a Bearer challenge.
        assert!(
            parse_resource_metadata_challenge(r#"ApiKey resource_metadata="https://x/prm""#)
                .is_none()
        );
        // A longer parameter name that merely ends in the one we want.
        assert!(parse_resource_metadata_challenge(
            r#"Bearer other_resource_metadata="https://evil.example/prm""#
        )
        .is_none());
    }

    #[test]
    fn test_validate_endpoint_origin_mismatch() {
        let err =
            validate_endpoint_origin("https://example.com/resource", "https://evil.com/token")
                .unwrap_err();
        assert!(matches!(err, DiscoveryError::CrossOriginEndpoint { .. }));
    }
}
