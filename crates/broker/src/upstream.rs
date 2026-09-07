//! The broker's outbound client for proxied and MCP calls.
//!
//! This client carries injected credentials to third parties, so it is
//! stricter than the one that talks to the AgentCordon server: it never
//! follows a redirect (a 3xx goes back to the caller with the credential
//! still unsent to the new location), it times out, and it refuses to buffer
//! a response beyond a fixed cap.

use std::time::Duration;

use reqwest::header::HeaderMap;

/// Largest upstream response body the broker will hold in memory.
pub const MAX_RESPONSE_BYTES: usize = 10 * 1024 * 1024;

/// Whole-request deadline for one upstream call.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

/// Headers that describe a single connection rather than the message
/// (RFC 9110 §7.6.1). They are meaningless once the message crosses the
/// broker, and forwarding some of them (`Upgrade`, `Transfer-Encoding`)
/// would let a caller change how the connection itself behaves.
const HOP_BY_HOP: [&str; 8] = [
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

pub fn is_hop_by_hop(name: &str) -> bool {
    HOP_BY_HOP.iter().any(|h| name.eq_ignore_ascii_case(h))
}

pub fn build_client() -> Result<reqwest::Client, reqwest::Error> {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(REQUEST_TIMEOUT)
        .user_agent(concat!("agentcordon-broker/", env!("CARGO_PKG_VERSION")))
        .build()
}

#[derive(Debug, thiserror::Error)]
pub enum UpstreamError {
    #[error("upstream request failed: {0}")]
    Transport(#[from] reqwest::Error),
    #[error("upstream response exceeds {MAX_RESPONSE_BYTES} bytes")]
    TooLarge,
}

/// An upstream response read to completion, ready to hand to the caller.
pub struct UpstreamResponse {
    pub status: u16,
    /// End-to-end headers as `(name, value)` in arrival order; repeated
    /// names appear once per value.
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// Read a response through the cap, dropping hop-by-hop headers.
pub async fn collect(mut resp: reqwest::Response) -> Result<UpstreamResponse, UpstreamError> {
    let status = resp.status().as_u16();
    let headers = end_to_end_headers(resp.headers());
    let body = read_body_capped(&mut resp).await?;
    Ok(UpstreamResponse {
        status,
        headers,
        body,
    })
}

/// Read the body in chunks, giving up as soon as the total passes the cap
/// rather than after the whole response has been buffered.
pub async fn read_body_capped(resp: &mut reqwest::Response) -> Result<Vec<u8>, UpstreamError> {
    if resp
        .content_length()
        .is_some_and(|len| len > MAX_RESPONSE_BYTES as u64)
    {
        return Err(UpstreamError::TooLarge);
    }
    let mut body = Vec::new();
    while let Some(chunk) = resp.chunk().await? {
        if body.len() + chunk.len() > MAX_RESPONSE_BYTES {
            return Err(UpstreamError::TooLarge);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn end_to_end_headers(headers: &HeaderMap) -> Vec<(String, String)> {
    headers
        .iter()
        .filter(|(name, _)| !is_hop_by_hop(name.as_str()))
        .map(|(name, value)| {
            (
                name.to_string(),
                String::from_utf8_lossy(value.as_bytes()).into_owned(),
            )
        })
        .collect()
}
