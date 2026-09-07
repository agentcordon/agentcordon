//! The client's network address, for per-address limits.
//!
//! Prefers the peer address the listener recorded (`ConnectInfo`, installed
//! by `main.rs`). Falls back to `X-Forwarded-For` only when the deployment
//! says a trusted reverse proxy sets it; otherwise that header is
//! attacker-controlled and every caller shares one bucket, which is the
//! safe direction to fail in. Never fails to extract.

use std::convert::Infallible;
use std::net::SocketAddr;

use axum::{
    extract::{ConnectInfo, FromRef, FromRequestParts},
    http::request::Parts,
};

use crate::state::AppState;

/// Best-available client address as a string, or `"unknown"`.
#[derive(Debug, Clone)]
pub struct ClientAddr(pub String);

impl ClientAddr {
    pub fn resolve(parts: &Parts, trust_forwarded_headers: bool) -> Self {
        if let Some(ConnectInfo(addr)) = parts.extensions.get::<ConnectInfo<SocketAddr>>() {
            return ClientAddr(addr.ip().to_string());
        }
        if trust_forwarded_headers {
            if let Some(first) = parts
                .headers
                .get("x-forwarded-for")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.split(',').next())
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                return ClientAddr(first.to_string());
            }
        }
        ClientAddr("unknown".to_string())
    }
}

impl<S> FromRequestParts<S> for ClientAddr
where
    AppState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = Infallible;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let app_state = AppState::from_ref(state);
        Ok(Self::resolve(
            parts,
            app_state.config.trust_forwarded_headers,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Request;

    fn parts(xff: Option<&str>, peer: Option<&str>) -> Parts {
        let mut builder = Request::builder().uri("/");
        if let Some(v) = xff {
            builder = builder.header("x-forwarded-for", v);
        }
        let (mut parts, _) = builder.body(()).unwrap().into_parts();
        if let Some(p) = peer {
            let addr: SocketAddr = p.parse().unwrap();
            parts.extensions.insert(ConnectInfo(addr));
        }
        parts
    }

    #[test]
    fn peer_address_wins_over_any_header() {
        let p = parts(Some("203.0.113.7"), Some("10.1.2.3:9999"));
        assert_eq!(ClientAddr::resolve(&p, true).0, "10.1.2.3");
        assert_eq!(ClientAddr::resolve(&p, false).0, "10.1.2.3");
    }

    #[test]
    fn forwarded_header_used_only_when_trusted() {
        let p = parts(Some("203.0.113.7, 10.0.0.1"), None);
        assert_eq!(ClientAddr::resolve(&p, true).0, "203.0.113.7");
        assert_eq!(ClientAddr::resolve(&p, false).0, "unknown");
    }

    #[test]
    fn nothing_known_is_unknown() {
        let p = parts(None, None);
        assert_eq!(ClientAddr::resolve(&p, true).0, "unknown");
    }
}
