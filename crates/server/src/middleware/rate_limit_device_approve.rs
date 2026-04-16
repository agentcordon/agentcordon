//! In-memory per-(IP,user) rate limiter for `/oauth/device/approve` and
//! `/oauth/device/deny`.
//!
//! Caps attempts at 10 per 60-second sliding window per key; the 11th
//! attempt is short-circuited with `429 Too Many Requests` carrying a
//! `Retry-After` header. Only 4xx responses are counted — a successful
//! 200 approval does not consume budget.
//!
//! **Key composition**: `format!("{ip}|{user_fp}")`. The IP comes from
//! `X-Forwarded-For` if present (dev-server sits behind no proxy so
//! `ConnectInfo` collapses every caller to 127.0.0.1), else from the
//! `ConnectInfo<SocketAddr>` extension if the server was bound with
//! connect-info, else the literal `"unknown"`. The user fingerprint is
//! a SHA-256 hash of the session cookie (not the userId, which we would
//! have to do a DB round-trip to resolve). This satisfies the "include
//! user_id so a malicious user cannot DoS other users from the same IP"
//! requirement because session cookies are per-user.
//!
//! NOTE: `X-Forwarded-For` is trusted unconditionally here because the
//! local/dev deployment has no proxy. A production deployment must gate
//! this behind a trusted-proxy allowlist before relying on the header.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::{
    extract::{ConnectInfo, Request, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use dashmap::DashMap;
use sha2::{Digest, Sha256};

use crate::state::AppState;
use crate::utils::cookies::parse_cookie;

/// Attempts per window before responding 429.
const MAX_ATTEMPTS: u32 = 10;
/// Window length in seconds.
const WINDOW_SECS: u64 = 60;

const SESSION_COOKIE_NAME: &str = "agtcrdn_session";

#[derive(Debug, Clone, Copy)]
struct Bucket {
    count: u32,
    window_start: Instant,
}

/// Shared in-memory bucket map. Holds one entry per `{ip}|{user_fp}` key.
#[derive(Debug, Default)]
pub struct DeviceApproveRateLimiter {
    buckets: DashMap<String, Bucket>,
}

impl DeviceApproveRateLimiter {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            buckets: DashMap::new(),
        })
    }

    /// Return `Some(retry_after_secs)` if the key is currently over the
    /// threshold and must be rejected, else `None`.
    fn check(&self, key: &str) -> Option<u64> {
        let now = Instant::now();
        let window = Duration::from_secs(WINDOW_SECS);
        let bucket = self.buckets.get(key).map(|b| *b);
        match bucket {
            Some(b) if now.duration_since(b.window_start) < window => {
                if b.count >= MAX_ATTEMPTS {
                    let remaining = window
                        .saturating_sub(now.duration_since(b.window_start))
                        .as_secs()
                        .max(1);
                    Some(remaining)
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    /// Increment the counter for this key on a 4xx outcome. Rolls the
    /// window forward if the previous window has fully elapsed.
    fn record_failure(&self, key: &str) {
        let now = Instant::now();
        let window = Duration::from_secs(WINDOW_SECS);
        let mut entry = self
            .buckets
            .entry(key.to_string())
            .or_insert(Bucket {
                count: 0,
                window_start: now,
            });
        if now.duration_since(entry.window_start) >= window {
            entry.count = 1;
            entry.window_start = now;
        } else {
            entry.count = entry.count.saturating_add(1);
        }
    }
}

fn extract_client_ip(headers: &HeaderMap, connect_info: Option<SocketAddr>) -> String {
    if let Some(raw) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        if let Some(first) = raw.split(',').next() {
            let trimmed = first.trim();
            if !trimmed.is_empty() {
                return trimmed.to_string();
            }
        }
    }
    connect_info
        .map(|a| a.ip().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

fn extract_user_fingerprint(headers: &HeaderMap) -> String {
    let cookie_header = match headers
        .get(axum::http::header::COOKIE)
        .and_then(|v| v.to_str().ok())
    {
        Some(h) => h,
        None => return "anon".to_string(),
    };
    match parse_cookie(cookie_header, SESSION_COOKIE_NAME) {
        Some(token) => {
            let mut hasher = Sha256::new();
            hasher.update(token.as_bytes());
            hex::encode(hasher.finalize())[..16].to_string()
        }
        None => "anon".to_string(),
    }
}

/// Axum middleware: rate-limit `/oauth/device/approve` and `/oauth/device/deny`.
/// Counts only 4xx responses; 2xx/5xx do not consume budget.
pub async fn rate_limit_device_approve(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    let limiter = state.device_approve_limiter.clone();
    let headers = request.headers().clone();
    let connect_info = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0);
    let ip = extract_client_ip(&headers, connect_info);
    let user_fp = extract_user_fingerprint(&headers);
    let key = format!("{ip}|{user_fp}");

    if let Some(retry_after) = limiter.check(&key) {
        let mut resp = (
            StatusCode::TOO_MANY_REQUESTS,
            axum::Json(serde_json::json!({
                "error": "too_many_requests",
                "error_description": "too many device approval attempts; retry later",
            })),
        )
            .into_response();
        if let Ok(v) = HeaderValue::from_str(&retry_after.to_string()) {
            resp.headers_mut().insert("retry-after", v);
        }
        return resp;
    }

    let response = next.run(request).await;
    if response.status().is_client_error() {
        limiter.record_failure(&key);
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_allows_below_threshold() {
        let limiter = DeviceApproveRateLimiter::new();
        for _ in 0..MAX_ATTEMPTS - 1 {
            limiter.record_failure("k");
        }
        assert!(limiter.check("k").is_none());
    }

    #[test]
    fn check_blocks_at_threshold() {
        let limiter = DeviceApproveRateLimiter::new();
        for _ in 0..MAX_ATTEMPTS {
            limiter.record_failure("k");
        }
        assert!(limiter.check("k").is_some());
    }

    #[test]
    fn different_keys_independent() {
        let limiter = DeviceApproveRateLimiter::new();
        for _ in 0..MAX_ATTEMPTS {
            limiter.record_failure("a");
        }
        assert!(limiter.check("a").is_some());
        assert!(limiter.check("b").is_none());
    }

    #[test]
    fn ip_from_xff_takes_precedence() {
        let mut h = HeaderMap::new();
        h.insert(
            "x-forwarded-for",
            HeaderValue::from_static("203.0.113.7, 10.0.0.1"),
        );
        let ci = "127.0.0.1:1234".parse::<SocketAddr>().ok();
        assert_eq!(extract_client_ip(&h, ci), "203.0.113.7");
    }

    #[test]
    fn ip_falls_back_to_connect_info() {
        let h = HeaderMap::new();
        let ci = "10.1.2.3:9999".parse::<SocketAddr>().ok();
        assert_eq!(extract_client_ip(&h, ci), "10.1.2.3");
    }

    #[test]
    fn ip_falls_back_to_unknown() {
        let h = HeaderMap::new();
        assert_eq!(extract_client_ip(&h, None), "unknown");
    }
}
