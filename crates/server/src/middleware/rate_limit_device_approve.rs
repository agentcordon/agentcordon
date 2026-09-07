//! In-memory per-(address, session) rate limiter for guessing device user
//! codes: `POST /oauth/device/approve`, `POST /oauth/device/deny`, and the
//! browser form `POST /activate`.
//!
//! Caps attempts at 10 per 60-second sliding window per key; the 11th
//! attempt is short-circuited with `429 Too Many Requests` carrying a
//! `Retry-After` header. A failed attempt is any 4xx response, or a
//! redirect to anywhere but the success page (the browser form answers a
//! bad or expired code with a redirect). A successful approval does not
//! consume budget.
//!
//! **Key composition**: `format!("{addr}|{user_fp}")`. The address comes
//! from [`ClientAddr`]: the listener's peer address, or `X-Forwarded-For`
//! only when the deployment trusts its proxy. The user fingerprint is a
//! SHA-256 hash of the session cookie, so one user cannot spend another's
//! budget from the same address.

use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::{
    extract::{Request, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use dashmap::DashMap;
use sha2::{Digest, Sha256};

use crate::extractors::ClientAddr;
use crate::response::OAuthError;
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
        let mut entry = self.buckets.entry(key.to_string()).or_insert(Bucket {
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
    let limiter = state.limits.device_approve.clone();
    let (parts, body) = request.into_parts();
    let ClientAddr(addr) = ClientAddr::resolve(&parts, state.config.trust_forwarded_headers);
    let user_fp = extract_user_fingerprint(&parts.headers);
    let key = format!("{addr}|{user_fp}");
    let request = Request::from_parts(parts, body);

    if let Some(retry_after) = limiter.check(&key) {
        let mut resp = OAuthError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "too_many_requests",
            "too many device approval attempts; retry later",
        )
        .into_response();
        if let Ok(v) = HeaderValue::from_str(&retry_after.to_string()) {
            resp.headers_mut().insert("retry-after", v);
        }
        return resp;
    }

    let response = next.run(request).await;
    if is_failed_attempt(&response) {
        limiter.record_failure(&key);
    }
    response
}

/// A 4xx, or a redirect to anywhere but the success page. The JSON routes
/// answer a bad code with 4xx; the browser form redirects to an
/// expired/denied page instead.
fn is_failed_attempt(response: &Response) -> bool {
    let status = response.status();
    if status.is_client_error() {
        return true;
    }
    if status.is_redirection() {
        let location = response
            .headers()
            .get(axum::http::header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        return location != "/activate/success";
    }
    false
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
}
