//! HTTP request metrics middleware.
//!
//! Records per-request counters and histograms for Prometheus exposition.
//! Path segments that look like UUIDs or numeric IDs are replaced with
//! `{id}` to prevent high-cardinality label explosion.

use std::time::Instant;

use axum::{extract::Request, middleware::Next, response::Response};

/// Middleware that records `http_requests_total` (counter) and
/// `http_request_duration_seconds` (histogram) for every request.
pub async fn record_http_metrics(request: Request, next: Next) -> Response {
    let method = request.method().to_string();
    let path = normalize_path(request.uri().path());

    let start = Instant::now();
    let response = next.run(request).await;
    let duration = start.elapsed().as_secs_f64();

    let status = response.status().as_u16().to_string();

    metrics::counter!("http_requests_total", "method" => method.clone(), "path" => path.clone(), "status" => status)
        .increment(1);
    metrics::histogram!("http_request_duration_seconds", "method" => method, "path" => path)
        .record(duration);

    response
}

/// Known path prefixes whose next segment is a dynamic name (not a UUID/numeric ID).
/// These are normalized to `{name}` to prevent high-cardinality label explosion
/// from user-defined names (e.g., vault names).
const DYNAMIC_NAME_PREFIXES: &[&str] = &["vaults"];

/// Replace UUID-shaped, numeric, and known dynamic-name path segments with
/// placeholders to keep label cardinality bounded.
fn normalize_path(path: &str) -> String {
    let segments: Vec<&str> = path.split('/').collect();
    let mut result = Vec::with_capacity(segments.len());

    for (i, segment) in segments.iter().enumerate() {
        if is_uuid(segment) || is_numeric_id(segment) {
            result.push("{id}");
        } else if i > 0 && DYNAMIC_NAME_PREFIXES.contains(&segments[i - 1]) {
            // The segment after a known prefix is a dynamic name — normalize it.
            result.push("{name}");
        } else {
            result.push(segment);
        }
    }

    result.join("/")
}

/// Check if a path segment looks like a UUID (8-4-4-4-12 hex).
fn is_uuid(s: &str) -> bool {
    if s.len() != 36 {
        return false;
    }
    let parts: Vec<&str> = s.split('-').collect();
    if parts.len() != 5 {
        return false;
    }
    let expected_lens = [8, 4, 4, 4, 12];
    parts
        .iter()
        .zip(expected_lens.iter())
        .all(|(part, &len)| part.len() == len && part.chars().all(|c| c.is_ascii_hexdigit()))
}

/// Check if a path segment is a purely numeric ID.
fn is_numeric_id(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_path_uuid() {
        assert_eq!(
            normalize_path("/api/v1/agents/550e8400-e29b-41d4-a716-446655440000"),
            "/api/v1/agents/{id}"
        );
    }

    #[test]
    fn test_normalize_path_numeric_id() {
        assert_eq!(
            normalize_path("/api/v1/agents/12345"),
            "/api/v1/agents/{id}"
        );
    }

    #[test]
    fn test_normalize_path_no_ids() {
        assert_eq!(normalize_path("/api/v1/agents"), "/api/v1/agents");
    }

    #[test]
    fn test_normalize_path_multiple_ids() {
        assert_eq!(
            normalize_path("/api/v1/agents/550e8400-e29b-41d4-a716-446655440000/grants/99"),
            "/api/v1/agents/{id}/grants/{id}"
        );
    }

    #[test]
    fn test_is_uuid() {
        assert!(is_uuid("550e8400-e29b-41d4-a716-446655440000"));
        assert!(!is_uuid("not-a-uuid"));
        assert!(!is_uuid("550e8400e29b41d4a716446655440000")); // no dashes
    }

    #[test]
    fn test_normalize_path_vault_name() {
        assert_eq!(
            normalize_path("/api/v1/vaults/my-custom-vault/credentials"),
            "/api/v1/vaults/{name}/credentials"
        );
    }

    #[test]
    fn test_normalize_path_vault_shares() {
        assert_eq!(
            normalize_path("/api/v1/vaults/production/shares"),
            "/api/v1/vaults/{name}/shares"
        );
    }

    #[test]
    fn test_normalize_path_vault_shares_user_id() {
        assert_eq!(
            normalize_path("/api/v1/vaults/staging/shares/550e8400-e29b-41d4-a716-446655440000"),
            "/api/v1/vaults/{name}/shares/{id}"
        );
    }

    #[test]
    fn test_normalize_path_vaults_list() {
        // Just /vaults with no sub-path should not be affected
        assert_eq!(normalize_path("/api/v1/vaults"), "/api/v1/vaults");
    }
}
