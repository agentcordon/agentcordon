use axum::{extract::Request, middleware::Next, response::Response};
use std::time::Instant;

use super::request_id::CorrelationId;

/// Middleware that logs each HTTP request with method, path, status, duration, and correlation ID.
///
/// IMPORTANT: This middleware MUST NOT log request or response bodies, as they
/// may contain secrets (API keys, passwords, credential values).
pub async fn log_request(request: Request, next: Next) -> Response {
    let method = request.method().clone();
    let path = request.uri().path().to_string();
    let correlation_id = request
        .extensions()
        .get::<CorrelationId>()
        .map(|c| c.0.clone())
        .unwrap_or_default();

    let start = Instant::now();
    let response = next.run(request).await;
    let duration_ms = start.elapsed().as_millis() as u64;
    let status = response.status().as_u16();

    // Log health/metrics probes at debug level to avoid noise from Docker/K8s healthchecks.
    if path == "/health" || path == "/metrics" {
        tracing::debug!(
            method = %method,
            path = %path,
            status = status,
            duration_ms = duration_ms,
            correlation_id = %correlation_id,
            "http request"
        );
    } else {
        tracing::info!(
            method = %method,
            path = %path,
            status = status,
            duration_ms = duration_ms,
            correlation_id = %correlation_id,
            "http request"
        );
    }

    response
}
