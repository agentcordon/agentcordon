use axum::{extract::Request, http::HeaderValue, middleware::Next, response::Response};
use uuid::Uuid;

/// Middleware that injects a correlation/request ID into every request and response.
pub async fn inject_request_id(mut request: Request, next: Next) -> Response {
    let request_id = Uuid::new_v4().to_string();

    request
        .headers_mut()
        .insert("x-request-id", HeaderValue::from_str(&request_id).unwrap());

    request
        .extensions_mut()
        .insert(CorrelationId(request_id.clone()));

    let mut response = next.run(request).await;

    response
        .headers_mut()
        .insert("x-request-id", HeaderValue::from_str(&request_id).unwrap());

    response
}

/// Correlation ID extension, available to handlers via `Extension<CorrelationId>`.
#[derive(Debug, Clone)]
pub struct CorrelationId(pub String);
