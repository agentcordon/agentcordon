//! OpenAPI specification endpoint.
//!
//! Serves the OpenAPI 3.1 YAML spec file at `GET /openapi.yaml` (nested under
//! `/api/v1` by the router, so the effective path is `/api/v1/openapi.yaml`).
//!
//! This endpoint is **unauthenticated** — it is public documentation that
//! enables agent and developer self-discovery.

use axum::{
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::IntoResponse,
    routing::get,
    Router,
};

use crate::state::AppState;

/// The OpenAPI spec file, embedded into the binary at compile time.
const OPENAPI_SPEC: &str = include_str!("../../../../../docs/openapi.yaml");

pub fn routes() -> Router<AppState> {
    Router::new().route("/openapi.yaml", get(serve_openapi_yaml))
}

/// `GET /api/v1/openapi.yaml` — returns the OpenAPI 3.1 specification.
///
/// Response uses `text/yaml; charset=utf-8` content type and a 5-minute
/// public cache-control header (the spec is deterministic per server version).
async fn serve_openapi_yaml() -> impl IntoResponse {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/yaml; charset=utf-8"),
    );
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=300"),
    );
    (StatusCode::OK, headers, OPENAPI_SPEC)
}
