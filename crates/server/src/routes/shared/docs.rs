//! Documentation endpoints for agent self-discovery.
//!
//! These endpoints return raw JSON (NOT wrapped in the standard `ApiResponse`
//! envelope). This is intentional: agents calling `/docs` or `/docs/quickstart`
//! may not yet know the envelope format, so the documentation itself must be
//! the bootstrapping point. The quickstart guide explicitly describes the
//! `ApiResponse` envelope used by all other endpoints.
//!
//! Neither endpoint requires authentication. The API surface is not secret --
//! it is the same for every AgentCordon instance and exposing it enables
//! autonomous agent self-discovery.

use axum::{
    extract::State,
    http::{header, HeaderMap},
    routing::get,
    Json, Router,
};

use crate::docs::{build_api_docs, build_quickstart_doc, ApiDocumentation, QuickstartDoc};
use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/docs", get(get_docs))
        .route("/docs/quickstart", get(get_quickstart))
}

/// `GET /api/v1/docs` -- returns the full API documentation as raw JSON.
///
/// Cache-Control is set to `public, max-age=300` because the documentation
/// is deterministic for a given server version and configuration.
async fn get_docs(State(state): State<AppState>) -> (HeaderMap, Json<ApiDocumentation>) {
    let docs = build_api_docs(&state.config);
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CACHE_CONTROL,
        "public, max-age=300".parse().unwrap(),
    );
    (headers, Json(docs))
}

/// `GET /api/v1/docs/quickstart` -- returns the concise getting-started guide
/// as raw JSON.
async fn get_quickstart(State(state): State<AppState>) -> (HeaderMap, Json<QuickstartDoc>) {
    let doc = build_quickstart_doc(&state.config);
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CACHE_CONTROL,
        "public, max-age=300".parse().unwrap(),
    );
    (headers, Json(doc))
}
