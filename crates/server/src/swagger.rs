//! Embedded Swagger UI serving.
//!
//! Bundles the Swagger UI dist files (JS, CSS, HTML) directly into the
//! binary using `rust-embed`. This means the server is fully self-contained
//! and requires no CDN or external network access (air-gap compatible).
//!
//! Routes:
//! - `GET /swagger`      — Swagger UI HTML page
//! - `GET /swagger/`     — Same (trailing slash handled)
//! - `GET /swagger/*`    — Swagger UI static assets (JS, CSS)

use axum::{
    body::Body,
    http::{header, StatusCode, Uri},
    response::{IntoResponse, Redirect, Response},
    routing::get,
    Router,
};
use rust_embed::Embed;

use crate::state::AppState;

#[derive(Embed)]
#[folder = "swagger-ui/"]
struct SwaggerUiAssets;

/// Build the top-level Swagger UI routes.
///
/// These are merged into the root router (NOT nested under `/api/v1`).
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/swagger", get(swagger_index))
        .route("/swagger/", get(swagger_index_trailing_slash))
        .route("/swagger/{*path}", get(swagger_asset))
}

/// `GET /swagger` — serves the Swagger UI index.html.
async fn swagger_index() -> impl IntoResponse {
    serve_embedded_file("index.html")
}

/// `GET /swagger/` — redirect to `/swagger` (no trailing slash).
async fn swagger_index_trailing_slash() -> impl IntoResponse {
    Redirect::permanent("/swagger")
}

/// `GET /swagger/*path` — serves embedded Swagger UI static assets.
async fn swagger_asset(uri: Uri) -> impl IntoResponse {
    let path = uri.path().trim_start_matches("/swagger/");
    if path.is_empty() {
        return serve_embedded_file("index.html");
    }
    serve_embedded_file(path)
}

/// Look up a file in the embedded Swagger UI assets and return it with the
/// correct MIME type.
fn serve_embedded_file(path: &str) -> Response {
    match SwaggerUiAssets::get(path) {
        Some(content) => {
            let mime = mime_guess::from_path(path).first_or_octet_stream();
            Response::builder()
                .header(header::CONTENT_TYPE, mime.as_ref())
                .header(header::CACHE_CONTROL, "public, max-age=3600")
                .body(Body::from(content.data.into_owned()))
                .unwrap()
        }
        None => Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Body::from("not found"))
            .unwrap(),
    }
}
