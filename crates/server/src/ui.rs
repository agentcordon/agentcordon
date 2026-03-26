use axum::{
    body::Body,
    http::{header, StatusCode, Uri},
    response::{IntoResponse, Response},
};
use rust_embed::Embed;

#[derive(Embed)]
#[folder = "static/"]
struct StaticAssets;

/// Serve embedded static assets (CSS, JS, images).
///
/// Unlike the previous SPA fallback, unknown paths now return 404 instead of
/// index.html. Page routing is handled by Askama template routes.
pub async fn static_handler(uri: Uri) -> impl IntoResponse {
    let path = uri.path().trim_start_matches('/');

    // Try the exact path first
    if !path.is_empty() {
        if let Some(content) = StaticAssets::get(path) {
            let mime = mime_guess::from_path(path).first_or_octet_stream();
            return Response::builder()
                .header(header::CONTENT_TYPE, mime.as_ref())
                .header(header::CACHE_CONTROL, "public, max-age=3600")
                .body(Body::from(content.data.into_owned()))
                .unwrap();
        }
    }

    // No SPA fallback — return 404 for unknown paths.
    // Page routing is handled by the page_routes() router.
    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
        .body(Body::from(
            "<!DOCTYPE html><html><head><title>404 — Agent Cordon</title>\
             <link rel=\"stylesheet\" href=\"/css/vault.css\"></head>\
             <body>\
             <nav class=\"top-bar\" style=\"border-bottom:1px solid var(--border,#e5e7eb);\">\
             <a href=\"/dashboard\" class=\"top-bar-logo\" style=\"display:flex;align-items:center;gap:8px;text-decoration:none;color:inherit;\">\
             <img src=\"/img/favicon.svg\" alt=\"\" width=\"24\" height=\"24\">\
             <span style=\"font-weight:600;\">Agent Cordon</span></a>\
             <div style=\"flex:1;\"></div>\
             <a href=\"/dashboard\" style=\"color:var(--ink-soft,#666);text-decoration:none;\">Dashboard</a>\
             </nav>\
             <div style=\"display:flex;align-items:center;justify-content:center;min-height:calc(100vh - 56px);\">\
             <div style=\"text-align:center;\"><h1 style=\"font-size:3rem;opacity:0.3;\">404</h1>\
             <p>Page not found.</p><a href=\"/dashboard\" class=\"btn btn-primary\" style=\"margin-top:1rem;display:inline-block;\">Go to Dashboard</a>\
             </div></div></body></html>",
        ))
        .unwrap()
}
