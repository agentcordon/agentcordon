//! GET /install.sh — serve an install script that downloads the CLI from GitHub Releases.
//!
//! The script template lives next to this module as `install_script.sh` and is
//! embedded at compile time. The `{server_url}` placeholder is substituted per
//! request so the script self-references the same origin the client used to
//! reach the server (honouring TLS-terminating reverse proxies).

use axum::{
    extract::State,
    http::{header, HeaderMap, StatusCode},
    response::IntoResponse,
};

use crate::state::AppState;

const TEMPLATE: &str = include_str!("install_script.sh");

pub async fn handler(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    let server_url = resolve_server_url(&state, &headers);
    let body = TEMPLATE.replace("{server_url}", &server_url);

    (
        StatusCode::OK,
        [("content-type", "text/x-shellscript; charset=utf-8")],
        body,
    )
}

fn resolve_server_url(state: &AppState, headers: &HeaderMap) -> String {
    if let Some(ref base_url) = state.config.base_url {
        return base_url.trim_end_matches('/').to_string();
    }
    let host = headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("localhost:3140");
    let scheme = headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("https");
    format!("{scheme}://{host}")
}
