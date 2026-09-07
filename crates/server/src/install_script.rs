//! GET /install.sh — serve an install script that downloads the CLI from GitHub Releases.
//!
//! The script template lives next to this module as `install_script.sh` and is
//! embedded at compile time. The `{server_url}` placeholder is substituted per
//! request so the script self-references the same origin the client used to
//! reach the server (honouring TLS-terminating reverse proxies).
//!
//! `{version}` (`{VERSION}` in the PowerShell script) is substituted with this
//! server's own crate version, so the installer downloads the matching release
//! rather than whatever `latest` happens to be. A server built from source is
//! routinely ahead of the newest published release, and v0.4.0 changed the
//! signed request payload — an installer that fetched `latest` handed new
//! users a CLI and broker that could not talk to the server they had just
//! stood up.

use axum::{
    extract::State,
    http::{header, HeaderMap, StatusCode},
    response::IntoResponse,
};

use crate::state::AppState;

const TEMPLATE: &str = include_str!("install_script.sh");

/// The Windows installer, kept under `tools/` at the repository root because
/// it is also shipped as a release asset. `{SERVER_URL}` is substituted per
/// request exactly as for the Unix script.
const PS1_TEMPLATE: &str = include_str!("../../../tools/install.ps1");

pub async fn handler(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    let server_url = resolve_server_url(&state, &headers);
    let body = TEMPLATE
        .replace("{server_url}", &server_url)
        .replace("{version}", env!("CARGO_PKG_VERSION"));

    (
        StatusCode::OK,
        [("content-type", "text/x-shellscript; charset=utf-8")],
        body,
    )
}

/// GET /install.ps1: the PowerShell installer behind the documented
/// `irm https://<server>/install.ps1 | iex` one-liner. Served as plain text so
/// `Invoke-RestMethod` hands `Invoke-Expression` a string, not a parsed object.
pub async fn ps1_handler(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    let server_url = resolve_server_url(&state, &headers);
    let body = PS1_TEMPLATE
        .replace("{SERVER_URL}", &server_url)
        .replace("{VERSION}", env!("CARGO_PKG_VERSION"));

    (
        StatusCode::OK,
        [("content-type", "text/plain; charset=utf-8")],
        body,
    )
}

/// The URL the served installer will point back at.
///
/// `AGTCRDN_BASE_URL` is the operator's answer and always wins. Without it,
/// the request itself is all there is to go on: the `Host` the client used,
/// and the scheme.
///
/// **The scheme is `http` unless a proxy says otherwise.** This server never
/// terminates TLS — a TLS deployment is always a reverse proxy in front —
/// so a request that arrives with no `X-Forwarded-Proto` arrived over plain
/// HTTP. Assuming `https` emitted an installer pointing at a URL that does
/// not answer, and it did so silently: the documented symptom of a missing
/// `AGTCRDN_BASE_URL` is a `0.0.0.0` URL, which this path never produces, so
/// a user had nothing to recognise. A TLS-terminating proxy must send
/// `X-Forwarded-Proto: https` (or the operator must set `AGTCRDN_BASE_URL`).
fn resolve_server_url(state: &AppState, headers: &HeaderMap) -> String {
    if let Some(ref base_url) = state.config.base_url {
        return base_url.trim_end_matches('/').to_string();
    }
    let host = headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("localhost:3140");
    let scheme = forwarded_scheme(headers).unwrap_or("http");
    format!("{scheme}://{host}")
}

/// The scheme a reverse proxy reports in `X-Forwarded-Proto`, if any.
///
/// A proxy chain sends a comma-separated list, oldest hop first; the first
/// entry is the client's own hop. Anything that is not `http` or `https` is
/// ignored rather than pasted into a URL.
fn forwarded_scheme(headers: &HeaderMap) -> Option<&'static str> {
    let value = headers.get("x-forwarded-proto")?.to_str().ok()?;
    match value
        .split(',')
        .next()?
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "https" => Some("https"),
        "http" => Some("http"),
        _ => None,
    }
}
