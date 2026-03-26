//! Special page handlers: agent registration.

use askama::Template;
use axum::{
    extract::{Query, Request},
    response::Response,
};
use serde::Deserialize;

use super::{render_template, CsrfToken, UserContext};

// ---------------------------------------------------------------------------
// Register query params (for CLI registration flow)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct RegisterQuery {
    pub pk_hash: Option<String>,
    pub cc: Option<String>,
}

// ---------------------------------------------------------------------------
// Agent Registration
// ---------------------------------------------------------------------------

#[derive(Template)]
#[template(path = "pages/agent_registration.html")]
pub struct AgentRegistrationPage {
    pub show_nav: bool,
    pub current_page: String,
    pub user: UserContext,
    pub csrf_token: String,
    /// When present, show approval form instead of instructions.
    pub fingerprint: String,
    pub pk_hash: String,
    pub code_challenge: String,
}

/// GET /register — render the agent registration page.
///
/// When `pk_hash` and `cc` query params are present (from CLI `register` flow),
/// shows a fingerprint + Approve button. Otherwise shows instructions.
pub async fn agent_registration_page(
    Query(query): Query<RegisterQuery>,
    request: Request,
) -> Response {
    let user = match super::extract_page_user(&request) {
        Ok(u) => u,
        Err(redirect) => return redirect,
    };
    let csrf = request
        .extensions()
        .get::<CsrfToken>()
        .cloned()
        .unwrap_or(CsrfToken(String::new()));

    // Validate and sanitize query params (hex only, prevent XSS)
    let pk_hash_raw = query.pk_hash.unwrap_or_default();
    let pk_hash_clean = pk_hash_raw
        .strip_prefix("sha256:")
        .unwrap_or(&pk_hash_raw)
        .to_string();
    let pk_hash =
        if pk_hash_clean.len() == 64 && pk_hash_clean.chars().all(|c| c.is_ascii_hexdigit()) {
            pk_hash_clean
        } else {
            String::new()
        };

    let code_challenge_raw = query.cc.unwrap_or_default();
    let code_challenge = if code_challenge_raw.len() == 64
        && code_challenge_raw.chars().all(|c| c.is_ascii_hexdigit())
    {
        code_challenge_raw
    } else {
        String::new()
    };

    let fingerprint = if pk_hash.len() >= 16 {
        pk_hash[..16].to_string()
    } else {
        String::new()
    };

    render_template(&AgentRegistrationPage {
        show_nav: true,
        current_page: "agents".to_string(),
        user: UserContext::from(&user),
        csrf_token: csrf.0,
        fingerprint,
        pk_hash,
        code_challenge,
    })
}
