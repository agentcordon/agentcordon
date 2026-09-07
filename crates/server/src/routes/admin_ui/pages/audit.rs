//! Audit log page handler.
//!
//! The page is a shell: events come from `GET /api/v1/audit` (paged with
//! `limit`/`offset`) and a single event from `GET /api/v1/audit/{id}`.

use askama::Template;
use axum::{extract::Request, response::Response};

use super::{page_shell, render_template, UserContext};

// ---------------------------------------------------------------------------
// Audit Log
// ---------------------------------------------------------------------------

#[derive(Template)]
#[template(path = "pages/audit.html")]
pub struct AuditPage {
    pub show_nav: bool,
    pub current_page: String,
    pub user: UserContext,
    pub csrf_token: String,
}

/// GET /audit and GET /audit/{id} — render the audit log page.
///
/// The page reads the event id, when present, from its own URL and expands
/// that row once the list has loaded.
pub async fn audit_page(request: Request) -> Response {
    let shell = match page_shell(&request) {
        Ok(s) => s,
        Err(redirect) => return redirect,
    };

    render_template(&AuditPage {
        show_nav: true,
        current_page: "audit".to_string(),
        user: shell.user,
        csrf_token: shell.csrf_token,
    })
}
