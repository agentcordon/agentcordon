//! Login page handler.

use askama::Template;
use axum::{extract::Query, response::Response};
use serde::Deserialize;

use super::render_template;

// ---------------------------------------------------------------------------
// Login page template
// ---------------------------------------------------------------------------

#[derive(Template)]
#[template(path = "pages/login.html")]
pub struct LoginPage {
    pub show_nav: bool,
    pub error: Option<String>,
    pub next: Option<String>,
}

#[derive(Deserialize, Default)]
pub struct LoginQuery {
    pub next: Option<String>,
    pub error: Option<String>,
}

/// GET /login — render the login page.
pub async fn login_page(Query(query): Query<LoginQuery>) -> Response {
    render_template(&LoginPage {
        show_nav: false,
        error: query.error,
        next: query.next,
    })
}
