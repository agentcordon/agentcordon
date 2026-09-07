//! Dashboard page handler.

use askama::Template;
use axum::{extract::Request, response::Response};

use super::{page_shell, render_template, UserContext};

#[derive(Template)]
#[template(path = "pages/dashboard.html")]
pub struct DashboardPage {
    pub show_nav: bool,
    pub current_page: String,
    pub user: UserContext,
    pub csrf_token: String,
    /// The running build, for the health line under the page title. The tile
    /// that used to say "All systems operational" linked to the audit log and
    /// was not a count; the sentence belongs under the title
    /// (uat/artifacts/reviews/DESIGN-REVIEW.md §1.3).
    pub version: &'static str,
}

/// GET /dashboard — render the dashboard shell.
///
/// The counts come from `GET /api/v1/stats` and the activity tables from
/// `GET /api/v1/audit`, fetched by the page's script.
pub async fn dashboard_page(request: Request) -> Response {
    let shell = match page_shell(&request) {
        Ok(s) => s,
        Err(redirect) => return redirect,
    };

    render_template(&DashboardPage {
        show_nav: true,
        current_page: "dashboard".to_string(),
        user: shell.user,
        csrf_token: shell.csrf_token,
        version: env!("CARGO_PKG_VERSION"),
    })
}
