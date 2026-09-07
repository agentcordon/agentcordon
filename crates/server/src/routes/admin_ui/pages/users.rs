//! User management page handlers.
//!
//! There is one: the create form. The user *table* is a Settings section
//! (`/settings#users-section`), and `/users` and `/settings/users` both
//! redirect there — a standalone list page was a third surface for one
//! function, with its own button label
//! (uat/artifacts/fresh-user-docker-2.md F5).

use askama::Template;
use axum::{extract::Request, response::Response};

use super::{page_shell, render_template, UserContext};

// ---------------------------------------------------------------------------
// Users New
// ---------------------------------------------------------------------------

#[derive(Template)]
#[template(path = "pages/users/new.html")]
pub struct UserNewPage {
    pub show_nav: bool,
    pub current_page: String,
    pub user: UserContext,
    pub csrf_token: String,
}

/// GET /settings/users/new — render the new user form under settings.
pub async fn user_new_page_settings(request: Request) -> Response {
    let shell = match page_shell(&request) {
        Ok(s) => s,
        Err(redirect) => return redirect,
    };

    render_template(&UserNewPage {
        show_nav: true,
        current_page: "settings".to_string(),
        user: shell.user,
        csrf_token: shell.csrf_token,
    })
}
