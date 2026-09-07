//! Settings page handler.
//!
//! The page is a shell: OIDC providers come from `GET /api/v1/oidc-providers`,
//! OAuth provider clients from `GET /api/v1/oauth-provider-clients`, and the
//! user table from `GET /api/v1/users`.

use askama::Template;
use axum::{extract::Request, response::Response};

use super::{page_shell, render_template, UserContext};

// ---------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------

#[derive(Template)]
#[template(path = "pages/settings.html")]
pub struct SettingsPage {
    pub show_nav: bool,
    pub current_page: String,
    pub user: UserContext,
    pub csrf_token: String,
    pub version: &'static str,
}

/// GET /settings — render the settings page.
pub async fn settings_page(request: Request) -> Response {
    let shell = match page_shell(&request) {
        Ok(s) => s,
        Err(redirect) => return redirect,
    };

    render_template(&SettingsPage {
        show_nav: true,
        current_page: "settings".to_string(),
        user: shell.user,
        csrf_token: shell.csrf_token,
        version: env!("CARGO_PKG_VERSION"),
    })
}
