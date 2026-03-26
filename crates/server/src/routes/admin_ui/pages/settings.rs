//! Settings page handler.

use askama::Template;
use axum::{
    extract::{Request, State},
    response::Response,
};

use crate::state::AppState;
use agent_cordon_core::domain::oidc::OidcProviderSummary;

use super::{render_template, CsrfToken, UserContext};

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
    pub providers: Vec<OidcProviderSummary>,
    pub providers_json: String,
}

/// GET /settings — render the settings page.
pub async fn settings_page(State(state): State<AppState>, request: Request) -> Response {
    let user = match super::extract_page_user(&request) {
        Ok(u) => u,
        Err(redirect) => return redirect,
    };
    let csrf = request
        .extensions()
        .get::<CsrfToken>()
        .cloned()
        .unwrap_or(CsrfToken(String::new()));

    let user_ctx = UserContext::from(&user);

    // Only load admin-only data (OIDC providers) for admin users
    let providers = if user_ctx.is_admin {
        state.store.list_oidc_providers().await.unwrap_or_default()
    } else {
        vec![]
    };
    let providers_json = serde_json::to_string(&providers)
        .unwrap_or_else(|_| "[]".to_string())
        .replace("</", "<\\/");

    render_template(&SettingsPage {
        show_nav: true,
        current_page: "settings".to_string(),
        user: user_ctx,
        csrf_token: csrf.0,
        providers,
        providers_json,
    })
}
