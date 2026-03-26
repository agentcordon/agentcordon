//! User management page handlers.

use askama::Template;
use axum::{
    extract::{Request, State},
    response::Response,
};

use crate::state::AppState;

use super::{is_admin_user, render_template, CsrfToken, UserContext};

// ---------------------------------------------------------------------------
// View model for user list rows
// ---------------------------------------------------------------------------

/// Pre-formatted user data for Askama templates.
pub struct UserView {
    pub id: String,
    pub username: String,
    pub display_name: String,
    pub role: String,
    pub enabled: bool,
    pub is_root: bool,
    pub created_at: String,
}

// ---------------------------------------------------------------------------
// Users List
// ---------------------------------------------------------------------------

#[derive(Template)]
#[template(path = "pages/users/list.html")]
pub struct UserListPage {
    pub show_nav: bool,
    pub current_page: String,
    pub user: UserContext,
    pub csrf_token: String,
    pub users: Vec<UserView>,
    pub users_json: String,
}

/// GET /settings/users — render the users list page under settings.
pub async fn user_list_page_settings(State(state): State<AppState>, request: Request) -> Response {
    let user = match super::extract_page_user(&request) {
        Ok(u) => u,
        Err(redirect) => return redirect,
    };
    let csrf = request
        .extensions()
        .get::<CsrfToken>()
        .cloned()
        .unwrap_or(CsrfToken(String::new()));

    // Tenant scoping: admins see all users, non-admins see only themselves
    let users = if is_admin_user(&user) {
        state.store.list_users().await.unwrap_or_default()
    } else {
        // Non-admin users only see their own account
        match state.store.get_user(&user.id).await {
            Ok(Some(u)) => vec![u],
            _ => vec![],
        }
    };
    let user_views: Vec<UserView> = users
        .iter()
        .map(|u| UserView {
            id: u.id.0.to_string(),
            username: u.username.clone(),
            display_name: u.display_name.clone().unwrap_or_default(),
            role: format!("{:?}", u.role).to_lowercase(),
            enabled: u.enabled,
            is_root: u.is_root,
            created_at: u.created_at.format("%Y-%m-%d %H:%M").to_string(),
        })
        .collect();

    let users_json = serde_json::to_string(
        &user_views
            .iter()
            .map(|u| {
                serde_json::json!({
                    "id": u.id,
                    "username": u.username,
                    "display_name": u.display_name,
                    "role": u.role,
                    "enabled": u.enabled,
                    "is_root": u.is_root,
                    "created_at": u.created_at,
                })
            })
            .collect::<Vec<_>>(),
    )
    .unwrap_or_else(|_| "[]".to_string())
    .replace("</", "<\\/");

    render_template(&UserListPage {
        show_nav: true,
        current_page: "settings".to_string(),
        user: UserContext::from(&user),
        csrf_token: csrf.0,
        users: user_views,
        users_json,
    })
}

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
    let user = match super::extract_page_user(&request) {
        Ok(u) => u,
        Err(redirect) => return redirect,
    };
    let csrf = request
        .extensions()
        .get::<CsrfToken>()
        .cloned()
        .unwrap_or(CsrfToken(String::new()));

    render_template(&UserNewPage {
        show_nav: true,
        current_page: "settings".to_string(),
        user: UserContext::from(&user),
        csrf_token: csrf.0,
    })
}
