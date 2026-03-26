//! Policy page handlers.

use askama::Template;
use axum::{
    extract::{Path, Request, State},
    response::{IntoResponse, Response},
};
use uuid::Uuid;

use crate::state::AppState;

use super::{is_admin_user, render_template, CsrfToken, NotFoundPage, UserContext};

// ---------------------------------------------------------------------------
// View model for policy list rows
// ---------------------------------------------------------------------------

/// Pre-formatted policy data for Askama templates.
pub struct PolicyView {
    pub id: String,
    pub name: String,
    pub description: String,
    pub enabled: bool,
    pub is_system: bool,
    pub updated_at: String,
}

// ---------------------------------------------------------------------------
// Policies List
// ---------------------------------------------------------------------------

#[derive(Template)]
#[template(path = "pages/policies/list.html")]
pub struct PolicyListPage {
    pub show_nav: bool,
    pub current_page: String,
    pub user: UserContext,
    pub csrf_token: String,
    pub policies: Vec<PolicyView>,
}

/// GET /security — render the security (policies) list page.
pub async fn policy_list_page_security(
    State(state): State<AppState>,
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

    let all_policies = state.store.list_policies().await.unwrap_or_default();

    // Tenant scoping: admins see all policies, non-admins see only
    // grant policies that reference their owned workspaces.
    let policies = if is_admin_user(&user) {
        all_policies
    } else {
        let owned = state
            .store
            .get_workspaces_by_owner(&user.id)
            .await
            .unwrap_or_default();
        let owned_ids: std::collections::HashSet<String> =
            owned.iter().map(|w| w.id.0.to_string()).collect();
        all_policies
            .into_iter()
            .filter(|p| owned_ids.iter().any(|wid| p.name.contains(wid)))
            .collect()
    };

    let mut policy_views: Vec<PolicyView> = policies
        .iter()
        .map(|p| PolicyView {
            id: p.id.0.to_string(),
            name: p.name.clone(),
            description: p.description.clone().unwrap_or_default(),
            enabled: p.enabled,
            is_system: p.is_system,
            updated_at: p.updated_at.format("%Y-%m-%d %H:%M").to_string(),
        })
        .collect();
    // Sort: system policies first, then alphabetically by name
    policy_views.sort_by(|a, b| {
        b.is_system
            .cmp(&a.is_system)
            .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
    });

    render_template(&PolicyListPage {
        show_nav: true,
        current_page: "security".to_string(),
        user: UserContext::from(&user),
        csrf_token: csrf.0,
        policies: policy_views,
    })
}

// ---------------------------------------------------------------------------
// Policy Detail
// ---------------------------------------------------------------------------

#[derive(Template)]
#[template(path = "pages/policies/detail.html")]
pub struct PolicyDetailPage {
    pub show_nav: bool,
    pub current_page: String,
    pub user: UserContext,
    pub csrf_token: String,
    pub policy_id: String,
}

// ---------------------------------------------------------------------------
// Policy New
// ---------------------------------------------------------------------------

#[derive(Template)]
#[template(path = "pages/policies/new.html")]
pub struct PolicyNewPage {
    pub show_nav: bool,
    pub current_page: String,
    pub user: UserContext,
    pub csrf_token: String,
}

/// GET /security/new — render the new policy form (admin-only).
pub async fn policy_new_page_security(request: Request) -> Response {
    let user = match super::extract_page_user(&request) {
        Ok(u) => u,
        Err(redirect) => return redirect,
    };
    if !is_admin_user(&user) {
        return axum::response::Redirect::to("/security").into_response();
    }
    let csrf = request
        .extensions()
        .get::<CsrfToken>()
        .cloned()
        .unwrap_or(CsrfToken(String::new()));

    render_template(&PolicyNewPage {
        show_nav: true,
        current_page: "security".to_string(),
        user: UserContext::from(&user),
        csrf_token: csrf.0,
    })
}

// ---------------------------------------------------------------------------
// Policy Tester
// ---------------------------------------------------------------------------

#[derive(Template)]
#[template(path = "pages/policies/tester.html")]
pub struct PolicyTesterPage {
    pub show_nav: bool,
    pub current_page: String,
    pub user: UserContext,
    pub csrf_token: String,
}

/// GET /security/tester — render the standalone policy tester page (admin-only).
pub async fn policy_tester_page_security(request: Request) -> Response {
    let user = match super::extract_page_user(&request) {
        Ok(u) => u,
        Err(redirect) => return redirect,
    };
    if !is_admin_user(&user) {
        return axum::response::Redirect::to("/security").into_response();
    }
    let csrf = request
        .extensions()
        .get::<CsrfToken>()
        .cloned()
        .unwrap_or(CsrfToken(String::new()));

    render_template(&PolicyTesterPage {
        show_nav: true,
        current_page: "security".to_string(),
        user: UserContext::from(&user),
        csrf_token: csrf.0,
    })
}

/// GET /security/{id} — render the policy detail page.
pub async fn policy_detail_page_security(Path(id): Path<String>, request: Request) -> Response {
    if Uuid::parse_str(&id).is_err() {
        return render_template(&NotFoundPage { show_nav: true });
    }

    let user = match super::extract_page_user(&request) {
        Ok(u) => u,
        Err(redirect) => return redirect,
    };
    let csrf = request
        .extensions()
        .get::<CsrfToken>()
        .cloned()
        .unwrap_or(CsrfToken(String::new()));

    render_template(&PolicyDetailPage {
        show_nav: true,
        current_page: "security".to_string(),
        user: UserContext::from(&user),
        csrf_token: csrf.0,
        policy_id: id,
    })
}
