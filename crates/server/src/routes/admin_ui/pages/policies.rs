//! Policy page handlers.
//!
//! Every page is a shell: the list comes from `GET /api/v1/policies` and
//! the detail page from `GET /api/v1/policies/{id}`.

use askama::Template;
use axum::{
    extract::{Path, Request},
    response::{IntoResponse, Response},
};
use uuid::Uuid;

use super::{page_shell, render_template, NotFoundPage, UserContext};

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
}

/// GET /security — render the security (policies) list page.
pub async fn policy_list_page_security(request: Request) -> Response {
    let shell = match page_shell(&request) {
        Ok(s) => s,
        Err(redirect) => return redirect,
    };

    render_template(&PolicyListPage {
        show_nav: true,
        current_page: "security".to_string(),
        user: shell.user,
        csrf_token: shell.csrf_token,
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
    let shell = match page_shell(&request) {
        Ok(s) => s,
        Err(redirect) => return redirect,
    };
    if !shell.user.is_admin {
        return axum::response::Redirect::to("/security").into_response();
    }

    render_template(&PolicyNewPage {
        show_nav: true,
        current_page: "security".to_string(),
        user: shell.user,
        csrf_token: shell.csrf_token,
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
    let shell = match page_shell(&request) {
        Ok(s) => s,
        Err(redirect) => return redirect,
    };
    if !shell.user.is_admin {
        return axum::response::Redirect::to("/security").into_response();
    }

    render_template(&PolicyTesterPage {
        show_nav: true,
        current_page: "security".to_string(),
        user: shell.user,
        csrf_token: shell.csrf_token,
    })
}

/// GET /security/{id} — render the policy detail page.
pub async fn policy_detail_page_security(Path(id): Path<String>, request: Request) -> Response {
    if Uuid::parse_str(&id).is_err() {
        return render_template(&NotFoundPage { show_nav: true });
    }

    let shell = match page_shell(&request) {
        Ok(s) => s,
        Err(redirect) => return redirect,
    };

    render_template(&PolicyDetailPage {
        show_nav: true,
        current_page: "security".to_string(),
        user: shell.user,
        csrf_token: shell.csrf_token,
        policy_id: id,
    })
}
