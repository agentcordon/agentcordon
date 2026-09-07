//! Workspace page handlers.
//!
//! Every page here is a shell: the list comes from `GET /api/v1/workspaces`
//! and the detail page from `GET /api/v1/workspaces/{id}`, which its own
//! script fetches.

use askama::Template;
use axum::{
    extract::{Path, Request},
    response::{IntoResponse, Redirect, Response},
};
use uuid::Uuid;

use super::{page_shell, render_template, NotFoundPage, UserContext};

// ---------------------------------------------------------------------------
// Workspaces List
// ---------------------------------------------------------------------------

#[derive(Template)]
#[template(path = "pages/workspaces/list.html")]
pub struct WorkspaceListPage {
    pub show_nav: bool,
    pub current_page: String,
    pub user: UserContext,
    pub csrf_token: String,
}

/// GET /workspaces — render the workspaces list page.
pub async fn workspace_list_page(request: Request) -> Response {
    let shell = match page_shell(&request) {
        Ok(s) => s,
        Err(redirect) => return redirect,
    };

    render_template(&WorkspaceListPage {
        show_nav: true,
        current_page: "workspaces".to_string(),
        user: shell.user,
        csrf_token: shell.csrf_token,
    })
}

// ---------------------------------------------------------------------------
// Workspace Detail
// ---------------------------------------------------------------------------

#[derive(Template)]
#[template(path = "pages/workspaces/detail.html")]
pub struct WorkspaceDetailPage {
    pub show_nav: bool,
    pub current_page: String,
    pub user: UserContext,
    pub csrf_token: String,
    pub workspace_id: String,
}

/// GET /workspaces/{id} — the workspace's page (uat/artifacts/reviews/DESIGN-REVIEW.md §2.3).
pub async fn workspace_detail_page(Path(id): Path<String>, request: Request) -> Response {
    if Uuid::parse_str(&id).is_err() {
        return render_template(&NotFoundPage { show_nav: true });
    }

    let shell = match page_shell(&request) {
        Ok(s) => s,
        Err(redirect) => return redirect,
    };

    render_template(&WorkspaceDetailPage {
        show_nav: true,
        current_page: "workspaces".to_string(),
        user: shell.user,
        csrf_token: shell.csrf_token,
        workspace_id: id,
    })
}

/// GET /workspaces/{id}/view — the alias a phone used to be sent to.
pub async fn workspace_detail_view_redirect(Path(id): Path<String>) -> Response {
    if Uuid::parse_str(&id).is_err() {
        return render_template(&NotFoundPage { show_nav: true });
    }
    Redirect::permanent(&format!("/workspaces/{}", id)).into_response()
}
