//! Credential page handlers.
//!
//! Every page here is a shell: the list comes from `GET /api/v1/credentials`
//! and the detail page from `GET /api/v1/credentials/{id}`, which its own
//! script fetches.

use askama::Template;
use axum::{
    extract::{Path, Request},
    response::{IntoResponse, Redirect, Response},
};
use uuid::Uuid;

use super::{page_shell, render_template, NotFoundPage, UserContext};

// ---------------------------------------------------------------------------
// Credentials List
// ---------------------------------------------------------------------------

#[derive(Template)]
#[template(path = "pages/credentials/list.html")]
pub struct CredentialListPage {
    pub show_nav: bool,
    pub current_page: String,
    pub user: UserContext,
    pub csrf_token: String,
}

/// GET /credentials — render the credentials list page.
pub async fn credential_list_page(request: Request) -> Response {
    let shell = match page_shell(&request) {
        Ok(s) => s,
        Err(redirect) => return redirect,
    };

    render_template(&CredentialListPage {
        show_nav: true,
        current_page: "credentials".to_string(),
        user: shell.user,
        csrf_token: shell.csrf_token,
    })
}

// ---------------------------------------------------------------------------
// Credential Detail
// ---------------------------------------------------------------------------

#[derive(Template)]
#[template(path = "pages/credentials/detail.html")]
pub struct CredentialDetailPage {
    pub show_nav: bool,
    pub current_page: String,
    pub user: UserContext,
    pub csrf_token: String,
    pub credential_id: String,
}

/// GET /credentials/{id} — the credential's page.
///
/// One URL per credential. The list used to render a split pane and select
/// the row this URL named, which left the product with two routes for one
/// record, a mobile redirect between them, and a detail whose Permissions tab
/// did not fit the pane it was drawn in (uat/artifacts/reviews/DESIGN-REVIEW.md §2.3).
pub async fn credential_detail_page(Path(id): Path<String>, request: Request) -> Response {
    // Validate UUID format
    if Uuid::parse_str(&id).is_err() {
        return render_template(&NotFoundPage { show_nav: true });
    }

    let shell = match page_shell(&request) {
        Ok(s) => s,
        Err(redirect) => return redirect,
    };

    render_template(&CredentialDetailPage {
        show_nav: true,
        current_page: "credentials".to_string(),
        user: shell.user,
        csrf_token: shell.csrf_token,
        credential_id: id,
    })
}

/// GET /credentials/{id}/view — the alias a phone used to be sent to, kept so
/// links already in the wild land on the page rather than a 404.
pub async fn credential_detail_view_redirect(Path(id): Path<String>) -> Response {
    if Uuid::parse_str(&id).is_err() {
        return render_template(&NotFoundPage { show_nav: true });
    }
    Redirect::permanent(&format!("/credentials/{}", id)).into_response()
}

// ---------------------------------------------------------------------------
// Credential New
// ---------------------------------------------------------------------------

#[derive(Template)]
#[template(path = "pages/credentials/new.html")]
pub struct CredentialNewPage {
    pub show_nav: bool,
    pub current_page: String,
    pub user: UserContext,
    pub csrf_token: String,
}

/// GET /credentials/new — render the new credential form.
pub async fn credential_new_page(request: Request) -> Response {
    let shell = match page_shell(&request) {
        Ok(s) => s,
        Err(redirect) => return redirect,
    };

    render_template(&CredentialNewPage {
        show_nav: true,
        current_page: "credentials".to_string(),
        user: shell.user,
        csrf_token: shell.csrf_token,
    })
}
