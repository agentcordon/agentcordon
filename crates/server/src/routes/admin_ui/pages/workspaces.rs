//! Workspace page handlers.

use askama::Template;
use axum::{
    extract::{Path, Request, State},
    response::Response,
};
use uuid::Uuid;

use agent_cordon_core::domain::user::UserId;

use crate::state::AppState;

use super::{is_admin_user, render_template, CsrfToken, NotFoundPage, UserContext};

/// Enrich workspace JSON values with `owner_username` resolved from `owner_id`.
async fn enrich_workspace_json_owner(
    store: &dyn agent_cordon_core::storage::Store,
    workspaces: &mut [serde_json::Value],
) {
    for val in workspaces.iter_mut() {
        if let Some(obj) = val.as_object_mut() {
            if let Some(owner_id_str) = obj.get("owner_id").and_then(|v| v.as_str()) {
                if let Ok(uuid) = Uuid::parse_str(owner_id_str) {
                    if let Ok(Some(user)) = store.get_user(&UserId(uuid)).await {
                        let name = user.display_name.unwrap_or(user.username);
                        obj.insert(
                            "owner_username".to_string(),
                            serde_json::Value::String(name),
                        );
                    }
                }
            }
        }
    }
}

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
    pub workspaces_json: String,
    /// Used only for server-side `is_empty()` check in the template.
    pub workspaces: Vec<serde_json::Value>,
}

/// GET /workspaces — render the workspaces list page.
pub async fn workspace_list_page(State(state): State<AppState>, request: Request) -> Response {
    let user = match super::extract_page_user(&request) {
        Ok(u) => u,
        Err(redirect) => return redirect,
    };
    let csrf = request
        .extensions()
        .get::<CsrfToken>()
        .cloned()
        .unwrap_or(CsrfToken(String::new()));

    // Tenant scoping: admins see all, non-admins see only their owned workspaces
    let workspaces = if is_admin_user(&user) {
        state.store.list_workspaces().await.unwrap_or_default()
    } else {
        state
            .store
            .get_workspaces_by_owner(&user.id)
            .await
            .unwrap_or_default()
    };

    let mut workspaces_with_status: Vec<serde_json::Value> = workspaces
        .iter()
        .map(|w| {
            let mut val = serde_json::to_value(w).unwrap_or_default();
            if let Some(obj) = val.as_object_mut() {
                let status = format!("{:?}", w.status).to_lowercase();
                obj.insert("status".to_string(), serde_json::Value::String(status));
            }
            val
        })
        .collect();
    enrich_workspace_json_owner(&*state.store, &mut workspaces_with_status).await;
    let workspaces_json = serde_json::to_string(&workspaces_with_status)
        .unwrap_or_else(|_| "[]".to_string())
        .replace("</", "<\\/");

    render_template(&WorkspaceListPage {
        show_nav: true,
        current_page: "workspaces".to_string(),
        user: UserContext::from(&user),
        csrf_token: csrf.0,
        workspaces_json,
        workspaces: workspaces_with_status,
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

/// GET /workspaces/{id} — render the list page with the workspace auto-selected.
pub async fn workspace_detail_page(
    Path(id): Path<String>,
    State(state): State<AppState>,
    request: Request,
) -> Response {
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

    // Tenant scoping: admins see all, non-admins see only their owned workspaces
    let workspaces = if is_admin_user(&user) {
        state.store.list_workspaces().await.unwrap_or_default()
    } else {
        state
            .store
            .get_workspaces_by_owner(&user.id)
            .await
            .unwrap_or_default()
    };
    let mut workspaces_with_status: Vec<serde_json::Value> = workspaces
        .iter()
        .map(|w| {
            let mut val = serde_json::to_value(w).unwrap_or_default();
            if let Some(obj) = val.as_object_mut() {
                let status = format!("{:?}", w.status).to_lowercase();
                obj.insert("status".to_string(), serde_json::Value::String(status));
            }
            val
        })
        .collect();
    enrich_workspace_json_owner(&*state.store, &mut workspaces_with_status).await;
    let workspaces_json = serde_json::to_string(&workspaces_with_status)
        .unwrap_or_else(|_| "[]".to_string())
        .replace("</", "<\\/");

    render_template(&WorkspaceListPage {
        show_nav: true,
        current_page: "workspaces".to_string(),
        user: UserContext::from(&user),
        csrf_token: csrf.0,
        workspaces_json,
        workspaces: workspaces_with_status,
    })
}

/// GET /workspaces/{id}/view — standalone full-page detail view (used by mobile).
pub async fn workspace_detail_view_page(Path(id): Path<String>, request: Request) -> Response {
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

    render_template(&WorkspaceDetailPage {
        show_nav: true,
        current_page: "workspaces".to_string(),
        user: UserContext::from(&user),
        csrf_token: csrf.0,
        workspace_id: id,
    })
}

// ---------------------------------------------------------------------------
// Workspace Detail Partial (for split-view AJAX loading)
// ---------------------------------------------------------------------------

#[derive(Template)]
#[template(path = "partials/workspace_detail_pane.html")]
pub struct WorkspaceDetailPane {
    pub csrf_token: String,
    pub workspace_id: String,
}

/// GET /workspaces/{id}/detail-partial — HTML fragment for split-view right pane.
pub async fn workspace_detail_partial(Path(id): Path<String>, request: Request) -> Response {
    if Uuid::parse_str(&id).is_err() {
        return Response::builder()
            .status(axum::http::StatusCode::NOT_FOUND)
            .header(axum::http::header::CONTENT_TYPE, "text/html; charset=utf-8")
            .body(axum::body::Body::from("not found"))
            .unwrap();
    }

    let _user = match super::extract_page_user(&request) {
        Ok(u) => u,
        Err(redirect) => return redirect,
    };
    let csrf = request
        .extensions()
        .get::<CsrfToken>()
        .cloned()
        .unwrap_or(CsrfToken(String::new()));

    render_template(&WorkspaceDetailPane {
        csrf_token: csrf.0,
        workspace_id: id,
    })
}
