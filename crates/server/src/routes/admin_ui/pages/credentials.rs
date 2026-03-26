//! Credential page handlers.

use askama::Template;
use axum::{
    extract::{Path, Request, State},
    response::Response,
};
use uuid::Uuid;

use crate::state::AppState;
use agent_cordon_core::domain::credential::{CredentialId, CredentialSummary, StoredCredential};
use agent_cordon_core::domain::policy::PolicyDecisionResult;
use agent_cordon_core::domain::user::User;
use agent_cordon_core::policy::{
    actions, PolicyContext, PolicyEngine, PolicyPrincipal, PolicyResource,
};

use super::{render_template, CsrfToken, NotFoundPage, UserContext};

// ---------------------------------------------------------------------------
// Cedar-filtered credential loading (shared by list + detail page handlers)
// ---------------------------------------------------------------------------

/// Load credentials visible to the given user, filtered through Cedar policy.
///
/// Root users bypass Cedar (handled inside the Cedar engine) and see everything.
/// Non-root users see only credentials permitted by their Cedar policies.
async fn list_credentials_for_user(state: &AppState, user: &User) -> Vec<CredentialSummary> {
    let all_summaries = state.store.list_credentials().await.unwrap_or_default();
    let all_stored = state
        .store
        .list_all_stored_credentials()
        .await
        .unwrap_or_default();

    let cred_map: std::collections::HashMap<CredentialId, StoredCredential> =
        all_stored.into_iter().map(|c| (c.id.clone(), c)).collect();

    let principal = PolicyPrincipal::User(user);
    let context = PolicyContext {
        target_url: None,
        requested_scopes: vec![],
        ..Default::default()
    };

    // Load workspaces owned by this user for workspace-principal Cedar checks
    let owned_workspaces = state
        .store
        .get_workspaces_by_owner(&user.id)
        .await
        .unwrap_or_default();

    let mut allowed = Vec::new();
    for summary in all_summaries {
        let cred = match cred_map.get(&summary.id) {
            Some(c) => c.clone(),
            None => continue,
        };

        // 1. Check Cedar with User principal
        match state.policy_engine.evaluate(
            &principal,
            actions::LIST,
            &PolicyResource::Credential {
                credential: cred.clone(),
            },
            &context,
        ) {
            Ok(decision) if decision.decision != PolicyDecisionResult::Forbid => {
                allowed.push(summary);
                continue;
            }
            Ok(_) => {} // Cedar denied with user principal — try workspace principals
            Err(e) => {
                tracing::warn!(
                    credential_id = %summary.id.0,
                    error = %e,
                    "Cedar evaluation failed for credential in UI (user principal), trying workspace principals"
                );
            }
        }

        // 2. Check Cedar with each owned Workspace principal
        let mut ws_allowed = false;
        for ws in &owned_workspaces {
            match state.policy_engine.evaluate(
                &PolicyPrincipal::Workspace(ws),
                actions::LIST,
                &PolicyResource::Credential {
                    credential: cred.clone(),
                },
                &context,
            ) {
                Ok(decision) if decision.decision != PolicyDecisionResult::Forbid => {
                    ws_allowed = true;
                    break;
                }
                Ok(_) => {}
                Err(e) => {
                    tracing::warn!(
                        credential_id = %summary.id.0,
                        workspace_id = %ws.id.0,
                        error = %e,
                        "Cedar evaluation failed for credential in UI (workspace principal), skipping"
                    );
                }
            }
        }
        if ws_allowed {
            allowed.push(summary);
        }
    }

    allowed
}

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
    pub credentials: Vec<CredentialSummary>,
    pub credentials_json: String,
}

/// GET /credentials — render the credentials list page.
pub async fn credential_list_page(State(state): State<AppState>, request: Request) -> Response {
    let user = match super::extract_page_user(&request) {
        Ok(u) => u,
        Err(redirect) => return redirect,
    };
    let csrf = request
        .extensions()
        .get::<CsrfToken>()
        .cloned()
        .unwrap_or(CsrfToken(String::new()));

    let credentials = list_credentials_for_user(&state, &user).await;
    let credentials_json = serde_json::to_string(&credentials)
        .unwrap_or_else(|_| "[]".to_string())
        .replace("</", "<\\/");

    render_template(&CredentialListPage {
        show_nav: true,
        current_page: "credentials".to_string(),
        user: UserContext::from(&user),
        csrf_token: csrf.0,
        credentials,
        credentials_json,
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

/// GET /credentials/{id} — render the list page with the credential auto-selected.
///
/// The split-pane `list.html` reads the credential ID from the URL path and
/// auto-selects it, so refreshing `/credentials/{id}` shows the same view as
/// navigating there via `pushState`.
pub async fn credential_detail_page(
    Path(id): Path<String>,
    State(state): State<AppState>,
    request: Request,
) -> Response {
    // Validate UUID format
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

    let credentials = list_credentials_for_user(&state, &user).await;
    let credentials_json = serde_json::to_string(&credentials)
        .unwrap_or_else(|_| "[]".to_string())
        .replace("</", "<\\/");

    render_template(&CredentialListPage {
        show_nav: true,
        current_page: "credentials".to_string(),
        user: UserContext::from(&user),
        csrf_token: csrf.0,
        credentials,
        credentials_json,
    })
}

/// GET /credentials/{id}/view — standalone full-page detail view (used by mobile).
pub async fn credential_detail_view_page(Path(id): Path<String>, request: Request) -> Response {
    // Validate UUID format
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

    render_template(&CredentialDetailPage {
        show_nav: true,
        current_page: "credentials".to_string(),
        user: UserContext::from(&user),
        csrf_token: csrf.0,
        credential_id: id,
    })
}

// ---------------------------------------------------------------------------
// Credential Detail Partial (for split-view AJAX loading)
// ---------------------------------------------------------------------------

#[derive(Template)]
#[template(path = "partials/credential_detail_pane.html")]
pub struct CredentialDetailPane {
    pub csrf_token: String,
    pub credential_id: String,
}

/// GET /credentials/{id}/detail-partial — HTML fragment for split-view right pane.
pub async fn credential_detail_partial(Path(id): Path<String>, request: Request) -> Response {
    // Validate UUID format
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

    render_template(&CredentialDetailPane {
        csrf_token: csrf.0,
        credential_id: id,
    })
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
    let user = match super::extract_page_user(&request) {
        Ok(u) => u,
        Err(redirect) => return redirect,
    };
    let csrf = request
        .extensions()
        .get::<CsrfToken>()
        .cloned()
        .unwrap_or(CsrfToken(String::new()));

    render_template(&CredentialNewPage {
        show_nav: true,
        current_page: "credentials".to_string(),
        user: UserContext::from(&user),
        csrf_token: csrf.0,
    })
}
