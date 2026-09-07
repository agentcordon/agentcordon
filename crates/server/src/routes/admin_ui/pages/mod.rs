//! Page route handlers for Askama-rendered HTML pages.
//!
//! All authenticated page routes use `page_auth` middleware that redirects
//! to `/login` (not 401 JSON) when the session is invalid.

pub mod activate;
pub mod audit;
pub mod auth;
pub mod credentials;
pub mod dashboard;
pub mod mcp_servers;
pub mod policies;
pub mod settings;
pub mod special;
pub mod users;
pub mod workspaces;

use axum::{
    body::Body,
    extract::{Path, Request, State},
    http::{header, StatusCode},
    middleware::Next,
    response::{IntoResponse, Redirect, Response},
    routing::get,
    Router,
};

use agent_cordon_core::crypto::session::hash_session_token_hmac;
use agent_cordon_core::domain::user::User;
use askama::Template;

use crate::state::AppState;
use crate::utils::cookies::parse_cookie;

// ---------------------------------------------------------------------------
// Template → Response helper
// ---------------------------------------------------------------------------

/// Render an Askama template to an axum HTML response.
///
/// Returns 200 with `text/html` content type, or 500 if rendering fails.
pub fn render_template(tmpl: &impl Template) -> Response {
    match tmpl.render() {
        Ok(html) => Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
            .body(Body::from(html))
            .unwrap(),
        Err(e) => {
            tracing::error!(error = %e, "template render error");
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
                .body(Body::from("<h1>500 — Internal Server Error</h1>"))
                .unwrap()
        }
    }
}

// ---------------------------------------------------------------------------
// UserContext — lightweight user info passed to all templates
// ---------------------------------------------------------------------------

/// User context available to all authenticated page templates.
#[derive(Debug, Clone)]
pub struct UserContext {
    pub username: String,
    pub display_name: Option<String>,
    pub role: String,
    /// `true` if user is admin or root — used for tenant scoping.
    pub is_admin: bool,
    /// The user's UUID string — used for tenant-scoped queries.
    pub user_id: String,
}

impl From<&User> for UserContext {
    fn from(user: &User) -> Self {
        Self {
            username: user.username.clone(),
            display_name: user.display_name.clone(),
            role: format!("{:?}", user.role).to_lowercase(),
            is_admin: user.is_admin(),
            user_id: user.id.0.to_string(),
        }
    }
}

// ---------------------------------------------------------------------------
// Error page templates
// ---------------------------------------------------------------------------

#[derive(Template)]
#[template(path = "errors/404.html")]
pub struct NotFoundPage {
    pub show_nav: bool,
}

#[derive(Template)]
#[template(path = "errors/500.html")]
pub struct ErrorPage {
    pub show_nav: bool,
}

// ---------------------------------------------------------------------------
// Safe User extraction helper
// ---------------------------------------------------------------------------

/// Extract the authenticated `User` from request extensions, or return a
/// redirect to `/login` if the extension is missing (should not happen when
/// `page_auth` middleware is active, but avoids a panic).
#[allow(clippy::result_large_err)]
pub fn extract_page_user(request: &Request) -> Result<User, Response> {
    request
        .extensions()
        .get::<User>()
        .cloned()
        .ok_or_else(|| Redirect::to("/login").into_response())
}

/// What every authenticated page shell renders: the signed-in user and the
/// session's CSRF token. A page adds at most the entity id from its URL;
/// every list and record it shows is fetched by its script from the admin
/// API, so the page can never show more than the (Cedar-filtered) API does.
pub struct PageShell {
    pub user: UserContext,
    pub csrf_token: String,
}

/// Read the shell context `page_auth` placed in the request extensions, or
/// the redirect to `/login` when the session is missing.
#[allow(clippy::result_large_err)]
pub fn page_shell(request: &Request) -> Result<PageShell, Response> {
    let user = extract_page_user(request)?;
    let csrf_token = request
        .extensions()
        .get::<CsrfToken>()
        .map(|t| t.0.clone())
        .unwrap_or_default();
    Ok(PageShell {
        user: UserContext::from(&user),
        csrf_token,
    })
}

// ---------------------------------------------------------------------------
// Page auth middleware
// ---------------------------------------------------------------------------

const SESSION_COOKIE_NAME: &str = "agtcrdn_session";
const CSRF_COOKIE_NAME: &str = "agtcrdn_csrf";

/// Middleware that redirects unauthenticated users to `/login` for page routes.
///
/// On success, injects the `User` and `CsrfToken` into request extensions so
/// handlers can access them without re-extracting the session.
pub async fn page_auth(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Response {
    let cookie_header = request
        .headers()
        .get(axum::http::header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let session_token = match parse_cookie(cookie_header, SESSION_COOKIE_NAME) {
        Some(t) => t.to_string(),
        None => return redirect_to_login(&request),
    };

    let token_hash = hash_session_token_hmac(&session_token, &state.crypto.session_hash_key);

    let session = match state.store.get_session(&token_hash).await {
        Ok(Some(s)) if s.expires_at >= chrono::Utc::now() => s,
        _ => return redirect_to_login(&request),
    };

    let user = match state.store.get_user(&session.user_id).await {
        Ok(Some(u)) if u.enabled => u,
        _ => {
            return Redirect::to("/login").into_response();
        }
    };

    // Touch session
    state.services.users.touch_session(&token_hash).await;

    // Extract CSRF token from cookie for templates
    let csrf_token = parse_cookie(cookie_header, CSRF_COOKIE_NAME)
        .unwrap_or("")
        .to_string();

    request.extensions_mut().insert(user);
    request.extensions_mut().insert(CsrfToken(csrf_token));

    next.run(request).await
}

/// CSRF token extracted from cookie, available in request extensions.
#[derive(Clone)]
pub struct CsrfToken(pub String);

/// Build a 303 redirect to `/login` preserving the caller's full path and
/// query string in the `next` param so the post-login JS can land them back
/// on the exact URL they tried to reach — e.g. `/activate?user_code=X` from
/// an RFC 8628 `verification_uri_complete` link.
///
/// The value is URL-encoded once here; the client-side login JS reads it via
/// `URLSearchParams.get('next')` (which URL-decodes) and validates the decoded
/// value starts with `/` and does not start with `//` before navigating,
/// preventing open-redirect attacks.
fn redirect_to_login(request: &Request) -> Response {
    let path_and_query = request
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");
    Redirect::to(&format!(
        "/login?next={}",
        urlencoding::encode(path_and_query)
    ))
    .into_response()
}

// ---------------------------------------------------------------------------
// Route registration
// ---------------------------------------------------------------------------

/// Build the page routes router.
///
/// Unauthenticated routes (login) are registered directly.
/// Authenticated routes are wrapped in `page_auth` middleware.
pub fn page_routes(app_state: AppState) -> Router<AppState> {
    // Unauthenticated routes
    let public = Router::new().route("/login", get(auth::login_page));

    // Authenticated routes (redirect to /login if no session)
    let authenticated = Router::new()
        .route("/", get(dashboard_redirect))
        .route("/dashboard", get(dashboard::dashboard_page))
        // Entity pages
        .route("/credentials", get(credentials::credential_list_page))
        .route("/credentials/new", get(credentials::credential_new_page))
        .route(
            "/credentials/{id}",
            get(credentials::credential_detail_page),
        )
        .route(
            "/credentials/{id}/view",
            get(credentials::credential_detail_view_redirect),
        )
        .route("/workspaces", get(workspaces::workspace_list_page))
        .route("/workspaces/{id}", get(workspaces::workspace_detail_page))
        .route(
            "/workspaces/{id}/view",
            get(workspaces::workspace_detail_view_redirect),
        )
        // Security pages (renamed from policies)
        .route("/security", get(policies::policy_list_page_security))
        .route("/security/new", get(policies::policy_new_page_security))
        .route(
            "/security/tester",
            get(policies::policy_tester_page_security),
        )
        .route("/security/{id}", get(policies::policy_detail_page_security))
        // Legacy redirects: /policies → /security
        .route("/policies", get(redirect_policies_to_security))
        .route("/policies/new", get(redirect_policies_new_to_security))
        .route("/policies/{id}", get(redirect_policies_detail_to_security))
        // Legacy redirects: /agents, /devices → /workspaces
        .route("/agents", get(redirect_agents_to_workspaces))
        .route("/devices", get(redirect_devices_to_workspaces))
        // Legacy redirect: /mcp → /mcp-servers
        .route("/mcp", get(redirect_mcp_to_mcp_servers))
        .route("/mcp-marketplace", get(redirect_marketplace_to_mcp_servers))
        .route("/marketplace", get(redirect_marketplace_to_mcp_servers))
        .route("/mcp-servers", get(mcp_servers::mcp_server_list_page))
        .route(
            "/mcp-servers/marketplace",
            get(mcp_servers::mcp_marketplace_page),
        )
        .route(
            "/mcp-servers/{id}",
            get(mcp_servers::mcp_server_detail_page),
        )
        .route("/audit", get(audit::audit_page))
        .route("/audit/{id}", get(audit::audit_page))
        // User management is a Settings section, not a page. The table, the
        // rail and the one "Add User" button all live at
        // `/settings#users-section`; the create form is the one screen of its
        // own, because it is a form (uat/artifacts/fresh-user-docker-2.md F5).
        .route("/settings/users", get(redirect_users_to_settings))
        .route("/settings/users/new", get(users::user_new_page_settings))
        .route("/users", get(redirect_users_to_settings))
        .route("/users/new", get(redirect_users_new_to_settings))
        .route("/settings", get(settings::settings_page))
        .route("/register", get(special::agent_registration_page))
        // RFC 8628 device-flow activation page. `GET` renders the consent
        // form; `POST` records the approve/deny decision via
        // `DeviceCodeService` (which emits the audit event). Both routes
        // require an authenticated session because the approving user's
        // identity is the whole point of the step.
        // The form is a user-code guessing surface like the JSON approve
        // route, so it shares that route's per-(address, session) limiter.
        // `page_auth` wraps this whole router, so only signed-in requests
        // reach the limiter.
        .route(
            "/activate",
            get(activate::get)
                .post(activate::post)
                .layer(axum::middleware::from_fn_with_state(
                    app_state.clone(),
                    crate::middleware::rate_limit_device_approve::rate_limit_device_approve,
                )),
        )
        .route("/activate/success", get(activate::success_page))
        .route("/activate/denied", get(activate::denied_page))
        .route("/activate/expired", get(activate::expired_page))
        .layer(axum::middleware::from_fn_with_state(app_state, page_auth));

    public.merge(authenticated)
}

/// GET / → redirect to /dashboard
async fn dashboard_redirect() -> Redirect {
    Redirect::permanent("/dashboard")
}

/// GET /policies → 301 redirect to /security
async fn redirect_policies_to_security() -> Redirect {
    Redirect::permanent("/security")
}

/// GET /policies/new → 301 redirect to /security/new
async fn redirect_policies_new_to_security() -> Redirect {
    Redirect::permanent("/security/new")
}

/// GET /policies/{id} → 301 redirect to /security/{id}
async fn redirect_policies_detail_to_security(Path(id): Path<String>) -> Redirect {
    Redirect::permanent(&format!("/security/{}", id))
}

/// GET /users and GET /settings/users → 301 redirect to the Settings section.
///
/// There was a standalone Users page here with no rail and a **New User**
/// button beside Settings' **Add User** — three ways to one function and two
/// labels for one action.
async fn redirect_users_to_settings() -> Redirect {
    Redirect::permanent("/settings#users-section")
}

/// GET /users/new → 301 redirect to /settings/users/new
async fn redirect_users_new_to_settings() -> Redirect {
    Redirect::permanent("/settings/users/new")
}

/// GET /agents → 301 redirect to /workspaces
async fn redirect_agents_to_workspaces() -> Redirect {
    Redirect::permanent("/workspaces")
}

/// GET /devices → 301 redirect to /workspaces
async fn redirect_devices_to_workspaces() -> Redirect {
    Redirect::permanent("/workspaces")
}

/// GET /mcp → 302 redirect to /mcp-servers
async fn redirect_mcp_to_mcp_servers() -> Redirect {
    Redirect::to("/mcp-servers")
}

/// GET /marketplace and /mcp-marketplace → 302 redirect to the marketplace
/// page. They used to point at the list's `#marketplace` anchor, which is the
/// half of the page that moved (uat/artifacts/reviews/DESIGN-REVIEW.md §2.5).
async fn redirect_marketplace_to_mcp_servers() -> Redirect {
    Redirect::to("/mcp-servers/marketplace")
}
