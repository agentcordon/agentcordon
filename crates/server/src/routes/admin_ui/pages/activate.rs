//! RFC 8628 device-flow activation page (`GET|POST /activate`).
//!
//! This is the browser-facing consent page that the user visits after
//! running e.g. `agentcordon register` in a terminal. It is a sibling of
//! `oauth/authorize.rs`'s consent flow — same HMAC-from-session CSRF
//! pattern, same form-POST style — but specifically for device-code
//! authorization rather than the interactive OAuth authorization_code flow.
//!
//! The security property of the browser-side approve path is "the
//! authenticated user visually verified the `user_code` and clicked
//! Approve". The `public_key_hash` binding is already persisted as
//! `pk_hash_prefill` at device-code issue time, so the service
//! transparently trusts that the approving session belongs to the human
//! who re-typed the user_code.

use askama::Template;
use axum::{
    extract::{Query, Request, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Redirect, Response},
    Form,
};
use serde::Deserialize;
use subtle::ConstantTimeEq;

use agent_cordon_core::domain::user::User;
use agent_cordon_core::oauth2::eff_wordlist::normalize_user_code;
use agent_cordon_core::oauth2::types::DeviceCodeStatus;

use crate::device_code_service::DeviceCodeService;
use crate::extractors::AuthenticatedUser;
use crate::middleware::request_id::CorrelationId;
use crate::routes::oauth::authorize::{compute_csrf_token, extract_session_token};
use crate::routes::oauth::device::provision_workspace_for_approved_device_code;
use crate::state::AppState;

use super::{extract_page_user, render_template};

// ---------------------------------------------------------------------------
// Templates
// ---------------------------------------------------------------------------

#[derive(Template)]
#[template(path = "pages/activate.html")]
struct ActivatePage {
    error_message: Option<String>,
    user_code_prefill: Option<String>,
    /// Workspace name the device code will bind to, when the issuing broker
    /// supplied `workspace_name` at device-code-issue time. Rendered above the
    /// scopes list so the approving user can visually confirm which workspace
    /// they are authorizing — critical in cross-context flows where the code
    /// was generated on a different machine than the browser.
    workspace_name: Option<String>,
    scopes_description: Vec<String>,
    csrf_token: String,
}

#[derive(Template)]
#[template(path = "pages/activate_success.html")]
struct ActivateSuccessPage;

#[derive(Template)]
#[template(path = "pages/activate_denied.html")]
struct ActivateDeniedPage;

#[derive(Template)]
#[template(path = "pages/activate_expired.html")]
struct ActivateExpiredPage;

// ---------------------------------------------------------------------------
// Query + form types
// ---------------------------------------------------------------------------

#[derive(Deserialize, Default)]
pub struct ActivateQuery {
    pub user_code: Option<String>,
}

#[derive(Deserialize)]
pub struct ActivateForm {
    pub csrf_token: String,
    pub user_code: String,
    pub decision: String,
}

// ---------------------------------------------------------------------------
// GET /activate
// ---------------------------------------------------------------------------

/// GET /activate — render the device-flow activation page, or redirect to
/// a terminal-state page if the supplied `user_code` is already resolved.
pub async fn get(
    State(state): State<AppState>,
    Query(query): Query<ActivateQuery>,
    request: Request,
) -> Response {
    if let Err(redirect) = extract_page_user(&request) {
        return redirect;
    }

    let csrf = csrf_for_request(&state, &request);

    let Some(user_code_raw) = query
        .user_code
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    else {
        // No user_code in the URL → blank form so the user can type one.
        return render_template(&ActivatePage {
            error_message: None,
            user_code_prefill: None,
            workspace_name: None,
            scopes_description: vec![],
            csrf_token: csrf,
        });
    };

    let user_code = normalize_user_code(user_code_raw);
    let service = DeviceCodeService::new(state.store.clone());
    match service.get_by_user_code(&user_code).await {
        Ok(None) => Redirect::to("/activate/expired").into_response(),
        Ok(Some(row)) => match row.status {
            DeviceCodeStatus::Expired | DeviceCodeStatus::Consumed => {
                Redirect::to("/activate/expired").into_response()
            }
            DeviceCodeStatus::Denied => Redirect::to("/activate/denied").into_response(),
            DeviceCodeStatus::Approved => Redirect::to("/activate/success").into_response(),
            DeviceCodeStatus::Pending => render_template(&ActivatePage {
                error_message: None,
                user_code_prefill: Some(user_code),
                workspace_name: row.workspace_name_prefill.clone(),
                scopes_description: row.scopes.iter().map(|s| s.to_string()).collect(),
                csrf_token: csrf,
            }),
        },
        Err(e) => {
            tracing::error!(error = %e, "device_code lookup failed on GET /activate");
            render_template(&ActivatePage {
                error_message: Some("Something went wrong. Please try again.".to_string()),
                user_code_prefill: Some(user_code),
                workspace_name: None,
                scopes_description: vec![],
                csrf_token: csrf,
            })
        }
    }
}

// ---------------------------------------------------------------------------
// POST /activate
// ---------------------------------------------------------------------------

/// POST /activate — process the user's approve / deny decision.
pub async fn post(
    State(state): State<AppState>,
    axum::Extension(corr): axum::Extension<CorrelationId>,
    axum::Extension(user): axum::Extension<User>,
    headers: HeaderMap,
    Form(form): Form<ActivateForm>,
) -> Response {
    // Validate CSRF: recompute from the session cookie using HMAC, compare
    // constant-time against the submitted hidden form field.
    let Some(expected) = compute_expected_csrf(&state, &headers) else {
        return (StatusCode::UNAUTHORIZED, "session required").into_response();
    };
    if !bool::from(form.csrf_token.as_bytes().ct_eq(expected.as_bytes())) {
        return (StatusCode::FORBIDDEN, "invalid csrf_token").into_response();
    }

    // Policy gate — mirrors the API `/oauth/device/approve` endpoint. Without
    // this check, any authenticated user (including a `Viewer`, or any
    // operator the admin has specifically denied `manage_workspaces` for)
    // could approve a pending device code from the browser and — on first
    // registration of a prefilled workspace_name — become `owner_id` of the
    // resulting workspace row. Both approve AND deny are gated so a viewer
    // can't cancel another operator's pending enrollment either. The
    // underlying `AuditingPolicyEngine::evaluate` emits a `PolicyEvaluated`
    // audit event on both permit and deny, so we do NOT hand-build one here.
    let auth = AuthenticatedUser {
        is_root: user.is_root,
        user: user.clone(),
    };
    if let Err(e) = crate::routes::admin_api::check_cedar_permission(
        &state,
        &auth,
        agent_cordon_core::policy::actions::MANAGE_WORKSPACES,
        agent_cordon_core::policy::PolicyResource::System,
    ) {
        return match e {
            // HTML-first UX: re-render the activate page with a user-friendly
            // message instead of the raw 403 JSON payload the API sibling
            // returns. The audit event was already emitted inside evaluate().
            crate::response::ApiError::Forbidden(_) => render_with_error(
                &state,
                &headers,
                Some(normalize_user_code(form.user_code.trim())),
                "You do not have permission to approve device activations. \
                 Contact your administrator.",
            ),
            other => other.into_response(),
        };
    }

    let user_code = normalize_user_code(form.user_code.trim());
    if user_code.is_empty() {
        return render_with_error(&state, &headers, None, "Enter an activation code.");
    }

    let service = DeviceCodeService::new(state.store.clone());
    let row = match service.get_by_user_code(&user_code).await {
        Ok(Some(r)) => r,
        Ok(None) => {
            return render_with_error(
                &state,
                &headers,
                Some(user_code.clone()),
                "This activation code is no longer valid.",
            );
        }
        Err(e) => {
            tracing::error!(error = %e, "device_code lookup failed on POST /activate");
            return render_with_error(
                &state,
                &headers,
                Some(user_code.clone()),
                "Something went wrong. Please try again.",
            );
        }
    };

    // Only pending rows can be approved or denied. Terminal rows (approved,
    // denied, expired, consumed) are "no longer valid" from the user's POV.
    if !matches!(row.status, DeviceCodeStatus::Pending) {
        return render_with_error(
            &state,
            &headers,
            Some(user_code),
            "This activation code is no longer valid.",
        );
    }

    match form.decision.as_str() {
        "approve" => match service
            .approve(
                &user_code,
                &user.id.0.to_string(),
                Some(&user.username),
                row.workspace_name_prefill.as_deref(),
                &corr.0,
            )
            .await
        {
            // Row is now approved. If the issuer asked us to bind a
            // workspace identity (`workspace_name_prefill` set), provision
            // the workspace record + OAuth client the same way the API
            // approve endpoint does — otherwise `/oauth/token`'s lookup by
            // workspace name returns None and the CLI loops on
            // `invalid_grant` forever (round-2 beta P0).
            Ok(true) => {
                match provision_workspace_for_approved_device_code(&state, &auth, &row).await {
                    Ok(()) => Redirect::to("/activate/success").into_response(),
                    Err(e) => {
                        tracing::error!(
                            error = ?e,
                            workspace_name = ?row.workspace_name_prefill,
                            "device_code approved but workspace provisioning failed from /activate"
                        );
                        render_with_error(
                            &state,
                            &headers,
                            Some(user_code),
                            "Approved, but workspace provisioning failed. \
                             Please retry the device flow from your CLI.",
                        )
                    }
                }
            }
            Ok(false) => render_with_error(
                &state,
                &headers,
                Some(user_code),
                "This activation code can't be approved.",
            ),
            Err(e) => {
                tracing::error!(error = %e, "device_code approve failed from /activate");
                render_with_error(
                    &state,
                    &headers,
                    Some(user_code),
                    "Something went wrong. Please try again.",
                )
            }
        },
        "deny" => match service
            .deny(
                &user_code,
                &user.id.0.to_string(),
                Some(&user.username),
                row.workspace_name_prefill.as_deref(),
                &corr.0,
            )
            .await
        {
            Ok(true) => Redirect::to("/activate/denied").into_response(),
            Ok(false) => render_with_error(
                &state,
                &headers,
                Some(user_code),
                "This activation code can't be denied.",
            ),
            Err(e) => {
                tracing::error!(error = %e, "device_code deny failed from /activate");
                render_with_error(
                    &state,
                    &headers,
                    Some(user_code),
                    "Something went wrong. Please try again.",
                )
            }
        },
        _ => (StatusCode::BAD_REQUEST, "invalid decision").into_response(),
    }
}

// ---------------------------------------------------------------------------
// Terminal-state pages
// ---------------------------------------------------------------------------

pub async fn success_page() -> Response {
    render_template(&ActivateSuccessPage)
}

pub async fn denied_page() -> Response {
    render_template(&ActivateDeniedPage)
}

pub async fn expired_page() -> Response {
    render_template(&ActivateExpiredPage)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Compute the HMAC-derived CSRF token for the current session, if any.
/// Mirrors `oauth/authorize.rs::compute_csrf_token` so the same session
/// produces a deterministic token that can be recomputed on POST — no
/// server-side CSRF state is needed.
fn compute_expected_csrf(state: &AppState, headers: &HeaderMap) -> Option<String> {
    let session_token = extract_session_token(headers)?;
    Some(compute_csrf_token(
        &session_token,
        &state.session_hash_key,
    ))
}

/// Same as `compute_expected_csrf` but returns an empty string when the
/// session token isn't available. Used for GET rendering, where we prefer
/// to show the page over erroring out — the POST path still validates.
fn csrf_from_headers(state: &AppState, headers: &HeaderMap) -> String {
    compute_expected_csrf(state, headers).unwrap_or_default()
}

/// Same as above but takes a `Request` — used by the GET handler which
/// owns the whole request.
fn csrf_for_request(state: &AppState, request: &Request) -> String {
    csrf_from_headers(state, request.headers())
}

/// Re-render `activate.html` with an error message after a failed POST.
/// We don't re-look-up the scopes here — once the user hit Approve / Deny
/// they've already seen the consent panel, and keeping the fallback path
/// simple avoids extra DB round-trips.
fn render_with_error(
    state: &AppState,
    headers: &HeaderMap,
    user_code_prefill: Option<String>,
    error_message: &str,
) -> Response {
    render_template(&ActivatePage {
        error_message: Some(error_message.to_string()),
        user_code_prefill,
        // On error re-render we don't re-look-up the device_code row, so we
        // don't have workspace_name_prefill available — leave blank. The
        // happy path GET /activate above is where the user sees it.
        workspace_name: None,
        scopes_description: vec![],
        csrf_token: csrf_from_headers(state, headers),
    })
}
