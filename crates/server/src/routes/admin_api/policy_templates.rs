//! Policy template endpoint.
//!
//! GET /api/v1/policy-templates — returns pre-defined Cedar policy templates.
//!
//! Templates are loaded from embedded JSON files at compile time. Operators can
//! override or extend them at runtime by setting `AGTCRDN_POLICY_TEMPLATES_DIR`
//! to a directory containing additional `.json` files (same schema). Runtime
//! templates override embedded ones by matching `key`.

use axum::extract::State;
use axum::{routing::get, Json, Router};

use crate::extractors::AuthenticatedUser;
use crate::response::{ApiError, ApiResponse};
use crate::state::{AppState, CatalogState};
use crate::templates::PolicyTemplate;

pub fn routes() -> Router<AppState> {
    Router::new().route("/policy-templates", get(list_templates))
}

/// GET /api/v1/policy-templates — list available policy templates.
async fn list_templates(
    _auth: AuthenticatedUser,
    State(catalog): State<CatalogState>,
) -> Result<Json<ApiResponse<Vec<PolicyTemplate>>>, ApiError> {
    Ok(Json(ApiResponse::ok((*catalog.policy_templates).clone())))
}
