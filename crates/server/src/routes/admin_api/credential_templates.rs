//! Credential templates endpoint.
//!
//! GET /api/v1/credential-templates — returns templates for common services.
//!
//! Templates are loaded from embedded JSON files at compile time. Operators can
//! override or extend them at runtime by setting `AGTCRDN_CREDENTIAL_TEMPLATES_DIR`
//! to a directory containing additional `.json` files (same schema). Runtime
//! templates override embedded ones by matching `key`.

use axum::extract::State;
use axum::{routing::get, Json, Router};

use crate::extractors::AuthenticatedUser;
use crate::response::{ApiError, ApiResponse};
use crate::state::{AppState, CatalogState};
use crate::templates::CredentialTemplate;

pub fn routes() -> Router<AppState> {
    Router::new().route("/credential-templates", get(list_templates))
}

/// GET /api/v1/credential-templates — list available credential templates.
async fn list_templates(
    _auth: AuthenticatedUser,
    State(catalog): State<CatalogState>,
) -> Result<Json<ApiResponse<Vec<CredentialTemplate>>>, ApiError> {
    Ok(Json(ApiResponse::ok(
        (*catalog.credential_templates).clone(),
    )))
}
