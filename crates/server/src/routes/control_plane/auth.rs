use axum::{routing::get, Json, Router};

use agent_cordon_core::domain::workspace::Workspace;

use crate::extractors::AuthenticatedWorkspace;
use crate::response::{ApiError, ApiResponse};
use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new().route("/auth/whoami", get(whoami))
}

async fn whoami(auth: AuthenticatedWorkspace) -> Result<Json<ApiResponse<Workspace>>, ApiError> {
    Ok(Json(ApiResponse::ok(auth.workspace)))
}
