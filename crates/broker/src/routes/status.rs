use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;

use crate::auth::AuthenticatedWorkspace;
use crate::state::SharedState;

pub async fn get_status(
    State(state): State<SharedState>,
    request: axum::extract::Request,
) -> impl IntoResponse {
    let auth = request
        .extensions()
        .get::<AuthenticatedWorkspace>()
        .cloned()
        .unwrap();

    let workspaces = state.workspaces.read().await;
    let ws = match workspaces.get(&auth.pk_hash) {
        Some(ws) => ws,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                axum::Json(serde_json::json!({
                    "error": { "code": "unauthorized", "message": "Workspace not registered" }
                })),
            );
        }
    };

    (
        StatusCode::OK,
        axum::Json(serde_json::json!({
            "data": {
                "registered": true,
                "scopes": ws.scopes,
                "token_expires_at": ws.token_expires_at.to_rfc3339(),
                "token_status": ws.token_status,
                "server_url": state.server_url,
            }
        })),
    )
}
