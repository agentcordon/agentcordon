use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;

use crate::state::SharedState;

pub async fn get_health(State(state): State<SharedState>) -> impl IntoResponse {
    let workspace_count = state.workspaces.read().await.len();
    let server_reachable = {
        let client = crate::server_client::ServerClient::new(
            state.http_client.clone(),
            state.server_url.clone(),
        );
        client.health_check().await
    };

    (
        StatusCode::OK,
        axum::Json(serde_json::json!({
            "status": "ok",
            "version": "3.0.0",
            "workspaces": workspace_count,
            "server_url": state.server_url,
            "server_reachable": server_reachable,
        })),
    )
}
