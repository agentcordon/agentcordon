use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;

use crate::auth::AuthenticatedWorkspace;
use crate::server_client::ServerClient;
use crate::state::SharedState;

use super::helpers::{require_scope, with_token_refresh};

pub async fn get_credentials(
    State(state): State<SharedState>,
    request: axum::extract::Request,
) -> impl IntoResponse {
    let auth = request
        .extensions()
        .get::<AuthenticatedWorkspace>()
        .cloned()
        .unwrap();

    // Scope pre-check: workspace must have credentials:discover
    if let Err(e) = require_scope(
        &state,
        &auth.pk_hash,
        "credentials:discover",
        "credentials.list",
    )
    .await
    {
        return e;
    }

    let server_client = ServerClient::new(state.http_client.clone(), state.server_url.clone());

    match with_token_refresh(&state, &auth.pk_hash, |token| {
        let sc = server_client.clone();
        async move { sc.list_credentials(&token).await }
    })
    .await
    {
        Ok(creds) => (
            StatusCode::OK,
            axum::Json(serde_json::json!({ "data": creds })),
        ),
        Err(e) => e,
    }
}
