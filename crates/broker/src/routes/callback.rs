use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse};
use chrono::Utc;
use serde::Deserialize;

use crate::server_client::ServerClient;
use crate::state::{SharedState, WorkspaceState};
use crate::token_store;

#[derive(Debug, Deserialize)]
pub struct CallbackParams {
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
    pub error_description: Option<String>,
    pub client_id: Option<String>,
}

pub async fn get_callback(
    State(state): State<SharedState>,
    Query(params): Query<CallbackParams>,
) -> impl IntoResponse {
    // Check for error from the server
    if let Some(error) = &params.error {
        let desc = params
            .error_description
            .as_deref()
            .unwrap_or("Unknown error");
        return (
            StatusCode::OK,
            Html(format!(
                r#"<!DOCTYPE html>
<html><head><title>AgentCordon — Authorization Denied</title></head>
<body style="font-family: sans-serif; max-width: 600px; margin: 80px auto; text-align: center;">
<h1>Authorization Denied</h1>
<p>Error: <code>{}</code></p>
<p>{}</p>
<p>You may close this tab.</p>
</body></html>"#,
                html_escape(error),
                html_escape(desc),
            )),
        );
    }

    let code = match &params.code {
        Some(c) => c.clone(),
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Html(error_page("Missing authorization code")),
            );
        }
    };

    let oauth_state = match &params.state {
        Some(s) => s.clone(),
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Html(error_page("Missing state parameter")),
            );
        }
    };

    // Look up pending registration
    let mut pending = {
        let mut pending_map = state.pending.write().await;
        match pending_map.remove(&oauth_state) {
            Some(p) => p,
            None => {
                return (
                    StatusCode::BAD_REQUEST,
                    Html(error_page("Unknown or expired state parameter")),
                );
            }
        }
    };

    // Use client_id from callback params if pending doesn't have one (new workspace flow)
    if pending.client_id.is_empty() {
        match &params.client_id {
            Some(cid) if !cid.is_empty() => {
                pending.client_id = cid.clone();
            }
            _ => {
                return (
                    StatusCode::BAD_REQUEST,
                    Html(error_page("Missing client_id in callback")),
                );
            }
        }
    }

    // Exchange authorization code for tokens
    let server_client = ServerClient::new(state.http_client.clone(), state.server_url.clone());

    let token_resp = match server_client
        .exchange_auth_code(
            &code,
            &pending.code_verifier,
            &pending.redirect_uri,
            &pending.client_id,
        )
        .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = %e, "token exchange failed");
            return (
                StatusCode::OK,
                Html(error_page("Token exchange failed. Please try again.")),
            );
        }
    };

    // Store workspace tokens
    let scopes: Vec<String> = token_resp
        .scope
        .as_deref()
        .unwrap_or("")
        .split_whitespace()
        .map(|s| s.to_string())
        .collect();

    let ws_state = WorkspaceState {
        client_id: pending.client_id,
        access_token: token_resp.access_token,
        refresh_token: token_resp.refresh_token.unwrap_or_default(),
        scopes,
        token_expires_at: Utc::now() + chrono::Duration::seconds(token_resp.expires_in as i64),
        workspace_name: pending.workspace_name.clone(),
        token_status: crate::state::TokenStatus::Valid,
    };

    {
        let mut workspaces = state.workspaces.write().await;
        workspaces.insert(pending.pk_hash.clone(), ws_state);

        // Persist to encrypted store
        if let Err(e) = token_store::save(
            &state.config.token_store_path(),
            &workspaces,
            &state.encryption_key,
        ) {
            tracing::error!(error = %e, "failed to persist token store after callback");
        }
    }

    // Write recovery store (plaintext fallback)
    token_store::save_recovery_store(&state).await;

    tracing::info!(
        workspace = pending.workspace_name,
        "workspace registered successfully"
    );

    (
        StatusCode::OK,
        Html(format!(
            r#"<!DOCTYPE html>
<html><head><title>AgentCordon — Authorization Complete</title></head>
<body style="font-family: sans-serif; max-width: 600px; margin: 80px auto; text-align: center;">
<h1>Authorization Complete</h1>
<p>Workspace <strong>{}</strong> has been registered with the broker.</p>
<p>You may close this tab.</p>
</body></html>"#,
            html_escape(&pending.workspace_name),
        )),
    )
}

fn error_page(message: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html><head><title>AgentCordon — Error</title></head>
<body style="font-family: sans-serif; max-width: 600px; margin: 80px auto; text-align: center;">
<h1>Error</h1>
<p>{}</p>
<p>You may close this tab.</p>
</body></html>"#,
        html_escape(message),
    )
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}
