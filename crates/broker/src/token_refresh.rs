//! Background token refresh task.
//!
//! Proactively refreshes OAuth tokens before they expire,
//! and marks workspaces as `revoked` on refresh failure.

use chrono::Utc;
use tracing::{info, warn};

use crate::server_client::ServerClient;
use crate::state::SharedState;
use crate::token_store;

/// Spawn the background token refresh loop.
///
/// Checks all workspace tokens every 30 seconds. If a token expires within
/// `config.token_ttl_buffer` seconds, attempts a proactive refresh.
pub fn spawn_refresh_task(state: SharedState) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
        loop {
            interval.tick().await;
            refresh_expiring_tokens(&state).await;
        }
    })
}

async fn refresh_expiring_tokens(state: &SharedState) {
    let buffer_secs = state.config.token_ttl_buffer as i64;
    let now = Utc::now();

    // Collect workspaces that need refresh
    let to_refresh: Vec<(String, String, String)> = {
        let workspaces = state.workspaces.read().await;
        workspaces
            .iter()
            .filter(|(_, ws)| {
                ws.token_status == "valid"
                    && (ws.token_expires_at - now).num_seconds() < buffer_secs
            })
            .map(|(pk_hash, ws)| {
                (
                    pk_hash.clone(),
                    ws.refresh_token.clone(),
                    ws.client_id.clone(),
                )
            })
            .collect()
    };

    if to_refresh.is_empty() {
        return;
    }

    let server_client = ServerClient::new(state.http_client.clone(), state.server_url.clone());

    for (pk_hash, refresh_token, client_id) in to_refresh {
        match server_client
            .refresh_token(&refresh_token, &client_id)
            .await
        {
            Ok(token_resp) => {
                let mut workspaces = state.workspaces.write().await;
                if let Some(ws) = workspaces.get_mut(&pk_hash) {
                    ws.access_token = token_resp.access_token;
                    if let Some(rt) = token_resp.refresh_token {
                        ws.refresh_token = rt;
                    }
                    ws.token_expires_at =
                        Utc::now() + chrono::Duration::seconds(token_resp.expires_in as i64);
                    ws.token_status = "valid".to_string();
                    info!(
                        workspace = ws.workspace_name,
                        "proactively refreshed OAuth token"
                    );
                }
                drop(workspaces);

                // Persist updated tokens
                let workspaces = state.workspaces.read().await;
                if let Err(e) = token_store::save(
                    &state.config.token_store_path(),
                    &workspaces,
                    &state.encryption_key,
                ) {
                    warn!(error = %e, "failed to persist token store after refresh");
                }
            }
            Err(e) => {
                warn!(
                    pk_hash = pk_hash,
                    error = %e,
                    "token refresh failed — marking workspace as revoked"
                );
                let mut workspaces = state.workspaces.write().await;
                if let Some(ws) = workspaces.get_mut(&pk_hash) {
                    ws.token_status = "revoked".to_string();
                }
            }
        }
    }
}

/// Attempt a reactive token refresh for a specific workspace (on 401 from server).
///
/// Returns `true` if the refresh succeeded and the caller should retry.
pub async fn try_reactive_refresh(state: &SharedState, pk_hash: &str) -> bool {
    let (refresh_token, client_id) = {
        let workspaces = state.workspaces.read().await;
        match workspaces.get(pk_hash) {
            Some(ws) if ws.token_status == "valid" || ws.token_status == "expired" => {
                (ws.refresh_token.clone(), ws.client_id.clone())
            }
            _ => return false,
        }
    };

    let server_client = ServerClient::new(state.http_client.clone(), state.server_url.clone());

    match server_client
        .refresh_token(&refresh_token, &client_id)
        .await
    {
        Ok(token_resp) => {
            let mut workspaces = state.workspaces.write().await;
            if let Some(ws) = workspaces.get_mut(pk_hash) {
                ws.access_token = token_resp.access_token;
                if let Some(rt) = token_resp.refresh_token {
                    ws.refresh_token = rt;
                }
                ws.token_expires_at =
                    Utc::now() + chrono::Duration::seconds(token_resp.expires_in as i64);
                ws.token_status = "valid".to_string();
            }
            drop(workspaces);

            let workspaces = state.workspaces.read().await;
            if let Err(e) = token_store::save(
                &state.config.token_store_path(),
                &workspaces,
                &state.encryption_key,
            ) {
                warn!(error = %e, "failed to persist token store after reactive refresh");
            }

            true
        }
        Err(e) => {
            warn!(error = %e, "reactive token refresh failed — marking as revoked");
            let mut workspaces = state.workspaces.write().await;
            if let Some(ws) = workspaces.get_mut(pk_hash) {
                ws.token_status = "revoked".to_string();
            }
            false
        }
    }
}
