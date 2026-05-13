//! Background token refresh task.
//!
//! Proactively refreshes OAuth tokens before they expire,
//! and marks workspaces as `revoked` on refresh failure.

use std::time::Instant;

use chrono::Utc;
use tracing::{info, warn};

use crate::server_client::{ServerClient, ServerClientError};
use crate::state::{SharedState, TokenStatus};
use crate::token_store;

/// Classification of a refresh failure used to decide whether to flip the
/// workspace to `Revoked` (terminal) or leave it `Valid` so the next tick
/// retries (transient).
#[derive(Debug, PartialEq, Eq)]
enum RefreshErrorKind {
    /// Server definitively rejected the refresh token (RFC 6749 §5.2 OAuth
    /// error envelope on a 4xx response). Re-registration is required.
    Terminal,
    /// Network failure, server 5xx, or unparseable response. The refresh
    /// token may still be valid; retry on the next tick.
    Transient,
}

/// Classify a refresh failure. Terminal iff the response is a 4xx with a
/// JSON body containing an `"error"` field — which is the RFC 6749 OAuth
/// error envelope. Anything else (5xx, network, malformed body) is treated
/// as transient so a brief outage cannot permanently brick a workspace.
fn classify_refresh_error(err: &ServerClientError) -> RefreshErrorKind {
    match err {
        ServerClientError::ServerError { status, body } if (400..500).contains(status) => {
            match serde_json::from_str::<serde_json::Value>(body) {
                Ok(v) if v.get("error").and_then(|e| e.as_str()).is_some() => {
                    RefreshErrorKind::Terminal
                }
                _ => RefreshErrorKind::Transient,
            }
        }
        _ => RefreshErrorKind::Transient,
    }
}

/// Spawn the background token refresh loop.
///
/// Checks all workspace tokens every 30 seconds. If a token expires within
/// `config.token_ttl_buffer` seconds, attempts a proactive refresh.
pub fn spawn_refresh_task(state: SharedState) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
        loop {
            interval.tick().await;
            cleanup_stale_pending(&state).await;
            refresh_expiring_tokens(&state).await;
        }
    })
}

/// Remove pending device-flow registrations whose device code has passed
/// its server-advertised TTL (with a small grace buffer). The background
/// poll task also removes entries on terminal outcomes; this sweep is a
/// safety net for tasks that never ran (e.g. broker just started with a
/// stale pending entry from a previous session — currently impossible
/// since pending is in-memory, but guards against future persistence).
async fn cleanup_stale_pending(state: &SharedState) {
    const GRACE: std::time::Duration = std::time::Duration::from_secs(60);
    let now = Instant::now();
    let mut pending = state.pending.write().await;
    let before = pending.len();
    pending.retain(|_, reg| now.duration_since(reg.created_at) < reg.expires_in + GRACE);
    let removed = before - pending.len();
    if removed > 0 {
        info!(removed, "cleaned up stale pending device registrations");
    }
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
                ws.token_status == TokenStatus::Valid
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
                let refresh_rotated = token_resp.refresh_token.is_some();
                let mut workspaces = state.workspaces.write().await;
                if let Some(ws) = workspaces.get_mut(&pk_hash) {
                    ws.access_token = token_resp.access_token;
                    if let Some(rt) = token_resp.refresh_token {
                        ws.refresh_token = rt;
                    }
                    ws.token_expires_at =
                        Utc::now() + chrono::Duration::seconds(token_resp.expires_in as i64);
                    ws.token_status = TokenStatus::Valid;
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
                drop(workspaces);

                // Update recovery store when refresh token was rotated
                if refresh_rotated {
                    token_store::save_recovery_store(state).await;
                }
            }
            Err(e) => match classify_refresh_error(&e) {
                RefreshErrorKind::Terminal => {
                    warn!(
                        pk_hash = pk_hash,
                        error = %e,
                        "token refresh terminally rejected by server — marking workspace as revoked"
                    );
                    let mut workspaces = state.workspaces.write().await;
                    if let Some(ws) = workspaces.get_mut(&pk_hash) {
                        ws.token_status = TokenStatus::Revoked;
                    }
                }
                RefreshErrorKind::Transient => {
                    info!(
                        pk_hash = pk_hash,
                        error = %e,
                        "token refresh failed transiently — leaving workspace valid for retry"
                    );
                }
            },
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
            Some(ws)
                if ws.token_status == TokenStatus::Valid
                    || ws.token_status == TokenStatus::Expired =>
            {
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
            let refresh_rotated = token_resp.refresh_token.is_some();
            let mut workspaces = state.workspaces.write().await;
            if let Some(ws) = workspaces.get_mut(pk_hash) {
                ws.access_token = token_resp.access_token;
                if let Some(rt) = token_resp.refresh_token {
                    ws.refresh_token = rt;
                }
                ws.token_expires_at =
                    Utc::now() + chrono::Duration::seconds(token_resp.expires_in as i64);
                ws.token_status = TokenStatus::Valid;
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
            drop(workspaces);

            // Update recovery store when refresh token was rotated
            if refresh_rotated {
                token_store::save_recovery_store(state).await;
            }

            true
        }
        Err(e) => {
            match classify_refresh_error(&e) {
                RefreshErrorKind::Terminal => {
                    warn!(error = %e, "reactive token refresh terminally rejected — marking as revoked");
                    let mut workspaces = state.workspaces.write().await;
                    if let Some(ws) = workspaces.get_mut(pk_hash) {
                        ws.token_status = TokenStatus::Revoked;
                    }
                }
                RefreshErrorKind::Transient => {
                    info!(error = %e, "reactive token refresh failed transiently — leaving workspace valid");
                }
            }
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server_client::ServerClientError;

    #[test]
    fn classifies_invalid_grant_as_terminal() {
        // Server explicitly rejected the refresh token (RFC 6749 §5.2).
        // The refresh token is dead — re-register is the only path.
        let err = ServerClientError::ServerError {
            status: 400,
            body:
                r#"{"error":"invalid_grant","error_description":"refresh token has been revoked"}"#
                    .to_string(),
        };
        assert!(matches!(
            classify_refresh_error(&err),
            RefreshErrorKind::Terminal
        ));
    }

    #[test]
    fn classifies_request_failed_as_transient() {
        // Network error: DNS, TCP reset, broker briefly offline. The refresh
        // token is fine; we just couldn't reach the server. Must NOT brick
        // the workspace — the next tick should retry.
        let err = ServerClientError::RequestFailed("connection refused".to_string());
        assert!(matches!(
            classify_refresh_error(&err),
            RefreshErrorKind::Transient
        ));
    }

    #[test]
    fn classifies_invalid_client_as_terminal() {
        // 401 invalid_client also means the broker's identity is wrong —
        // re-registration is the recovery path, retrying won't help.
        let err = ServerClientError::ServerError {
            status: 401,
            body: r#"{"error":"invalid_client","error_description":"unknown client"}"#.to_string(),
        };
        assert!(matches!(
            classify_refresh_error(&err),
            RefreshErrorKind::Terminal
        ));
    }

    #[test]
    fn classifies_5xx_as_transient() {
        // Server temporarily down (deploy, restart, overload). Refresh token
        // is intact; the next tick will succeed once the server is back.
        let err = ServerClientError::ServerError {
            status: 503,
            body: "service unavailable".to_string(),
        };
        assert!(matches!(
            classify_refresh_error(&err),
            RefreshErrorKind::Transient
        ));
    }

    #[test]
    fn classifies_4xx_with_unparseable_body_as_transient() {
        // 4xx but the body isn't an OAuth error envelope — could be a
        // proxy/CDN injecting an HTML error page. Be lenient: retry rather
        // than nuke a workspace on ambiguous evidence.
        let err = ServerClientError::ServerError {
            status: 400,
            body: "<html>bad gateway</html>".to_string(),
        };
        assert!(matches!(
            classify_refresh_error(&err),
            RefreshErrorKind::Transient
        ));
    }

    #[test]
    fn classifies_invalid_response_as_transient() {
        // We got *something* back but couldn't deserialize. Server is
        // misbehaving but the refresh token isn't necessarily dead.
        let err = ServerClientError::InvalidResponse("missing field".to_string());
        assert!(matches!(
            classify_refresh_error(&err),
            RefreshErrorKind::Transient
        ));
    }
}
