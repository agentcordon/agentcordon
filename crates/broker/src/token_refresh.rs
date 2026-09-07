//! Background token refresh task and single-flight reactive refresh.
//!
//! Proactively refreshes OAuth tokens before they expire, marks workspaces
//! as `revoked` on terminal refresh failure, and serialises refreshes per
//! workspace so two callers that both saw a 401 spend the refresh token
//! once between them.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use chrono::Utc;
use tracing::{info, warn};

use crate::server_client::{ServerClient, ServerClientError};
use crate::state::{SharedState, TokenStatus};
use crate::token_store;

/// A refresh that completed this recently satisfies a caller that arrives
/// holding a 401 from before it: the token it was refused with is gone.
const RECENT_REFRESH: Duration = Duration::from_secs(5);

/// Per-workspace refresh locks.
///
/// The lock's payload is the instant of the last successful refresh under
/// it. A caller acquires the lock, re-reads the workspace, and refreshes
/// only if nobody else did since it decided to.
#[derive(Default)]
pub struct RefreshLocks {
    inner: Mutex<HashMap<String, Arc<tokio::sync::Mutex<Option<Instant>>>>>,
}

impl RefreshLocks {
    /// The lock for `pk_hash`, created on first use.
    pub fn for_workspace(&self, pk_hash: &str) -> Arc<tokio::sync::Mutex<Option<Instant>>> {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entry(pk_hash.to_string())
            .or_default()
            .clone()
    }
}

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
        let mut interval = tokio::time::interval(Duration::from_secs(30));
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
    const GRACE: Duration = Duration::from_secs(60);
    let now = Instant::now();
    let mut pending = state.pending.write().await;
    let before = pending.len();
    pending.retain(|_, reg| now.duration_since(reg.created_at) < reg.expires_in + GRACE);
    let removed = before - pending.len();
    if removed > 0 {
        info!(removed, "cleaned up stale pending device registrations");
    }
}

/// Whether a workspace's token is within the proactive-refresh buffer.
fn expiring_soon(ws: &crate::state::WorkspaceState, buffer_secs: i64) -> bool {
    ws.token_status == TokenStatus::Valid
        && (ws.token_expires_at - Utc::now()).num_seconds() < buffer_secs
}

async fn refresh_expiring_tokens(state: &SharedState) {
    let buffer_secs = state.config.token_ttl_buffer as i64;

    let candidates: Vec<String> = {
        let workspaces = state.workspaces.read().await;
        workspaces
            .iter()
            .filter(|(_, ws)| expiring_soon(ws, buffer_secs))
            .map(|(pk_hash, _)| pk_hash.clone())
            .collect()
    };

    for pk_hash in candidates {
        let lock = state.refresh_locks.for_workspace(&pk_hash);
        let mut last_refresh = lock.lock().await;

        // Re-read under the lock: a reactive refresh may have run since
        // the candidate list was built.
        let credentials = {
            let workspaces = state.workspaces.read().await;
            workspaces
                .get(&pk_hash)
                .filter(|ws| expiring_soon(ws, buffer_secs))
                .map(|ws| (ws.refresh_token.clone(), ws.client_id.clone()))
        };
        let Some((refresh_token, client_id)) = credentials else {
            continue;
        };

        match refresh_workspace(state, &pk_hash, &refresh_token, &client_id).await {
            Ok(()) => {
                *last_refresh = Some(Instant::now());
                info!(pk_hash = pk_hash, "proactively refreshed OAuth token");
            }
            Err(e) => match classify_refresh_error(&e) {
                RefreshErrorKind::Terminal => {
                    warn!(
                        pk_hash = pk_hash,
                        error = %e,
                        "token refresh terminally rejected by server — marking workspace as revoked"
                    );
                    mark_revoked(state, &pk_hash).await;
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

/// Attempt a reactive token refresh for a specific workspace (on 401 from
/// the server).
///
/// Single-flight per workspace: the caller notes the access token it was
/// refused with, waits for the workspace's refresh lock, and re-reads the
/// state. If the token changed while it waited, or a refresh completed
/// within `RECENT_REFRESH`, the refresh already happened and the caller
/// should retry with the new token without spending another refresh.
///
/// Returns `true` if the workspace now holds a token the caller should
/// retry with.
pub async fn try_reactive_refresh(state: &SharedState, pk_hash: &str) -> bool {
    let refused_with = {
        let workspaces = state.workspaces.read().await;
        match workspaces.get(pk_hash) {
            Some(ws) if ws.token_status != TokenStatus::Revoked => ws.access_token.clone(),
            _ => return false,
        }
    };

    let lock = state.refresh_locks.for_workspace(pk_hash);
    let mut last_refresh = lock.lock().await;

    let current = {
        let workspaces = state.workspaces.read().await;
        match workspaces.get(pk_hash) {
            Some(ws) if ws.token_status != TokenStatus::Revoked => (
                ws.access_token.clone(),
                ws.refresh_token.clone(),
                ws.client_id.clone(),
            ),
            _ => return false,
        }
    };
    let (access_token, refresh_token, client_id) = current;

    let refreshed_meanwhile = access_token != refused_with
        || last_refresh.is_some_and(|at| at.elapsed() < RECENT_REFRESH);
    if refreshed_meanwhile {
        info!(
            pk_hash = pk_hash,
            "token already refreshed by a concurrent request"
        );
        return true;
    }

    match refresh_workspace(state, pk_hash, &refresh_token, &client_id).await {
        Ok(()) => {
            *last_refresh = Some(Instant::now());
            true
        }
        Err(e) => {
            match classify_refresh_error(&e) {
                RefreshErrorKind::Terminal => {
                    warn!(error = %e, "reactive token refresh terminally rejected — marking as revoked");
                    mark_revoked(state, pk_hash).await;
                }
                RefreshErrorKind::Transient => {
                    info!(error = %e, "reactive token refresh failed transiently — leaving workspace valid");
                }
            }
            false
        }
    }
}

/// Call the server's token endpoint and, on success, install the new
/// token, persist the encrypted store, and update the recovery store when
/// the refresh token rotated. Callers hold the workspace's refresh lock.
async fn refresh_workspace(
    state: &SharedState,
    pk_hash: &str,
    refresh_token: &str,
    client_id: &str,
) -> Result<(), ServerClientError> {
    let server_client = ServerClient::new(state.http_client.clone(), state.server_url.clone());
    let token_resp = server_client
        .refresh_token(refresh_token, client_id)
        .await?;
    let refresh_rotated = token_resp.refresh_token.is_some();

    {
        let mut workspaces = state.workspaces.write().await;
        if let Some(ws) = workspaces.get_mut(pk_hash) {
            ws.access_token = token_resp.access_token;
            if let Some(rt) = token_resp.refresh_token {
                ws.refresh_token = rt;
            }
            ws.token_expires_at = Utc::now() + chrono::Duration::seconds(token_resp.expires_in);
            ws.token_status = TokenStatus::Valid;
        }
    }

    {
        let workspaces = state.workspaces.read().await;
        if let Err(e) = token_store::save(
            &state.config.token_store_path(),
            &workspaces,
            &state.encryption_key,
        ) {
            warn!(error = %e, "failed to persist token store after refresh");
        }
    }

    if refresh_rotated {
        token_store::save_recovery_store(state).await;
    }

    Ok(())
}

async fn mark_revoked(state: &SharedState, pk_hash: &str) {
    let mut workspaces = state.workspaces.write().await;
    if let Some(ws) = workspaces.get_mut(pk_hash) {
        ws.token_status = TokenStatus::Revoked;
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
