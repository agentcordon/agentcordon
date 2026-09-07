//! Workspace registration via RFC 8628 Device Authorization Grant.
//!
//! Flow:
//! 1. CLI POSTs workspace name + Ed25519 public key + self-signature.
//! 2. Broker verifies the signature and computes `pk_hash`.
//! 3. Broker calls the server's `/api/v1/oauth/device/code` endpoint.
//! 4. Broker stores a [`PendingDeviceRegistration`] keyed by `pk_hash` and
//!    spawns a background task that polls the server's token endpoint until
//!    approval, denial, or expiry.
//! 5. Broker returns the `user_code` + `verification_uri` to the CLI so the
//!    human can approve in a browser. The opaque `device_code` NEVER leaves
//!    the broker.
//!
//! Re-registration semantics: if a pending entry already exists for the
//! same `pk_hash`, it is replaced. If an approved workspace already exists,
//! a new device flow is initiated — the server will replace the owning user
//! on approval (per v0.3.0 locked decision #1).

use std::time::{Duration, Instant};

use agentcordon_identity::VerifyError;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use chrono::Utc;
use serde::Deserialize;
use tracing::{error, info, warn};

use agent_cordon_core::wire::oauth::DEFAULT_DEVICE_POLL_INTERVAL_SECS;

use crate::server_client::{DeviceTokenPollResult, ServerClient};
use crate::state::{PendingDeviceRegistration, SharedState, TokenStatus, WorkspaceState};
use crate::token_store;

/// Well-known public bootstrap client_id for the broker. Baked into the
/// binary (per v0.3.0 locked decision #3) — the server permits this
/// client to use the device_code grant.
pub const BROKER_CLIENT_ID: &str = "agentcordon-broker";

#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    pub workspace_name: String,
    pub public_key: String,
    pub scopes: Vec<String>,
    /// Unix seconds, decimal; checked against the broker clock with the
    /// same skew window as a signed request.
    pub timestamp: String,
    /// 16 random bytes, lowercase hex; refused if this key already used it
    /// within the window.
    pub nonce: String,
    pub signature: String,
}

pub async fn post_register(
    State(state): State<SharedState>,
    axum::Json(body): axum::Json<RegisterRequest>,
) -> impl IntoResponse {
    // 1. Verify the Ed25519 self-signature over
    //    `workspace_name \n public_key \n scopes_joined \n timestamp \n nonce`
    //    (the identity crate's register payload, the same one the CLI
    //    signs) and take the pk_hash from the verified key. Re-registration
    //    of an already-approved workspace is allowed — the server handles
    //    owner replacement on approval.
    let now = Utc::now().timestamp();
    let pk_hash = match agentcordon_identity::verify_register(
        &body.public_key,
        &body.workspace_name,
        &body.scopes,
        &body.timestamp,
        &body.nonce,
        &body.signature,
        now,
    ) {
        Ok(hash) => hash,
        Err(VerifyError::InvalidPublicKey) => return bad_request("Invalid public key"),
        Err(VerifyError::InvalidSignature) => return bad_request("Invalid signature"),
        Err(VerifyError::SignatureMismatch) => return bad_request("Signature verification failed"),
        Err(VerifyError::TimestampOutOfRange | VerifyError::InvalidNonce) => {
            return unauthorized("Register request timestamp or nonce rejected")
        }
    };

    // 2. Replay: the same self-signed body presented again within the
    //    window is refused, exactly like a replayed signed request.
    if !state.nonces.check_and_insert(&pk_hash, &body.nonce, now) {
        return unauthorized("Register request timestamp or nonce rejected");
    }

    // Clear any stale error from a previous attempt so polling `/status`
    // doesn't surface yesterday's failure.
    {
        state.registration_errors.write().await.remove(&pk_hash);
    }

    // 3. Request a device code from the server.
    let server_client = ServerClient::new(state.http_client.clone(), state.server_url.clone());
    let device = match server_client
        .request_device_code(
            BROKER_CLIENT_ID,
            &body.scopes,
            &body.workspace_name,
            &pk_hash,
        )
        .await
    {
        Ok(d) => d,
        Err(e) => {
            // Log without secrets — the request contains no device_code yet.
            error!(error = %e, "device authorization request failed");
            return (
                StatusCode::BAD_GATEWAY,
                axum::Json(serde_json::json!({
                    "error": {
                        "code": "bad_gateway",
                        "message": "Failed to initiate device authorization with server"
                    }
                })),
            );
        }
    };

    // 4. Store the pending entry (replacing any prior one for this pk_hash).
    let pending_entry = PendingDeviceRegistration {
        workspace_name: body.workspace_name.clone(),
        device_code: device.device_code.clone(),
        created_at: Instant::now(),
        expires_in: Duration::from_secs(device.expires_in.max(0) as u64),
    };
    {
        let mut pending = state.pending.write().await;
        pending.insert(pk_hash.clone(), pending_entry);
    }

    info!(
        workspace = %body.workspace_name,
        user_code = %device.user_code,
        "device authorization initiated"
    );

    // 5. Spawn the background poll task. It owns its own state clone.
    tokio::spawn(poll_device_code_task(
        state.clone(),
        pk_hash.clone(),
        device.device_code.clone(),
        Duration::from_secs(
            device
                .interval
                .unwrap_or(DEFAULT_DEVICE_POLL_INTERVAL_SECS)
                .max(1) as u64,
        ),
    ));

    (
        StatusCode::OK,
        axum::Json(serde_json::json!({
            "data": {
                "user_code": device.user_code,
                "verification_uri": device.verification_uri,
                "verification_uri_complete": device.verification_uri_complete,
                "expires_in": device.expires_in,
                "interval": device.interval,
                "status": "awaiting_approval"
            }
        })),
    )
}

/// Background task: poll `/oauth/token` with the device_code grant until
/// approved, denied, or expired. Obeys `slow_down` by doubling the interval.
async fn poll_device_code_task(
    state: SharedState,
    pk_hash: String,
    device_code: String,
    initial_interval: Duration,
) {
    let server_client = ServerClient::new(state.http_client.clone(), state.server_url.clone());
    let mut interval = initial_interval;
    let start = Instant::now();

    // Hard cap at 15 minutes as a belt-and-braces against a server that
    // never returns expired_token. RFC 8628 default TTL is 10 minutes.
    let hard_deadline = Duration::from_secs(900);

    loop {
        tokio::time::sleep(interval).await;

        // Check the entry still exists (may have been cancelled by
        // deregister or superseded by a new /register).
        let still_pending = {
            let pending = state.pending.read().await;
            pending
                .get(&pk_hash)
                .map(|p| p.device_code == device_code)
                .unwrap_or(false)
        };
        if !still_pending {
            return;
        }

        if start.elapsed() > hard_deadline {
            record_registration_failure(&state, &pk_hash, "device code polling timed out").await;
            return;
        }

        match server_client
            .poll_device_token(&device_code, BROKER_CLIENT_ID)
            .await
        {
            DeviceTokenPollResult::Pending => continue,
            DeviceTokenPollResult::SlowDown => {
                interval = (interval * 2).min(Duration::from_secs(60));
                info!(
                    new_interval_secs = interval.as_secs(),
                    "device poll received slow_down"
                );
                continue;
            }
            DeviceTokenPollResult::Transport(msg) => {
                warn!(error = %msg, "device poll transport error, retrying");
                continue;
            }
            DeviceTokenPollResult::Expired => {
                record_registration_failure(&state, &pk_hash, "device code expired").await;
                return;
            }
            DeviceTokenPollResult::Denied => {
                record_registration_failure(&state, &pk_hash, "authorization denied by user").await;
                return;
            }
            DeviceTokenPollResult::Other(code) => {
                record_registration_failure(&state, &pk_hash, &format!("server error: {code}"))
                    .await;
                return;
            }
            DeviceTokenPollResult::Success(token_resp) => {
                install_approved_workspace(&state, &pk_hash, token_resp).await;
                return;
            }
        }
    }
}

async fn install_approved_workspace(
    state: &SharedState,
    pk_hash: &str,
    token_resp: crate::server_client::TokenResponse,
) {
    // Pull workspace_name from the pending entry, then remove it.
    let workspace_name = {
        let mut pending = state.pending.write().await;
        pending
            .remove(pk_hash)
            .map(|p| p.workspace_name)
            .unwrap_or_else(|| "workspace".to_string())
    };

    let ws_state = build_workspace_state(workspace_name.clone(), token_resp);

    {
        let mut workspaces = state.workspaces.write().await;
        workspaces.insert(pk_hash.to_string(), ws_state);

        if let Err(e) = token_store::save(
            &state.config.token_store_path(),
            &workspaces,
            &state.encryption_key,
        ) {
            error!(error = %e, "failed to persist token store after device approval");
        }
    }

    token_store::save_recovery_store(state).await;

    info!(
        workspace = %workspace_name,
        "workspace registered successfully via device flow"
    );
}

async fn record_registration_failure(state: &SharedState, pk_hash: &str, message: &str) {
    {
        let mut pending = state.pending.write().await;
        pending.remove(pk_hash);
    }
    {
        let mut errs = state.registration_errors.write().await;
        errs.insert(pk_hash.to_string(), message.to_string());
    }
    warn!(pk_hash = %pk_hash, reason = %message, "device flow registration failed");
}

/// Build a `WorkspaceState` from the server's `TokenResponse`, picking the
/// per-workspace `client_id` returned by the server. Falls back to the
/// bootstrap `BROKER_CLIENT_ID` only if the server omits the field — which
/// happens against a pre-fix server and produces refresh failures
/// (`invalid_grant: client_id mismatch`) until the server is upgraded.
fn build_workspace_state(
    workspace_name: String,
    token_resp: crate::server_client::TokenResponse,
) -> WorkspaceState {
    let scopes: Vec<String> = token_resp
        .scope
        .as_deref()
        .unwrap_or("")
        .split_whitespace()
        .map(|s| s.to_string())
        .collect();

    let client_id = token_resp.client_id.unwrap_or_else(|| {
        warn!(
            workspace = %workspace_name,
            "server did not return client_id in token response — falling back to bootstrap; \
             refresh will fail with invalid_grant until server is upgraded"
        );
        BROKER_CLIENT_ID.to_string()
    });

    WorkspaceState {
        client_id,
        access_token: token_resp.access_token,
        refresh_token: token_resp.refresh_token.unwrap_or_default(),
        scopes,
        token_expires_at: Utc::now() + chrono::Duration::seconds(token_resp.expires_in),
        workspace_name,
        token_status: TokenStatus::Valid,
    }
}

fn bad_request(message: &str) -> (StatusCode, axum::Json<serde_json::Value>) {
    (
        StatusCode::BAD_REQUEST,
        axum::Json(serde_json::json!({
            "error": { "code": "bad_request", "message": message }
        })),
    )
}

fn unauthorized(message: &str) -> (StatusCode, axum::Json<serde_json::Value>) {
    (
        StatusCode::UNAUTHORIZED,
        axum::Json(serde_json::json!({
            "error": { "code": "unauthorized", "message": message }
        })),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server_client::TokenResponse;

    fn make_token_response(client_id: Option<&str>) -> TokenResponse {
        TokenResponse {
            access_token: "at".to_string(),
            token_type: "Bearer".to_string(),
            expires_in: 900,
            refresh_token: Some("rt".to_string()),
            scope: Some("credentials:discover".to_string()),
            client_id: client_id.map(|s| s.to_string()),
        }
    }

    #[test]
    fn build_workspace_state_uses_per_workspace_client_id_when_present() {
        // The bug fix: the broker MUST take the per-workspace client_id from
        // the server's token response and persist it on the workspace, so
        // subsequent refresh_token grants don't get rejected with
        // `invalid_grant: client_id mismatch`.
        let ws =
            build_workspace_state("ws".to_string(), make_token_response(Some("ws-client-xyz")));
        assert_eq!(ws.client_id, "ws-client-xyz");
    }

    #[test]
    fn build_workspace_state_falls_back_to_bootstrap_when_client_id_absent() {
        // Back-compat with a pre-fix server that doesn't return client_id:
        // we keep the old behaviour (bootstrap client_id) so registration
        // still completes — refresh will fail, but that's no worse than today.
        let ws = build_workspace_state("ws".to_string(), make_token_response(None));
        assert_eq!(ws.client_id, BROKER_CLIENT_ID);
    }
}
