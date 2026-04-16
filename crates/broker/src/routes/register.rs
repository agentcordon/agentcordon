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

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use chrono::Utc;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tracing::{error, info, warn};

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
    pub signature: String,
}

pub async fn post_register(
    State(state): State<SharedState>,
    axum::Json(body): axum::Json<RegisterRequest>,
) -> impl IntoResponse {
    // 1. Decode & verify the Ed25519 self-signature.
    let pk_bytes = match hex::decode(&body.public_key) {
        Ok(b) if b.len() == 32 => b,
        _ => return bad_request("Invalid public key"),
    };
    let pk_array: [u8; 32] = pk_bytes.clone().try_into().unwrap();
    let verifying_key = match VerifyingKey::from_bytes(&pk_array) {
        Ok(k) => k,
        Err(_) => return bad_request("Invalid public key"),
    };

    // Signed payload: workspace_name \n public_key \n scopes_joined
    let scopes_joined = body.scopes.join(" ");
    let signed_payload = format!(
        "{}\n{}\n{}",
        body.workspace_name, body.public_key, scopes_joined
    );

    let sig_bytes = match hex::decode(&body.signature) {
        Ok(b) if b.len() == 64 => b,
        _ => return bad_request("Invalid signature"),
    };
    let sig_array: [u8; 64] = sig_bytes.try_into().unwrap();
    let signature = Signature::from_bytes(&sig_array);

    if verifying_key
        .verify(signed_payload.as_bytes(), &signature)
        .is_err()
    {
        return bad_request("Signature verification failed");
    }

    // 2. Compute pk_hash. Re-registration of an already-approved workspace
    //    is allowed — the server handles owner replacement on approval.
    let pk_hash = hex::encode(Sha256::digest(&pk_bytes));

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
        expires_in: Duration::from_secs(device.expires_in),
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
        Duration::from_secs(device.interval.max(1)),
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
    let scopes: Vec<String> = token_resp
        .scope
        .as_deref()
        .unwrap_or("")
        .split_whitespace()
        .map(|s| s.to_string())
        .collect();

    // Pull workspace_name from the pending entry, then remove it.
    let workspace_name = {
        let mut pending = state.pending.write().await;
        pending
            .remove(pk_hash)
            .map(|p| p.workspace_name)
            .unwrap_or_else(|| "workspace".to_string())
    };

    let ws_state = WorkspaceState {
        client_id: BROKER_CLIENT_ID.to_string(),
        access_token: token_resp.access_token,
        refresh_token: token_resp.refresh_token.unwrap_or_default(),
        scopes,
        token_expires_at: Utc::now() + chrono::Duration::seconds(token_resp.expires_in as i64),
        workspace_name: workspace_name.clone(),
        token_status: TokenStatus::Valid,
    };

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

fn bad_request(message: &str) -> (StatusCode, axum::Json<serde_json::Value>) {
    (
        StatusCode::BAD_REQUEST,
        axum::Json(serde_json::json!({
            "error": { "code": "bad_request", "message": message }
        })),
    )
}
