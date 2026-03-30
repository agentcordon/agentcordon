use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::server_client::ServerClient;
use crate::state::{PendingRegistration, SharedState};

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
    // 1. Verify the self-signature in the body
    let pk_bytes = match hex::decode(&body.public_key) {
        Ok(b) if b.len() == 32 => b,
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                axum::Json(serde_json::json!({
                    "error": { "code": "bad_request", "message": "Invalid public key" }
                })),
            );
        }
    };

    let pk_array: [u8; 32] = pk_bytes.clone().try_into().unwrap();
    let verifying_key = match VerifyingKey::from_bytes(&pk_array) {
        Ok(k) => k,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                axum::Json(serde_json::json!({
                    "error": { "code": "bad_request", "message": "Invalid public key" }
                })),
            );
        }
    };

    // Signed payload: workspace_name || public_key || scopes_joined
    let scopes_joined = body.scopes.join(" ");
    let signed_payload = format!(
        "{}{}{}",
        body.workspace_name, body.public_key, scopes_joined
    );

    let sig_bytes = match hex::decode(&body.signature) {
        Ok(b) if b.len() == 64 => b,
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                axum::Json(serde_json::json!({
                    "error": { "code": "bad_request", "message": "Invalid signature" }
                })),
            );
        }
    };
    let sig_array: [u8; 64] = sig_bytes.try_into().unwrap();
    let signature = Signature::from_bytes(&sig_array);

    if verifying_key
        .verify(signed_payload.as_bytes(), &signature)
        .is_err()
    {
        return (
            StatusCode::BAD_REQUEST,
            axum::Json(serde_json::json!({
                "error": { "code": "bad_request", "message": "Signature verification failed" }
            })),
        );
    }

    // 2. Compute pk_hash and check for existing registration
    let pk_hash = hex::encode(Sha256::digest(&pk_bytes));

    {
        let workspaces = state.workspaces.read().await;
        if workspaces.contains_key(&pk_hash) {
            return (
                StatusCode::CONFLICT,
                axum::Json(serde_json::json!({
                    "error": { "code": "conflict", "message": "Workspace already registered" }
                })),
            );
        }
    }

    // 3. Generate PKCE code_verifier and code_challenge
    let code_verifier = {
        let mut buf = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut buf);
        URL_SAFE_NO_PAD.encode(buf)
    };
    let code_challenge = {
        let hash = Sha256::digest(code_verifier.as_bytes());
        URL_SAFE_NO_PAD.encode(hash)
    };

    // 4. Generate state parameter
    let oauth_state = {
        let mut buf = [0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut buf);
        hex::encode(buf)
    };

    // 5. Determine redirect URI (broker's callback endpoint)
    // We use the port the broker is bound to. Since we don't know it here,
    // we read it from the config. For auto-port, the daemon sets it after bind.
    let redirect_uri = format!("http://localhost:{}/callback", state.config.port);

    // 6. Register OAuth client with the server
    let server_client = ServerClient::new(state.http_client.clone(), state.server_url.clone());

    let client_response = match server_client
        .register_oauth_client(&body.workspace_name, &redirect_uri, &body.scopes, &pk_hash)
        .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = %e, "failed to register OAuth client with server");
            return (
                StatusCode::BAD_GATEWAY,
                axum::Json(serde_json::json!({
                    "error": { "code": "bad_gateway", "message": "Failed to register with server" }
                })),
            );
        }
    };

    // 7. Build authorization URL
    let scope_param = body.scopes.join(" ");
    let auth_url = format!(
        "{}/api/v1/oauth/authorize?response_type=code&client_id={}&redirect_uri={}&scope={}&state={}&code_challenge={}&code_challenge_method=S256",
        state.server_url,
        urlencoding::encode(&client_response.client_id),
        urlencoding::encode(&redirect_uri),
        urlencoding::encode(&scope_param),
        urlencoding::encode(&oauth_state),
        urlencoding::encode(&code_challenge),
    );

    // 8. Store pending registration
    {
        let mut pending = state.pending.write().await;
        pending.insert(
            oauth_state.clone(),
            PendingRegistration {
                workspace_name: body.workspace_name,
                client_id: client_response.client_id,
                code_verifier,
                redirect_uri,
                state: oauth_state,
                pk_hash,
            },
        );
    }

    (
        StatusCode::OK,
        axum::Json(serde_json::json!({
            "data": {
                "authorization_url": auth_url,
                "status": "awaiting_consent"
            }
        })),
    )
}
