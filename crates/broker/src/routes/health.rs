use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use sha2::{Digest, Sha256};

use crate::state::SharedState;

/// The broker's P-256 public key as the CLI pins it: the uncompressed SEC1
/// point (65 bytes) base64url-encoded without padding, and its SHA-256
/// fingerprint as lowercase hex.
pub fn published_key(key: &p256::SecretKey) -> (String, String) {
    let point = key.public_key().to_encoded_point(false);
    let bytes = point.as_bytes();
    (
        URL_SAFE_NO_PAD.encode(bytes),
        hex::encode(Sha256::digest(bytes)),
    )
}

/// `GET /health`: liveness plus the broker's public key and fingerprint so
/// a CLI can pin the broker it enrolled with and refuse another one.
pub async fn get_health(State(state): State<SharedState>) -> impl IntoResponse {
    let workspace_count = state.workspaces.read().await.len();
    let server_reachable = {
        let client = crate::server_client::ServerClient::new(
            state.http_client.clone(),
            state.server_url.clone(),
        );
        client.health_check().await
    };
    let (encryption_public_key, key_fingerprint) = published_key(&state.encryption_key);

    (
        StatusCode::OK,
        axum::Json(serde_json::json!({
            "status": "ok",
            "version": env!("CARGO_PKG_VERSION"),
            "workspaces": workspace_count,
            "server_url": state.server_url,
            "server_reachable": server_reachable,
            "encryption_public_key": encryption_public_key,
            "key_fingerprint": key_fingerprint,
        })),
    )
}
