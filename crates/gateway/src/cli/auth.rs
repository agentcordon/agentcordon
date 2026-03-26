use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::Signer;

use agent_cordon_core::crypto::ed25519;

use super::client::{ApiClient, ApiResponse};
use super::output;
use super::state::{self, WorkspaceState};
use super::GlobalFlags;

/// Challenge response from the server.
#[derive(serde::Deserialize)]
struct ChallengeData {
    challenge: String,
    issued_at: String,
    #[allow(dead_code)]
    audience: Option<String>,
}

/// Verification response from the server.
#[derive(serde::Deserialize)]
struct VerifyData {
    identity_jwt: String,
    expires_in: Option<u64>,
}

/// Run the `auth` command — force-refresh JWT.
pub async fn run(flags: &GlobalFlags) -> Result<(), String> {
    if !state::has_workspace_key() {
        return Err("No workspace identity. Run 'init' + 'register' first.".to_string());
    }

    let mut st = WorkspaceState::load();
    let pk_hash = st
        .workspace_pk_hash
        .as_ref()
        .filter(|h| !h.is_empty())
        .ok_or("No workspace identity registered. Run 'register' first.")?
        .clone();

    // Force refresh by clearing cached JWT
    st.jwt = None;
    st.jwt_expires_at = Some("0".to_string());
    st.save()?;

    let server_url = st.resolve_server_url(&flags.server);
    let token = do_challenge_response(&server_url, &mut st).await?;
    st.save()?;

    let expires_in = st
        .jwt_expires_at
        .as_ref()
        .and_then(|e| e.parse::<i64>().ok())
        .map(|e| {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;
            e - now
        })
        .unwrap_or(0);

    output::print_result(
        flags.json,
        &format!(
            "JWT refreshed via workspace identity.\nExpires in: {}m {}s",
            expires_in / 60,
            expires_in % 60
        ),
        &serde_json::json!({
            "token": token,
            "expires_in": expires_in,
            "method": "workspace_identity",
            "identity": pk_hash,
        }),
    );
    Ok(())
}

/// Ensure a valid JWT, refreshing if needed. Returns the JWT string.
pub async fn ensure_jwt(flags: &GlobalFlags) -> Result<String, String> {
    // Check for env var override first
    if let Ok(jwt) = std::env::var("AGENTCORDON_IDENTITY_JWT") {
        if !jwt.is_empty() {
            return Ok(jwt);
        }
    }

    if !state::has_workspace_key() {
        return Err("No workspace identity. Run 'init' + 'register' first.".to_string());
    }

    let mut st = WorkspaceState::load();

    // Return cached JWT if still valid
    if st.jwt_valid() {
        return st
            .jwt
            .clone()
            .ok_or_else(|| "JWT missing from state".to_string());
    }

    // Refresh via challenge-response
    let server_url = st.resolve_server_url(&flags.server);
    let token = do_challenge_response(&server_url, &mut st).await?;
    st.save()?;
    Ok(token)
}

/// Perform the challenge-response auth flow against the server.
/// Updates state with the new JWT and expiry. Returns the JWT.
pub async fn do_challenge_response(
    server_url: &str,
    state: &mut WorkspaceState,
) -> Result<String, String> {
    let dir = state::workspace_dir();
    let signing_key =
        ed25519::load_keypair(&dir).map_err(|e| format!("failed to load keypair: {}", e))?;
    let pubkey = signing_key.verifying_key();

    // Get pk_hash without sha256: prefix for API calls
    let pk_hash_full = state
        .workspace_pk_hash
        .as_ref()
        .filter(|h| !h.is_empty())
        .ok_or("No workspace identity registered. Run 'register' first.")?;
    let pk_hash_hex = pk_hash_full.strip_prefix("sha256:").unwrap_or(pk_hash_full);

    let client = ApiClient::new(server_url);

    // Step 1: Request challenge
    let challenge_resp: ApiResponse<ChallengeData> = client
        .post_unauth(
            "/api/v1/workspaces/identify",
            &serde_json::json!({"public_key_hash": pk_hash_hex}),
        )
        .await
        .map_err(|e| format!("challenge request failed: {}", e))?;

    let challenge_bytes = URL_SAFE_NO_PAD
        .decode(&challenge_resp.data.challenge)
        .map_err(|e| format!("failed to decode challenge: {}", e))?;

    // Parse issued_at ISO8601 to epoch seconds
    let issued_at_epoch = chrono::DateTime::parse_from_rfc3339(&challenge_resp.data.issued_at)
        .map_err(|e| format!("failed to parse issued_at: {}", e))?
        .timestamp();

    let audience = ed25519::CHALLENGE_AUDIENCE;

    // Step 2: Build and sign payload
    let payload = ed25519::build_challenge_payload(
        &challenge_bytes,
        issued_at_epoch,
        audience,
        &pubkey.to_bytes(),
    );
    let signature = signing_key.sign(&payload);

    // Step 3: POST verify (all values base64url-encoded)
    let pubkey_b64 = URL_SAFE_NO_PAD.encode(pubkey.to_bytes());
    let sig_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());
    let payload_b64 = URL_SAFE_NO_PAD.encode(&payload);

    let verify_resp: ApiResponse<VerifyData> = client
        .post_unauth(
            "/api/v1/workspaces/identify/verify",
            &serde_json::json!({
                "public_key": pubkey_b64,
                "signature": sig_b64,
                "signed_payload": payload_b64,
            }),
        )
        .await
        .map_err(|e| format!("verification failed: {}", e))?;

    let token = verify_resp.data.identity_jwt;
    let expires_in = verify_resp.data.expires_in.unwrap_or(300);

    if token.is_empty() {
        return Err("No identity JWT in verify response".to_string());
    }

    // Cache JWT + expiry in state
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    state.jwt = Some(token.clone());
    state.jwt_expires_at = Some((now + expires_in).to_string());

    Ok(token)
}
