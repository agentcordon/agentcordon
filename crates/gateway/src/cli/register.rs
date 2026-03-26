use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::Signer;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use sha2::{Digest, Sha256};

use agent_cordon_core::crypto::ed25519;

use crate::identity::WorkspaceIdentity;

use super::client::{ApiClient, ApiResponse};
use super::output;
use super::state::{self, WorkspaceState};
use super::GlobalFlags;

const PENDING_FILE: &str = ".agentcordon/pending_registration.json";

#[derive(serde::Serialize, serde::Deserialize)]
struct PendingRegistration {
    nonce: String,
    code_challenge: String,
    pk_hash: String,
    server_url: String,
    timestamp: String,
    #[serde(default)]
    name: String,
}

#[derive(serde::Deserialize)]
struct RegisterResponse {
    workspace_id: String,
    identity_jwt: Option<String>,
    name: Option<String>,
}

/// Information returned by `start_registration` for callers that need
/// to orchestrate the registration flow (e.g. `init --server`).
pub struct RegistrationInfo {
    pub url: String,
    pub fingerprint: String,
    pub code_challenge: String,
}

/// Phase 1: generate a PKCE challenge, save pending state, and return
/// the registration URL + fingerprint + code_challenge.
pub fn start_registration(
    pk_hash: &str,
    server_url: &str,
    name: Option<&str>,
) -> Result<RegistrationInfo, String> {
    let nonce_bytes: [u8; 32] = rand::random();
    let nonce_hex = hex::encode(nonce_bytes);
    let code_challenge = hex::encode(Sha256::digest(nonce_bytes));

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .to_string();

    let pending = PendingRegistration {
        nonce: nonce_hex,
        code_challenge: code_challenge.clone(),
        pk_hash: pk_hash.to_string(),
        server_url: server_url.to_string(),
        timestamp,
        name: name.unwrap_or("").to_string(),
    };

    let json = serde_json::to_string_pretty(&pending)
        .map_err(|e| format!("failed to serialize pending registration: {}", e))?;
    std::fs::create_dir_all(".agentcordon")
        .map_err(|e| format!("failed to create .agentcordon/: {}", e))?;
    std::fs::write(PENDING_FILE, &json)
        .map_err(|e| format!("failed to write pending registration: {}", e))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(PENDING_FILE, std::fs::Permissions::from_mode(0o600));
    }

    let url = format!(
        "{}/register?pk_hash={}&cc={}",
        server_url, pk_hash, code_challenge
    );
    let pk_hash_hex_part = pk_hash.strip_prefix("sha256:").unwrap_or(pk_hash);
    let fingerprint = pk_hash_hex_part[..16.min(pk_hash_hex_part.len())].to_string();

    Ok(RegistrationInfo {
        url,
        fingerprint,
        code_challenge,
    })
}

/// Phase 2: exchange approval code for workspace registration.
/// Returns the workspace_id on success.
pub async fn complete_registration(
    flags: &GlobalFlags,
    signing_key: &ed25519_dalek::SigningKey,
    pub_hex: &str,
    pk_hash: &str,
    pk_hash_hex: &str,
    approval_code: &str,
    server_url: &str,
    name: Option<String>,
    server_explicit: bool,
) -> Result<String, String> {
    let pending_json = std::fs::read_to_string(PENDING_FILE)
        .map_err(|_| "No pending registration found. Run 'register' first (without --code).")?;
    let pending: PendingRegistration = serde_json::from_str(&pending_json)
        .map_err(|e| format!("invalid pending registration state: {}", e))?;

    let nonce_hex = &pending.nonce;
    let nonce_bytes =
        hex::decode(nonce_hex).map_err(|e| format!("invalid nonce in pending state: {}", e))?;

    // Use pending registration's server URL unless the user explicitly passed --server
    let effective_server = if !pending.server_url.is_empty() && !server_explicit {
        &pending.server_url
    } else {
        server_url
    };

    let effective_name = name.or_else(|| {
        if pending.name.is_empty() {
            None
        } else {
            Some(pending.name.clone())
        }
    });

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let pk_hash_raw =
        hex::decode(pk_hash_hex).map_err(|e| format!("invalid pk_hash hex: {}", e))?;

    let mut payload = Vec::new();
    payload.extend_from_slice(b"agentcordon:registration-v1");
    payload.extend_from_slice(approval_code.as_bytes());
    payload.extend_from_slice(&pk_hash_raw);
    payload.extend_from_slice(&nonce_bytes);
    payload.extend_from_slice(&timestamp.to_be_bytes());

    let signature = signing_key.sign(&payload);
    let sig_hex = hex::encode(signature.to_bytes());

    // Build registration body — include both Ed25519 public key and P-256 encryption public key.
    let mut body = serde_json::json!({
        "approval_code": approval_code,
        "public_key": pub_hex,
        "nonce": nonce_hex,
        "timestamp": timestamp,
        "signature": sig_hex,
    });

    if let Some(ref n) = effective_name {
        body["name"] = serde_json::Value::String(n.clone());
    }

    // Include P-256 encryption public key if available.
    let dir = state::workspace_dir();
    if WorkspaceIdentity::has_encryption_key(&dir) {
        if let Ok(identity) = WorkspaceIdentity::load_from_dir(&dir) {
            let enc_pub = identity.encryption_key.public_key();
            let enc_point = enc_pub.to_encoded_point(false);
            let enc_pub_jwk = p256_point_to_jwk(enc_point.as_bytes());
            body["encryption_key"] = enc_pub_jwk;
        }
    }

    let client = ApiClient::new(effective_server);
    let resp: ApiResponse<RegisterResponse> = client
        .post_unauth("/api/v1/workspaces/register", &body)
        .await
        .map_err(|e| format!("registration failed: {}", e))?;

    // Save state
    let jwt_expiry = timestamp + 300;
    let mut st = WorkspaceState::load();
    st.agent_id = Some(resp.data.workspace_id.clone());
    st.workspace_public_key = Some(pub_hex.to_string());
    st.workspace_pk_hash = Some(pk_hash.to_string());
    if let Some(ref jwt) = resp.data.identity_jwt {
        st.jwt = Some(jwt.clone());
        st.jwt_expires_at = Some(jwt_expiry.to_string());
    }
    st.server_url = Some(effective_server.to_string());
    st.save()?;

    // Delete pending registration
    let _ = std::fs::remove_file(PENDING_FILE);

    let resp_name = resp.data.name.as_deref().or(effective_name.as_deref());

    output::print_result(
        flags.json,
        &format!(
            "Registration successful!\nWorkspace ID: {}\nIdentity: {}{}",
            resp.data.workspace_id,
            pk_hash,
            resp_name
                .map(|n| format!("\nName: {}", n))
                .unwrap_or_default()
        ),
        &serde_json::json!({
            "status": "registered",
            "workspace_id": resp.data.workspace_id,
            "identity": pk_hash,
            "name": resp_name.unwrap_or(""),
        }),
    );

    Ok(resp.data.workspace_id.clone())
}

/// Legacy entry point — delegates to start_registration / complete_registration.
pub async fn run(
    flags: &GlobalFlags,
    server: Option<String>,
    code: Option<String>,
    name: Option<String>,
) -> Result<(), String> {
    eprintln!("Warning: 'register' is deprecated. Use 'agentcordon init --server <url>' instead.");

    // Auto-initialize keys if they don't exist yet
    if !state::has_workspace_key() {
        let generated = super::init::ensure_keys_exist()?;
        if generated {
            output::print_result(
                flags.json,
                "Workspace identity created automatically.",
                &serde_json::json!({"auto_init": true}),
            );
        }
    }

    let dir = state::workspace_dir();
    let signing_key =
        ed25519::load_keypair(&dir).map_err(|e| format!("failed to load keypair: {}", e))?;
    let pubkey = signing_key.verifying_key();
    let pk_hash_hex = ed25519::compute_pk_hash(&pubkey.to_bytes());
    let pk_hash = format!("sha256:{}", pk_hash_hex);
    let pub_hex = hex::encode(pubkey.to_bytes());

    let st = WorkspaceState::load();
    let server_url = if let Some(ref s) = server {
        s.trim_end_matches('/').to_string()
    } else {
        st.resolve_server_url(&flags.server)
    };

    if let Some(approval_code) = code {
        complete_registration(
            flags,
            &signing_key,
            &pub_hex,
            &pk_hash,
            &pk_hash_hex,
            &approval_code,
            &server_url,
            name,
            server.is_some(),
        )
        .await?;
        Ok(())
    } else {
        let info = start_registration(&pk_hash, &server_url, name.as_deref())?;
        output::print_result(
            flags.json,
            &format!(
                "Registration URL:\n  {}\n\nFingerprint: {}\n\nOpen the URL above, approve the registration, then run:\n  agentcordon register --code <APPROVAL_CODE>",
                info.url, info.fingerprint
            ),
            &serde_json::json!({
                "status": "pending",
                "registration_url": info.url,
                "fingerprint": info.fingerprint,
                "pk_hash": pk_hash,
            }),
        );
        Ok(())
    }
}

/// Convert an uncompressed P-256 point (65 bytes) to a JWK JSON value.
pub(crate) fn p256_point_to_jwk(uncompressed: &[u8]) -> serde_json::Value {
    let x = URL_SAFE_NO_PAD.encode(&uncompressed[1..33]);
    let y = URL_SAFE_NO_PAD.encode(&uncompressed[33..65]);

    serde_json::json!({
        "kty": "EC",
        "crv": "P-256",
        "x": x,
        "y": y,
        "use": "enc",
    })
}
