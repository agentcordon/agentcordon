//! Background MCP config sync task.
//!
//! Periodically fetches MCP server configurations (with ECIES-encrypted
//! credentials) from the AgentCordon server and caches them in broker state.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use tracing::warn;

use crate::server_client::{McpCredentialEnvelope, McpServerSyncEntry, ServerClient, VendEnvelope};
use crate::state::{CachedCredential, CachedMcpServer, SharedState};
use crate::token_refresh;
use crate::vend::decrypt_vend_envelope;

/// Spawn the background MCP config sync loop.
///
/// Syncs MCP server configs every `config.mcp_sync_interval` seconds for
/// each registered workspace. Decrypts ECIES credential envelopes and
/// caches the results in `state.mcp_configs`.
pub fn spawn_mcp_sync_task(state: SharedState) -> tokio::task::JoinHandle<()> {
    let interval_secs = state.config.mcp_sync_interval;
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(interval_secs));
        loop {
            interval.tick().await;
            sync_all_workspaces(&state).await;
        }
    })
}

/// Encode the broker's P-256 public key as base64url (uncompressed, 65 bytes).
fn broker_public_key_b64(encryption_key: &p256::SecretKey) -> String {
    let pub_point = encryption_key.public_key().to_encoded_point(false);
    URL_SAFE_NO_PAD.encode(pub_point.as_bytes())
}

/// On-demand sync for a single workspace (called on cache miss in call_tool).
pub async fn sync_workspace_now(state: &SharedState, pk_hash: &str) {
    let pub_key_b64 = broker_public_key_b64(&state.encryption_key);
    let server_client = ServerClient::new(state.http_client.clone(), state.server_url.clone());

    match sync_workspace(state, &server_client, pk_hash, &pub_key_b64).await {
        Ok(servers) => {
            let count = servers.len();
            let with_creds = servers.iter().filter(|s| s.credential.is_some()).count();
            let mut configs = state.mcp_configs.write().await;
            configs.insert(pk_hash.to_string(), servers);
            drop(configs);
            tracing::info!(
                pk_hash = %pk_hash, count, with_creds,
                "on-demand MCP sync complete"
            );
        }
        Err(e) => {
            warn!(pk_hash = %pk_hash, error = %e, "on-demand MCP sync failed");
        }
    }
}

/// Sync MCP configs for all registered workspaces.
async fn sync_all_workspaces(state: &SharedState) {
    let pub_key_b64 = broker_public_key_b64(&state.encryption_key);

    // Collect (pk_hash, access_token) pairs under a short-lived read lock.
    let workspace_tokens: Vec<(String, String)> = {
        let workspaces = state.workspaces.read().await;
        workspaces
            .iter()
            .filter(|(_, ws)| ws.token_status == crate::state::TokenStatus::Valid)
            .map(|(pk_hash, ws)| (pk_hash.clone(), ws.access_token.clone()))
            .collect()
    };

    if workspace_tokens.is_empty() {
        return;
    }

    let server_client = ServerClient::new(state.http_client.clone(), state.server_url.clone());

    for (pk_hash, _) in &workspace_tokens {
        match sync_workspace(state, &server_client, pk_hash, &pub_key_b64).await {
            Ok(servers) => {
                let count = servers.len();
                let mut configs = state.mcp_configs.write().await;
                configs.insert(pk_hash.clone(), servers);
                drop(configs);
                tracing::debug!(pk_hash = %pk_hash, count, "synced MCP configs");
            }
            Err(e) => {
                warn!(pk_hash = %pk_hash, error = %e, "MCP config sync failed, keeping existing cache");
            }
        }
    }
}

/// Sync MCP configs for a single workspace, with automatic 401 retry.
async fn sync_workspace(
    state: &SharedState,
    server_client: &ServerClient,
    pk_hash: &str,
    pub_key_b64: &str,
) -> Result<Vec<CachedMcpServer>, String> {
    // First attempt
    let token = get_token(state, pk_hash).ok_or("no access token")?;
    match server_client
        .list_mcp_servers_with_credentials(&token, pub_key_b64)
        .await
    {
        Ok(entries) => return Ok(build_cached_servers(entries, &state.encryption_key)),
        Err(crate::server_client::ServerClientError::ServerError { status: 401, .. }) => {
            // Try reactive refresh
            if !token_refresh::try_reactive_refresh(state, pk_hash).await {
                return Err("token refresh failed".to_string());
            }
        }
        Err(e) => return Err(e.to_string()),
    }

    // Retry after refresh
    let token = get_token(state, pk_hash).ok_or("no access token after refresh")?;
    server_client
        .list_mcp_servers_with_credentials(&token, pub_key_b64)
        .await
        .map(|entries| build_cached_servers(entries, &state.encryption_key))
        .map_err(|e| e.to_string())
}

/// Get a workspace's current access token (blocking-free snapshot).
fn get_token(state: &SharedState, pk_hash: &str) -> Option<String> {
    state
        .workspaces
        .try_read()
        .ok()
        .and_then(|ws| ws.get(pk_hash).map(|w| w.access_token.clone()))
}

/// Convert sync entries into cached MCP servers, decrypting credential envelopes.
fn build_cached_servers(
    entries: Vec<McpServerSyncEntry>,
    encryption_key: &p256::SecretKey,
) -> Vec<CachedMcpServer> {
    let now = chrono::Utc::now();
    entries
        .into_iter()
        .map(|entry| {
            let credential = entry
                .credential_envelopes
                .as_ref()
                .and_then(|envs| envs.first())
                .and_then(|env| decrypt_mcp_credential(env, encryption_key));

            CachedMcpServer {
                id: entry.id,
                name: entry.name,
                url: entry.url.unwrap_or_default(),
                transport: entry.transport,
                auth_method: entry.auth_method,
                tools: entry.tools,
                enabled: entry.enabled,
                credential,
                last_synced: now,
            }
        })
        .collect()
}

/// Decrypt a single MCP credential envelope, returning None on failure.
fn decrypt_mcp_credential(
    env: &McpCredentialEnvelope,
    encryption_key: &p256::SecretKey,
) -> Option<CachedCredential> {
    let vend_envelope = VendEnvelope {
        version: env.encrypted_envelope.version,
        ephemeral_public_key: env.encrypted_envelope.ephemeral_public_key.clone(),
        ciphertext: env.encrypted_envelope.ciphertext.clone(),
        nonce: env.encrypted_envelope.nonce.clone(),
        aad: env.encrypted_envelope.aad.clone(),
    };

    match decrypt_vend_envelope(&vend_envelope, encryption_key) {
        Ok(vended) => Some(CachedCredential {
            credential_type: env.credential_type.clone(),
            value: vended.value,
            transform_name: env.transform_name.clone(),
            metadata: vended.metadata,
        }),
        Err(e) => {
            warn!(
                credential = %env.credential_name,
                error = %e,
                "failed to decrypt MCP credential envelope"
            );
            None
        }
    }
}
