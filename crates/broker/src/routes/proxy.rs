use std::collections::HashMap;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use serde::Deserialize;

use agent_cordon_core::proxy::url_safety::validate_proxy_target_resolved;

use crate::auth::AuthenticatedWorkspace;
use crate::credential_transform::{self, CredentialMaterial};
use crate::server_client::ServerClient;
use crate::state::SharedState;
use crate::vend;

use super::helpers::{error_response, require_scope, with_token_refresh};

#[derive(Debug, Deserialize)]
pub struct ProxyRequest {
    pub method: String,
    pub url: String,
    pub credential: String,
    pub headers: Option<HashMap<String, String>>,
    pub body: Option<String>,
}

pub async fn post_proxy(
    State(state): State<SharedState>,
    request: axum::extract::Request,
) -> impl IntoResponse {
    let auth = request
        .extensions()
        .get::<AuthenticatedWorkspace>()
        .cloned()
        .unwrap();

    // Read body
    let body_bytes = match axum::body::to_bytes(request.into_body(), 10 * 1024 * 1024).await {
        Ok(b) => b,
        Err(_) => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "bad_request",
                "Failed to read request body",
            );
        }
    };

    let proxy_req: ProxyRequest = match serde_json::from_slice(&body_bytes) {
        Ok(r) => r,
        Err(e) => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "bad_request",
                &format!("Invalid request: {}", e),
            );
        }
    };

    // Validate HTTP method
    if reqwest::Method::from_bytes(proxy_req.method.to_uppercase().as_bytes()).is_err() {
        return error_response(
            StatusCode::BAD_REQUEST,
            "bad_request",
            &format!("Invalid HTTP method: {}", proxy_req.method),
        );
    }

    // SSRF validation — async DNS resolution prevents DNS rebinding attacks
    if !state.config.proxy_allow_loopback {
        if let Err(reason) = validate_proxy_target_resolved(&proxy_req.url).await {
            return error_response(
                StatusCode::BAD_REQUEST,
                "bad_request",
                &format!("Blocked by SSRF protection: {}", reason),
            );
        }
    }

    // Scope pre-check: workspace must have credentials:vend
    if let Err(e) = require_scope(&state, &auth.pk_hash, "credentials:vend", "proxy").await {
        return e;
    }

    // Compute broker's public key (base64url-encoded uncompressed P-256 point)
    let pub_key = state.encryption_key.public_key();
    let pub_key_point = pub_key.to_encoded_point(false);
    let broker_pub_key_b64 = URL_SAFE_NO_PAD.encode(pub_key_point.as_bytes());

    // Vend credential from server with automatic 401 retry
    let server_client = ServerClient::new(state.http_client.clone(), state.server_url.clone());
    let credential_name = proxy_req.credential.clone();
    let bpk = broker_pub_key_b64.clone();

    let vend_response = match with_token_refresh(&state, &auth.pk_hash, |token| {
        let sc = server_client.clone();
        let cred = credential_name.clone();
        let key = bpk.clone();
        async move { sc.vend_credential(&cred, &token, &key).await }
    })
    .await
    {
        Ok(r) => r,
        Err(e) => return e,
    };

    // ECIES decrypt
    let decrypted =
        match vend::decrypt_vend_envelope(&vend_response.encrypted_envelope, &state.encryption_key)
        {
            Ok(c) => c,
            Err(e) => {
                tracing::error!(error = %e, "credential decryption failed");
                return error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    "Credential decryption failed",
                );
            }
        };

    // For oauth2_client_credentials, exchange the client secret for an access
    // token via the provider's token endpoint before applying the bearer transform.
    let credential_value = if decrypted
        .credential_type
        .as_deref()
        == Some("oauth2_client_credentials")
    {
        let client_id = decrypted.metadata.get("oauth2_client_id").cloned().unwrap_or_default();
        let token_endpoint = decrypted.metadata.get("oauth2_token_endpoint").cloned().unwrap_or_default();
        let scopes = decrypted.metadata.get("oauth2_scopes").cloned().unwrap_or_default();

        if client_id.is_empty() || token_endpoint.is_empty() {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "oauth2_client_credentials credential missing client_id or token_endpoint metadata",
            );
        }

        // Build a minimal StoredCredential for the token manager's cache key.
        // Derive a deterministic UUID from the credential name via SHA-256 so
        // repeated proxy calls for the same credential reuse the cached token.
        use sha2::{Sha256, Digest};
        let hash = Sha256::digest(proxy_req.credential.as_bytes());
        let cache_id = uuid::Uuid::from_bytes(hash[..16].try_into().unwrap());
        let cache_cred = agent_cordon_core::domain::credential::StoredCredential {
            id: agent_cordon_core::domain::credential::CredentialId(cache_id),
            name: proxy_req.credential.clone(),
            service: String::new(),
            encrypted_value: vec![],
            nonce: vec![],
            scopes: vec![],
            metadata: serde_json::json!({
                "oauth2_client_id": client_id,
                "oauth2_token_endpoint": token_endpoint,
                "oauth2_scopes": scopes,
            }),
            created_by: None,
            created_by_user: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            allowed_url_pattern: None,
            expires_at: None,
            transform_script: None,
            transform_name: None,
            vault: String::new(),
            credential_type: "oauth2_client_credentials".to_string(),
            tags: vec![],
            description: None,
            target_identity: None,
            key_version: 0,
        };

        match state.oauth2_cc.get_token(&cache_cred, &decrypted.value).await {
            Ok(result) => {
                tracing::debug!(
                    credential = %proxy_req.credential,
                    cached = !result.was_refreshed,
                    "oauth2 client_credentials token acquired"
                );
                result.access_token
            }
            Err(e) => {
                tracing::error!(error = %e, "oauth2 client_credentials token exchange failed");
                return error_response(
                    StatusCode::BAD_GATEWAY,
                    "bad_gateway",
                    &format!("OAuth2 token exchange failed: {}", e),
                );
            }
        }
    } else {
        decrypted.value
    };

    // Apply credential transform
    let material = CredentialMaterial {
        credential_type: decrypted.credential_type,
        value: credential_value,
        username: decrypted.username,
        metadata: decrypted.metadata,
    };

    let mut user_headers = proxy_req.headers.unwrap_or_default();

    let transformed = match credential_transform::apply(
        &material,
        vend_response.transform_name.as_deref(),
        &proxy_req.method,
        &proxy_req.url,
        &user_headers,
        proxy_req.body.as_deref(),
    ) {
        Ok(t) => t,
        Err(e) => {
            tracing::error!(error = %e, "credential transform failed");
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "Credential transform failed",
            );
        }
    };

    // Merge transform headers
    for (k, v) in &transformed.headers {
        user_headers.insert(k.clone(), v.clone());
    }

    // Build final URL with query params
    let final_url = if transformed.query_params.is_empty() {
        proxy_req.url.clone()
    } else {
        let query: Vec<String> = transformed
            .query_params
            .iter()
            .map(|(k, v)| format!("{}={}", urlencoding::encode(k), urlencoding::encode(v)))
            .collect();
        let sep = if proxy_req.url.contains('?') {
            "&"
        } else {
            "?"
        };
        format!("{}{}{}", proxy_req.url, sep, query.join("&"))
    };

    // Execute upstream request
    let http_method =
        reqwest::Method::from_bytes(proxy_req.method.to_uppercase().as_bytes()).unwrap();

    let mut upstream_req = state.http_client.request(http_method, &final_url);
    for (key, value) in &user_headers {
        upstream_req = upstream_req.header(key.as_str(), value.as_str());
    }
    if let Some(body_str) = &proxy_req.body {
        if let Ok(json_body) = serde_json::from_str::<serde_json::Value>(body_str) {
            upstream_req = upstream_req.json(&json_body);
        } else {
            upstream_req = upstream_req.body(body_str.clone());
        }
    }

    let upstream_resp = match upstream_req.send().await {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = %e, "upstream request failed");
            return error_response(
                StatusCode::BAD_GATEWAY,
                "bad_gateway",
                "Upstream request failed",
            );
        }
    };

    // Build response
    let resp_status = upstream_resp.status().as_u16();
    let mut resp_headers = HashMap::new();
    for (key, value) in upstream_resp.headers() {
        if let Ok(v) = value.to_str() {
            resp_headers.insert(key.to_string(), v.to_string());
        }
    }
    let resp_body = match upstream_resp.text().await {
        Ok(t) => t,
        Err(e) => {
            return error_response(
                StatusCode::BAD_GATEWAY,
                "bad_gateway",
                &format!("Failed to read upstream response: {}", e),
            );
        }
    };

    // Return proxied response
    let body_json: serde_json::Value =
        serde_json::from_str(&resp_body).unwrap_or(serde_json::Value::String(resp_body));

    (
        StatusCode::OK,
        axum::Json(serde_json::json!({
            "data": {
                "status_code": resp_status,
                "headers": resp_headers,
                "body": body_json,
            }
        })),
    )
}
