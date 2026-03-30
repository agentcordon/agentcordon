use std::collections::HashMap;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use serde::Deserialize;

use agent_cordon_core::proxy::url_safety::validate_proxy_target;

use crate::auth::AuthenticatedWorkspace;
use crate::credential_transform::{self, CredentialMaterial};
use crate::server_client::ServerClient;
use crate::state::SharedState;
use crate::token_refresh;
use crate::vend;

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
            return (
                StatusCode::BAD_REQUEST,
                axum::Json(serde_json::json!({
                    "error": { "code": "bad_request", "message": "Failed to read request body" }
                })),
            );
        }
    };

    let proxy_req: ProxyRequest = match serde_json::from_slice(&body_bytes) {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                axum::Json(serde_json::json!({
                    "error": { "code": "bad_request", "message": format!("Invalid request: {}", e) }
                })),
            );
        }
    };

    // Validate HTTP method
    if reqwest::Method::from_bytes(proxy_req.method.to_uppercase().as_bytes()).is_err() {
        return (
            StatusCode::BAD_REQUEST,
            axum::Json(serde_json::json!({
                "error": { "code": "bad_request", "message": format!("Invalid HTTP method: {}", proxy_req.method) }
            })),
        );
    }

    // SSRF validation
    if !state.config.proxy_allow_loopback {
        if let Err(reason) = validate_proxy_target(&proxy_req.url) {
            return (
                StatusCode::BAD_REQUEST,
                axum::Json(serde_json::json!({
                    "error": { "code": "bad_request", "message": format!("Blocked by SSRF protection: {}", reason) }
                })),
            );
        }
    }

    // Get workspace access token
    let access_token = {
        let workspaces = state.workspaces.read().await;
        match workspaces.get(&auth.pk_hash) {
            Some(ws) => ws.access_token.clone(),
            None => {
                return (
                    StatusCode::UNAUTHORIZED,
                    axum::Json(serde_json::json!({
                        "error": { "code": "unauthorized", "message": "Workspace not registered" }
                    })),
                );
            }
        }
    };

    // Compute broker's public key (base64url-encoded uncompressed P-256 point)
    let pub_key = state.encryption_key.public_key();
    let pub_key_point = pub_key.to_encoded_point(false);
    let broker_pub_key_b64 = URL_SAFE_NO_PAD.encode(pub_key_point.as_bytes());

    // Vend credential from server
    let server_client = ServerClient::new(state.http_client.clone(), state.server_url.clone());

    let vend_response = match server_client
        .vend_credential(&proxy_req.credential, &access_token, &broker_pub_key_b64)
        .await
    {
        Ok(r) => r,
        Err(crate::server_client::ServerClientError::ServerError {
            status: 401,
            ref body,
        }) if body.contains("workspace not found") => {
            tracing::warn!("server reports workspace not found — workspace may have been deleted");
            return error_response(StatusCode::UNAUTHORIZED, "unauthorized", "Workspace not found on server (workspace may have been deleted). Try: agentcordon register --force");
        }
        Err(crate::server_client::ServerClientError::ServerError { status: 401, .. }) => {
            // Try reactive refresh
            if token_refresh::try_reactive_refresh(&state, &auth.pk_hash).await {
                let new_token = {
                    let workspaces = state.workspaces.read().await;
                    workspaces
                        .get(&auth.pk_hash)
                        .map(|ws| ws.access_token.clone())
                };
                if let Some(token) = new_token {
                    match server_client
                        .vend_credential(&proxy_req.credential, &token, &broker_pub_key_b64)
                        .await
                    {
                        Ok(r) => r,
                        Err(e) => {
                            return error_response(
                                StatusCode::BAD_GATEWAY,
                                "bad_gateway",
                                &e.to_string(),
                            );
                        }
                    }
                } else {
                    return error_response(
                        StatusCode::UNAUTHORIZED,
                        "unauthorized",
                        "Token refresh failed",
                    );
                }
            } else {
                return error_response(
                    StatusCode::UNAUTHORIZED,
                    "unauthorized",
                    "Token expired and refresh failed",
                );
            }
        }
        Err(crate::server_client::ServerClientError::ServerError { status: 403, .. }) => {
            return error_response(
                StatusCode::FORBIDDEN,
                "forbidden",
                "Access denied by server policy",
            );
        }
        Err(crate::server_client::ServerClientError::ServerError { status: 404, .. }) => {
            return error_response(StatusCode::NOT_FOUND, "not_found", "Credential not found");
        }
        Err(e) => {
            tracing::error!(error = %e, "credential vend failed");
            return error_response(StatusCode::BAD_GATEWAY, "bad_gateway", "Credential vend failed");
        }
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

    // Apply credential transform
    let material = CredentialMaterial {
        credential_type: decrypted.credential_type,
        value: decrypted.value,
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

fn error_response(
    status: StatusCode,
    code: &str,
    message: &str,
) -> (StatusCode, axum::Json<serde_json::Value>) {
    (
        status,
        axum::Json(serde_json::json!({
            "error": { "code": code, "message": message }
        })),
    )
}
