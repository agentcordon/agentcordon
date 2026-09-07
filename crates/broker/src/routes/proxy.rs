use std::borrow::Cow;
use std::collections::HashMap;

use axum::extract::State;
use axum::http::header::CONTENT_TYPE;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use serde::Deserialize;

use agent_cordon_core::proxy::leak_scanner::{self, LeakScanner};
use agent_cordon_core::proxy::url_match::url_matches_pattern;
use agent_cordon_core::proxy::url_safety::validate_proxy_target_resolved;

use crate::auth::AuthenticatedWorkspace;
use crate::credential_transform::{self, CredentialMaterial};
use crate::server_client::ServerClient;
use crate::state::SharedState;
use crate::upstream;
use crate::vend;

use super::helpers::{error_response, with_token_refresh};

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
    let http_method = match reqwest::Method::from_bytes(proxy_req.method.to_uppercase().as_bytes())
    {
        Ok(m) => m,
        Err(_) => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "bad_request",
                &format!("Invalid HTTP method: {}", proxy_req.method),
            );
        }
    };

    // SSRF validation — async DNS resolution prevents DNS rebinding attacks
    if !state.config.proxy_allow_loopback {
        if let Err(reason) = validate_proxy_target_resolved(&proxy_req.url).await {
            return error_response(
                StatusCode::BAD_REQUEST,
                "bad_request",
                &format!(
                    "Blocked by SSRF protection: {reason}.{}",
                    super::helpers::LOOPBACK_HINT
                ),
            );
        }
    }

    // Compute broker's public key (base64url-encoded uncompressed P-256 point)
    let pub_key = state.encryption_key.public_key();
    let pub_key_point = pub_key.to_encoded_point(false);
    let broker_pub_key_b64 = URL_SAFE_NO_PAD.encode(pub_key_point.as_bytes());

    // Vend credential from server with automatic 401 retry
    let server_client = ServerClient::new(state.http_client.clone(), state.server_url.clone());
    let credential_name = proxy_req.credential.clone();
    let bpk = broker_pub_key_b64.clone();
    let target_method = http_method.to_string();
    let target_url = proxy_req.url.clone();

    let vend_response = match with_token_refresh(&state, &auth.pk_hash, |token| {
        let sc = server_client.clone();
        let cred = credential_name.clone();
        let key = bpk.clone();
        let (m, u) = (target_method.clone(), target_url.clone());
        async move { sc.vend_credential(&cred, &token, &key, &m, &u).await }
    })
    .await
    {
        Ok(r) => r,
        Err(e) => return e,
    };

    // The server bound this vend to a pattern; check the target against it
    // again here, in the process that will actually inject, so a mismatched
    // or stale vend never reaches an upstream. The check runs on the URL the
    // caller asked for, before the credential's own query material is added.
    // A credential without a pattern is only acceptable for the generic
    // type; anything else fails closed.
    let pattern_ok = match vend_response.allowed_url_pattern.as_deref() {
        Some(pattern) => url_matches_pattern(&proxy_req.url, pattern),
        None => vend_response.credential_type == "generic",
    };
    if !pattern_ok {
        tracing::warn!(
            credential = %proxy_req.credential,
            credential_type = %vend_response.credential_type,
            "refusing to inject: target outside the vended URL pattern"
        );
        // Same code the server uses for its own copy of this check, so the
        // caller reads one cause however far the request got.
        let message = match vend_response.allowed_url_pattern.as_deref() {
            Some(pattern) => format!(
                "credential '{}' is fenced to the URL pattern {pattern}, which does not \
                 cover {}. This is the credential's allowed_url_pattern, not a policy \
                 decision.",
                proxy_req.credential, proxy_req.url
            ),
            None => format!(
                "credential '{}' has no allowed_url_pattern, and a {} credential may \
                 only be injected into a target its pattern covers.",
                proxy_req.credential, vend_response.credential_type
            ),
        };
        return error_response(StatusCode::FORBIDDEN, "url_pattern_denied", &message);
    }

    // ECIES decrypt
    let decrypted =
        match vend::decrypt_vend_envelope(&vend_response.encrypted_envelope, &state.encryption_key)
            .await
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

    // An `oauth2_client_credentials` (or `oauth2_user_authorization`)
    // credential arrives already exchanged: the server vended the upstream
    // access token, so it is injected like any bearer. The broker never
    // holds the client secret or refresh token and never calls a token
    // endpoint.
    let credential_value = decrypted.value;

    // Apply credential transform. `credential_type` comes from the outer
    // `VendResponse`, not from the envelope plaintext.
    let material = CredentialMaterial {
        credential_type: Some(vend_response.credential_type.clone()),
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

    // The secret material the injection put on the wire is a needle for the
    // response scan. `injected_needles` decides what counts as secret: the
    // signature yes, the `host` and `x-amz-date` a signer also emits no.
    let scanner = LeakScanner::new(leak_scanner::injected_needles(
        &material.value,
        transformed
            .headers
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str())),
        transformed.query_params.values().map(String::as_str),
    ));

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
    let mut upstream_req = state.upstream_client.request(http_method, &final_url);
    for (key, value) in &user_headers {
        if !upstream::is_hop_by_hop(key) {
            upstream_req = upstream_req.header(key.as_str(), value.as_str());
        }
    }
    if let Some(body_str) = &proxy_req.body {
        // `agentcordon proxy --body` sends no Content-Type of its own and
        // has always meant JSON; keep labelling such a body so existing
        // calls still work. A caller's own Content-Type is passed through.
        if !user_headers
            .keys()
            .any(|k| k.eq_ignore_ascii_case("content-type"))
        {
            upstream_req = upstream_req.header(CONTENT_TYPE, "application/json");
        }
        upstream_req = upstream_req.body(body_str.clone());
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

    let collected = match upstream::collect(upstream_resp).await {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(error = %e, "upstream response rejected");
            return error_response(
                StatusCode::BAD_GATEWAY,
                "bad_gateway",
                &format!("Failed to read upstream response: {}", e),
            );
        }
    };

    // Redact anything the upstream echoed back, in the body and in every
    // header value, before the response leaves the broker.
    let mut leaked = false;
    let resp_body = match scanner.redact(&String::from_utf8_lossy(&collected.body)) {
        Cow::Borrowed(clean) => clean.to_string(),
        Cow::Owned(redacted) => {
            leaked = true;
            redacted
        }
    };
    let resp_headers: Vec<(String, String)> = collected
        .headers
        .into_iter()
        .map(|(name, value)| {
            let value = match scanner.redact(&value) {
                Cow::Borrowed(_) => value,
                Cow::Owned(redacted) => {
                    leaked = true;
                    redacted
                }
            };
            (name, value)
        })
        .collect();
    if leaked {
        tracing::warn!(
            credential = %proxy_req.credential,
            "upstream response echoed an injected credential value; redacted"
        );
    }

    // Return proxied response
    let body_json: serde_json::Value =
        serde_json::from_str(&resp_body).unwrap_or(serde_json::Value::String(resp_body));

    (
        StatusCode::OK,
        axum::Json(serde_json::json!({
            "data": {
                "status_code": collected.status,
                "headers": resp_headers,
                "body": body_json,
            }
        })),
    )
}
