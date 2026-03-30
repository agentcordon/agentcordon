use std::collections::HashMap;

use agent_cordon_core::crypto::SecretEncryptor;
use agent_cordon_core::domain::audit::{
    enrich_metadata_with_policy_reasoning, AuditDecision, AuditEvent, AuditEventType,
};
use agent_cordon_core::domain::policy::PolicyDecisionResult;
use agent_cordon_core::policy::{
    actions, PolicyContext, PolicyEngine, PolicyPrincipal, PolicyResource,
};
use agent_cordon_core::proxy::leak_scanner::scan_for_leaked_credentials;
use agent_cordon_core::proxy::placeholder::{extract_placeholders, substitute_placeholders};
use agent_cordon_core::proxy::url_match::url_matches_pattern;
use agent_cordon_core::proxy::url_safety::{validate_proxy_target, validate_proxy_target_resolved};
use agent_cordon_core::transform::rhai_engine::resolve_transform;
use axum::{extract::State, routing::post, Json, Router};
use serde::{Deserialize, Serialize};

use crate::extractors::AuthenticatedWorkspace;
use crate::middleware::request_id::CorrelationId;
use crate::response::{ApiError, ApiResponse};
use crate::state::AppState;

/// Headers that transform scripts are not allowed to set.
/// These are security-critical headers that, if overridden by a malicious or
/// misconfigured transform, could bypass authentication, enable request
/// smuggling, or corrupt session state.
const BLOCKED_TRANSFORM_HEADERS: &[&str] = &[
    "host",
    "authorization",
    "cookie",
    "set-cookie",
    "x-csrf-token",
    "transfer-encoding",
    "content-length",
    "proxy-authorization",
    "proxy-authenticate",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-real-ip",
];

/// Check if a header name is blocked for transform output.
fn is_blocked_header(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    BLOCKED_TRANSFORM_HEADERS.contains(&lower.as_str())
}

pub fn routes() -> Router<AppState> {
    Router::new().route("/proxy/execute", post(execute_proxy))
}

#[derive(Deserialize)]
struct ProxyExecuteRequest {
    method: String,
    url: String,
    headers: Option<HashMap<String, String>>,
    body: Option<String>,
}

#[derive(Serialize)]
struct ProxyExecuteResponse {
    status_code: u16,
    headers: HashMap<String, String>,
    body: Option<String>,
}

/// Supported HTTP methods for proxy requests.
fn parse_method(method: &str) -> Result<reqwest::Method, ApiError> {
    match method.to_uppercase().as_str() {
        "GET" => Ok(reqwest::Method::GET),
        "POST" => Ok(reqwest::Method::POST),
        "PUT" => Ok(reqwest::Method::PUT),
        "PATCH" => Ok(reqwest::Method::PATCH),
        "DELETE" => Ok(reqwest::Method::DELETE),
        "HEAD" => Ok(reqwest::Method::HEAD),
        "OPTIONS" => Ok(reqwest::Method::OPTIONS),
        _ => Err(ApiError::BadRequest(format!(
            "unsupported HTTP method: {}",
            method
        ))),
    }
}

async fn execute_proxy(
    State(state): State<AppState>,
    auth: AuthenticatedWorkspace,
    axum::Extension(corr): axum::Extension<CorrelationId>,
    Json(req): Json<ProxyExecuteRequest>,
) -> Result<Json<ApiResponse<ProxyExecuteResponse>>, ApiError> {
    auth.require_scope(agent_cordon_core::oauth2::types::OAuthScope::CredentialsVend)?;
    let method = parse_method(&req.method)?;

    // Collect all placeholder names from url, headers, and body
    let mut all_text = req.url.clone();
    if let Some(ref headers) = req.headers {
        for value in headers.values() {
            all_text.push(' ');
            all_text.push_str(value);
        }
    }
    if let Some(ref body) = req.body {
        all_text.push(' ');
        all_text.push_str(body);
    }

    let placeholder_names = extract_placeholders(&all_text);
    if placeholder_names.is_empty() {
        return Err(ApiError::BadRequest(
            "no credential placeholders found in request".to_string(),
        ));
    }

    // Resolve the raw URL (before substitution) for URL whitelisting.
    // We need to substitute only the URL placeholders to get the target URL
    // for whitelist checking. However, the URL itself may contain placeholders
    // that are credentials (e.g., query params). We'll resolve the full URL
    // after all credentials are resolved, then check the whitelist against
    // the substituted URL for each credential.

    // Resolve each placeholder: lookup, policy check, URL whitelist, decrypt
    let mut credential_values: HashMap<String, String> = HashMap::new();
    let mut credential_pairs: Vec<(String, String)> = Vec::new();
    let mut extra_transform_headers: HashMap<String, String> = HashMap::new();
    for name in &placeholder_names {
        // Look up credential by name, scoped to the calling workspace first,
        // then fall back to global name lookup for admin-created credentials.
        let cred = match state
            .store
            .get_credential_by_workspace_and_name(&auth.workspace.id, name)
            .await?
        {
            Some(c) => c,
            None => state
                .store
                .get_credential_by_name(name)
                .await?
                .ok_or_else(|| ApiError::NotFound(format!("credential not found: {}", name)))?,
        };

        // Check credential expiry (fail fast, before policy evaluation)
        if cred.is_expired() {
            // Audit the expiry denial
            let event = AuditEvent::builder(AuditEventType::CredentialExpired)
                .action("vend_credential")
                .workspace_actor(&auth.workspace.id, &auth.workspace.name)
                .resource("credential", &cred.id.0.to_string())
                .correlation_id(&corr.0)
                .decision(AuditDecision::Forbid, Some("bypass:credential_expired"))
                .details(serde_json::json!({
                    "credential_name": name,
                    "expires_at": cred.expires_at.map(|dt| dt.to_rfc3339()),
                    "target_url": req.url,
                }))
                .build();
            if let Err(e) = state.store.append_audit_event(&event).await {
                tracing::warn!(error = %e, "Failed to write audit event");
            }
            return Err(ApiError::Forbidden(format!(
                "credential has expired: {}",
                name
            )));
        }

        // Evaluate Cedar policy: vend_credential
        let decision = state.policy_engine.evaluate(
            &PolicyPrincipal::Workspace(&auth.workspace),
            actions::VEND_CREDENTIAL,
            &PolicyResource::Credential {
                credential: cred.clone(),
            },
            &PolicyContext {
                target_url: Some(req.url.clone()),
                requested_scopes: cred.scopes.clone(),
                ..Default::default()
            },
        )?;

        if decision.decision == PolicyDecisionResult::Forbid {
            metrics::counter!("proxy_requests_total", "status" => "denied").increment(1);
            // Audit denial with policy reasoning
            let policy_ctx = PolicyContext {
                target_url: Some(req.url.clone()),
                requested_scopes: cred.scopes.clone(),
                ..Default::default()
            };
            let mut metadata = serde_json::json!({
                "credential_name": name,
                "target_url": req.url,
                "reason": "policy_denied",
            });
            enrich_metadata_with_policy_reasoning(
                &mut metadata,
                &decision,
                Some(&policy_ctx),
                None,
            );
            let event = AuditEvent::builder(AuditEventType::ProxyRequestDenied)
                .action("vend_credential")
                .workspace_actor(&auth.workspace.id, &auth.workspace.name)
                .resource("credential", &cred.id.0.to_string())
                .correlation_id(&corr.0)
                .decision(AuditDecision::Forbid, Some(&decision.reasons.join(", ")))
                .details(metadata)
                .build();
            if let Err(e) = state.store.append_audit_event(&event).await {
                tracing::warn!(error = %e, "Failed to write audit event");
            }
            return Err(ApiError::Forbidden(format!(
                "access denied by policy for credential: {}",
                name
            )));
        }

        // Check URL whitelist
        if let Some(ref pattern) = cred.allowed_url_pattern {
            if !url_matches_pattern(&req.url, pattern) {
                // Audit URL mismatch
                let event = AuditEvent::builder(AuditEventType::ProxyRequestDenied)
                    .action("vend_credential")
                    .workspace_actor(&auth.workspace.id, &auth.workspace.name)
                    .resource("credential", &cred.id.0.to_string())
                    .correlation_id(&corr.0)
                    .decision(AuditDecision::Forbid, Some("bypass:url_mismatch"))
                    .details(serde_json::json!({
                        "credential_name": name,
                        "target_url": req.url,
                        "allowed_pattern": pattern,
                        "reason": "url_mismatch",
                    }))
                    .build();
                if let Err(e) = state.store.append_audit_event(&event).await {
                    tracing::warn!(error = %e, "Failed to write audit event");
                }
                return Err(ApiError::Forbidden(format!(
                    "URL not allowed for credential: {}",
                    name
                )));
            }
        }

        // Decrypt credential value with credential ID as AAD
        let plaintext = state.encryptor.decrypt(
            &cred.encrypted_value,
            &cred.nonce,
            cred.id.0.to_string().as_bytes(),
        )?;
        let value = String::from_utf8(plaintext)
            .map_err(|_| ApiError::Internal("credential value is not valid UTF-8".to_string()))?;

        // OAuth2 Client Credentials: acquire token and inject as Bearer header
        if cred.credential_type == "oauth2_client_credentials" {
            let token_result = state
                .oauth2_token_manager
                .get_token(&cred, &value)
                .await
                .map_err(|e| {
                    // Log full error server-side for debugging
                    tracing::warn!(
                        credential = %name,
                        error = %e,
                        "OAuth2 token acquisition failed"
                    );
                    // Audit token failure (decision_reason keeps detail for SOC)
                    let fail_event = AuditEvent::builder(AuditEventType::Oauth2TokenFailed)
                        .action("vend_credential")
                        .workspace_actor(&auth.workspace.id, &auth.workspace.name)
                        .resource("credential", &cred.id.0.to_string())
                        .correlation_id(&corr.0)
                        .decision(
                            AuditDecision::Error,
                            Some(&format!("bypass:oauth2_token_failed: {}", e)),
                        )
                        .details(serde_json::json!({
                            "credential_name": name,
                            "target_url": req.url,
                        }))
                        .build();
                    let store = state.store.clone();
                    tokio::spawn(async move {
                        if let Err(e) = store.append_audit_event(&fail_event).await {
                            tracing::warn!(error = %e, "Failed to write audit event");
                        }
                    });
                    // Return generic message to client — do not leak upstream error body
                    ApiError::BadGateway("OAuth2 token acquisition failed".to_string())
                })?;

            // Audit token acquisition/refresh
            let audit_event_type = if token_result.was_refreshed {
                // Check if we had a previous cache entry (refreshed vs first-time)
                AuditEventType::Oauth2TokenAcquired
            } else {
                // Served from cache — no audit needed for cache hits
                AuditEventType::Oauth2TokenAcquired // Not emitted (see below)
            };

            if token_result.was_refreshed {
                let token_event = AuditEvent::builder(audit_event_type)
                    .action("oauth2_token")
                    .workspace_actor(&auth.workspace.id, &auth.workspace.name)
                    .resource("credential", &cred.id.0.to_string())
                    .correlation_id(&corr.0)
                    .decision(AuditDecision::Permit, Some("bypass:oauth2_token_acquired"))
                    .details(serde_json::json!({
                        "credential_name": name,
                        "target_url": req.url,
                    }))
                    .build();
                if let Err(e) = state.store.append_audit_event(&token_event).await {
                    tracing::warn!(error = %e, "Failed to write audit event");
                }
            }

            // Substitute placeholder with the access token value.
            // The request template controls how it's used (e.g., "Authorization": "Bearer {{cred}}")
            credential_pairs.push((name.clone(), value));
            credential_values.insert(name.clone(), token_result.access_token);

            continue;
        }

        // Apply transform (custom script > named built-in > identity passthrough)
        let transform_output = resolve_transform(
            cred.transform_name.as_deref(),
            cred.transform_script.as_deref(),
            &value,
            &req.method,
            &req.url,
            req.headers.as_ref().unwrap_or(&HashMap::new()),
            req.body.as_deref().unwrap_or(""),
        )
        .map_err(|e| ApiError::Internal(format!("transform error: {}", e)))?;

        // Audit transform execution if a transform was applied
        if cred.transform_name.is_some() || cred.transform_script.is_some() {
            let transform_event = AuditEvent::builder(AuditEventType::TransformExecuted)
                .action("transform")
                .workspace_actor(&auth.workspace.id, &auth.workspace.name)
                .resource("credential", &cred.id.0.to_string())
                .correlation_id(&corr.0)
                .decision(AuditDecision::Permit, Some("bypass:transform_executed"))
                .details(serde_json::json!({
                    "credential_name": name,
                    "transform_name": cred.transform_name,
                    "has_script": cred.transform_script.is_some(),
                }))
                .build();
            if let Err(e) = state.store.append_audit_event(&transform_event).await {
                tracing::warn!(error = %e, "Failed to write audit event");
            }
        }

        // Use raw secret for leak scanning, transformed value for substitution
        credential_pairs.push((name.clone(), value));
        credential_values.insert(name.clone(), transform_output.value);

        // Collect extra headers from the transform (e.g., SigV4 adds x-amz-date, etc.)
        // Silently drop blocked headers to prevent transforms from overriding
        // security-critical headers.
        for (hk, hv) in transform_output.extra_headers {
            if is_blocked_header(&hk) {
                tracing::warn!(
                    header = %hk,
                    credential = %name,
                    "transform tried to set blocked header; dropping"
                );
                continue;
            }
            extra_transform_headers.insert(hk, hv);
        }
    }

    // Substitute placeholders in url, headers, and body
    let final_url = substitute_placeholders(&req.url, &credential_values);
    let mut final_headers: HashMap<String, String> = req
        .headers
        .as_ref()
        .map(|h| {
            h.iter()
                .map(|(k, v)| (k.clone(), substitute_placeholders(v, &credential_values)))
                .collect()
        })
        .unwrap_or_default();

    // Apply extra headers from transforms (e.g., SigV4 x-amz-date, x-amz-content-sha256, host)
    for (hk, hv) in extra_transform_headers {
        final_headers.entry(hk).or_insert(hv);
    }
    let final_body = req
        .body
        .as_ref()
        .map(|b| substitute_placeholders(b, &credential_values));

    // SSRF protection: validate the resolved URL is not targeting internal networks.
    // Uses async DNS resolution to catch domains that resolve to private IPs.
    if !state.config.proxy_allow_loopback {
        validate_proxy_target_resolved(&final_url)
            .await
            .map_err(|reason| {
                // Audit SSRF attempt
                let event = AuditEvent::builder(AuditEventType::ProxyRequestDenied)
                    .action("vend_credential")
                    .workspace_actor(&auth.workspace.id, &auth.workspace.name)
                    .resource_type("proxy")
                    .correlation_id(&corr.0)
                    .decision(
                        AuditDecision::Forbid,
                        Some(&format!("bypass:ssrf_blocked: {}", reason)),
                    )
                    .details(serde_json::json!({
                        "reason": "ssrf_blocked",
                        "detail": reason,
                    }))
                    .build();
                // Best-effort audit; we still block the request regardless
                let store = state.store.clone();
                tokio::spawn(async move {
                    if let Err(e) = store.append_audit_event(&event).await {
                        tracing::warn!(error = %e, "Failed to write audit event");
                    }
                });
                ApiError::Forbidden(format!("target URL not allowed: {}", reason))
            })?;
    }

    // Use the shared HTTP client from AppState
    let client = state.http_client.clone();

    // Build the request
    let mut request_builder = client.request(method, &final_url);

    for (key, value) in &final_headers {
        request_builder = request_builder.header(key.as_str(), value.as_str());
    }

    if let Some(ref body) = final_body {
        request_builder = request_builder.body(body.clone());
    }

    // Send the request, following same-domain redirects manually
    let response = send_with_same_domain_redirects(
        client,
        request_builder,
        &final_url,
        &final_headers,
        final_body.as_deref(),
        state.config.proxy_allow_loopback,
    )
    .await
    .map_err(|e| {
        // Log the full error server-side for debugging, but do NOT return
        // internal network details to the client (prevents SSRF reconnaissance).
        tracing::error!(error = %e, "upstream proxy request failed");
        metrics::counter!("proxy_requests_total", "status" => "error").increment(1);
        ApiError::BadGateway("upstream request failed".to_string())
    })?;

    let status_code = response.status().as_u16();
    let response_headers: HashMap<String, String> = response
        .headers()
        .iter()
        .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();

    // Enforce response size limit: check Content-Length header first (fast path)
    let max_bytes = state.config.proxy_max_response_bytes;
    if let Some(cl) = response_headers.get("content-length") {
        if let Ok(len) = cl.parse::<usize>() {
            if len > max_bytes {
                tracing::warn!(
                    content_length = len,
                    max_bytes = max_bytes,
                    "upstream response exceeds size limit"
                );
                return Err(ApiError::BadGateway(format!(
                    "upstream response too large: {} bytes exceeds {} byte limit",
                    len, max_bytes
                )));
            }
        }
    }

    // Read the body in chunks with a bounded limit to prevent OOM from
    // malicious upstreams that send a huge body (or lie about Content-Length).
    // This avoids buffering the full body before checking size.
    let mut body_buf = Vec::new();
    let mut response = response;
    loop {
        match response.chunk().await {
            Ok(Some(chunk)) => {
                if body_buf.len() + chunk.len() > max_bytes {
                    tracing::warn!(
                        accumulated = body_buf.len(),
                        chunk_len = chunk.len(),
                        max_bytes = max_bytes,
                        "upstream response body exceeds size limit (streaming)"
                    );
                    return Err(ApiError::BadGateway(format!(
                        "upstream response too large: exceeds {} byte limit",
                        max_bytes
                    )));
                }
                body_buf.extend_from_slice(&chunk);
            }
            Ok(None) => break, // End of stream
            Err(e) => {
                tracing::error!(error = %e, "failed to read upstream response body");
                return Err(ApiError::BadGateway(
                    "failed to read upstream response".to_string(),
                ));
            }
        }
    }
    let response_body = String::from_utf8_lossy(&body_buf).to_string();

    // Scan for leaked credentials BEFORE returning
    if let Some(leaked_name) = scan_for_leaked_credentials(&response_body, &credential_pairs) {
        // Audit credential leak
        let event = AuditEvent::builder(AuditEventType::CredentialLeakDetected)
            .action("vend_credential")
            .workspace_actor(&auth.workspace.id, &auth.workspace.name)
            .resource_type("credential")
            .correlation_id(&corr.0)
            .decision(
                AuditDecision::Forbid,
                Some(&format!("bypass:credential_leak_detected: {}", leaked_name)),
            )
            .details(serde_json::json!({
                "credential_name": leaked_name,
                "target_url": req.url,
                "upstream_status": status_code,
                "reason": "credential_leak_detected",
            }))
            .build();
        if let Err(e) = state.store.append_audit_event(&event).await {
            tracing::warn!(error = %e, "Failed to write audit event");
        }

        // Drop credential values from memory
        drop(credential_values);
        drop(credential_pairs);

        return Err(ApiError::CredentialLeakDetected(format!(
            "credential value detected in upstream response (credential: {}). Response withheld.",
            leaked_name
        )));
    }

    // Audit successful proxy execution
    let credential_names: Vec<&str> = placeholder_names.iter().map(|s| s.as_str()).collect();
    let event = AuditEvent::builder(AuditEventType::ProxyRequestExecuted)
        .action("vend_credential")
        .workspace_actor(&auth.workspace.id, &auth.workspace.name)
        .resource_type("proxy")
        .correlation_id(&corr.0)
        .decision(AuditDecision::Permit, Some("bypass:proxy_executed"))
        .details(serde_json::json!({
            "target_url": req.url,
            "method": req.method,
            "credential_name": credential_names.first().copied().unwrap_or(""),
            "credentials_used": credential_names,
            "upstream_status": status_code,
        }))
        .build();
    if let Err(e) = state.store.append_audit_event(&event).await {
        tracing::warn!(error = %e, "Failed to write audit event");
    }

    metrics::counter!("proxy_requests_total", "status" => "success").increment(1);

    // Drop credential values from memory
    drop(credential_values);
    drop(credential_pairs);

    let body_opt = if response_body.is_empty() {
        None
    } else {
        Some(response_body)
    };

    Ok(Json(ApiResponse::ok(ProxyExecuteResponse {
        status_code,
        headers: response_headers,
        body: body_opt,
    })))
}

/// Follow same-domain redirects manually (up to 10 hops).
/// Cross-domain redirects are NOT followed — the redirect response is returned as-is.
async fn send_with_same_domain_redirects(
    client: reqwest::Client,
    initial_request: reqwest::RequestBuilder,
    original_url: &str,
    headers: &HashMap<String, String>,
    body: Option<&str>,
    allow_loopback: bool,
) -> Result<reqwest::Response, reqwest::Error> {
    let mut response = initial_request.send().await?;
    let original_parsed = reqwest::Url::parse(original_url).ok();

    for _ in 0..10 {
        if !response.status().is_redirection() {
            return Ok(response);
        }

        let location = match response.headers().get("location") {
            Some(loc) => match loc.to_str() {
                Ok(s) => s.to_string(),
                Err(_) => return Ok(response),
            },
            None => return Ok(response),
        };

        // Resolve relative URLs against the original URL
        let redirect_url = match reqwest::Url::parse(&location) {
            Ok(url) => url,
            Err(_) => {
                // Try resolving as relative
                match original_parsed
                    .as_ref()
                    .and_then(|base| base.join(&location).ok())
                {
                    Some(url) => url,
                    None => return Ok(response),
                }
            }
        };

        // Check same-domain: scheme + host + port must match
        let is_same_domain = original_parsed.as_ref().is_some_and(|orig| {
            orig.scheme() == redirect_url.scheme()
                && orig.host() == redirect_url.host()
                && orig.port() == redirect_url.port()
        });

        if !is_same_domain {
            // Cross-domain redirect — return the redirect response without following
            return Ok(response);
        }

        // SSRF check on redirect target (even same-domain could resolve to private IP)
        if !allow_loopback && validate_proxy_target(redirect_url.as_str()).is_err() {
            return Ok(response);
        }

        // Follow same-domain redirect with a GET (standard redirect behavior).
        // Strip credential-bearing headers to prevent leaking secrets if the
        // redirect target echoes headers or logs them.
        let mut req_builder = client.get(redirect_url.as_str());
        for (key, value) in headers {
            let lower = key.to_ascii_lowercase();
            if lower == "authorization" || lower == "cookie" || lower == "proxy-authorization" {
                continue; // Strip credential headers on redirect
            }
            req_builder = req_builder.header(key.as_str(), value.as_str());
        }
        // Note: body is not forwarded on redirects (standard HTTP behavior)
        let _ = body;
        response = req_builder.send().await?;
    }

    // Max redirects reached — return whatever we got
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blocked_headers() {
        assert!(is_blocked_header("Host"));
        assert!(is_blocked_header("host"));
        assert!(is_blocked_header("HOST"));
        assert!(is_blocked_header("Authorization"));
        assert!(is_blocked_header("authorization"));
        assert!(is_blocked_header("Cookie"));
        assert!(is_blocked_header("Set-Cookie"));
        assert!(is_blocked_header("X-CSRF-Token"));
        assert!(is_blocked_header("x-csrf-token"));
        assert!(is_blocked_header("Transfer-Encoding"));
        assert!(is_blocked_header("Content-Length"));
    }

    #[test]
    fn test_allowed_headers() {
        assert!(!is_blocked_header("X-Custom-Header"));
        assert!(!is_blocked_header("Content-Type"));
        assert!(!is_blocked_header("Accept"));
        assert!(!is_blocked_header("x-amz-date"));
        assert!(!is_blocked_header("x-amz-content-sha256"));
    }
}
