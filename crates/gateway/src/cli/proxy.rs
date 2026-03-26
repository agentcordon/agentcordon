use std::collections::HashMap;

use agent_cordon_core::proxy::url_safety::validate_proxy_target;

use super::auth;
use super::state::{self, WorkspaceState};
use super::GlobalFlags;
use crate::cp_client::CredentialMaterial;
use crate::identity::WorkspaceIdentity;
use crate::{credential_transform, vend};

pub async fn run(
    flags: &GlobalFlags,
    credential: &str,
    method: &str,
    url: &str,
    headers: &[String],
    body: Option<&str>,
    verbose: bool,
) -> Result<(), String> {
    // 1. Ensure JWT (authenticates to server via challenge-response)
    let jwt = auth::ensure_jwt(flags).await?;

    // 2. Resolve server URL (NOT device URL)
    let st = WorkspaceState::load();
    let server_url = st.resolve_server_url(&flags.server);

    // 3. Load workspace identity to get P-256 encryption key
    let workspace_dir = state::workspace_dir();
    let identity = WorkspaceIdentity::load_from_dir(&workspace_dir)
        .map_err(|e| format!("failed to load workspace identity: {}", e))?;

    // 4. Build HTTP client
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .user_agent("agentcordon-cli/1.3.0")
        .build()
        .map_err(|e| format!("failed to create HTTP client: {}", e))?;

    // 5. Vend + ECIES decrypt
    // For name-based lookups, use vend-device/{name} directly (avoids LIST permission check).
    // For UUID-based lookups, use the existing credentials/{id}/vend endpoint.
    let vend_result = if uuid::Uuid::parse_str(credential).is_ok() {
        vend::vend_and_decrypt(
            &http,
            &server_url,
            &jwt,
            &identity.encryption_key,
            credential,
        )
        .await
    } else {
        vend::vend_and_decrypt_by_name(
            &http,
            &server_url,
            &jwt,
            &identity.encryption_key,
            credential,
        )
        .await
    }
    .map_err(|e| format!("credential vend failed: {}", e))?;

    // 6. SSRF validation on target URL
    let allow_loopback = std::env::var("AGTCRDN_PROXY_ALLOW_LOOPBACK")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false);

    if !allow_loopback {
        validate_proxy_target(url).map_err(|reason| {
            format!(
                "blocked by SSRF protection: {}. Set AGTCRDN_PROXY_ALLOW_LOOPBACK=true for local development",
                reason
            )
        })?;
    }

    // 7. Parse user-provided headers
    let mut user_headers: HashMap<String, String> = HashMap::new();
    for h in headers {
        if let Some((k, v)) = h.split_once(':') {
            user_headers.insert(k.trim().to_string(), v.trim().to_string());
        }
    }

    // 8. Apply credential transform (bearer, basic, api_key, etc.)
    let material = CredentialMaterial {
        credential_type: vend_result.credential.credential_type,
        value: vend_result.credential.value,
        username: vend_result.credential.username,
        metadata: vend_result.credential.metadata,
    };

    let transformed = credential_transform::apply(
        &material,
        vend_result.transform_name.as_deref(),
        method,
        url,
        &user_headers,
        body,
    )
    .map_err(|e| format!("credential transform failed: {}", e))?;

    // Merge transform headers into user headers (transform wins on conflict)
    for (k, v) in &transformed.headers {
        user_headers.insert(k.clone(), v.clone());
    }

    // Build final URL with any query params from the transform
    let final_url = if transformed.query_params.is_empty() {
        url.to_string()
    } else {
        let query_string: Vec<String> = transformed
            .query_params
            .iter()
            .map(|(k, v)| format!("{}={}", urlencoding(k), urlencoding(v)))
            .collect();
        let separator = if url.contains('?') { "&" } else { "?" };
        format!("{}{}{}", url, separator, query_string.join("&"))
    };

    // 9. Make the upstream HTTP call
    let http_method = reqwest::Method::from_bytes(method.to_uppercase().as_bytes())
        .map_err(|_| format!("invalid HTTP method: {}", method))?;

    let mut request = http.request(http_method, &final_url);
    for (key, value) in &user_headers {
        request = request.header(key.as_str(), value.as_str());
    }
    if let Some(body_str) = body {
        if let Ok(json_body) = serde_json::from_str::<serde_json::Value>(body_str) {
            request = request.json(&json_body);
        } else {
            request = request.body(body_str.to_string());
        }
    }

    let response = request
        .send()
        .await
        .map_err(|e| format!("upstream request failed: {}", e))?;

    // 10. Print response
    let resp_status = response.status().as_u16();
    let mut resp_headers = HashMap::new();
    for (key, value) in response.headers() {
        if let Ok(v) = value.to_str() {
            resp_headers.insert(key.to_string(), v.to_string());
        }
    }
    let resp_body = response
        .text()
        .await
        .map_err(|e| format!("failed to read response: {}", e))?;

    if flags.json || verbose {
        // Full envelope: status + headers + body
        let body_json: serde_json::Value =
            serde_json::from_str(&resp_body).unwrap_or(serde_json::Value::String(resp_body));
        let envelope = serde_json::json!({
            "status": resp_status,
            "headers": resp_headers,
            "body": body_json,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&envelope).expect("JSON serialization cannot fail")
        );
    } else {
        if resp_status >= 400 {
            return Err(format!("HTTP {} error: {}", resp_status, resp_body));
        }
        // Body-only for agent-friendly consumption
        if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&resp_body) {
            println!(
                "{}",
                serde_json::to_string_pretty(&parsed).expect("JSON serialization cannot fail")
            );
        } else {
            println!("{}", resp_body);
        }
    }

    Ok(())
}

/// Minimal percent-encoding for query parameter keys/values.
fn urlencoding(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' | '.' | '~' => c.to_string(),
            _ => format!("%{:02X}", c as u32),
        })
        .collect()
}
