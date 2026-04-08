use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::broker::BrokerClient;
use crate::error::CliError;

#[derive(Serialize)]
struct ProxyRequest {
    method: String,
    url: String,
    credential: String,
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    headers: HashMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    body: Option<String>,
}

#[derive(Deserialize)]
struct ProxyResponse {
    data: ProxyData,
}

#[derive(Deserialize)]
struct ProxyData {
    status_code: u16,
    headers: HashMap<String, String>,
    body: serde_json::Value,
}

/// Proxy an HTTP request through the broker with credential injection.
pub async fn run(
    credential: String,
    method: String,
    url: String,
    extra_headers: Vec<String>,
    body: Option<String>,
    json_output: bool,
    raw_output: bool,
) -> Result<(), CliError> {
    let client = BrokerClient::connect().await?;

    // Parse extra headers
    let mut headers = HashMap::new();
    for h in &extra_headers {
        let (key, value) = h.split_once(':').ok_or_else(|| {
            CliError::general(format!("invalid header format: {h} (expected KEY:VALUE)"))
        })?;
        headers.insert(key.trim().to_string(), value.trim().to_string());
    }

    // Handle @file body
    let body =
        match body {
            Some(b) if b.starts_with('@') => {
                let path = &b[1..];
                Some(std::fs::read_to_string(path).map_err(|e| {
                    CliError::general(format!("failed to read body file {path}: {e}"))
                })?)
            }
            other => other,
        };

    let req = ProxyRequest {
        method: method.to_uppercase(),
        url,
        credential,
        headers,
        body,
    };

    let (status, body_text) = client.post_raw("/proxy", &req).await?;
    if !(200..300).contains(&status) {
        // Try to render the broker's error envelope with any helpful fields
        // (e.g. server-side `candidates` array on a 300 Multiple Choices for
        // ambiguous credential names). Fall back to a generic message.
        if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&body_text) {
            if let Some(err) = parsed.get("error") {
                let code = err.get("code").and_then(|c| c.as_str()).unwrap_or("error");
                let message = err
                    .get("message")
                    .and_then(|m| m.as_str())
                    .unwrap_or("request failed");
                eprintln!("Error: {} ({})", message, code);
                if let Some(candidates) = err.get("candidates").and_then(|c| c.as_array()) {
                    if !candidates.is_empty() {
                        eprintln!("\nHint: multiple credentials match. Use one of these IDs:");
                        for cand in candidates {
                            let name = cand
                                .get("name")
                                .and_then(|n| n.as_str())
                                .unwrap_or("(unknown)");
                            let id = cand
                                .get("id")
                                .and_then(|i| i.as_str())
                                .unwrap_or("(unknown)");
                            eprintln!("  {id}  {name}");
                        }
                    }
                }
                return Err(CliError::upstream_error(format!(
                    "broker returned HTTP {status}"
                )));
            }
        }
        return Err(CliError::general(format!(
            "broker returned HTTP {status}: {body_text}"
        )));
    }

    let resp: ProxyResponse = serde_json::from_str(&body_text)
        .map_err(|e| CliError::general(format!("invalid proxy response: {e}")))?;
    let data = resp.data;
    let body_str = match &data.body {
        serde_json::Value::String(s) => s.clone(),
        other => serde_json::to_string(other).unwrap_or_default(),
    };

    if raw_output {
        print!("{body_str}");
        return Ok(());
    }

    if json_output {
        println!("HTTP {}", data.status_code);
        for (k, v) in &data.headers {
            println!("{k}: {v}");
        }
        println!();
        println!(
            "{}",
            serde_json::to_string_pretty(&data.body).unwrap_or(body_str)
        );
    } else {
        println!("HTTP {}", data.status_code);
        for (k, v) in &data.headers {
            println!("{k}: {v}");
        }
        println!();
        println!("{body_str}");
    }

    if data.status_code >= 400 {
        return Err(CliError::upstream_error(format!(
            "upstream returned HTTP {}",
            data.status_code
        )));
    }

    Ok(())
}
