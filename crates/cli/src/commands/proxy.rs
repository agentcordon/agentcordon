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
    body: String,
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
        let (key, value) = h
            .split_once(':')
            .ok_or_else(|| CliError::general(format!("invalid header format: {h} (expected KEY:VALUE)")))?;
        headers.insert(key.trim().to_string(), value.trim().to_string());
    }

    // Handle @file body
    let body = match body {
        Some(b) if b.starts_with('@') => {
            let path = &b[1..];
            Some(
                std::fs::read_to_string(path)
                    .map_err(|e| CliError::general(format!("failed to read body file {path}: {e}")))?,
            )
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

    let resp: ProxyResponse = client.post("/proxy", &req).await?;
    let data = resp.data;

    if raw_output {
        // Just the body for piping
        print!("{}", data.body);
        return Ok(());
    }

    if json_output {
        // Pretty-print the body as JSON if possible
        println!("HTTP {}", data.status_code);
        for (k, v) in &data.headers {
            println!("{k}: {v}");
        }
        println!();
        if let Ok(json_val) = serde_json::from_str::<serde_json::Value>(&data.body) {
            println!(
                "{}",
                serde_json::to_string_pretty(&json_val).unwrap_or(data.body)
            );
        } else {
            println!("{}", data.body);
        }
    } else {
        println!("HTTP {}", data.status_code);
        for (k, v) in &data.headers {
            println!("{k}: {v}");
        }
        println!();
        println!("{}", data.body);
    }

    if data.status_code >= 400 {
        return Err(CliError::upstream_error(format!(
            "upstream returned HTTP {}",
            data.status_code
        )));
    }

    Ok(())
}
