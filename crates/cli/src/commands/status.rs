use serde::Deserialize;

use crate::broker::BrokerClient;
use crate::error::CliError;

#[derive(Deserialize)]
struct StatusResponse {
    data: StatusData,
}

#[derive(Deserialize)]
struct StatusData {
    registered: bool,
    #[serde(default)]
    scopes: Vec<String>,
    token_expires_at: Option<String>,
    token_status: Option<String>,
    server_url: Option<String>,
}

/// Check workspace registration and broker connectivity.
pub async fn run() -> Result<(), CliError> {
    let client = BrokerClient::connect().await?;

    let resp: StatusResponse = client.get("/status").await?;
    let data = resp.data;

    println!("Broker: {} (healthy)", client.base_url());

    if let Some(server_url) = &data.server_url {
        println!("Server: {server_url} (reachable)");
    }

    println!("Workspace: {}", client.keypair().identity());
    println!("Registered: {}", if data.registered { "yes" } else { "no" });

    if !data.scopes.is_empty() {
        println!("Scopes: {}", data.scopes.join(", "));
    }

    if let Some(token_status) = &data.token_status {
        let expires = data
            .token_expires_at
            .as_deref()
            .map(format_expiry)
            .unwrap_or_default();
        println!("Token: {token_status}{expires}");
    }

    Ok(())
}

/// Format an ISO 8601 expiry time as a human-readable duration.
fn format_expiry(expires_at: &str) -> String {
    if let Ok(expiry) = chrono::DateTime::parse_from_rfc3339(expires_at) {
        let now = chrono::Utc::now();
        let diff = expiry.signed_duration_since(now);
        if diff.num_seconds() <= 0 {
            return " (expired)".to_string();
        }
        let mins = diff.num_minutes();
        let secs = diff.num_seconds() % 60;
        format!(" (expires in {mins}m {secs:02}s)")
    } else {
        String::new()
    }
}
