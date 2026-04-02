use std::time::Duration;

use ed25519_dalek::Signer;
use serde::{Deserialize, Serialize};

use crate::broker::BrokerClient;
use crate::error::CliError;

#[derive(Serialize)]
struct RegisterRequest {
    workspace_name: String,
    public_key: String,
    scopes: Vec<String>,
    signature: String,
}

#[derive(Deserialize)]
struct RegisterResponse {
    data: RegisterData,
}

#[derive(Deserialize)]
struct RegisterData {
    authorization_url: String,
    #[allow(dead_code)]
    status: String,
}

#[derive(Deserialize)]
struct StatusResponse {
    data: StatusData,
}

#[derive(Deserialize)]
struct StatusData {
    registered: bool,
    #[serde(default)]
    scopes: Vec<String>,
}

/// Register this workspace with the broker, initiating OAuth consent.
pub async fn run(scopes: Vec<String>, force: bool) -> Result<(), CliError> {
    let client = BrokerClient::connect_for_registration().await?;

    // If --force, clear any stale broker registration first
    if force {
        println!("Force mode: clearing existing broker registration...");
        match client.post_signed_empty("/deregister").await {
            Ok(_) => println!("Previous registration cleared."),
            Err(_) => {
                // Not registered or broker doesn't recognize us — that's fine
                println!("No existing registration to clear (continuing).");
            }
        }
    }

    let scopes = if scopes.is_empty() {
        vec![
            "credentials:discover".to_string(),
            "credentials:vend".to_string(),
            "mcp:discover".to_string(),
            "mcp:invoke".to_string(),
        ]
    } else {
        scopes
    };

    // Derive workspace name from current directory
    let workspace_name = std::env::current_dir()
        .ok()
        .and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_string()))
        .unwrap_or_else(|| "workspace".to_string());

    let public_key = client.keypair().public_key_hex();

    // Sign: workspace_name \n public_key \n scopes_joined
    // Field separators prevent boundary manipulation attacks.
    let scopes_joined = scopes.join(" ");
    let sign_payload = format!("{workspace_name}\n{public_key}\n{scopes_joined}");
    let signature = client
        .keypair()
        .signing_key
        .sign(sign_payload.as_bytes());
    let signature_hex = hex::encode(signature.to_bytes());

    let req = RegisterRequest {
        workspace_name,
        public_key,
        scopes: scopes.clone(),
        signature: signature_hex,
    };

    let resp: RegisterResponse = client.post_unsigned("/register", &req).await?;

    // Try to open browser
    let url = &resp.data.authorization_url;
    if open_browser(url).is_err() {
        println!("Open this URL in your browser to authorize:");
        println!("  {url}");
    } else {
        println!("Opened authorization URL in browser.");
    }

    // Poll for registration completion (timeout: 5 minutes)
    println!("Waiting for authorization...");
    let timeout = Duration::from_secs(300);
    let poll_interval = Duration::from_secs(2);
    let start = std::time::Instant::now();

    loop {
        if start.elapsed() > timeout {
            return Err(CliError::general(
                "registration timed out. Visit the URL manually.",
            ));
        }

        tokio::time::sleep(poll_interval).await;

        match client.get_raw("/status").await {
            Ok((status, body)) => {
                if status == 200 {
                    if let Ok(status_resp) = serde_json::from_str::<StatusResponse>(&body) {
                        if status_resp.data.registered {
                            let scope_list = status_resp.data.scopes.join(", ");
                            println!("Registered successfully. Scopes: [{scope_list}]");
                            return Ok(());
                        }
                    }
                } else if status == 403 {
                    return Err(CliError::authorization_denied(
                        "authorization denied by user",
                    ));
                }
            }
            Err(_) => {
                // Broker may be processing, continue polling
            }
        }
    }
}

/// Attempt to open URL in default browser.
fn open_browser(url: &str) -> Result<(), CliError> {
    #[cfg(target_os = "linux")]
    let cmd = "xdg-open";
    #[cfg(target_os = "macos")]
    let cmd = "open";
    #[cfg(target_os = "windows")]
    let cmd = "start";
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    return Err(CliError::general("cannot detect browser command"));

    std::process::Command::new(cmd)
        .arg(url)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|e| CliError::general(format!("failed to open browser: {e}")))?;

    Ok(())
}
