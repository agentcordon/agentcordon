//! `agentcordon register` — initiate RFC 8628 device flow.
//!
//! UX mirrors `gh auth login`: print the one-time code, pause for Enter,
//! open the activation URL in the user's browser, then poll the broker's
//! `/status` endpoint until the background device-code poll task inside
//! the broker reports the workspace as registered (or errored).

use std::io::{self, BufRead, Write};
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
    user_code: String,
    verification_uri: String,
    #[serde(default)]
    verification_uri_complete: Option<String>,
    expires_in: u64,
    #[allow(dead_code)]
    #[serde(default)]
    interval: Option<u64>,
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

/// Register this workspace with the broker via device flow.
pub async fn run(scopes: Vec<String>, force: bool, no_browser: bool) -> Result<(), CliError> {
    let client = BrokerClient::connect_for_registration().await?;

    if force {
        println!("Force mode: clearing existing broker registration...");
        match client.post_signed_empty("/deregister").await {
            Ok(_) => println!("Previous registration cleared."),
            Err(_) => println!("No existing registration to clear (continuing)."),
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

    let workspace_name = std::env::current_dir()
        .ok()
        .and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_string()))
        .unwrap_or_else(|| "workspace".to_string());

    let public_key = client.keypair().public_key_hex();

    let scopes_joined = scopes.join(" ");
    let sign_payload = format!("{workspace_name}\n{public_key}\n{scopes_joined}");
    let signature = client.keypair().signing_key.sign(sign_payload.as_bytes());
    let signature_hex = hex::encode(signature.to_bytes());

    let req = RegisterRequest {
        workspace_name: workspace_name.clone(),
        public_key,
        scopes: scopes.clone(),
        signature: signature_hex,
    };

    let resp: RegisterResponse = client.post_unsigned("/register", &req).await?;

    let activation_url = resp
        .data
        .verification_uri_complete
        .clone()
        .unwrap_or_else(|| resp.data.verification_uri.clone());

    // Print to stderr per locked decision #7 so the user_code is visible
    // even when stdout is captured.
    eprintln!();
    eprintln!("! First, copy your one-time code: {}", resp.data.user_code);
    eprintln!(
        "Press Enter to open {} in your browser...",
        resp.data.verification_uri
    );
    let _ = io::stderr().flush();

    if !no_browser {
        // Wait for the user to press Enter, then open the browser.
        let stdin = io::stdin();
        let mut line = String::new();
        let _ = stdin.lock().read_line(&mut line);

        if open_browser(&activation_url).is_err() {
            eprintln!("Could not open browser automatically. Open this URL manually:");
            eprintln!("  {activation_url}");
        }
    } else {
        eprintln!("Open this URL in your browser to authorize:");
        eprintln!("  {activation_url}");
    }

    eprintln!();
    eprint!("Waiting for approval... ");
    let _ = io::stderr().flush();

    // Poll the broker until the background device-code task reports the
    // workspace as registered (or surfaces an error via the auth middleware).
    let timeout = Duration::from_secs(resp.data.expires_in.max(60));
    let poll_interval = Duration::from_secs(2);
    let start = std::time::Instant::now();

    loop {
        if start.elapsed() > timeout {
            eprintln!();
            return Err(CliError::general(
                "Code expired. Run agentcordon register to try again.",
            ));
        }

        tokio::time::sleep(poll_interval).await;

        match client.get_raw("/status").await {
            Ok((status, body)) => {
                if status == 200 {
                    if let Ok(status_resp) = serde_json::from_str::<StatusResponse>(&body) {
                        if status_resp.data.registered {
                            eprintln!("done!");
                            let scope_list = status_resp.data.scopes.join(", ");
                            println!("Logged in as {workspace_name}. Scopes: [{scope_list}]");
                            return Ok(());
                        }
                    }
                } else if status == 403 {
                    eprintln!();
                    return Err(CliError::authorization_denied("Authorization denied."));
                } else if status == 401 {
                    if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&body) {
                        let code = parsed
                            .get("error")
                            .and_then(|e| e.get("code"))
                            .and_then(|c| c.as_str())
                            .unwrap_or("");
                        if code == "registration_failed" {
                            let msg = parsed
                                .get("error")
                                .and_then(|e| e.get("message"))
                                .and_then(|m| m.as_str())
                                .unwrap_or("device flow failed")
                                .to_string();
                            eprintln!();
                            if msg.contains("expired") {
                                return Err(CliError::general(
                                    "Code expired. Run agentcordon register to try again.",
                                ));
                            }
                            if msg.contains("denied") {
                                return Err(CliError::authorization_denied(
                                    "Authorization denied.",
                                ));
                            }
                            return Err(CliError::authorization_denied(msg));
                        }
                    }
                }
            }
            Err(_) => {
                // Broker may be starting/restarting; keep polling.
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
    let cmd = "cmd";
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    return Err(CliError::general("cannot detect browser command"));

    #[cfg(target_os = "windows")]
    let args: Vec<&str> = vec!["/C", "start", "", url];
    #[cfg(not(target_os = "windows"))]
    let args: Vec<&str> = vec![url];

    std::process::Command::new(cmd)
        .args(&args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|e| CliError::general(format!("failed to open browser: {e}")))?;

    Ok(())
}
