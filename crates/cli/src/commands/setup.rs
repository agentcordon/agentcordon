use std::path::PathBuf;

use crate::error::CliError;

/// One-command onboarding: starts broker, generates keys, registers workspace.
pub async fn run(server_url: String) -> Result<(), CliError> {
    println!("Setting up AgentCordon...\n");

    // 1. Check/start broker
    let broker_url = ensure_broker_running(&server_url).await?;
    println!("  Broker: {broker_url}");

    // 2. Init keypair (idempotent)
    super::init::run()?;

    // 3. Register with broker (default scopes, no force)
    let scopes = vec![
        "credentials:discover".to_string(),
        "credentials:vend".to_string(),
    ];
    super::register::run(scopes, false).await?;

    println!("\n  Setup complete! Try:");
    println!("    agentcordon credentials");
    println!("    agentcordon proxy <credential> GET <url>");
    Ok(())
}

/// Ensure the broker is running, starting it if necessary.
async fn ensure_broker_running(server_url: &str) -> Result<String, CliError> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(2))
        .build()
        .map_err(|e| CliError::general(format!("failed to create HTTP client: {e}")))?;

    // Try existing broker via env var or port file
    if let Ok(url) = discover_existing_broker(&client).await {
        return Ok(url);
    }

    // Start broker in background
    println!("  Starting broker daemon...");
    let broker_port = find_broker_port();

    std::process::Command::new("agentcordon-broker")
        .arg("--server-url")
        .arg(server_url)
        .arg("--port")
        .arg(broker_port.to_string())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|e| {
            CliError::general(format!(
                "failed to start broker: {e}\n\
                 Install it with: curl -fsSL http://your-server/install.sh | bash"
            ))
        })?;

    // Wait for health
    let broker_url = format!("http://localhost:{broker_port}");
    for _ in 0..20 {
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        if client
            .get(format!("{broker_url}/health"))
            .send()
            .await
            .is_ok()
        {
            return Ok(broker_url);
        }
    }

    Err(CliError::general(
        "broker failed to start within 5 seconds",
    ))
}

/// Try to discover an already-running broker.
async fn discover_existing_broker(client: &reqwest::Client) -> Result<String, CliError> {
    // 1. Environment override
    if let Ok(url) = std::env::var("AGTCRDN_BROKER_URL") {
        let url = url.trim_end_matches('/').to_string();
        if client
            .get(format!("{url}/health"))
            .send()
            .await
            .is_ok()
        {
            return Ok(url);
        }
    }

    // 2. Port file
    let port_path = broker_port_path();
    if let Ok(port_str) = std::fs::read_to_string(&port_path) {
        if let Ok(port) = port_str.trim().parse::<u16>() {
            let url = format!("http://localhost:{port}");
            if client
                .get(format!("{url}/health"))
                .send()
                .await
                .is_ok()
            {
                return Ok(url);
            }
        }
    }

    Err(CliError::general("no existing broker found"))
}

/// Get the broker port file path (~/.agentcordon/broker.port).
fn broker_port_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    PathBuf::from(home).join(".agentcordon").join("broker.port")
}

/// Pick a port for the broker (default 9876).
fn find_broker_port() -> u16 {
    9876
}
