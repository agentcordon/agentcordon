use std::path::PathBuf;

use crate::error::CliError;
use crate::platform;

/// One-command onboarding: starts broker, generates keys, registers workspace.
pub async fn run(server_url: String) -> Result<(), CliError> {
    println!("Setting up AgentCordon...\n");

    // 1. Check/start broker
    let broker_url = ensure_broker_running(&server_url).await?;
    println!("  Broker: {broker_url}");

    // 2. Init keypair (idempotent)
    super::init::run("claude-code")?;

    // 3. Register with broker (default scopes, no force)
    let scopes = vec![
        "credentials:discover".to_string(),
        "credentials:vend".to_string(),
        "mcp:discover".to_string(),
        "mcp:invoke".to_string(),
    ];
    super::register::run(scopes, false, false).await?;

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

    let mut cmd = std::process::Command::new("agentcordon-broker");
    cmd.arg("--server-url")
        .arg(server_url)
        .arg("--port")
        .arg(broker_port.to_string())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());

    // On Windows, attach the broker to a Job Object so it dies when the
    // CLI exits (per v0.3.0 locked decision #4). On Unix this is a plain
    // `Command::spawn`.
    platform::spawn_broker(&mut cmd).map_err(|e| {
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

    Err(CliError::general("broker failed to start within 5 seconds"))
}

/// Try to discover an already-running broker.
async fn discover_existing_broker(client: &reqwest::Client) -> Result<String, CliError> {
    // 1. Environment override
    if let Ok(url) = std::env::var("AGTCRDN_BROKER_URL") {
        let url = url.trim_end_matches('/').to_string();
        if client.get(format!("{url}/health")).send().await.is_ok() {
            return Ok(url);
        }
    }

    // 2. Port file
    let port_path = broker_port_path()?;
    if let Ok(port_str) = std::fs::read_to_string(&port_path) {
        if let Ok(port) = port_str.trim().parse::<u16>() {
            let url = format!("http://localhost:{port}");
            if client.get(format!("{url}/health")).send().await.is_ok() {
                return Ok(url);
            }
        }
    }

    Err(CliError::general("no existing broker found"))
}

/// Get the broker port file path (~/.agentcordon/broker.port).
///
/// Returns an error if no user home directory can be resolved on the
/// current platform (e.g. `HOME` unset on Unix, `USERPROFILE` unset on
/// Windows). The caller surfaces this to the user rather than silently
/// writing to a nonsense path.
fn broker_port_path() -> Result<PathBuf, CliError> {
    broker_port_path_from(dirs::home_dir())
}

/// Inner form of `broker_port_path` taking the resolved home-dir lookup
/// as a parameter so the error path can be exercised under test without
/// relying on the host's `HOME` / passwd-database state.
fn broker_port_path_from(home: Option<PathBuf>) -> Result<PathBuf, CliError> {
    let home = home.ok_or_else(|| {
        CliError::general(
            "could not resolve user home directory; \
             set HOME (Unix/macOS) or USERPROFILE (Windows)",
        )
    })?;
    Ok(home.join(".agentcordon").join("broker.port"))
}

/// Pick a port for the broker (default 9876).
fn find_broker_port() -> u16 {
    9876
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, MutexGuard};
    use tempfile::TempDir;

    /// Serialise env-var mutation across parallel tests. `HOME` /
    /// `USERPROFILE` are process-global, so tests that touch them must
    /// run one at a time. Copy of the `EnvGuard` pattern in
    /// `crates/cli/src/commands/init.rs:413-435`.
    struct EnvGuard {
        _lock: MutexGuard<'static, ()>,
        prior_home: Option<String>,
        prior_userprofile: Option<String>,
    }

    impl EnvGuard {
        fn new() -> Self {
            static LOCK: Mutex<()> = Mutex::new(());
            let lock = LOCK.lock().unwrap_or_else(|e| e.into_inner());
            let prior_home = std::env::var("HOME").ok();
            let prior_userprofile = std::env::var("USERPROFILE").ok();
            Self {
                _lock: lock,
                prior_home,
                prior_userprofile,
            }
        }

        fn set_home(&self, path: &std::path::Path) {
            // SAFETY: tests are serialised via the mutex above.
            unsafe {
                std::env::set_var("HOME", path);
            }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            // SAFETY: tests are serialised via the mutex above.
            unsafe {
                match &self.prior_home {
                    Some(v) => std::env::set_var("HOME", v),
                    None => std::env::remove_var("HOME"),
                }
                match &self.prior_userprofile {
                    Some(v) => std::env::set_var("USERPROFILE", v),
                    None => std::env::remove_var("USERPROFILE"),
                }
            }
        }
    }

    #[test]
    fn resolves_home_when_present() {
        let dir = TempDir::new().unwrap();
        let guard = EnvGuard::new();
        guard.set_home(dir.path());

        let resolved = broker_port_path().expect("home should resolve");
        assert_eq!(
            resolved,
            dir.path().join(".agentcordon").join("broker.port")
        );
    }

    /// Pins the error path of the resolver without depending on whether
    /// the host's `dirs::home_dir()` returns `None` — on Linux the crate
    /// falls back to `getpwuid_r`, so simply clearing `HOME` does not
    /// force `None`. `broker_port_path_from` takes the lookup result as
    /// input, letting us exercise the `None` branch directly.
    #[test]
    fn errors_when_no_home() {
        let err = broker_port_path_from(None).expect_err("missing home should error");
        assert!(
            err.message.contains("home directory"),
            "unexpected error message: {}",
            err.message
        );
    }
}
